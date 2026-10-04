//! [`OlmSessionManager`] -- per-`(user, device)` Olm 1:1 sessions:
//! `/keys/claim`, to-device encryption/decryption, and the payload-binding
//! checks that keep a forwarded/injected key from being trusted (plan §3
//! `crypto/olm_sessions.rs`; research doc §3.3's security note, §4.5's
//! "Olm session desync/corruption" pitfall).
//!
//! # Session storage: one record per session id, capped and evicted
//!
//! [`crate::store::CryptoStore::save_olm_session`] (a prior piece) takes a
//! `session_id` and REPLACES that session's own record -- it never keeps a
//! superseded ratchet snapshot around. This is a hard security property,
//! not a space optimization: an Olm session pickle IS its full ratchet
//! state, including every chain/message key it has derived and not yet
//! forgotten, so an un-replaced older snapshot of the SAME session id would
//! be a live forward-secrecy leak (an already-consumed message key
//! surviving somewhere the session's own current state has forgotten it)
//! and a replay vector (that stale snapshot could decrypt a message its
//! later self has already consumed and would now correctly refuse). The
//! store also caps how many DISTINCT session ids it keeps per peer curve
//! key, evicting the least-recently-used one -- see
//! [`crate::store::CryptoStore::save_olm_session`]'s own doc.
//!
//! With that guarantee in place, this module's own job on both sides is
//! simple, no bookkeeping of its own required:
//!
//! - **Encrypting** ("the most recently used session for that device", plan
//!   §3) is the store's own first-returned entry --
//!   [`crate::store::CryptoStore::olm_sessions_for_device`] already orders
//!   its result most-recently-used first.
//! - **Decrypting** ("try each known session, newest first", plan §3) is a
//!   plain walk of that same list, in that same order -- at most one
//!   candidate per distinct session id, each one already the ONLY
//!   snapshot the store keeps for it, so there is no older, not-yet-
//!   consumed copy of an already-superseded state left anywhere to
//!   accidentally resurrect. This is what makes the "a pre-key message for
//!   an EXISTING session replays through that session, never a second
//!   inbound session" rule true safely: [`mail4agent_vodozemac::olm::Session::
//!   decrypt`] does not care whether a message is tagged pre-key or
//!   normal, it only needs a session whose receiving chains still cover
//!   that message's ratchet position -- and since only one, current
//!   snapshot of that session ever exists, its chains always reflect
//!   everything this module has ever actually consumed from it.
//!
//! # Every mutation is persisted before this module returns
//!
//! Every path that advances a session's ratchet -- encrypting, decrypting
//! through an existing session, or establishing a brand-new inbound
//! session -- calls [`crate::store::CryptoStore::save_olm_session`] (and,
//! for a new inbound session, [`OlmAccountState::create_inbound_session`]
//! persists the OTK-consuming account mutation too) before returning the
//! plaintext or ciphertext to the caller. [`crate::persist::FlushEpoch`]
//! (a later piece, `outgoing_queue`, M12) is what actually enforces the
//! barrier -- this module's job is only to make sure it always has
//! something to enforce: the mutation is marked dirty here, in the same
//! synchronous call, before any ciphertext that depended on it could leave
//! the process. Because this crate has no concurrency (`lib.rs`'s own
//! module doc), encryption for one device pair is sequential by
//! construction -- there is no interleaving that could reuse a message key
//! across two different plaintexts, which is exactly the "sending two Olm
//! messages at the same ratchet position" corruption class research doc
//! §4.5 warns about.
//!
//! # What "out of order" means here, and what a replay looks like
//!
//! vodozemac's receiving ratchet tolerates a message arriving out of send
//! order by stashing skipped message keys (up to its own internal limits)
//! and consuming the matching one the moment the corresponding message
//! actually arrives (`mail4agent_vodozemac`'s own `receiver_chain` module). Once a
//! message key has been used -- whether it was consumed in order or pulled
//! from the skipped stash -- it is deleted from that session's CURRENT
//! state, and the store's replace-not-append contract (above) means that
//! state IS the only copy left anywhere; decrypting the SAME ciphertext
//! bytes again always fails, first against every already-established
//! session for that sender (a `DecryptionError` here is simply "try the
//! next distinct session"), and then -- since a replayed message is still
//! tagged pre-key if the original was -- against [`OlmAccountState::
//! create_inbound_session`], which fails too, because the one-time key
//! that pre-key message names was already consumed the first time a
//! message from that same session established it. Either way, the net,
//! externally observable result [`OlmSessionManager::decrypt_to_device`]
//! gives a caller is an `Err`, never a second copy of the plaintext -- and
//! this holds even after a full unload/reload of the store from its
//! persisted records, since there is never a stale snapshot in those
//! records to reload in the first place.
//!
//! # Payload binding
//!
//! [`OlmSessionManager::decrypt_to_device`] rejects a successfully-
//! decrypted plaintext whose JSON payload does not bind to what the outer
//! event and this account's own identity claim: `recipient` must be this
//! account's own user id, `recipient_keys.ed25519` must be this account's
//! own Ed25519 key, `sender` must equal the to-device event's own `sender`
//! field, and `keys.ed25519` must equal the STORED Ed25519 key of the
//! device whose Curve25519 key is the envelope's `sender_key` -- never the
//! payload's own say-so. A `sender_key` this account has no
//! [`StoredDevice`] for at all marks that user outdated and returns
//! [`OlmDecryptError::UnknownSenderDevice`] so a caller can retry after a
//! `/keys/query` round trip, rather than silently trusting an unverified
//! claim. That lookup runs BEFORE any session is touched (it needs only the
//! event's own `sender` and the envelope's `sender_key`, both readable
//! without decrypting): a pre-key message from a not-yet-known device must
//! not consume its one-time key or advance a ratchet, or the retry after
//! the `/keys/query` would be a replay of already-consumed state and the
//! room key inside it would be lost for good.

use crate::canonical_json;
use crate::crypto::account::OlmAccountState;
use crate::crypto::device_tracker::{DeviceTracker, StoredDevice};
use crate::error::MessengerError;
use crate::ids::{DeviceId, RequestId, UserId};
use crate::store::CryptoStore;
use crate::wire::{OlmCiphertextInfo, OlmEncryptedContent, OutgoingRequest};
use base64::Engine;
use mail4agent_vodozemac::olm::{OlmMessage, Session, SessionConfig, SessionPickle};
use mail4agent_vodozemac::{Curve25519PublicKey, Ed25519PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The `signed_curve25519` key-type name `/keys/claim` uses (research doc
/// §3.2) -- this crate has exactly one one-time-key algorithm in scope.
const SIGNED_CURVE25519: &str = "signed_curve25519";

/// Base64 codec for wire-transported ciphertext/key bytes: unpadded
/// standard alphabet on encode, tolerant of an unexpected padding on
/// decode -- matches Matrix's own wire convention (and `mail4agent_vodozemac`'s
/// own internal pickle/message encoding), kept as this crate's own
/// independent wire-layer codec rather than reusing `mail4agent_vodozemac`'s pub
/// helpers, which exist for its pickle format, not as a cross-crate wire
/// utility (see this crate's `Cargo.toml` note on the `base64` dependency).
fn wire_base64_engine() -> base64::engine::GeneralPurpose {
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::NO_PAD
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    )
}

fn pickle_session(session: &Session) -> Result<Vec<u8>, MessengerError> {
    serde_json::to_vec(&session.pickle())
        .map_err(|source| MessengerError::Crypto(format!("encode pickled Olm session: {source}")))
}

fn unpickle_session(bytes: &[u8]) -> Result<Session, MessengerError> {
    let pickle: SessionPickle = serde_json::from_slice(bytes)
        .map_err(|source| MessengerError::Crypto(format!("decode pickled Olm session: {source}")))?;
    Ok(Session::from_pickle(pickle))
}

/// The Olm plaintext payload every to-device `m.room.encrypted` message
/// carries (research doc §3.1's "Olm-wrapped" shape) -- built by
/// [`OlmSessionManager::encrypt_to_device`], validated by
/// [`OlmSessionManager::decrypt_to_device`].
#[derive(Serialize, Deserialize)]
struct OlmPlaintextPayload {
    #[serde(rename = "type")]
    event_type: String,
    content: serde_json::Value,
    sender: UserId,
    sender_device: DeviceId,
    keys: OlmPlaintextKeys,
    recipient: UserId,
    recipient_keys: OlmPlaintextKeys,
}

#[derive(Serialize, Deserialize)]
struct OlmPlaintextKeys {
    ed25519: String,
}

/// `/keys/claim`'s response shape, the parts this module reads (research
/// doc §3.2): `one_time_keys.{user_id}.{device_id}.{key_id}` -> the
/// claimed key's own signed JSON object.
#[derive(Deserialize)]
struct KeysClaimResponseBody {
    #[serde(default)]
    one_time_keys: BTreeMap<UserId, BTreeMap<DeviceId, BTreeMap<String, serde_json::Value>>>,
}

/// The result of applying a `/keys/claim` response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeysClaimOutcome {
    /// Devices a fresh outbound session was established with.
    pub established: Vec<(UserId, DeviceId)>,
    /// Devices whose claimed key was refused -- never used to start a
    /// session.
    pub refused: Vec<KeysClaimRefusal>,
}

/// Why [`OlmSessionManager::on_keys_claim_response`] refused a claimed
/// one-time key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysClaimRefusal {
    /// The device the refused key was claimed for.
    pub user_id: UserId,
    /// The device the refused key was claimed for.
    pub device_id: DeviceId,
    /// Why it was refused.
    pub reason: String,
}

/// A successfully decrypted and payload-validated to-device event (plan
/// §3's field list).
#[derive(Debug, Clone, PartialEq)]
pub struct DecryptedToDevice {
    /// The sender, as bound by the validated payload (equal to the outer
    /// event's own `sender`).
    pub sender: UserId,
    /// The sending device's Curve25519 identity key.
    pub sender_device_curve25519: Curve25519PublicKey,
    /// The sending device's Ed25519 signing key.
    pub sender_ed25519: Ed25519PublicKey,
    /// The payload's own `type` (the inner to-device event type, e.g.
    /// `"m.room_key"`).
    pub event_type: String,
    /// The payload's own `content`.
    pub content: serde_json::Value,
}

/// Every way [`OlmSessionManager::decrypt_to_device`] can fail. Kept
/// distinct from [`MessengerError`] (rather than folding into
/// `MessengerError::Crypto`) because a caller must be able to tell
/// [`OlmDecryptError::UnknownSenderDevice`] -- a retry-after-`/keys/query`
/// condition, not a hard failure -- apart from every other variant.
#[derive(Debug, thiserror::Error)]
pub enum OlmDecryptError {
    /// The envelope's `ciphertext` map has no entry keyed by this
    /// account's own Curve25519 identity key -- this message was not
    /// addressed to this device at all.
    #[error("the Olm envelope has no ciphertext entry for this device's own curve25519 key")]
    NotAddressedToUs,
    /// The ciphertext body was not valid base64, or did not decode to a
    /// well-formed Olm message.
    #[error("malformed Olm ciphertext: {0}")]
    MalformedCiphertext(String),
    /// No known session for the sender's curve25519 key could decrypt this
    /// message, and it was not a pre-key message (so no new session could
    /// be established from it either).
    #[error("no known Olm session for sender key {0} decrypted this message, and it is not a pre-key message")]
    NoMatchingSession(String),
    /// A pre-key message failed to establish a fresh inbound session --
    /// e.g. the claimed one-time key is unknown to this account (already
    /// used, or never ours; this is also the symptom of a replayed
    /// pre-key message once its originating session already exists, see
    /// the module doc).
    #[error("failed to establish an inbound Olm session: {0}")]
    SessionEstablishment(String),
    /// The sender's `sender_key` (Curve25519) is not a device this
    /// account has stored keys for yet. `user_id` has been marked
    /// outdated; retry after a `/keys/query` round trip.
    #[error("sender device for curve25519 key {curve25519} is not yet known to this account")]
    UnknownSenderDevice {
        /// The event's claimed sender.
        user_id: UserId,
        /// The unrecognized sender curve25519 key, base64.
        curve25519: String,
    },
    /// The decrypted payload failed a binding check against the outer
    /// event or this account's own identity.
    #[error("payload binding check failed: {0}")]
    PayloadMismatch(String),
    /// The decrypted bytes were not the expected JSON payload shape.
    #[error("decrypted payload was not valid JSON: {0}")]
    InvalidPayload(#[from] serde_json::Error),
    /// A [`crate::store::CryptoStore`] operation failed.
    #[error("store: {0}")]
    Store(#[from] crate::store::StoreError),
    /// A [`MessengerError`] surfaced by another module this method calls
    /// into (account persistence, device-list decode, ...).
    #[error("{0}")]
    Messenger(#[from] MessengerError),
}

/// Per-`(user, device)` Olm 1:1 session management. See the module doc for
/// the storage-selection and payload-binding rules this type enforces.
/// Carries no state of its own -- every method reads/writes through the
/// caller's [`CryptoStore`] and [`OlmAccountState`].
pub struct OlmSessionManager;

impl OlmSessionManager {
    /// Converts a vodozemac [`OlmMessage`] into this crate's wire shape.
    pub fn encode_olm_message(message: &OlmMessage) -> OlmCiphertextInfo {
        let (message_type, ciphertext) = message.to_parts();
        OlmCiphertextInfo { message_type: message_type as u8, body: wire_base64_engine().encode(ciphertext) }
    }

    /// Reverses [`OlmSessionManager::encode_olm_message`].
    pub fn decode_olm_message(info: &OlmCiphertextInfo) -> Result<OlmMessage, MessengerError> {
        let bytes = wire_base64_engine()
            .decode(&info.body)
            .map_err(|source| MessengerError::Crypto(format!("malformed Olm ciphertext body: {source}")))?;
        OlmMessage::from_parts(info.message_type as usize, &bytes)
            .map_err(|source| MessengerError::Crypto(format!("malformed Olm message: {source}")))
    }

    /// Devices from `devices` this account has no Olm session with yet, in
    /// input order.
    pub fn sessions_missing_for<'a, S: CryptoStore>(
        store: &S,
        devices: &'a [StoredDevice],
    ) -> Result<Vec<&'a StoredDevice>, MessengerError> {
        let mut missing = Vec::new();
        for device in devices {
            let curve_b64 = device.curve25519.to_base64();
            if store.olm_sessions_for_device(&curve_b64)?.is_empty() {
                missing.push(device);
            }
        }
        Ok(missing)
    }

    /// Builds a `POST /keys/claim` request for `devices`, or `None` if
    /// `devices` is empty.
    pub fn keys_claim_request(id: RequestId, devices: &[&StoredDevice]) -> Option<OutgoingRequest> {
        if devices.is_empty() {
            return None;
        }
        let mut by_user: BTreeMap<UserId, serde_json::Map<String, serde_json::Value>> = BTreeMap::new();
        for device in devices {
            by_user.entry(device.user_id.clone()).or_default().insert(
                device.device_id.as_str().to_string(),
                serde_json::Value::String(SIGNED_CURVE25519.to_string()),
            );
        }
        let mut top = serde_json::Map::new();
        for (user_id, device_map) in by_user {
            top.insert(user_id.as_str().to_string(), serde_json::Value::Object(device_map));
        }
        let body = serde_json::json!({ "one_time_keys": serde_json::Value::Object(top) });
        Some(OutgoingRequest::keys_claim(id, body))
    }

    /// Applies a `/keys/claim` response: for each of `requested`, verifies
    /// the claimed key's signature against THAT device's own stored
    /// Ed25519 key (never a key the response body itself might claim),
    /// refuses an unsigned/mis-signed/absent key, and otherwise
    /// establishes and persists a fresh outbound [`Session`] immediately.
    /// A device present in `requested` but absent from the response
    /// (nothing left to claim) is silently skipped -- neither established
    /// nor refused.
    pub fn on_keys_claim_response<S: CryptoStore>(
        store: &mut S,
        account: &OlmAccountState,
        requested: &[&StoredDevice],
        body: &[u8],
    ) -> Result<KeysClaimOutcome, MessengerError> {
        let parsed: KeysClaimResponseBody = serde_json::from_slice(body)?;
        let mut outcome = KeysClaimOutcome::default();

        for device in requested {
            let Some(by_key_id) =
                parsed.one_time_keys.get(&device.user_id).and_then(|by_device| by_device.get(&device.device_id))
            else {
                continue;
            };
            let Some((key_id, raw)) = by_key_id.iter().next() else { continue };

            match Self::verify_and_claim(account, device, key_id, raw) {
                Ok(session) => {
                    let curve_b64 = device.curve25519.to_base64();
                    let session_id = session.session_id();
                    store.save_olm_session(&curve_b64, &session_id, pickle_session(&session)?)?;
                    outcome.established.push((device.user_id.clone(), device.device_id.clone()));
                }
                Err(reason) => outcome.refused.push(KeysClaimRefusal {
                    user_id: device.user_id.clone(),
                    device_id: device.device_id.clone(),
                    reason,
                }),
            }
        }

        Ok(outcome)
    }

    fn verify_and_claim(
        account: &OlmAccountState,
        device: &StoredDevice,
        key_id: &str,
        raw: &serde_json::Value,
    ) -> Result<Session, String> {
        if !key_id.starts_with(SIGNED_CURVE25519) {
            return Err(format!("unexpected one-time-key algorithm in key id {key_id:?}"));
        }
        let sig_key_id = format!("ed25519:{}", device.device_id.as_str());
        canonical_json::verify_json_signature(raw, device.user_id.as_str(), &sig_key_id, &device.ed25519)
            .map_err(|source| format!("claimed one-time key signature failed to verify: {source}"))?;

        let key_b64 = raw
            .get("key")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "claimed one-time key object has no \"key\" field".to_string())?;
        let one_time_key = Curve25519PublicKey::from_base64(key_b64)
            .map_err(|source| format!("malformed claimed one-time key: {source}"))?;

        account
            .create_outbound_session(SessionConfig::version_1(), device.curve25519, one_time_key)
            .map_err(|source| format!("failed to create outbound Olm session: {source}"))
    }

    /// Encrypts `content` (an inner to-device event's own `content`,
    /// tagged `event_type`) for `target`, using the most recently used
    /// session for that device (see the module doc). Persists the
    /// ratchet-advanced session before returning.
    pub fn encrypt_to_device<S: CryptoStore>(
        store: &mut S,
        account: &OlmAccountState,
        our_user_id: &UserId,
        our_device_id: &DeviceId,
        target: &StoredDevice,
        event_type: &str,
        content: serde_json::Value,
    ) -> Result<OlmEncryptedContent, MessengerError> {
        let their_curve_b64 = target.curve25519.to_base64();
        let sessions = store.olm_sessions_for_device(&their_curve_b64)?;
        // The store already orders these most-recently-used first (see the
        // module doc) -- the first entry IS "the most recently used
        // session for that device".
        let latest = sessions.into_iter().next().ok_or_else(|| {
            MessengerError::Crypto(format!(
                "no Olm session established with device {} of {} yet",
                target.device_id.as_str(),
                target.user_id.as_str()
            ))
        })?;
        let mut session = unpickle_session(&latest)?;

        let payload = OlmPlaintextPayload {
            event_type: event_type.to_string(),
            content,
            sender: our_user_id.clone(),
            sender_device: our_device_id.clone(),
            keys: OlmPlaintextKeys { ed25519: account.identity_keys().ed25519.to_base64() },
            recipient: target.user_id.clone(),
            recipient_keys: OlmPlaintextKeys { ed25519: target.ed25519.to_base64() },
        };
        let plaintext = serde_json::to_vec(&payload)?;

        let olm_message = session.encrypt(plaintext).map_err(|source| {
            MessengerError::Crypto(format!("Olm encrypt to {}: {source}", target.device_id.as_str()))
        })?;

        // Flush-before-send: the ratchet-advanced session lands on disk in
        // this same synchronous call, before the ciphertext below is ever
        // handed to a caller that might enqueue it for sending.
        let session_id = session.session_id();
        store.save_olm_session(&their_curve_b64, &session_id, pickle_session(&session)?)?;

        let mut ciphertext = BTreeMap::new();
        ciphertext.insert(their_curve_b64, Self::encode_olm_message(&olm_message));

        Ok(OlmEncryptedContent { sender_key: account.identity_keys().curve25519.to_base64(), ciphertext })
    }

    /// Decrypts and payload-validates one to-device `m.room.encrypted`
    /// (Olm) event. See the module doc for the exact ordering (existing
    /// sessions before a new inbound one) and binding checks.
    pub fn decrypt_to_device<S: CryptoStore>(
        store: &mut S,
        account: &mut OlmAccountState,
        our_user_id: &UserId,
        event_sender: &UserId,
        content: &OlmEncryptedContent,
    ) -> Result<DecryptedToDevice, OlmDecryptError> {
        let our_curve_b64 = account.identity_keys().curve25519.to_base64();
        let cipher_info = content.ciphertext.get(&our_curve_b64).ok_or(OlmDecryptError::NotAddressedToUs)?;
        let olm_message = Self::decode_olm_message(cipher_info)
            .map_err(|source| OlmDecryptError::MalformedCiphertext(source.to_string()))?;

        let sender_curve_b64 = content.sender_key.clone();

        // The sender's device must already be known -- checked before any
        // session is created or advanced (module doc, "Payload binding").
        let sender_devices = DeviceTracker::devices_for_user(store, event_sender)?;
        let Some(sender_device) = sender_devices.iter().find(|device| device.curve25519.to_base64() == sender_curve_b64) else {
            store.mark_user_tracked(event_sender, true)?;
            return Err(OlmDecryptError::UnknownSenderDevice { user_id: event_sender.clone(), curve25519: sender_curve_b64 });
        };

        // Already at most one snapshot per distinct session id, ordered
        // most-recently-used first (see the module doc) -- a plain walk in
        // that order is "try each known session, newest first" as-is.
        let known_sessions: Vec<Vec<u8>> = store.olm_sessions_for_device(&sender_curve_b64)?;

        let mut established: Option<(Session, Vec<u8>)> = None;
        for pickle_bytes in &known_sessions {
            let mut session = unpickle_session(pickle_bytes)
                .map_err(|source| OlmDecryptError::SessionEstablishment(format!("corrupt stored session: {source}")))?;
            if let Ok(plaintext) = session.decrypt(&olm_message) {
                established = Some((session, plaintext));
                break;
            }
        }

        let plaintext = match established {
            Some((session, plaintext)) => {
                let session_id = session.session_id();
                store.save_olm_session(&sender_curve_b64, &session_id, pickle_session(&session)?)?;
                plaintext
            }
            None => match &olm_message {
                OlmMessage::PreKey(pre_key_message) => {
                    let sender_curve = Curve25519PublicKey::from_base64(&sender_curve_b64).map_err(|source| {
                        OlmDecryptError::MalformedCiphertext(format!("malformed sender_key: {source}"))
                    })?;
                    let result = account
                        .create_inbound_session(store, SessionConfig::version_1(), sender_curve, pre_key_message)
                        .map_err(|source| OlmDecryptError::SessionEstablishment(source.to_string()))?;
                    let session_id = result.session.session_id();
                    store.save_olm_session(&sender_curve_b64, &session_id, pickle_session(&result.session)?)?;
                    result.plaintext
                }
                OlmMessage::Normal(_) => return Err(OlmDecryptError::NoMatchingSession(sender_curve_b64)),
            },
        };

        let payload: OlmPlaintextPayload = serde_json::from_slice(&plaintext)?;

        if payload.recipient != *our_user_id {
            return Err(OlmDecryptError::PayloadMismatch(format!(
                "payload recipient {:?} does not match this account's own user id {:?}",
                payload.recipient.as_str(),
                our_user_id.as_str()
            )));
        }
        let our_ed25519_b64 = account.identity_keys().ed25519.to_base64();
        if payload.recipient_keys.ed25519 != our_ed25519_b64 {
            return Err(OlmDecryptError::PayloadMismatch(
                "payload recipient_keys.ed25519 does not match this account's own ed25519 key".to_string(),
            ));
        }
        if payload.sender != *event_sender {
            return Err(OlmDecryptError::PayloadMismatch(format!(
                "payload sender {:?} does not match the to-device event's own sender {:?}",
                payload.sender.as_str(),
                event_sender.as_str()
            )));
        }

        if payload.keys.ed25519 != sender_device.ed25519.to_base64() {
            return Err(OlmDecryptError::PayloadMismatch(
                "payload keys.ed25519 does not match the stored ed25519 key of the sender device".to_string(),
            ));
        }

        Ok(DecryptedToDevice {
            sender: payload.sender,
            sender_device_curve25519: sender_device.curve25519,
            sender_ed25519: sender_device.ed25519,
            event_type: payload.event_type,
            content: payload.content,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{InsecurePlainCodecForTests, Store};

    fn new_store(device_id: &str) -> Store<InsecurePlainCodecForTests> {
        Store::new(DeviceId::parse(device_id).expect("valid device id"), InsecurePlainCodecForTests)
    }

    fn user(name: &str) -> UserId {
        UserId::parse(format!("@{name}:example.org")).expect("valid user id")
    }

    fn device(name: &str) -> DeviceId {
        DeviceId::parse(name).expect("valid device id")
    }

    /// No fallback-key consumption in scope for these tests -- reports the
    /// type as still available so `on_sync_counts` calls only exercise the
    /// one-time-key top-up path.
    fn fallback_present() -> Vec<String> {
        vec![SIGNED_CURVE25519.to_string()]
    }

    fn stored_device(user_id: &UserId, device_id: &DeviceId, account: &OlmAccountState) -> StoredDevice {
        let identity = account.identity_keys();
        StoredDevice {
            user_id: user_id.clone(),
            device_id: device_id.clone(),
            curve25519: identity.curve25519,
            ed25519: identity.ed25519,
            algorithms: vec!["m.olm.v1.curve25519-aes-sha2".to_string(), "m.megolm.v1.aes-sha2".to_string()],
            display_name: None,
            verified: false,
            blocked: false,
        }
    }

    /// Reshapes a real `/keys/upload` request body's `one_time_keys` map
    /// (built by [`OlmAccountState::keys_upload_request`]) into the
    /// `/keys/claim` response shape for `(user_id, device_id)`'s FIRST
    /// one-time key -- the two nest an identically-shaped signed key
    /// object, only the surrounding map keys differ.
    fn claim_response_body_from_upload(upload_body: &serde_json::Value, user_id: &UserId, device_id: &DeviceId) -> Vec<u8> {
        let one_time_keys =
            upload_body.get("one_time_keys").and_then(serde_json::Value::as_object).expect("upload carries OTKs");
        let (key_id, key_value) = one_time_keys.iter().next().expect("at least one OTK");
        serde_json::to_vec(&serde_json::json!({
            "one_time_keys": { user_id.as_str(): { device_id.as_str(): { key_id: key_value } } }
        }))
        .expect("valid JSON")
    }

    #[test]
    fn olm_session_established_via_claimed_otk() {
        let mut alice_store = new_store("ALICEDEV");
        let alice_account = OlmAccountState::load_or_create(&mut alice_store).expect("create alice's account");

        let bob_user = user("bob");
        let bob_device_id = device("BOBDEV");
        let mut bob_store = new_store("BOBDEV");
        let mut bob_account = OlmAccountState::load_or_create(&mut bob_store).expect("create bob's account");
        bob_account.on_sync_counts(&mut bob_store, 0, &fallback_present()).expect("top up bob's OTKs");

        let upload = bob_account
            .keys_upload_request(RequestId::next(0), &bob_user, &bob_device_id)
            .expect("builds a request")
            .expect("something to upload");
        let claim_body =
            claim_response_body_from_upload(&upload.body.expect("upload has a body"), &bob_user, &bob_device_id);
        let bob_device = stored_device(&bob_user, &bob_device_id, &bob_account);

        let outcome = OlmSessionManager::on_keys_claim_response(&mut alice_store, &alice_account, &[&bob_device], &claim_body)
            .expect("applies the claim response");

        assert_eq!(outcome.established, vec![(bob_user, bob_device_id)]);
        assert!(outcome.refused.is_empty());
        let sessions = alice_store
            .olm_sessions_for_device(&bob_account.identity_keys().curve25519.to_base64())
            .expect("no error");
        assert_eq!(sessions.len(), 1, "exactly one session established");
    }

    #[test]
    fn olm_session_rejects_out_of_order_ratchet_message() {
        let mut alice_store = new_store("ALICEDEV");
        let alice_account = OlmAccountState::load_or_create(&mut alice_store).expect("create alice's account");
        let alice_user = user("alice");
        let alice_device_id = device("ALICEDEV");

        let bob_user = user("bob");
        let bob_device_id = device("BOBDEV");
        let mut bob_store = new_store("BOBDEV");
        let mut bob_account = OlmAccountState::load_or_create(&mut bob_store).expect("create bob's account");
        bob_account.on_sync_counts(&mut bob_store, 0, &fallback_present()).expect("top up bob's OTKs");

        let upload = bob_account
            .keys_upload_request(RequestId::next(0), &bob_user, &bob_device_id)
            .expect("builds a request")
            .expect("something to upload");
        let claim_body =
            claim_response_body_from_upload(&upload.body.expect("upload has a body"), &bob_user, &bob_device_id);
        let bob_device = stored_device(&bob_user, &bob_device_id, &bob_account);
        OlmSessionManager::on_keys_claim_response(&mut alice_store, &alice_account, &[&bob_device], &claim_body)
            .expect("alice establishes a session with bob");

        // Bob needs to know Alice's device before he can validate a
        // payload from her.
        let alice_device_keys =
            alice_account.device_keys_json(&alice_user, &alice_device_id).expect("sign alice's device_keys");
        let query_body = serde_json::to_vec(&serde_json::json!({
            "device_keys": { alice_user.as_str(): { alice_device_id.as_str(): alice_device_keys } }
        }))
        .expect("valid JSON");
        DeviceTracker::on_keys_query_response(&mut bob_store, &query_body).expect("bob learns alice's device");

        // Alice sends two messages. Neither is ever answered, so both stay
        // tagged pre-key (module doc) -- Bob still has to be able to
        // decrypt them out of order.
        let message_0 = OlmSessionManager::encrypt_to_device(
            &mut alice_store,
            &alice_account,
            &alice_user,
            &alice_device_id,
            &bob_device,
            "m.test",
            serde_json::json!({ "i": 0 }),
        )
        .expect("encrypt message 0");
        let message_1 = OlmSessionManager::encrypt_to_device(
            &mut alice_store,
            &alice_account,
            &alice_user,
            &alice_device_id,
            &bob_device,
            "m.test",
            serde_json::json!({ "i": 1 }),
        )
        .expect("encrypt message 1");

        // Out of order: message 1 arrives and decrypts first (establishing
        // Bob's session), then message 0 fills the gap.
        let decrypted_1 = OlmSessionManager::decrypt_to_device(&mut bob_store, &mut bob_account, &bob_user, &alice_user, &message_1)
            .expect("message 1 decrypts, establishing the session");
        assert_eq!(decrypted_1.content, serde_json::json!({ "i": 1 }));

        let decrypted_0 = OlmSessionManager::decrypt_to_device(&mut bob_store, &mut bob_account, &bob_user, &alice_user, &message_0)
            .expect("message 0 decrypts through the same, already-established session");
        assert_eq!(decrypted_0.content, serde_json::json!({ "i": 0 }));

        // Replay: the exact same ciphertext bytes, decrypted again, must
        // never yield a second plaintext (module doc's precise definition
        // of what a replay looks like at the vodozemac layer).
        let replay = OlmSessionManager::decrypt_to_device(&mut bob_store, &mut bob_account, &bob_user, &alice_user, &message_0);
        assert!(replay.is_err(), "replaying an already-decrypted message must be rejected");
        assert!(
            matches!(replay, Err(OlmDecryptError::SessionEstablishment(_))),
            "got {replay:?}"
        );
    }

    #[test]
    fn replay_is_rejected_after_reload_from_records() {
        let mut alice_store = new_store("ALICEDEV");
        let alice_account = OlmAccountState::load_or_create(&mut alice_store).expect("create alice's account");
        let alice_user = user("alice");
        let alice_device_id = device("ALICEDEV");

        let bob_user = user("bob");
        let bob_device_id = device("BOBDEV");
        let mut bob_store = new_store("BOBDEV");
        let mut bob_account = OlmAccountState::load_or_create(&mut bob_store).expect("create bob's account");
        bob_account.on_sync_counts(&mut bob_store, 0, &fallback_present()).expect("top up bob's OTKs");

        let upload = bob_account
            .keys_upload_request(RequestId::next(0), &bob_user, &bob_device_id)
            .expect("builds a request")
            .expect("something to upload");
        let claim_body =
            claim_response_body_from_upload(&upload.body.expect("upload has a body"), &bob_user, &bob_device_id);
        let bob_device = stored_device(&bob_user, &bob_device_id, &bob_account);
        OlmSessionManager::on_keys_claim_response(&mut alice_store, &alice_account, &[&bob_device], &claim_body)
            .expect("alice establishes a session with bob");

        let alice_device_keys =
            alice_account.device_keys_json(&alice_user, &alice_device_id).expect("sign alice's device_keys");
        let query_body = serde_json::to_vec(&serde_json::json!({
            "device_keys": { alice_user.as_str(): { alice_device_id.as_str(): alice_device_keys } }
        }))
        .expect("valid JSON");
        DeviceTracker::on_keys_query_response(&mut bob_store, &query_body).expect("bob learns alice's device");

        let message_0 = OlmSessionManager::encrypt_to_device(
            &mut alice_store,
            &alice_account,
            &alice_user,
            &alice_device_id,
            &bob_device,
            "m.test",
            serde_json::json!({ "i": 0 }),
        )
        .expect("encrypt message 0");

        OlmSessionManager::decrypt_to_device(&mut bob_store, &mut bob_account, &bob_user, &alice_user, &message_0)
            .expect("message 0 decrypts and establishes bob's session");

        // Flush everything bob has dirtied so far (account, alice's
        // device, the Olm session) into one set of durable records, then
        // rebuild a completely fresh `Store`/`OlmAccountState` from just
        // those records -- simulating a process restart between the first
        // decrypt and the replay attempt below.
        let batch = bob_store.take_flush_batch().expect("decrypting dirtied the store");
        bob_store.ack_flush(batch.id);
        let mut reloaded_store =
            Store::load(batch.records, InsecurePlainCodecForTests, bob_device_id.clone()).expect("reload succeeds");
        let mut reloaded_account =
            OlmAccountState::load_or_create(&mut reloaded_store).expect("reload reuses the persisted account");

        let replay = OlmSessionManager::decrypt_to_device(
            &mut reloaded_store,
            &mut reloaded_account,
            &bob_user,
            &alice_user,
            &message_0,
        );
        assert!(replay.is_err(), "a replay must still be rejected after a full store reload");
        assert!(
            matches!(replay, Err(OlmDecryptError::SessionEstablishment(_))),
            "got {replay:?}"
        );
    }

    #[test]
    fn unknown_sender_prekey_message_stays_decryptable_after_the_device_is_learned() {
        let mut alice_store = new_store("ALICEDEV");
        let alice_account = OlmAccountState::load_or_create(&mut alice_store).expect("create alice's account");
        let alice_user = user("alice");
        let alice_device_id = device("ALICEDEV");

        let bob_user = user("bob");
        let bob_device_id = device("BOBDEV");
        let mut bob_store = new_store("BOBDEV");
        let mut bob_account = OlmAccountState::load_or_create(&mut bob_store).expect("create bob's account");
        bob_account.on_sync_counts(&mut bob_store, 0, &fallback_present()).expect("top up bob's OTKs");

        let upload = bob_account
            .keys_upload_request(RequestId::next(0), &bob_user, &bob_device_id)
            .expect("builds a request")
            .expect("something to upload");
        let claim_body =
            claim_response_body_from_upload(&upload.body.expect("upload has a body"), &bob_user, &bob_device_id);
        let bob_device = stored_device(&bob_user, &bob_device_id, &bob_account);
        OlmSessionManager::on_keys_claim_response(&mut alice_store, &alice_account, &[&bob_device], &claim_body)
            .expect("alice establishes a session with bob");
        let message_0 = OlmSessionManager::encrypt_to_device(
            &mut alice_store,
            &alice_account,
            &alice_user,
            &alice_device_id,
            &bob_device,
            "m.test",
            serde_json::json!({ "i": 0 }),
        )
        .expect("encrypt message 0");

        // First attempt: bob has never seen alice's device (the live case: the
        // to-device room key can arrive before any `/keys/query` for her).
        let first = OlmSessionManager::decrypt_to_device(&mut bob_store, &mut bob_account, &bob_user, &alice_user, &message_0);
        assert!(matches!(first, Err(OlmDecryptError::UnknownSenderDevice { .. })), "got {first:?}");
        let alice_curve = alice_account.identity_keys().curve25519.to_base64();
        assert!(
            bob_store.olm_sessions_for_device(&alice_curve).expect("no error").is_empty(),
            "the refused attempt must not create an inbound session (it would consume the one-time key)"
        );

        // Bob learns alice's device, then retries the SAME message.
        let alice_device_keys =
            alice_account.device_keys_json(&alice_user, &alice_device_id).expect("sign alice's device_keys");
        let query_body = serde_json::to_vec(&serde_json::json!({
            "device_keys": { alice_user.as_str(): { alice_device_id.as_str(): alice_device_keys } }
        }))
        .expect("valid JSON");
        DeviceTracker::on_keys_query_response(&mut bob_store, &query_body).expect("bob learns alice's device");
        let retry = OlmSessionManager::decrypt_to_device(&mut bob_store, &mut bob_account, &bob_user, &alice_user, &message_0)
            .expect("the retry decrypts: nothing was consumed by the refused attempt");
        assert_eq!(retry.content, serde_json::json!({ "i": 0 }));
    }
}
