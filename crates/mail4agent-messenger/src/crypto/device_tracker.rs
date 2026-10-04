//! [`DeviceTracker`] -- tracked users, per-user device lists, and the
//! `/keys/query` half of device-list tracking (plan §3
//! `crypto/device_tracker.rs`; research doc §3.2/§4.5's "device-list
//! desync" pitfall).
//!
//! # What "tracked" means
//!
//! A user becomes tracked the first time this device learns (via `/sync`'s
//! `device_lists.changed`) that it shares a room with them, or is force-
//! tracked by a caller ahead of time (e.g. before starting a DM). Every
//! tracked user carries an `outdated` flag: `true` means "the device list
//! this store has for them (if any) might be stale, ask `/keys/query`
//! before trusting it for anything security-sensitive (Olm-encrypting a new
//! `m.room_key`, sharing to their devices, verification)". See
//! [`crate::crypto::olm_sessions::OlmSessionManager`]'s module doc for the
//! one place that matters most.
//!
//! # Own devices are tracked like anyone else's
//!
//! This account's own other devices are not special-cased anywhere in this
//! module: `/keys/query`'s `device_keys` map includes the caller's own user
//! id exactly like any other, and this account needs its own other
//! devices' keys for the same reason it needs a peer's -- Megolm room keys
//! are Olm-shared to every one of a room's members' devices, including the
//! sending device's own siblings (plan §4.2).
//!
//! # Why a key change is never silently applied
//!
//! A device id is minted once by the homeserver at login and never
//! legitimately changes the Curve25519/Ed25519 keys it was first seen with
//! (research doc §4.5's device-list-desync pitfall, one layer down: the
//! failure mode this guards against is a compromised or malicious server
//! substituting a different device's keys under a familiar device id to
//! intercept a room key). [`DeviceTracker::on_keys_query_response`] treats a
//! same-device-id, different-keys response as a security event
//! ([`DeviceKeyChanged`]), not an update: the OLD, previously-verified keys
//! are kept, and the caller decides what to do about the alert (surface a
//! "device changed" warning, refuse to share new room keys to it until the
//! user re-verifies, ...). The same holds for a device whose self-signature
//! no longer verifies at all -- it is dropped, and if a previously-known,
//! still-valid record exists for that device id, that old record is kept
//! rather than erased by an unverifiable update.
//!
//! # `left` users have no store-level "forget"
//!
//! [`crate::store::CryptoStore`] (a prior piece) exposes only
//! `tracked_users`/`mark_user_tracked` -- there is no primitive to delete a
//! tracked-user record outright. [`DeviceTracker::on_device_lists`]
//! therefore cannot fully forget a user who no longer shares a room with
//! this device; it marks an already-tracked `left` user not-outdated (so
//! `keys_query_request` stops re-fetching them) and otherwise leaves the
//! record in place. A full purge, if ever needed, is a later piece's job.

use crate::canonical_json;
use crate::error::MessengerError;
use crate::ids::{DeviceId, RequestId, UserId};
use crate::store::CryptoStore;
use crate::wire::OutgoingRequest;
use mail4agent_vodozemac::{Curve25519PublicKey, Ed25519PublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// One device this store knows about for some user, learned from a
/// `/keys/query` response whose self-signature verified (plan §3's
/// `StoredDevice` shape).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredDevice {
    /// The device's owner.
    pub user_id: UserId,
    /// The device's own id.
    pub device_id: DeviceId,
    /// The device's Curve25519 identity key.
    pub curve25519: Curve25519PublicKey,
    /// The device's Ed25519 signing key.
    pub ed25519: Ed25519PublicKey,
    /// The Matrix E2EE algorithms this device advertises.
    pub algorithms: Vec<String>,
    /// The device's self-reported display name, if any.
    pub display_name: Option<String>,
    /// Whether the local user has verified this device. Never set `true`
    /// by this module -- verification (SAS, cross-signing) is a later
    /// piece.
    pub verified: bool,
    /// Whether the local user has blocked this device. Never set `true` by
    /// this module.
    pub blocked: bool,
}

/// A device dropped outright while applying a `/keys/query` response --
/// never stored (or, if a previously-known valid record existed, left
/// unchanged rather than overwritten -- see the module doc).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DroppedDevice {
    /// The device's claimed owner.
    pub user_id: UserId,
    /// The device's claimed id.
    pub device_id: DeviceId,
    /// Why this device was refused.
    pub reason: String,
}

/// A previously-known device whose Curve25519 or Ed25519 key changed in a
/// new `/keys/query` response -- the OLD keys are kept (see the module
/// doc). A caller should surface this as a security event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceKeyChanged {
    /// The device's owner.
    pub user_id: UserId,
    /// The device whose keys changed.
    pub device_id: DeviceId,
}

/// The result of merging one `/keys/query` response into the store.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeysQueryOutcome {
    /// Users whose tracked device list this response refreshed (no longer
    /// outdated).
    pub resolved_users: Vec<UserId>,
    /// A device this response carried that was accepted (new, or an
    /// unchanged re-publish of an already-known device).
    pub accepted_devices: Vec<(UserId, DeviceId)>,
    /// A device this response carried that failed validation and was never
    /// stored.
    pub dropped_devices: Vec<DroppedDevice>,
    /// A previously-known device whose keys changed -- flagged, not
    /// applied.
    pub key_changes: Vec<DeviceKeyChanged>,
}

/// The stored payload behind [`crate::store::CryptoStore::devices_for_user`]
/// -- a thin wrapper (rather than a bare `Vec<StoredDevice>`) so a later
/// field can be added without reshaping the record, matching
/// `crypto::account`'s own `AccountRecord` convention.
#[derive(Serialize, Deserialize)]
struct DeviceListRecord {
    devices: Vec<StoredDevice>,
}

/// One device object nested under `/keys/query`'s
/// `device_keys.{user_id}.{device_id}` (research doc §3.2). Parsed from the
/// raw [`Value`] so the ORIGINAL bytes (not a re-serialization) are what
/// gets signature-checked.
#[derive(Deserialize)]
struct DeviceKeysObject {
    user_id: UserId,
    device_id: DeviceId,
    #[serde(default)]
    algorithms: Vec<String>,
    #[serde(default)]
    keys: BTreeMap<String, String>,
    #[serde(default)]
    unsigned: DeviceKeysUnsigned,
}

#[derive(Default, Deserialize)]
struct DeviceKeysUnsigned {
    #[serde(default)]
    device_display_name: Option<String>,
}

/// `/keys/query`'s response shape, the parts this module reads (research
/// doc §3.2). `failures` is intentionally not modeled: a user present there
/// simply stays outdated, which already happens by omission (this module
/// only resolves a user found in `device_keys`).
#[derive(Deserialize)]
struct KeysQueryResponseBody {
    #[serde(default)]
    device_keys: BTreeMap<UserId, BTreeMap<DeviceId, Value>>,
}

/// Device-list tracking: outdated bookkeeping, `/keys/query` request
/// building, and validating `/keys/query` responses. See the module doc for
/// the security invariants this type enforces. Carries no state of its own
/// -- every method reads/writes through the caller's [`CryptoStore`].
pub struct DeviceTracker;

impl DeviceTracker {
    /// Applies `/sync`'s `device_lists.changed`/`device_lists.left` (plan
    /// §3, research doc §3.2). See the module doc for what happens to a
    /// `left` user.
    pub fn on_device_lists<S: CryptoStore>(
        store: &mut S,
        changed: &[UserId],
        left: &[UserId],
    ) -> Result<(), MessengerError> {
        for user_id in changed {
            store.mark_user_tracked(user_id, true)?;
        }

        if !left.is_empty() {
            let currently_tracked: BTreeSet<UserId> =
                store.tracked_users()?.into_iter().map(|(user_id, _)| user_id).collect();
            for user_id in left {
                if currently_tracked.contains(user_id) {
                    store.mark_user_tracked(user_id, false)?;
                }
            }
        }
        Ok(())
    }

    /// Builds a `POST /keys/query` request for every currently-outdated
    /// tracked user, or `None` if none are outdated.
    pub fn keys_query_request<S: CryptoStore>(
        store: &S,
        id: RequestId,
    ) -> Result<Option<OutgoingRequest>, MessengerError> {
        let outdated: Vec<UserId> = store
            .tracked_users()?
            .into_iter()
            .filter_map(|(user_id, outdated)| outdated.then_some(user_id))
            .collect();
        if outdated.is_empty() {
            return Ok(None);
        }

        let mut device_keys = serde_json::Map::new();
        for user_id in &outdated {
            device_keys.insert(user_id.as_str().to_string(), Value::Array(Vec::new()));
        }
        let body = serde_json::json!({ "device_keys": Value::Object(device_keys) });
        Ok(Some(OutgoingRequest::keys_query(id, body)))
    }

    /// Every device this store currently has stored for `user_id`, or an
    /// empty list if none.
    pub fn devices_for_user<S: CryptoStore>(
        store: &S,
        user_id: &UserId,
    ) -> Result<Vec<StoredDevice>, MessengerError> {
        match store.devices_for_user(user_id)? {
            Some(bytes) => {
                let record: DeviceListRecord = serde_json::from_slice(bytes).map_err(|source| {
                    MessengerError::Crypto(format!("decode stored device list for {user_id}: {source}"))
                })?;
                Ok(record.devices)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Applies a `/keys/query` response body (plan §3): verifies each
    /// device's self-signature over canonical JSON with its OWN claimed
    /// Ed25519 key, drops anything that doesn't check out, flags (without
    /// applying) a key change on an already-known device id, and persists
    /// the resulting per-user device lists. Marks every user present in
    /// `device_keys` (even with zero devices) not-outdated.
    pub fn on_keys_query_response<S: CryptoStore>(
        store: &mut S,
        body: &[u8],
    ) -> Result<KeysQueryOutcome, MessengerError> {
        let parsed: KeysQueryResponseBody = serde_json::from_slice(body)?;
        let mut outcome = KeysQueryOutcome::default();

        for (user_id, devices_by_id) in parsed.device_keys {
            let existing = Self::devices_for_user(store, &user_id)?;
            let mut existing_by_id: BTreeMap<DeviceId, StoredDevice> =
                existing.into_iter().map(|device| (device.device_id.clone(), device)).collect();
            let mut merged: Vec<StoredDevice> = Vec::with_capacity(devices_by_id.len());

            for (device_id, raw) in &devices_by_id {
                match Self::verify_device(&user_id, device_id, raw) {
                    Ok(candidate) => match existing_by_id.remove(device_id) {
                        Some(known)
                            if known.curve25519 != candidate.curve25519 || known.ed25519 != candidate.ed25519 =>
                        {
                            outcome.key_changes.push(DeviceKeyChanged {
                                user_id: user_id.clone(),
                                device_id: device_id.clone(),
                            });
                            merged.push(known);
                        }
                        Some(known) => {
                            outcome.accepted_devices.push((user_id.clone(), device_id.clone()));
                            merged.push(StoredDevice {
                                verified: known.verified,
                                blocked: known.blocked,
                                ..candidate
                            });
                        }
                        None => {
                            outcome.accepted_devices.push((user_id.clone(), device_id.clone()));
                            merged.push(candidate);
                        }
                    },
                    Err(reason) => {
                        outcome.dropped_devices.push(DroppedDevice {
                            user_id: user_id.clone(),
                            device_id: device_id.clone(),
                            reason,
                        });
                        if let Some(known) = existing_by_id.remove(device_id) {
                            merged.push(known);
                        }
                    }
                }
            }

            let record = DeviceListRecord { devices: merged };
            let bytes = serde_json::to_vec(&record).map_err(|source| {
                MessengerError::Crypto(format!("encode stored device list for {user_id}: {source}"))
            })?;
            store.save_devices(&user_id, bytes)?;
            store.mark_user_tracked(&user_id, false)?;
            outcome.resolved_users.push(user_id);
        }

        Ok(outcome)
    }

    /// Validates one `device_keys.{user_id}.{device_id}` object: `user_id`/
    /// `device_id` must match the map keys it was nested under, it must
    /// carry its own Curve25519/Ed25519 keys, and its self-signature
    /// (`signatures.{user_id}.ed25519:{device_id}`) must verify against its
    /// OWN claimed Ed25519 key. `Err` carries a human-readable reason,
    /// never the underlying error type (kept crate-internal, same
    /// reasoning as [`MessengerError::Crypto`]).
    fn verify_device(user_id: &UserId, device_id: &DeviceId, raw: &Value) -> Result<StoredDevice, String> {
        let parsed: DeviceKeysObject = serde_json::from_value(raw.clone())
            .map_err(|source| format!("malformed device_keys object: {source}"))?;

        if parsed.user_id != *user_id {
            return Err(format!(
                "user_id {:?} in the object does not match the map key {:?}",
                parsed.user_id.as_str(),
                user_id.as_str()
            ));
        }
        if parsed.device_id != *device_id {
            return Err(format!(
                "device_id {:?} in the object does not match the map key {:?}",
                parsed.device_id.as_str(),
                device_id.as_str()
            ));
        }

        let ed25519_b64 = parsed
            .keys
            .get(&format!("ed25519:{}", device_id.as_str()))
            .ok_or_else(|| "missing the device's own ed25519 key".to_string())?;
        let ed25519 =
            Ed25519PublicKey::from_base64(ed25519_b64).map_err(|source| format!("malformed ed25519 key: {source}"))?;

        let curve25519_b64 = parsed
            .keys
            .get(&format!("curve25519:{}", device_id.as_str()))
            .ok_or_else(|| "missing the device's own curve25519 key".to_string())?;
        let curve25519 = Curve25519PublicKey::from_base64(curve25519_b64)
            .map_err(|source| format!("malformed curve25519 key: {source}"))?;

        let key_id = format!("ed25519:{}", device_id.as_str());
        canonical_json::verify_json_signature(raw, user_id.as_str(), &key_id, &ed25519)
            .map_err(|source| format!("self-signature failed to verify: {source}"))?;

        Ok(StoredDevice {
            user_id: user_id.clone(),
            device_id: device_id.clone(),
            curve25519,
            ed25519,
            algorithms: parsed.algorithms,
            display_name: parsed.unsigned.device_display_name,
            verified: false,
            blocked: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{InsecurePlainCodecForTests, Store};
    use mail4agent_vodozemac::olm::Account;

    fn new_store() -> Store<InsecurePlainCodecForTests> {
        Store::new(DeviceId::parse("OURDEVICE").expect("valid device id"), InsecurePlainCodecForTests)
    }

    fn user(name: &str) -> UserId {
        UserId::parse(format!("@{name}:example.org")).expect("valid user id")
    }

    fn device(name: &str) -> DeviceId {
        DeviceId::parse(name).expect("valid device id")
    }

    /// Builds a self-signed `device_keys` object for `(user_id, device_id)`
    /// using a fresh vodozemac [`Account`], mirroring
    /// `crypto::account::OlmAccountState::device_keys_json`'s shape exactly
    /// (this module only ever receives such objects over the wire, never
    /// builds them itself).
    fn signed_device_keys(account: &Account, user_id: &UserId, device_id: &DeviceId) -> Value {
        let identity = account.identity_keys();
        let mut value = serde_json::json!({
            "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
            "device_id": device_id.as_str(),
            "user_id": user_id.as_str(),
            "keys": {
                format!("curve25519:{}", device_id.as_str()): identity.curve25519.to_base64(),
                format!("ed25519:{}", device_id.as_str()): identity.ed25519.to_base64(),
            },
        });
        let key_id = format!("ed25519:{}", device_id.as_str());
        canonical_json::sign_json(&mut value, user_id.as_str(), &key_id, |bytes| account.sign(bytes))
            .expect("signing a freshly built device_keys object succeeds");
        value
    }

    fn keys_query_body(entries: &[(&UserId, &DeviceId, Value)]) -> Vec<u8> {
        let mut device_keys = serde_json::Map::new();
        for (user_id, device_id, value) in entries {
            let by_device = device_keys
                .entry(user_id.as_str().to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            by_device
                .as_object_mut()
                .expect("just inserted as an object")
                .insert(device_id.as_str().to_string(), value.clone());
        }
        serde_json::to_vec(&serde_json::json!({ "device_keys": device_keys })).expect("valid JSON")
    }

    #[test]
    fn device_tracker_marks_outdated_on_sync_device_lists_changed() {
        let mut store = new_store();
        let bob = user("bob");
        assert!(store.tracked_users().expect("no error").is_empty(), "nothing tracked yet");

        DeviceTracker::on_device_lists(&mut store, std::slice::from_ref(&bob), &[]).expect("applies device_lists.changed");
        assert_eq!(store.tracked_users().expect("no error"), vec![(bob.clone(), true)]);

        let request = DeviceTracker::keys_query_request(&store, RequestId::next(0))
            .expect("builds a request")
            .expect("bob is outdated, something to query");
        assert_eq!(request.body.expect("keys_query has a body")["device_keys"][bob.as_str()], serde_json::json!([]));

        // A `left` notification for an untracked user is a no-op; for an
        // already-tracked one it clears the outdated flag (module doc: no
        // store-level "forget" primitive exists).
        let carol = user("carol");
        DeviceTracker::on_device_lists(&mut store, &[], std::slice::from_ref(&carol))
            .expect("left, but never tracked: no-op");
        assert!(store.tracked_users().expect("no error").iter().all(|(u, _)| *u != carol));

        DeviceTracker::on_device_lists(&mut store, &[], std::slice::from_ref(&bob)).expect("bob left");
        assert_eq!(store.tracked_users().expect("no error"), vec![(bob, false)]);
    }

    #[test]
    fn unsigned_device_keys_are_dropped() {
        let mut store = new_store();
        let alice = user("alice");
        let dev1 = device("DEV1");

        let account = Account::new();
        let mut tampered = signed_device_keys(&account, &alice, &dev1);
        // Corrupt the signature -- still present, still base64, but no
        // longer valid for the payload it is attached to.
        let sig_path = tampered["signatures"][alice.as_str()]["ed25519:DEV1"]
            .as_str()
            .expect("signature present")
            .to_string();
        let sig_len = sig_path.len();
        let mut corrupted = sig_path.into_bytes();
        corrupted[0] ^= 0xFF;
        tampered["signatures"][alice.as_str()]["ed25519:DEV1"] =
            Value::String(mail4agent_vodozemac::base64_encode(&corrupted[..sig_len]));

        let body = keys_query_body(&[(&alice, &dev1, tampered)]);
        let outcome = DeviceTracker::on_keys_query_response(&mut store, &body).expect("applies response");

        assert!(outcome.accepted_devices.is_empty());
        assert_eq!(outcome.dropped_devices.len(), 1);
        assert_eq!(outcome.dropped_devices[0].user_id, alice);
        assert_eq!(outcome.dropped_devices[0].device_id, dev1);
        assert!(
            outcome.dropped_devices[0].reason.contains("signature"),
            "reason names the problem: {}",
            outcome.dropped_devices[0].reason
        );

        assert!(
            DeviceTracker::devices_for_user(&store, &alice).expect("no error").is_empty(),
            "an unsigned device is never stored"
        );
        assert_eq!(store.tracked_users().expect("no error"), vec![(alice, false)], "the user is still resolved");
    }

    #[test]
    fn key_change_on_a_known_device_id_is_flagged_and_the_old_keys_are_kept() {
        let mut store = new_store();
        let bob = user("bob");
        let dev1 = device("DEV1");

        let original_account = Account::new();
        let first_body =
            keys_query_body(&[(&bob, &dev1, signed_device_keys(&original_account, &bob, &dev1))]);
        DeviceTracker::on_keys_query_response(&mut store, &first_body).expect("first query applies");
        let original =
            DeviceTracker::devices_for_user(&store, &bob).expect("no error").into_iter().next().expect("stored");

        let impostor_account = Account::new();
        let second_body =
            keys_query_body(&[(&bob, &dev1, signed_device_keys(&impostor_account, &bob, &dev1))]);
        let outcome = DeviceTracker::on_keys_query_response(&mut store, &second_body).expect("second query applies");

        assert_eq!(outcome.key_changes, vec![DeviceKeyChanged { user_id: bob.clone(), device_id: dev1.clone() }]);
        assert!(outcome.accepted_devices.is_empty());

        let stored = DeviceTracker::devices_for_user(&store, &bob).expect("no error").into_iter().next().expect("kept");
        assert_eq!(stored, original, "the OLD keys are kept, never overwritten by an unexplained key change");
    }
}
