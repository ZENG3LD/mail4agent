//! [`OlmAccountState`] — the device's own Olm account: generate-once
//! identity, one-time/fallback key maintenance driven by `/sync`'s own
//! counters, and the signed `device_keys`/`/keys/upload` request bodies
//! (plan §0 "Olm account identity + one-time keys: random, per device,
//! persisted", §4.1 "first unlock", §4.4 "OTK exhaustion").
//!
//! # Generate once, never re-derive
//!
//! Unlike the vault's deterministic-from-vault-key material (DM identity,
//! cross-signing seeds — plan §0's other derivation model), the Olm
//! account's own Curve25519/Ed25519 identity and its one-time keys are
//! **random per device** and persisted at rest, never re-derived. Re-deriving
//! them on a later unlock would silently orphan every Olm session and
//! already-published device key a previous run set up. [`OlmAccountState::
//! load_or_create`] enforces this: a fresh account is generated only when
//! the store has none yet, and is saved through the store *immediately*
//! (before any request that could use it) — the flush-before-send rule (this
//! crate's [`crate::persist`] doc) is what makes a crash between generation
//! and the first `/keys/upload` safe: the identity is already on disk, so a
//! restart reuses it rather than minting a second one.
//!
//! # `device_keys_published`
//!
//! The Matrix `/keys/upload` endpoint is additive for one-time/fallback keys
//! but device identity keys only need to be sent once (republishing them is
//! harmless but wasteful, and a resend would still need a fresh signature
//! computed for no reason). This state persists as part of the same account
//! record `/keys/upload`'s own success flips it, `mail4agent_vodozemac::olm::Account`
//! itself has no notion of "have I told the server about my identity keys
//! yet" (it only tracks *un*published one-time/fallback keys) — [`AccountRecord`]
//! carries this flag alongside the pickle so a `device_keys_published: true`
//! account load never re-includes `device_keys` in a later
//! [`OlmAccountState::keys_upload_request`] call.

use crate::canonical_json;
use crate::error::MessengerError;
use crate::ids::{DeviceId, RequestId, UserId};
use crate::store::CryptoStore;
use crate::wire::OutgoingRequest;
use mail4agent_vodozemac::olm::{
    Account, AccountPickle, IdentityKeys, InboundCreationResult, PreKeyMessage, Session, SessionConfig,
    SessionCreationError,
};
use mail4agent_vodozemac::Curve25519PublicKey;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The two Matrix E2EE algorithms this device advertises support for in its
/// `device_keys` (research doc §3.2 -- Olm 1:1 sessions plus Megolm group
/// sessions; there is no third algorithm this crate's scope needs).
const SUPPORTED_ALGORITHMS: [&str; 2] = ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"];

/// The `signed_curve25519` key-type name `/sync`'s
/// `device_unused_fallback_key_types` and `/keys/upload`'s key-id prefix
/// both use (research doc §3.2/§1.4). This crate has exactly one one-time-key
/// algorithm in scope, so this is a single constant rather than an enum.
const SIGNED_CURVE25519: &str = "signed_curve25519";

/// The durable record this module persists through
/// [`CryptoStore::account`]/[`CryptoStore::save_account`] — the pickled
/// `mail4agent_vodozemac` account plus the `device_keys_published` bookkeeping flag
/// described in the module doc. Record-level *encryption* is the store's own
/// [`crate::store::RecordCodec`] job (module doc of `crate::store`) -- what
/// this crate hands the store is always the plain serde pickle JSON.
#[derive(Serialize, Deserialize)]
struct AccountRecord {
    account: AccountPickle,
    device_keys_published: bool,
}

/// Computes the "keep this many one-time keys published" watermark from an
/// account's own maximum capacity: **half** of
/// `Account::max_number_of_one_time_keys()` (vodozemac's own constant is 50,
/// so this crate's watermark is 25 -- see
/// [`OlmAccountState::one_time_key_target`]).
///
/// This mirrors matrix-sdk-crypto's own default policy (plan §4.4, research
/// doc §4.5's OTK-exhaustion pitfall). The reason is spelled out in
/// vodozemac's own `Account::max_number_of_one_time_keys` doc comment: the
/// server's reported published-OTK count can lag behind pre-key messages
/// already in flight that consumed a key this device has not yet learned
/// (via `/sync`) was used. Topping up to only half of capacity rather than
/// all of it leaves headroom so a burst of late-arriving pre-key messages
/// never forces `Account::generate_one_time_keys` to discard a still-needed
/// private one-time key to make room for a new one.
fn target_one_time_key_count(max_number_of_one_time_keys: usize) -> usize {
    max_number_of_one_time_keys / 2
}

/// The device's own Olm account, plus the bookkeeping needed to keep its
/// one-time/fallback keys topped up and its `device_keys`/`/keys/upload`
/// requests idempotent across a retry. See the module doc for the
/// generate-once and `device_keys_published` rules this type enforces.
pub struct OlmAccountState {
    account: Account,
    device_keys_published: bool,
}

impl OlmAccountState {
    /// Loads the account [`CryptoStore::account`] already has, or generates
    /// a fresh one (random, OS entropy -- see the module doc) and saves it
    /// immediately if the store has none yet. Never re-derives an existing
    /// identity.
    ///
    /// Takes no `user_id`/`device_id`: [`CryptoStore`] is already scoped to
    /// one device (`crate::store`'s own `messenger/{device_id}/...` key
    /// layout), and this record carries no user-id-dependent state --
    /// `user_id`/`device_id` are only needed later, per call, by the signing
    /// methods below that actually embed them in signed JSON. Nor is there a
    /// seed parameter: `mail4agent_vodozemac::olm::Account::new()` has no hook for
    /// injecting entropy, only OS randomness, which is exactly what plan §0
    /// requires ("generate once with OS entropy").
    pub fn load_or_create<S: CryptoStore>(store: &mut S) -> Result<Self, MessengerError> {
        if let Some(bytes) = store.account()? {
            let record: AccountRecord = serde_json::from_slice(bytes)
                .map_err(|source| MessengerError::Crypto(format!("decode pickled Olm account: {source}")))?;
            return Ok(Self {
                account: Account::from_pickle(record.account),
                device_keys_published: record.device_keys_published,
            });
        }

        let state = Self { account: Account::new(), device_keys_published: false };
        state.save(store)?;
        Ok(state)
    }

    /// The account's public Curve25519 (identity) and Ed25519 (signing) keys.
    pub fn identity_keys(&self) -> IdentityKeys {
        self.account.identity_keys()
    }

    /// Half of [`Account::max_number_of_one_time_keys`] -- the watermark
    /// [`OlmAccountState::on_sync_counts`] tops one-time keys up to. Exposed
    /// so a caller (or a test) never has to hardcode vodozemac's own
    /// capacity constant.
    pub fn one_time_key_target(&self) -> usize {
        target_one_time_key_count(self.account.max_number_of_one_time_keys())
    }

    /// How many one-time keys this account currently holds that have not
    /// yet been marked published (i.e. would be included in the next
    /// [`OlmAccountState::keys_upload_request`]).
    pub fn pending_one_time_key_count(&self) -> usize {
        self.account.one_time_keys().len()
    }

    /// The currently unpublished fallback key's public part, if this account
    /// has generated one that has not yet been marked published.
    pub fn pending_fallback_key(&self) -> Option<Curve25519PublicKey> {
        self.account.fallback_key().values().next().copied()
    }

    /// Builds this device's signed `device_keys` object (research doc §3.2):
    /// algorithms, this device's own Curve25519/Ed25519 public keys, signed
    /// with the account's own Ed25519 key under `ed25519:{device_id}`.
    pub fn device_keys_json(&self, user_id: &UserId, device_id: &DeviceId) -> Result<Value, MessengerError> {
        let identity = self.account.identity_keys();
        let mut keys = Map::new();
        keys.insert(
            format!("curve25519:{}", device_id.as_str()),
            Value::String(identity.curve25519.to_base64()),
        );
        keys.insert(
            format!("ed25519:{}", device_id.as_str()),
            Value::String(identity.ed25519.to_base64()),
        );

        let mut value = serde_json::json!({
            "algorithms": SUPPORTED_ALGORITHMS,
            "device_id": device_id.as_str(),
            "user_id": user_id.as_str(),
        });
        if let Some(obj) = value.as_object_mut() {
            obj.insert("keys".to_string(), Value::Object(keys));
        }

        let key_id = format!("ed25519:{}", device_id.as_str());
        canonical_json::sign_json(&mut value, user_id.as_str(), &key_id, |bytes| self.account.sign(bytes))?;
        Ok(value)
    }

    /// Builds one signed `signed_curve25519` key object (a one-time key, or
    /// the fallback key when `fallback` is `true`) -- research doc §3.2's
    /// `{"key": ..., "signatures": {...}}` shape, plus `"fallback": true`
    /// when applicable.
    fn signed_one_time_key_json(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        public_key: Curve25519PublicKey,
        fallback: bool,
    ) -> Result<Value, MessengerError> {
        let mut value = serde_json::json!({ "key": public_key.to_base64() });
        if fallback {
            if let Some(obj) = value.as_object_mut() {
                obj.insert("fallback".to_string(), Value::Bool(true));
            }
        }
        let key_id = format!("ed25519:{}", device_id.as_str());
        canonical_json::sign_json(&mut value, user_id.as_str(), &key_id, |bytes| self.account.sign(bytes))?;
        Ok(value)
    }

    /// Feeds one `/sync` response's `device_one_time_keys_count.
    /// signed_curve25519` and `device_unused_fallback_key_types` back into
    /// the account (plan §4.4). Generates a fresh batch of one-time keys
    /// when `published_signed_curve25519_count` is below
    /// [`OlmAccountState::one_time_key_target`] **and** nothing generated
    /// earlier is still waiting to be uploaded (retry-safety: never
    /// regenerate while an unpublished batch already exists -- doing so
    /// would produce two different key sets under what may become
    /// overlapping key ids). Generates a fresh fallback key when
    /// `unused_fallback_key_types` does not report `signed_curve25519` as
    /// still available **and** this account is not already holding an
    /// unpublished one. Any generation is persisted through `store` before
    /// this call returns (the flush-before-send rule: a mutation reaches
    /// disk before anything can depend on it for an upload).
    pub fn on_sync_counts<S: CryptoStore>(
        &mut self,
        store: &mut S,
        published_signed_curve25519_count: u64,
        unused_fallback_key_types: &[String],
    ) -> Result<(), MessengerError> {
        let mut mutated = false;

        if self.account.one_time_keys().is_empty() {
            let target = self.one_time_key_target();
            let published = published_signed_curve25519_count as usize;
            if published < target {
                self.account.generate_one_time_keys(target - published);
                mutated = true;
            }
        }

        let fallback_still_available =
            unused_fallback_key_types.iter().any(|kind| kind == SIGNED_CURVE25519);
        if !fallback_still_available && self.account.fallback_key().is_empty() {
            self.account.generate_fallback_key();
            mutated = true;
        }

        if mutated {
            self.save(store)?;
        }
        Ok(())
    }

    /// Builds a `POST /keys/upload` request from whatever this account
    /// currently has unpublished: `device_keys` only when
    /// `device_keys_published` is still `false`, every currently unpublished
    /// one-time key, and the currently unpublished fallback key, if any.
    /// Returns `Ok(None)` when there is nothing to upload -- a caller should
    /// not enqueue an empty request. Calling this again before
    /// [`OlmAccountState::on_keys_upload_response`] acknowledges the
    /// previous attempt reproduces byte-identical key material (nothing
    /// mutates the account's unpublished sets except
    /// [`OlmAccountState::on_sync_counts`] and
    /// [`OlmAccountState::on_keys_upload_response`] themselves), which is
    /// exactly what makes resending on a retry safe.
    pub fn keys_upload_request(
        &self,
        id: RequestId,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Result<Option<OutgoingRequest>, MessengerError> {
        let one_time_keys = self.account.one_time_keys();
        let fallback_key = self.account.fallback_key();

        if self.device_keys_published && one_time_keys.is_empty() && fallback_key.is_empty() {
            return Ok(None);
        }

        let mut body = Map::new();
        if !self.device_keys_published {
            body.insert("device_keys".to_string(), self.device_keys_json(user_id, device_id)?);
        }
        if !one_time_keys.is_empty() {
            let mut otk_map = Map::new();
            for (key_id, public_key) in &one_time_keys {
                let signed = self.signed_one_time_key_json(user_id, device_id, *public_key, false)?;
                otk_map.insert(format!("{SIGNED_CURVE25519}:{}", key_id.to_base64()), signed);
            }
            body.insert("one_time_keys".to_string(), Value::Object(otk_map));
        }
        if !fallback_key.is_empty() {
            let mut fallback_map = Map::new();
            for (key_id, public_key) in &fallback_key {
                let signed = self.signed_one_time_key_json(user_id, device_id, *public_key, true)?;
                fallback_map.insert(format!("{SIGNED_CURVE25519}:{}", key_id.to_base64()), signed);
            }
            body.insert("fallback_keys".to_string(), Value::Object(fallback_map));
        }

        Ok(Some(OutgoingRequest::keys_upload(id, Value::Object(body))))
    }

    /// Marks every one-time/fallback key currently unpublished as published,
    /// and marks `device_keys_published` `true` -- call once a
    /// `/keys/upload` response has actually arrived successfully. The
    /// response's own `one_time_key_counts` field does not need to be
    /// threaded through this call: the next `/sync`'s own
    /// `device_one_time_keys_count` is what
    /// [`OlmAccountState::on_sync_counts`] reads for future top-ups, so this
    /// call only needs to know the upload succeeded. Persists the account
    /// through `store` before returning.
    pub fn on_keys_upload_response<S: CryptoStore>(&mut self, store: &mut S) -> Result<(), MessengerError> {
        self.account.mark_keys_as_published();
        self.device_keys_published = true;
        self.save(store)
    }

    /// Creates an outbound Olm [`Session`] with `identity_key`/
    /// `one_time_key` (a device this account just claimed a one-time key
    /// from -- see [`crate::crypto::olm_sessions::OlmSessionManager::
    /// on_keys_claim_response`]). Read-only on this account: nothing to
    /// persist.
    pub fn create_outbound_session(
        &self,
        session_config: SessionConfig,
        identity_key: Curve25519PublicKey,
        one_time_key: Curve25519PublicKey,
    ) -> Result<Session, SessionCreationError> {
        self.account.create_outbound_session(session_config, identity_key, one_time_key)
    }

    /// Creates an inbound Olm [`Session`] from a received pre-key message,
    /// consuming one of this account's one-time keys in the process.
    /// Persists the account through `store` before returning -- the plan's
    /// "save the ACCOUNT and the new session together" rule (§4.3): this
    /// call covers the account half; the caller ([`crate::crypto::
    /// olm_sessions::OlmSessionManager::decrypt_to_device`]) persists the
    /// new session itself immediately afterwards. The flush-before-send
    /// barrier only needs both mutations to predate the next
    /// `outgoing_requests()` call, not any particular order between them.
    pub fn create_inbound_session<S: CryptoStore>(
        &mut self,
        store: &mut S,
        session_config: SessionConfig,
        their_identity_key: Curve25519PublicKey,
        pre_key_message: &PreKeyMessage,
    ) -> Result<InboundCreationResult, MessengerError> {
        let result = self
            .account
            .create_inbound_session(session_config, their_identity_key, pre_key_message)
            .map_err(|source| MessengerError::Crypto(format!("create inbound Olm session: {source}")))?;
        self.save(store)?;
        Ok(result)
    }

    fn save<S: CryptoStore>(&self, store: &mut S) -> Result<(), MessengerError> {
        let record = AccountRecord { account: self.account.pickle(), device_keys_published: self.device_keys_published };
        let bytes = serde_json::to_vec(&record)
            .map_err(|source| MessengerError::Crypto(format!("encode pickled Olm account: {source}")))?;
        store.save_account(bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::DeviceId;
    use crate::store::{InsecurePlainCodecForTests, RecordCodec, Store};

    fn device_id() -> DeviceId {
        DeviceId::parse("DEV1").expect("valid device id")
    }

    fn user_id() -> UserId {
        UserId::parse("@alice:example.org").expect("valid user id")
    }

    fn new_store() -> Store<InsecurePlainCodecForTests> {
        Store::new(device_id(), InsecurePlainCodecForTests)
    }

    /// No `signed_curve25519` fallback consumption in scope -- reports the
    /// type as still available so `on_sync_counts` calls in these tests can
    /// isolate the one-time-key top-up path unless a test says otherwise.
    fn fallback_present() -> Vec<String> {
        vec![SIGNED_CURVE25519.to_string()]
    }

    fn drain<C: RecordCodec>(store: &mut Store<C>) {
        if let Some(batch) = store.take_flush_batch() {
            store.ack_flush(batch.id);
        }
    }

    #[test]
    fn ensure_account_generates_once_and_reuses_on_second_open() {
        let mut store = new_store();
        let first = OlmAccountState::load_or_create(&mut store)
            .expect("first open creates a fresh account");
        let first_identity = first.identity_keys();

        let batch = store.take_flush_batch().expect("creating the account dirtied the store");
        store.ack_flush(batch.id);
        let mut reloaded = Store::load(batch.records, InsecurePlainCodecForTests, device_id())
            .expect("reload from the flushed records");

        let second = OlmAccountState::load_or_create(&mut reloaded)
            .expect("second open reuses the persisted account");
        assert_eq!(second.identity_keys(), first_identity, "the same identity is reused, never re-derived");
        assert!(
            reloaded.take_flush_batch().is_none(),
            "reusing an existing account must not dirty the store again"
        );
    }

    #[test]
    fn ensure_account_tops_up_otks_below_watermark() {
        // Below the watermark: tops up exactly to it.
        let mut store = new_store();
        let mut state =
            OlmAccountState::load_or_create(&mut store).expect("create");
        drain(&mut store);

        let target = state.one_time_key_target();
        assert!(target > 0, "a freshly created account always has room for at least one key");
        let published = target / 2;

        state
            .on_sync_counts(&mut store, published as u64, &fallback_present())
            .expect("tops up below the watermark");
        assert_eq!(state.pending_one_time_key_count(), target - published, "tops up exactly to the watermark");
        assert!(
            store.take_flush_batch().is_some(),
            "a top-up must be persisted before it can be uploaded"
        );

        // Already at the watermark, starting from zero pending keys: no
        // generation, nothing new to persist.
        let mut store2 = new_store();
        let mut state2 =
            OlmAccountState::load_or_create(&mut store2).expect("create");
        drain(&mut store2);

        state2
            .on_sync_counts(&mut store2, target as u64, &fallback_present())
            .expect("no top-up needed at the watermark");
        assert_eq!(state2.pending_one_time_key_count(), 0);
        assert!(store2.take_flush_batch().is_none(), "nothing generated, nothing to persist");
    }

    #[test]
    fn ensure_account_uploads_fallback_key_when_unused_types_reports_empty() {
        let mut store = new_store();
        let mut state =
            OlmAccountState::load_or_create(&mut store).expect("create");
        drain(&mut store);

        // Already at the OTK watermark -- isolate the fallback-key path.
        let target = state.one_time_key_target() as u64;
        state.on_sync_counts(&mut store, target, &[]).expect("generates a fallback key");
        assert_eq!(state.pending_one_time_key_count(), 0, "OTKs are already at the watermark");
        assert!(state.pending_fallback_key().is_some(), "a fresh fallback key was generated");
        let batch = store.take_flush_batch().expect("the fallback key must be persisted before upload");
        store.ack_flush(batch.id);

        // A retry that still reports no unused fallback key type must not
        // mint a second one -- the still-unpublished one is resent as-is.
        let pending_before = state.pending_fallback_key();
        state.on_sync_counts(&mut store, target, &[]).expect("retry is a no-op");
        assert_eq!(state.pending_fallback_key(), pending_before, "retry keeps the same fallback key");
        assert!(store.take_flush_batch().is_none(), "nothing new to persist on retry");
    }

    #[test]
    fn device_keys_are_signed_and_verify() {
        let mut store = new_store();
        let state =
            OlmAccountState::load_or_create(&mut store).expect("create");
        let value = state.device_keys_json(&user_id(), &device_id()).expect("signs device keys");

        let identity = state.identity_keys();
        let key_id = format!("ed25519:{}", device_id().as_str());
        canonical_json::verify_json_signature(&value, user_id().as_str(), &key_id, &identity.ed25519)
            .expect("device_keys must verify against the device's own ed25519 key");
    }

    #[test]
    fn retry_resends_the_same_unpublished_keys() {
        let mut store = new_store();
        let mut state =
            OlmAccountState::load_or_create(&mut store).expect("create");
        drain(&mut store);

        state.on_sync_counts(&mut store, 0, &[]).expect("first top-up plus fallback");
        let batch = store.take_flush_batch().expect("generation is persisted before any upload attempt");
        store.ack_flush(batch.id);

        let first_request = state
            .keys_upload_request(RequestId::next(0), &user_id(), &device_id())
            .expect("builds a request")
            .expect("something to upload");

        // A retry before any response ever arrived: the shell calls
        // `on_sync_counts` again off a new `/sync` still reporting the same
        // low counts (the upload has not landed yet), then rebuilds the
        // request.
        state.on_sync_counts(&mut store, 0, &[]).expect("retry does not regenerate");
        assert!(store.take_flush_batch().is_none(), "nothing new was generated, nothing new to persist");

        let second_request = state
            .keys_upload_request(RequestId::next(1), &user_id(), &device_id())
            .expect("builds a request")
            .expect("still something to upload");

        assert_eq!(first_request.body, second_request.body, "a retry resends byte-identical key material");
    }

    #[test]
    fn upload_response_marks_keys_published() {
        let mut store = new_store();
        let mut state =
            OlmAccountState::load_or_create(&mut store).expect("create");
        drain(&mut store);

        state.on_sync_counts(&mut store, 0, &[]).expect("top up");
        drain(&mut store);

        let before = state
            .keys_upload_request(RequestId::next(0), &user_id(), &device_id())
            .expect("builds a request")
            .expect("device keys, OTKs, and a fallback key all await upload on the first attempt");
        let body = before.body.expect("keys_upload always carries a body");
        assert!(body.get("device_keys").is_some(), "the first upload includes device_keys");

        state.on_keys_upload_response(&mut store).expect("mark published");
        let batch = store.take_flush_batch().expect("marking keys published is itself persisted");
        store.ack_flush(batch.id);

        let after = state
            .keys_upload_request(RequestId::next(1), &user_id(), &device_id())
            .expect("builds a request");
        assert!(after.is_none(), "nothing is left to upload once everything is marked published");
    }
}
