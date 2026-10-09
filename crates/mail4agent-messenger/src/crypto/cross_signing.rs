//! Automatic cross-signing (M3). No agent-facing crypto UX: the first sync
//! of an account generates master / self-signing / user-signing Ed25519
//! keys (sealed in the store), uploads them via
//! `POST /keys/device_signing/upload`, then self-signs this device with the
//! self-signing key via `POST /keys/signatures/upload`. Peers treat
//! first-seen devices as trusted (TOFU, [`super::device_tracker`]) and get a
//! `DeviceKeyChanged` alert when keys later change.

use crate::canonical_json;
use crate::error::MessengerError;
use crate::ids::{DeviceId, UserId};
use crate::store::CryptoStore;
use mail4agent_vodozemac::Ed25519SecretKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Persisted state (inside the sealed store record).
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CrossSigningState {
    master: String,
    self_signing: String,
    user_signing: String,
    /// Keys accepted by the server.
    #[serde(default)]
    pub uploaded: bool,
    /// This device's self-signature accepted by the server.
    #[serde(default)]
    pub device_signed: bool,
}

fn secret(b64: &str) -> Result<Ed25519SecretKey, MessengerError> {
    Ed25519SecretKey::from_base64(b64).map_err(|e| MessengerError::Crypto(format!("cross-signing key: {e}")))
}

impl CrossSigningState {
    /// Loads the sealed state, generating keys on first use.
    pub fn load_or_create<S: CryptoStore>(store: &mut S) -> Result<Self, MessengerError> {
        if let Some(bytes) = store.cross_signing_keys()? {
            if let Ok(state) = serde_json::from_slice::<CrossSigningState>(bytes) {
                return Ok(state);
            }
        }
        let state = CrossSigningState {
            master: Ed25519SecretKey::new().to_base64(),
            self_signing: Ed25519SecretKey::new().to_base64(),
            user_signing: Ed25519SecretKey::new().to_base64(),
            uploaded: false,
            device_signed: false,
        };
        state.save(store)?;
        Ok(state)
    }

    /// Persists the state into the sealed store.
    pub fn save<S: CryptoStore>(&self, store: &mut S) -> Result<(), MessengerError> {
        let bytes = serde_json::to_vec(self).map_err(|e| MessengerError::Crypto(format!("encode cross-signing: {e}")))?;
        store.save_cross_signing_keys(bytes)?;
        Ok(())
    }

    fn key_object(user_id: &UserId, usage: &str, key: &Ed25519SecretKey) -> Value {
        let public = key.public_key().to_base64();
        json!({
            "user_id": user_id.as_str(),
            "usage": [usage],
            "keys": { format!("ed25519:{public}"): public },
        })
    }

    /// Body for `/keys/device_signing/upload`.
    pub fn upload_body(&self, user_id: &UserId) -> Result<Value, MessengerError> {
        let master = secret(&self.master)?;
        let master_id = format!("ed25519:{}", master.public_key().to_base64());
        let master_obj = Self::key_object(user_id, "master", &master);
        let mut self_obj = Self::key_object(user_id, "self_signing", &secret(&self.self_signing)?);
        let mut user_obj = Self::key_object(user_id, "user_signing", &secret(&self.user_signing)?);
        for obj in [&mut self_obj, &mut user_obj] {
            canonical_json::sign_json(obj, user_id.as_str(), &master_id, |b| master.sign(b))?;
        }
        Ok(json!({ "master_key": master_obj, "self_signing_key": self_obj, "user_signing_key": user_obj }))
    }

    /// Body for `/keys/signatures/upload`: `device_keys` (as uploaded)
    /// countersigned by the self-signing key.
    pub fn device_signature_body(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        mut device_keys: Value,
    ) -> Result<Value, MessengerError> {
        let ssk = secret(&self.self_signing)?;
        let key_id = format!("ed25519:{}", ssk.public_key().to_base64());
        canonical_json::sign_json(&mut device_keys, user_id.as_str(), &key_id, |b| ssk.sign(b))?;
        Ok(json!({ user_id.as_str(): { device_id.as_str(): device_keys } }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{InsecurePlainCodecForTests, Store};

    #[test]
    fn upload_body_has_three_keys_and_persists() {
        let mut store = Store::new(DeviceId::parse("DEV1").unwrap(), InsecurePlainCodecForTests);
        let user = UserId::parse("@a:x.org").unwrap();
        let s1 = CrossSigningState::load_or_create(&mut store).unwrap();
        let s2 = CrossSigningState::load_or_create(&mut store).unwrap();
        assert_eq!(s1.master, s2.master, "keys persist");
        let body = s1.upload_body(&user).unwrap();
        assert!(body["master_key"]["keys"].as_object().unwrap().len() == 1);
        assert!(body["self_signing_key"]["signatures"]["@a:x.org"].is_object());
    }
}
