//! The session identity: one session = one identity = one nick = one credential set.
//!
//! The identity is an ed25519 key pair the client generates itself. The private seed is kept in
//! the [`KeyVault`] and never leaves it except to sign; the agent behind the client is never given
//! it. A session is bound to ONE tier and ONE server: asking the store for the same session id
//! against a different server is an error, not a quiet second identity.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use m4a_seam::keyproof;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::backend::BackendKind;
use crate::error::{AgentError, Result};
use crate::vault::{random_bytes, KeyVault};

/// What is public and persistent about an identity. (The private seed is not in here.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionIdentity {
    pub session_id: String,
    pub tier: BackendKind,
    /// The server this identity belongs to (normalized base URL). Part of the binding.
    pub server_ref: String,
    pub key_id: String,
    /// Public key, base64url.
    pub public_key: String,
    /// Learned when the operator's invite is redeemed; the nick is the operator's choice.
    pub nick: Option<String>,
    pub enrolled: bool,
    /// The tier-1 (local mail node) session id of the same session, when known. The link is kept
    /// here and only here; it is one-to-one (see [`IdentityStore::bind_local`]).
    #[serde(default)]
    pub local_session: Option<String>,
}

fn seed_label(sid: &str) -> String {
    format!("identity-key/{sid}")
}
fn record_label(sid: &str) -> String {
    format!("identity/{sid}")
}
/// Where a backend keeps the current access token of a session.
pub fn token_label(sid: &str) -> String {
    format!("session-token/{sid}")
}

fn valid_session_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

impl SessionIdentity {
    /// Signs `msg` with the identity's private key (read from the vault just for this).
    pub fn sign(&self, vault: &dyn KeyVault, msg: &[u8]) -> Result<String> {
        let sk = signing_key(vault, &self.session_id)?;
        Ok(keyproof::encode(&sk.sign(msg).to_bytes()))
    }

    /// The signature for a login challenge.
    pub fn sign_login(&self, vault: &dyn KeyVault, c: &keyproof::Challenge) -> Result<String> {
        self.sign(vault, &keyproof::login_message(c, &self.key_id))
    }

    /// The proof that this client holds the key it is enrolling.
    pub fn sign_enroll(&self, vault: &dyn KeyVault, audience: &str, invite: &str) -> Result<String> {
        self.sign(vault, &keyproof::enroll_message(audience, invite, &self.public_key))
    }
}

fn signing_key(vault: &dyn KeyVault, sid: &str) -> Result<SigningKey> {
    let seed = vault.get(&seed_label(sid))?.ok_or_else(|| AgentError::Identity("the identity key is missing from the vault".into()))?;
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(<[u8; 32]>::try_from(&seed[..]).map_err(|_| AgentError::Identity("the identity key has the wrong size".into()))?);
    Ok(SigningKey::from_bytes(&seed))
}

/// Finds or creates identities. Everything is kept in the vault.
#[derive(Clone)]
pub struct IdentityStore {
    vault: Arc<dyn KeyVault>,
}

impl IdentityStore {
    pub fn new(vault: Arc<dyn KeyVault>) -> Self {
        Self { vault }
    }

    pub fn vault(&self) -> &dyn KeyVault {
        &*self.vault
    }

    /// The identity of `session_id` for `tier` on `server_ref`: loaded when it exists (and then it
    /// must match tier and server), generated (new key pair, kept in the vault) when it does not.
    pub fn resolve(&self, session_id: &str, tier: BackendKind, server_ref: &str) -> Result<SessionIdentity> {
        if !valid_session_id(session_id) {
            return Err(AgentError::Identity("session id must be 1-64 characters of [A-Za-z0-9._-]".into()));
        }
        let server_ref = server_ref.trim_end_matches('/').to_string();
        if let Some(raw) = self.vault.get(&record_label(session_id))? {
            let id: SessionIdentity = serde_json::from_slice(&raw).map_err(|e| AgentError::Identity(format!("stored identity: {e}")))?;
            if id.tier != tier || id.server_ref != server_ref {
                return Err(AgentError::Identity("this session is bound to another tier or server; use a new session id".into()));
            }
            signing_key(&*self.vault, session_id)?; // the key must still be there
            return Ok(id);
        }
        let seed = random_bytes(32);
        let sk = SigningKey::from_bytes(<&[u8; 32]>::try_from(&seed[..]).map_err(|_| AgentError::Identity("seed".into()))?);
        let pk = sk.verifying_key();
        let id = SessionIdentity { session_id: session_id.to_string(), tier, server_ref, key_id: keyproof::key_id_of(pk.as_bytes()), public_key: keyproof::encode(pk.as_bytes()), nick: None, enrolled: false, local_session: None };
        // The seed goes first: a record without its key would be a dead identity.
        self.vault.put(&seed_label(session_id), &seed)?;
        self.save(&id)?;
        Ok(id)
    }

    pub fn save(&self, id: &SessionIdentity) -> Result<()> {
        self.vault.put(&record_label(&id.session_id), &serde_json::to_vec(id).map_err(|e| AgentError::Identity(e.to_string()))?)
    }

    /// Links the session to its tier-1 session id. One session has one local id and one local id
    /// belongs to one session; a second, different link is an error (never a quiet overwrite).
    pub fn bind_local(&self, id: &mut SessionIdentity, local_id: &str) -> Result<()> {
        if !valid_session_id(local_id) {
            return Err(AgentError::Identity("local session id is not a valid id".into()));
        }
        if let Some(have) = &id.local_session {
            return if have == local_id { Ok(()) } else { Err(AgentError::Identity("this session is already linked to another local session".into())) };
        }
        let label = format!("local-link/{local_id}");
        if let Some(owner) = self.vault.get(&label)? {
            if owner[..] != *id.session_id.as_bytes() {
                return Err(AgentError::Identity("that local session belongs to another identity".into()));
            }
        }
        self.vault.put(&label, id.session_id.as_bytes())?;
        id.local_session = Some(local_id.to_string());
        self.save(id)
    }

    /// Records the nick the operator assigned. It is frozen after the first call: a different nick
    /// for the same identity is an error, the only way to another nick is a new identity.
    pub fn adopt_nick(&self, id: &mut SessionIdentity, nick: &str) -> Result<()> {
        match &id.nick {
            Some(n) if n == nick => Ok(()),
            Some(_) => Err(AgentError::Identity("this identity already has a different nick".into())),
            None => {
                id.nick = Some(nick.to_string());
                self.save(id)
            }
        }
    }

    /// A random 32-byte key for the session's local store (created on first ask).
    pub fn store_key(&self, session_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let label = format!("store-key/{session_id}");
        if let Some(k) = self.vault.get(&label)? {
            return Ok(k);
        }
        let k = random_bytes(32);
        self.vault.put(&label, &k)?;
        Ok(k)
    }

    /// Forgets the session entirely: key pair, record, token, store key. A later `resolve` makes a
    /// NEW identity (which the operator must approve again).
    pub fn forget(&self, session_id: &str) -> Result<()> {
        if let Some(raw) = self.vault.get(&record_label(session_id))? {
            if let Ok(id) = serde_json::from_slice::<SessionIdentity>(&raw) {
                if let Some(l) = id.local_session {
                    self.vault.delete(&format!("local-link/{l}"))?;
                }
            }
        }
        for l in [seed_label(session_id), record_label(session_id), token_label(session_id), format!("store-key/{session_id}")] {
            self.vault.delete(&l)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::MemoryVault;

    fn store() -> IdentityStore {
        IdentityStore::new(Arc::new(MemoryVault::new()))
    }

    #[test]
    fn an_identity_is_generated_once_and_found_again() {
        let s = store();
        let a = s.resolve("s1", BackendKind::Server, "https://p.example/").unwrap();
        assert!(!a.enrolled && a.nick.is_none());
        assert_eq!(a.server_ref, "https://p.example");
        assert_eq!(a.key_id, keyproof::key_id_of(&keyproof::decode(&a.public_key).unwrap()));
        assert_eq!(s.resolve("s1", BackendKind::Server, "https://p.example").unwrap(), a);
        let b = s.resolve("s2", BackendKind::Server, "https://p.example").unwrap();
        assert_ne!(a.key_id, b.key_id, "one session, one identity");
    }

    #[test]
    fn a_session_cannot_be_moved_to_another_server_or_tier() {
        let s = store();
        s.resolve("s1", BackendKind::Server, "https://p.example").unwrap();
        assert!(s.resolve("s1", BackendKind::Server, "https://other.example").is_err());
        assert!(s.resolve("s1", BackendKind::Matrix, "https://p.example").is_err());
        assert!(s.resolve("../x", BackendKind::Server, "https://p.example").is_err());
        assert!(s.resolve("", BackendKind::Server, "https://p.example").is_err());
    }

    #[test]
    fn signatures_verify_under_the_public_key_and_forget_makes_a_new_identity() {
        let s = store();
        let id = s.resolve("s1", BackendKind::Matrix, "https://p.example").unwrap();
        let c = keyproof::Challenge { challenge_id: "c".into(), nonce: "n".into(), expires_ms: 5, audience: "aud".into() };
        let sig = id.sign_login(s.vault(), &c).unwrap();
        assert!(keyproof::verify(&id.public_key, &keyproof::login_message(&c, &id.key_id), &sig));
        let sig = id.sign_enroll(s.vault(), "aud", "inv").unwrap();
        assert!(keyproof::verify(&id.public_key, &keyproof::enroll_message("aud", "inv", &id.public_key), &sig));
        s.forget("s1").unwrap();
        assert!(id.sign(s.vault(), b"x").is_err(), "the key is gone");
        let again = s.resolve("s1", BackendKind::Matrix, "https://p.example").unwrap();
        assert_ne!(again.key_id, id.key_id);
    }

    #[test]
    fn links_and_nicks_are_one_to_one_and_frozen() {
        let s = store();
        let mut a = s.resolve("s1", BackendKind::Server, "https://p.example").unwrap();
        let mut b = s.resolve("s2", BackendKind::Server, "https://p.example").unwrap();
        s.bind_local(&mut a, "local-1").unwrap();
        s.bind_local(&mut a, "local-1").unwrap();
        assert!(s.bind_local(&mut a, "local-2").is_err(), "one session, one local id");
        assert!(s.bind_local(&mut b, "local-1").is_err(), "one local id, one session");
        assert_eq!(s.resolve("s1", BackendKind::Server, "https://p.example").unwrap().local_session.as_deref(), Some("local-1"));
        s.adopt_nick(&mut a, "kestrel").unwrap();
        s.adopt_nick(&mut a, "kestrel").unwrap();
        assert!(s.adopt_nick(&mut a, "other").is_err());
        s.forget("s1").unwrap();
        let mut c = s.resolve("s3", BackendKind::Server, "https://p.example").unwrap();
        s.bind_local(&mut c, "local-1").unwrap(); // the link was released with the identity
    }

    #[test]
    fn the_debug_output_and_record_carry_no_private_key() {
        let s = store();
        let id = s.resolve("s1", BackendKind::Server, "https://p.example").unwrap();
        let seed = s.vault().get(&seed_label("s1")).unwrap().unwrap();
        let seed_b64 = keyproof::encode(&seed);
        assert!(!format!("{id:?}").contains(&seed_b64));
        assert!(!String::from_utf8_lossy(&serde_json::to_vec(&id).unwrap()).contains(&seed_b64));
    }
}
