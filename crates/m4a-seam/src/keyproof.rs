//! Proof-of-possession login: an identity is an ed25519 key pair held by the CLIENT; it proves
//! itself by signing a server challenge. No password, no shared secret, nothing an agent can read.
//!
//! Two signed statements, both over fixed UTF-8 text so every implementation signs the same bytes:
//!
//! ```text
//! m4a-key-login-v1          m4a-key-enroll-v1
//! <audience>                <audience>
//! <key_id>                  <sha256 hex of the invite code>
//! <challenge_id>            <key_id>
//! <nonce>                   <public key, base64url>
//! <expires_ms>
//! ```
//! (every line ends in a newline). Keys and signatures travel as unpadded base64url. `key_id` is
//! `k` plus the first 32 hex characters of SHA-256 of the raw public key; it is also the stable
//! credential reference of that identity.
//!
//! Replay protection is the verifier's job and is part of the contract: a challenge is bound to
//! one `key_id`, expires, and is consumed by the first attempt, successful or not (see
//! `m4a_product_kit::keylogin::ChallengeBook`). The audience stops a signature made for one
//! product from working on another.
//!
//! Matrix-style carriage (custom login type): `POST /login` with
//! `{"type": "org.m4a.login.signature", "key_id", "challenge_id", "signature"}`; a request with
//! only `key_id` is answered 401 with the challenge under the type's name.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The custom Matrix login type.
pub const LOGIN_TYPE: &str = "org.m4a.login.signature";
/// How long a challenge lives, milliseconds.
pub const CHALLENGE_TTL_MS: i64 = 60_000;

/// A login challenge as the verifier hands it out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    pub challenge_id: String,
    pub nonce: String,
    pub expires_ms: i64,
    pub audience: String,
}

/// `k` + 32 hex characters of SHA-256 over the raw public key bytes.
pub fn key_id_of(public_key: &[u8]) -> String {
    format!("k{}", &hex::encode(Sha256::digest(public_key))[..32])
}

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.as_bytes()).ok()
}

pub fn login_message(c: &Challenge, key_id: &str) -> Vec<u8> {
    format!("m4a-key-login-v1\n{}\n{}\n{}\n{}\n{}\n", c.audience, key_id, c.challenge_id, c.nonce, c.expires_ms).into_bytes()
}

pub fn invite_hash(invite_code: &str) -> String {
    hex::encode(Sha256::digest(invite_code.as_bytes()))
}

pub fn enroll_message(audience: &str, invite_code: &str, public_key_b64: &str) -> Vec<u8> {
    let key_id = decode(public_key_b64).map(|k| key_id_of(&k)).unwrap_or_default();
    format!("m4a-key-enroll-v1\n{}\n{}\n{}\n{}\n", audience, invite_hash(invite_code), key_id, public_key_b64).into_bytes()
}

/// Strict ed25519 verification of `signature_b64` over `message` by `public_key_b64`.
pub fn verify(public_key_b64: &str, message: &[u8], signature_b64: &str) -> bool {
    let Some(pk) = decode(public_key_b64).and_then(|b| <[u8; 32]>::try_from(b).ok()) else { return false };
    let Some(sig) = decode(signature_b64).and_then(|b| <[u8; 64]>::try_from(b).ok()) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
    vk.verify_strict(message, &Signature::from_bytes(&sig)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key() -> (SigningKey, String) {
        let sk = SigningKey::generate(&mut rand::thread_rng());
        let pk = encode(sk.verifying_key().as_bytes());
        (sk, pk)
    }

    fn challenge() -> Challenge {
        Challenge { challenge_id: "c1".into(), nonce: "n-0123".into(), expires_ms: 1_000, audience: "aud-a".into() }
    }

    #[test]
    fn login_signature_verifies_and_every_field_is_bound() {
        let (sk, pk) = key();
        let kid = key_id_of(&decode(&pk).unwrap());
        assert!(kid.starts_with('k') && kid.len() == 33);
        let c = challenge();
        let sig = encode(&sk.sign(&login_message(&c, &kid)).to_bytes());
        assert!(verify(&pk, &login_message(&c, &kid), &sig));
        for tweak in [
            Challenge { audience: "aud-b".into(), ..c.clone() },
            Challenge { nonce: "n-other".into(), ..c.clone() },
            Challenge { challenge_id: "c2".into(), ..c.clone() },
            Challenge { expires_ms: 2_000, ..c.clone() },
        ] {
            assert!(!verify(&pk, &login_message(&tweak, &kid), &sig), "{tweak:?}");
        }
        assert!(!verify(&pk, &login_message(&c, "kother"), &sig));
        let (_, other_pk) = key();
        assert!(!verify(&other_pk, &login_message(&c, &kid), &sig));
    }

    #[test]
    fn enroll_signature_binds_invite_audience_and_key() {
        let (sk, pk) = key();
        let sig = encode(&sk.sign(&enroll_message("aud-a", "invite-1", &pk)).to_bytes());
        assert!(verify(&pk, &enroll_message("aud-a", "invite-1", &pk), &sig));
        assert!(!verify(&pk, &enroll_message("aud-b", "invite-1", &pk), &sig));
        assert!(!verify(&pk, &enroll_message("aud-a", "invite-2", &pk), &sig));
    }

    #[test]
    fn garbage_is_refused_not_a_panic() {
        assert!(!verify("", b"x", ""));
        assert!(!verify("AAAA", b"x", "AAAA"));
        assert!(!verify(&encode(&[0u8; 32]), b"x", &encode(&[0u8; 64])));
        assert!(decode("not base64 !!").is_none());
    }
}
