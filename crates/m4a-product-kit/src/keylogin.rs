//! Login by proof of possession (see `m4a_seam::keyproof`): the challenge book that gives replay
//! protection, and the [`UserService`] operations built on it: invite, enroll, key login.

use std::collections::HashMap;
use std::sync::Mutex;

use m4a_seam::keyproof::{self, Challenge, CHALLENGE_TTL_MS};
use rand::RngCore;

use crate::model::{StoreError, User, UserStore};
use crate::service::{token_hash, ServiceError, Session, UserService};

const MAX_OPEN_CHALLENGES: usize = 10_000;
/// How long an invite lives.
pub const INVITE_TTL_MS: i64 = 7 * 86_400_000;

fn random_b64(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut b);
    keyproof::encode(&b)
}

/// Open challenges: each is bound to one key id, expires, and is consumed by the first attempt to
/// use it, whether the signature was good or not. In memory on purpose: a challenge lives a minute.
pub struct ChallengeBook {
    audience: String,
    open: Mutex<HashMap<String, (String, Challenge)>>,
}

impl ChallengeBook {
    /// `audience` names this product; signatures made for another audience do not verify.
    pub fn new(audience: impl Into<String>) -> Self {
        Self { audience: audience.into(), open: Mutex::new(HashMap::new()) }
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// A fresh challenge for `key_id` (handed out whether or not the key exists, so the answer does
    /// not reveal which keys are enrolled).
    pub fn issue(&self, key_id: &str, now_ms: i64) -> Challenge {
        let c = Challenge { challenge_id: random_b64(18), nonce: random_b64(24), expires_ms: now_ms + CHALLENGE_TTL_MS, audience: self.audience.clone() };
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        if open.len() >= MAX_OPEN_CHALLENGES {
            open.retain(|_, (_, c)| c.expires_ms > now_ms);
        }
        if open.len() < MAX_OPEN_CHALLENGES {
            open.insert(c.challenge_id.clone(), (key_id.to_string(), c.clone()));
        }
        c
    }

    /// Consumes a challenge: `Some` only when it exists, belongs to `key_id` and has not expired.
    pub fn take(&self, challenge_id: &str, key_id: &str, now_ms: i64) -> Option<Challenge> {
        let (owner, c) = self.open.lock().unwrap_or_else(|e| e.into_inner()).remove(challenge_id)?;
        (owner == key_id && c.expires_ms > now_ms).then_some(c)
    }
}

impl<S: UserStore> UserService<S> {
    /// The operator approves an identity once: a user is created (with `nick` if given and free,
    /// else a placeholder) and an invite code is returned for the client to enroll with. The code is
    /// shown once; only its hash is stored.
    pub fn invite(&self, nick: Option<&str>, tier: Option<&str>, now_ms: i64) -> Result<(String, User), ServiceError> {
        if !self.store.supports_keys() {
            return Err(ServiceError::Internal("this store does not support key login".into()));
        }
        let user = match nick {
            Some(n) => {
                crate::nick_rules::validate_nick(n, &self.rules.lists).map_err(|e| ServiceError::InvalidNick(e.0))?;
                self.store.insert_user(n, tier.unwrap_or_else(|| self.tiers.default_tier()), None, now_ms)?
            }
            None => self.create_user(None, now_ms)?,
        };
        let code = random_b64(24);
        self.store.create_invite_with(&token_hash(&code), user.id, now_ms + INVITE_TTL_MS, nick.is_some())?;
        Ok((code, user))
    }

    /// The client enrolls its public key with an invite code, proving it holds the private key
    /// (the signature covers the audience, the invite and the key). The key's credential is created
    /// and a session is issued; `cred_ref` is the key id, stable across logins.
    pub fn enroll(&self, audience: &str, code: &str, public_key_b64: &str, signature_b64: &str, label: &str, now_ms: i64, session_ttl_ms: i64) -> Result<(User, Session, String), ServiceError> {
        self.enroll_with_nick(audience, code, public_key_b64, signature_b64, label, None, now_ms, session_ttl_ms)
    }

    /// [`Self::enroll`] where the client also asks for a nick (its session name). The operator's
    /// approval is still the invite. If the operator reserved a nick in the invite and the request
    /// differs, the enrollment is refused and the invite stays usable. If the invite carries a
    /// placeholder, the request is checked by the nick rules and the lists, must be free, and
    /// replaces the placeholder before the key's credential exists. An empty request asks for nothing.
    pub fn enroll_with_nick(&self, audience: &str, code: &str, public_key_b64: &str, signature_b64: &str, label: &str, requested_nick: Option<&str>, now_ms: i64, session_ttl_ms: i64) -> Result<(User, Session, String), ServiceError> {
        let requested = requested_nick.map(str::trim).filter(|n| !n.is_empty());
        let raw = keyproof::decode(public_key_b64).filter(|k| k.len() == 32).ok_or(ServiceError::Unauthorized)?;
        if !keyproof::verify(public_key_b64, &keyproof::enroll_message(audience, code, public_key_b64), signature_b64) {
            return Err(ServiceError::Unauthorized);
        }
        let key_id = keyproof::key_id_of(&raw);
        let hash = token_hash(code);
        // Look first where the store can: a refused request must not spend the operator's invite.
        if let (Some(want), Some((user, reserved))) = (requested, self.store.peek_invite(&hash, now_ms)?) {
            self.check_requested_nick(&user, reserved, want, now_ms)?;
        }
        let (mut user, reserved) = self.store.take_invite_with(&hash, now_ms)?.ok_or(ServiceError::Unauthorized)?;
        if let Some(want) = requested {
            let renamed = self.check_requested_nick(&user, reserved, want, now_ms).and_then(|rename| {
                if rename {
                    self.store.update_nick(user.id, want, now_ms).map_err(ServiceError::from)
                } else {
                    Ok(user.clone())
                }
            });
            match renamed {
                Ok(u) => user = u,
                Err(e) => {
                    // Give the invite back (same code, fresh lifetime): the operator approved it.
                    let _ = self.store.create_invite_with(&hash, user.id, now_ms + INVITE_TTL_MS, reserved);
                    return Err(e);
                }
            }
        }
        let label: String = label.chars().filter(|c| !c.is_control()).take(64).collect();
        self.store.add_key(user.id, &key_id, public_key_b64, &label, now_ms)?;
        let session = self.key_session(&user, &key_id, now_ms, session_ttl_ms)?;
        Ok((user, session, key_id))
    }

    /// `Ok(true)`: replace the placeholder by `want`; `Ok(false)`: `want` is the nick the user has.
    fn check_requested_nick(&self, user: &User, reserved: bool, want: &str, now_ms: i64) -> Result<bool, ServiceError> {
        if want.eq_ignore_ascii_case(&user.nick) {
            return Ok(false);
        }
        if reserved {
            return Err(ServiceError::InvalidNick("the invite reserves another nick".into()));
        }
        crate::nick_rules::validate_nick(want, &self.rules.lists).map_err(|e| ServiceError::InvalidNick(e.0))?;
        if user.nick_changes >= 1 {
            let next = user.nick_changed_ms + self.rules.cooldown_days * 86_400_000;
            if now_ms < next {
                return Err(ServiceError::Cooldown { retry_after_ms: next - now_ms });
            }
        }
        if self.store.user_by_nick(want)?.is_some() {
            return Err(ServiceError::NickTaken);
        }
        Ok(true)
    }

    /// Verifies a signed challenge and hands out a fresh access token for the key's credential.
    pub fn key_login(&self, book: &ChallengeBook, key_id: &str, challenge_id: &str, signature_b64: &str, now_ms: i64, session_ttl_ms: i64) -> Result<(User, Session), ServiceError> {
        // The challenge is consumed first: a wrong signature burns it, so it cannot be guessed at.
        let challenge = book.take(challenge_id, key_id, now_ms).ok_or(ServiceError::Unauthorized)?;
        let (user, public_key) = match self.store.user_by_key(key_id) {
            Ok(Some(found)) => found,
            Ok(None) | Err(StoreError::NotFound) => return Err(ServiceError::Unauthorized),
            Err(e) => return Err(e.into()),
        };
        if challenge.audience != book.audience() || !keyproof::verify(&public_key, &keyproof::login_message(&challenge, key_id), signature_b64) {
            return Err(ServiceError::Unauthorized);
        }
        let session = self.key_session(&user, key_id, now_ms, session_ttl_ms)?;
        Ok((user, session))
    }

    /// Verifies a signed challenge like [`Self::key_login`] but issues no session: the proof alone,
    /// for callers that hand out something else (a one-time Matrix login token). The challenge is
    /// consumed whatever the outcome.
    pub fn key_proof(&self, book: &ChallengeBook, key_id: &str, challenge_id: &str, signature_b64: &str, now_ms: i64) -> Result<User, ServiceError> {
        let challenge = book.take(challenge_id, key_id, now_ms).ok_or(ServiceError::Unauthorized)?;
        let (user, public_key) = match self.store.user_by_key(key_id) {
            Ok(Some(found)) => found,
            Ok(None) | Err(StoreError::NotFound) => return Err(ServiceError::Unauthorized),
            Err(e) => return Err(e.into()),
        };
        if challenge.audience != book.audience() || !keyproof::verify(&public_key, &keyproof::login_message(&challenge, key_id), signature_b64) {
            return Err(ServiceError::Unauthorized);
        }
        Ok(user)
    }

    /// Removes a key and, with it, the ability to log in again.
    pub fn remove_key(&self, key_id: &str) -> Result<bool, ServiceError> {
        Ok(self.store.delete_key(key_id)?)
    }

    fn key_session(&self, user: &User, key_id: &str, now_ms: i64, ttl_ms: i64) -> Result<Session, ServiceError> {
        let token = random_b64(32);
        let have = self.store.credentials_of(user.id)?.iter().any(|c| c == key_id);
        if have {
            self.store.replace_token(key_id, &token_hash(&token), now_ms + ttl_ms)?;
        } else {
            self.store.add_credential(user.id, key_id, &token_hash(&token), now_ms)?;
            self.store.replace_token(key_id, &token_hash(&token), now_ms + ttl_ms)?;
        }
        Ok(Session { token, cred_ref: key_id.to_string() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_challenge_is_single_use_bound_to_its_key_and_expires() {
        let book = ChallengeBook::new("aud");
        let c = book.issue("k1", 1_000);
        assert_eq!(c.audience, "aud");
        assert!(book.take(&c.challenge_id, "k2", 1_001).is_none(), "wrong key");
        assert!(book.take(&c.challenge_id, "k1", 1_001).is_none(), "the wrong-key attempt consumed it");
        let c = book.issue("k1", 1_000);
        assert_eq!(book.take(&c.challenge_id, "k1", 1_001), Some(c.clone()));
        assert!(book.take(&c.challenge_id, "k1", 1_001).is_none(), "second use");
        let c = book.issue("k1", 1_000);
        assert!(book.take(&c.challenge_id, "k1", 1_000 + CHALLENGE_TTL_MS).is_none(), "expired");
        assert_ne!(book.issue("k1", 0).nonce, book.issue("k1", 0).nonce);
    }
}
