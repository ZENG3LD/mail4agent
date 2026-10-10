//! Product logic over a [`UserStore`]: placeholders, sessions, nick changes
//! with the cooldown, deletion. Every operation that the messenger must hear
//! about returns [`m4a_seam::Event`]s for the caller to publish.

use std::sync::Arc;

use m4a_seam::{Event, EventKind};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::model::{StoreError, User, UserStore};
use crate::nick_rules::{generate_placeholder, validate_nick, NickRules};
use crate::tiers::TierTable;

const DAY_MS: i64 = 86_400_000;

/// What the link needs to sign an assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthUser {
    pub nick: String,
    pub cred_ref: String,
    pub flag: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The secret the client presents; only its hash is stored.
    pub token: String,
    pub cred_ref: String,
}

#[derive(Debug)]
pub enum ServiceError {
    InvalidNick(String),
    NickTaken,
    /// Next change allowed in this many milliseconds.
    Cooldown { retry_after_ms: i64 },
    NotFound,
    Unauthorized,
    Internal(String),
}

impl From<StoreError> for ServiceError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NickTaken => Self::NickTaken,
            StoreError::NotFound => Self::NotFound,
            StoreError::Backend(m) => Self::Internal(m),
        }
    }
}

pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

pub fn new_event(kind: EventKind) -> Event {
    Event { id: random_hex(16), kind }
}

pub struct UserService<S: UserStore> {
    pub store: Arc<S>,
    pub rules: NickRules,
    pub tiers: TierTable,
}

impl<S: UserStore> UserService<S> {
    pub fn new(store: Arc<S>, rules: NickRules, tiers: TierTable) -> Self {
        Self { store, rules, tiers }
    }

    fn placeholder(&self) -> Result<String, ServiceError> {
        let store = &self.store;
        generate_placeholder(&mut rand::thread_rng(), &self.rules.lists, |c| matches!(store.user_by_nick(c), Ok(None)))
            .map_err(|e| ServiceError::Internal(e.0))
    }

    /// New user with a random 8-letter placeholder nick in the default tier.
    pub fn create_user(&self, secret_hash: Option<&str>, now_ms: i64) -> Result<User, ServiceError> {
        for _ in 0..4 {
            let nick = self.placeholder()?;
            match self.store.insert_user(&nick, self.tiers.default_tier(), secret_hash, now_ms) {
                Err(StoreError::NickTaken) => continue,
                other => return Ok(other?),
            }
        }
        Err(ServiceError::Internal("placeholder collisions".into()))
    }

    /// Issue a session (credential) for a user.
    pub fn issue_session(&self, user: &User, now_ms: i64) -> Result<Session, ServiceError> {
        let token = random_hex(32);
        let cred_ref = random_hex(12);
        self.store.add_credential(user.id, &cred_ref, &token_hash(&token), now_ms)?;
        Ok(Session { token, cred_ref })
    }

    /// A session whose access token expires after `access_ttl_ms`, with a refresh token valid for
    /// `refresh_ttl_ms`. Needs a store with [`UserStore::supports_refresh`].
    pub fn issue_refreshable_session(&self, user: &User, now_ms: i64, access_ttl_ms: i64, refresh_ttl_ms: i64) -> Result<(Session, String), ServiceError> {
        let session = self.issue_session(user, now_ms)?;
        let refresh = random_hex(32);
        self.store.set_refresh(&session.cred_ref, &token_hash(&refresh), now_ms + access_ttl_ms, now_ms + refresh_ttl_ms)?;
        Ok((session, refresh))
    }

    /// Exchanges a refresh token for a new access token and a new refresh token for the same
    /// credential (so the messenger-side device is unchanged). `None`: unknown or expired.
    pub fn refresh(&self, refresh_token: &str, now_ms: i64, access_ttl_ms: i64, refresh_ttl_ms: i64) -> Result<Option<(Session, String)>, ServiceError> {
        let Some(cred_ref) = self.store.take_refresh(&token_hash(refresh_token), now_ms)? else { return Ok(None) };
        let (token, refresh) = (random_hex(32), random_hex(32));
        self.store.replace_token(&cred_ref, &token_hash(&token), now_ms + access_ttl_ms)?;
        self.store.set_refresh(&cred_ref, &token_hash(&refresh), now_ms + access_ttl_ms, now_ms + refresh_ttl_ms)?;
        Ok(Some((Session { token, cred_ref }, refresh)))
    }

    /// Resolve a presented token to what the link asserts.
    pub fn authenticate(&self, token: &str) -> Result<Option<AuthUser>, ServiceError> {
        Ok(self.store.user_by_token_hash(&token_hash(token))?.map(|(u, cred_ref)| AuthUser { flag: self.tiers.flag(&u.tier), nick: u.nick, cred_ref }))
    }

    /// Find the user behind a door proof, creating it (placeholder nick) on first login.
    pub fn user_for_door(&self, source: &str, subject: &str, now_ms: i64) -> Result<User, ServiceError> {
        if let Some(u) = self.store.user_by_door(source, subject)? {
            return Ok(u);
        }
        let u = self.create_user(None, now_ms)?;
        self.store.link_door(u.id, source, subject)?;
        Ok(u)
    }

    /// Self-service nick change: grammar and lists, uniqueness, first change
    /// free then the cooldown. The messenger hears `nick.changed`.
    pub fn set_nick(&self, user: &User, new_nick: &str, now_ms: i64) -> Result<(User, Vec<Event>), ServiceError> {
        validate_nick(new_nick, &self.rules.lists).map_err(|e| ServiceError::InvalidNick(e.0))?;
        if user.nick_changes >= 1 {
            let next = user.nick_changed_ms + self.rules.cooldown_days * DAY_MS;
            if now_ms < next {
                return Err(ServiceError::Cooldown { retry_after_ms: next - now_ms });
            }
        }
        let updated = self.store.update_nick(user.id, new_nick, now_ms)?;
        let ev = new_event(EventKind::NickChanged { old: user.nick.clone(), new: updated.nick.clone() });
        Ok((updated, vec![ev]))
    }

    /// Snapshot(s) of every live credential for startup reconciliation. One complete snapshot
    /// when the user count is at most `chunk`; otherwise partial chunks (credential-level only,
    /// no retirement of unlisted identities, because no single message lists everyone).
    pub fn reconcile_snapshots(&self, chunk: usize) -> Result<Vec<m4a_seam::Reconcile>, ServiceError> {
        let all: Vec<m4a_seam::LiveNick> = self.store.live_credentials()?.into_iter().map(|(nick, creds)| m4a_seam::LiveNick { nick, creds }).collect();
        let complete = all.len() <= chunk.max(1);
        if complete {
            return Ok(vec![m4a_seam::Reconcile { id: random_hex(8), complete: true, nicks: all }]);
        }
        Ok(all.chunks(chunk.max(1)).map(|c| m4a_seam::Reconcile { id: random_hex(8), complete: false, nicks: c.to_vec() }).collect())
    }

    /// Log one credential out. Returns the event when it existed.
    pub fn revoke(&self, cred_ref: &str) -> Result<Vec<Event>, ServiceError> {
        Ok(match self.store.delete_credential(cred_ref)? {
            Some(_) => vec![new_event(EventKind::CredentialRevoked { cred_ref: cred_ref.to_string() })],
            None => vec![],
        })
    }

    /// Delete a user: every credential is revoked, then the account is deleted.
    pub fn delete(&self, nick: &str) -> Result<Vec<Event>, ServiceError> {
        let Some(u) = self.store.user_by_nick(nick)? else { return Err(ServiceError::NotFound) };
        let mut evs: Vec<Event> = self.store.credentials_of(u.id)?.into_iter().map(|c| new_event(EventKind::CredentialRevoked { cred_ref: c })).collect();
        self.store.delete_user(u.id)?;
        evs.push(new_event(EventKind::AccountDeleted { nick: u.nick }));
        Ok(evs)
    }
}
