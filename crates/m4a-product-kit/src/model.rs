//! User model and the storage trait a product implements over its own database.

use std::fmt;

/// One person of the product. `nick` is the messenger identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: i64,
    pub nick: String,
    /// Tariff tier name; the [`crate::tiers::TierTable`] maps it to the opaque flag.
    pub tier: String,
    /// Number of nick changes made so far (the first is free).
    pub nick_changes: u32,
    pub nick_changed_ms: i64,
}

#[derive(Debug)]
pub enum StoreError {
    /// The nick is used by another user.
    NickTaken,
    NotFound,
    Backend(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NickTaken => write!(f, "nick taken"),
            Self::NotFound => write!(f, "not found"),
            Self::Backend(m) => write!(f, "store: {m}"),
        }
    }
}

impl std::error::Error for StoreError {}

pub type StoreResult<T> = Result<T, StoreError>;

/// The product's user database, as the kit needs it. Nicks are unique
/// case-insensitively. A product with an existing database implements this
/// over its tables; the example crate has a SQLite implementation.
pub trait UserStore: Send + Sync {
    fn user_by_nick(&self, nick: &str) -> StoreResult<Option<User>>;
    /// `secret_hash` is an opaque password hash (or `None` for door-only users).
    fn insert_user(&self, nick: &str, tier: &str, secret_hash: Option<&str>, now_ms: i64) -> StoreResult<User>;
    fn secret_hash(&self, user_id: i64) -> StoreResult<Option<String>>;
    /// Changes the nick; must fail with [`StoreError::NickTaken`] on a collision.
    fn update_nick(&self, user_id: i64, new_nick: &str, now_ms: i64) -> StoreResult<User>;
    fn set_tier(&self, user_id: i64, tier: &str) -> StoreResult<()>;
    /// Removes the user and all its credentials and door links.
    fn delete_user(&self, user_id: i64) -> StoreResult<()>;
    fn add_credential(&self, user_id: i64, cred_ref: &str, token_hash: &str, now_ms: i64) -> StoreResult<()>;
    fn user_by_token_hash(&self, token_hash: &str) -> StoreResult<Option<(User, String)>>;
    /// Removes one credential; returns the owner's id when it existed.
    fn delete_credential(&self, cred_ref: &str) -> StoreResult<Option<i64>>;
    fn credentials_of(&self, user_id: i64) -> StoreResult<Vec<String>>;
    fn user_by_door(&self, source: &str, subject: &str) -> StoreResult<Option<User>>;
    fn link_door(&self, user_id: i64, source: &str, subject: &str) -> StoreResult<()>;
}
