//! The backend trait: what the client needs from any tier. Tiers are cargo features, so a tier
//! that is not wanted is not compiled.
//!
//! A backend gets a session (enroll once, then log in by signature) and, with the `engine`
//! feature, executes the engine's requests and waits for news.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::Result;
use crate::identity::{IdentityStore, SessionIdentity};

pub mod wire;
#[cfg(feature = "engine")]
pub mod live;
#[cfg(feature = "engine")]
pub mod attached;
#[cfg(all(feature = "engine", feature = "tier-matrix"))]
pub mod sliding;
#[cfg(feature = "tier-server")]
pub mod server;
#[cfg(feature = "tier-matrix")]
pub mod matrix;

/// Which tier an identity belongs to. Tier 1 (the local mail node) has no server and no login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    /// Tier 2: our server through its own product API.
    Server,
    /// Tier 3: the Matrix client API.
    Matrix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capabilities {
    /// Rooms and spaces (Matrix semantics).
    pub rooms: bool,
    /// Talks to other servers through federation.
    pub federation: bool,
}

/// A live session. The token is a secret: it is zeroized on drop and hidden from `Debug`.
pub struct Session {
    pub token: Zeroizing<String>,
    pub nick: String,
    /// Stable credential reference of the identity (its key id).
    pub cred_ref: String,
    /// Matrix tier only.
    pub user_id: Option<String>,
    pub device_id: Option<String>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("nick", &self.nick).field("cred_ref", &self.cred_ref).field("user_id", &self.user_id).field("device_id", &self.device_id).field("token", &"<hidden>").finish()
    }
}

pub trait Backend: Send + Sync {
    fn kind(&self) -> BackendKind;
    fn capabilities(&self) -> Capabilities;
    /// The normalized server base URL this backend talks to (the identity is bound to it).
    fn server_ref(&self) -> &str;
    /// A live session for `id`. First time: redeems the operator's `invite` (enroll the public key,
    /// proving possession of the private one); afterwards: logs in by signing a fresh challenge.
    /// Reuses the stored token while the server still accepts it. Persists what it learns.
    fn ensure_session(&self, ids: &IdentityStore, id: &mut SessionIdentity, invite: Option<&str>) -> Result<Session>;

    /// Performs one request of the engine as this session (bearer added, token refreshed once by
    /// signature if the server forgot it). Callable from any thread. Needs `ensure_session` first.
    #[cfg(feature = "engine")]
    fn execute(&self, request: &mail4agent_messenger::OutgoingRequest) -> Result<mail4agent_messenger::HttpResponseDescriptor>;

    /// A copy of this backend whose routing choices are frozen now, for a request that will run
    /// later on a worker (a long poll started for a local exchange must stay local). `None`: the
    /// backend has no such choices.
    #[cfg(feature = "engine")]
    fn frozen(&self) -> Option<std::sync::Arc<dyn Backend>> {
        None
    }

    /// `(user_id, device_id)` of the session (what the engine needs to open a core).
    #[cfg(feature = "engine")]
    fn whoami(&self) -> Result<(String, String)>;

    /// Whether this server serves the Matrix paths under `/_matrix` (found out, not assumed).
    #[cfg(feature = "engine")]
    fn keep_prefix(&self) -> bool;

    /// Waits up to `timeout` for news for this session: room events pushed on the server's push
    /// socket, or `Idle` (timeout, or the server has no push channel and the sync long poll is the
    /// wait).
    #[cfg(feature = "engine")]
    fn wait_for_news(&self, timeout: std::time::Duration) -> Result<crate::engine::News>;
}
