//! A backend over a session somebody else established: the host did its own login (a single
//! sign-on page, say) and hands over the resulting token, or a test talks to a stock homeserver.
//! It cannot log in by itself. Agents never get here with a secret of their own: only a host that
//! already holds one for them.

use std::time::Duration;

use mail4agent_messenger::{HttpResponseDescriptor, OutgoingRequest};

use super::live::Live;
use super::{Backend, BackendKind, Capabilities, Session};
use crate::engine::{HttpExec, News};
use crate::error::{AgentError, Result};
use crate::identity::{IdentityStore, SessionIdentity};

pub struct AttachedBackend {
    kind: BackendKind,
    base: String,
    live: Live,
    #[cfg(feature = "tier-matrix")]
    sliding: super::sliding::Sliding,
}

impl AttachedBackend {
    /// `base` is the server's origin. The spec prefix and sliding sync are asked of the server.
    pub fn new(kind: BackendKind, base: &str, token: &str) -> Result<Self> {
        let mut exec = HttpExec::new(base)?;
        exec.probe_prefix();
        Self::from_exec(kind, base, token, exec)
    }

    /// No network at all: `keep_prefix` says whether the server serves the paths under `/_matrix`,
    /// and sliding sync stays off.
    pub fn with_prefix(kind: BackendKind, base: &str, token: &str, keep_prefix: bool) -> Result<Self> {
        let mut exec = HttpExec::new(base)?;
        exec.set_keep_prefix(keep_prefix);
        let me = Self::from_exec(kind, base, token, exec)?;
        #[cfg(feature = "tier-matrix")]
        me.sliding.set_mode(super::matrix::SyncMode::V3);
        #[cfg(feature = "tier-matrix")]
        me.sliding.decide(&me.live);
        Ok(me)
    }

    fn from_exec(kind: BackendKind, base: &str, token: &str, exec: HttpExec) -> Result<Self> {
        let live = Live::new(exec);
        live.set_token(token);
        let me = Self {
            kind,
            base: base.trim_end_matches('/').to_string(),
            live,
            #[cfg(feature = "tier-matrix")]
            sliding: super::sliding::Sliding::new(),
        };
        #[cfg(feature = "tier-matrix")]
        if kind == BackendKind::Matrix {
            me.sliding.decide(&me.live);
        }
        Ok(me)
    }

    /// Plain `/sync` v3 only.
    #[cfg(feature = "tier-matrix")]
    pub fn without_sliding_sync(self) -> Self {
        self.sliding.set_mode(super::matrix::SyncMode::V3);
        self.sliding.decide(&self.live);
        self
    }

    #[cfg(feature = "tier-matrix")]
    pub fn uses_sliding_sync(&self) -> bool {
        self.sliding.active()
    }
}

impl Backend for AttachedBackend {
    fn kind(&self) -> BackendKind {
        self.kind
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities { rooms: self.kind == BackendKind::Matrix, federation: self.kind == BackendKind::Matrix }
    }
    fn server_ref(&self) -> &str {
        &self.base
    }
    fn ensure_session(&self, _: &IdentityStore, _: &mut SessionIdentity, _: Option<&str>) -> Result<Session> {
        Err(AgentError::Identity("this backend was handed an established session and cannot log in".into()))
    }
    fn execute(&self, request: &OutgoingRequest) -> Result<HttpResponseDescriptor> {
        #[cfg(feature = "tier-matrix")]
        if request.kind == mail4agent_messenger::OutgoingRequestKind::Sync {
            if let Some(answer) = self.sliding.sync(&self.live, request)? {
                return Ok(answer);
            }
        }
        self.live.execute(request)
    }
    fn whoami(&self) -> Result<(String, String)> {
        self.live.whoami()
    }
    fn keep_prefix(&self) -> bool {
        self.live.keep_prefix()
    }
    fn wait_for_news(&self, timeout: Duration) -> Result<News> {
        self.live.wait_for_news(timeout)
    }
}
