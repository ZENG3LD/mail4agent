//! The in-process bus as a backend: requests of a session this client holds go to the bus (which
//! answers locally or passes them on); everything else is the wrapped backend's.

use std::sync::Arc;
use std::time::Duration;

use m4a_agent::engine::News;
use m4a_agent::{AgentError, Backend, BackendKind, Capabilities, IdentityStore, Session, SessionIdentity};
use mail4agent_messenger::{HttpResponseDescriptor, OutgoingRequest};

use crate::machine::LocalBus;

pub(crate) struct BusBackend {
    pub(crate) inner: Arc<dyn Backend>,
    pub(crate) bus: Arc<LocalBus>,
    pub(crate) user_id: String,
    /// Set on a frozen copy: whether the exchange was local when the request was started.
    pub(crate) force_local: Option<bool>,
}

impl Backend for BusBackend {
    fn kind(&self) -> BackendKind {
        self.inner.kind()
    }
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }
    fn server_ref(&self) -> &str {
        self.inner.server_ref()
    }
    fn ensure_session(&self, ids: &IdentityStore, id: &mut SessionIdentity, invite: Option<&str>) -> Result<Session, AgentError> {
        self.inner.ensure_session(ids, id, invite)
    }
    fn execute(&self, request: &OutgoingRequest) -> Result<HttpResponseDescriptor, AgentError> {
        self.bus
            .fulfill(&self.user_id, request, self.force_local, &|r| self.inner.execute(r).map_err(crate::ShellError::from))
            .map(|(response, _hit_remote)| response)
            .map_err(|e| match e {
                crate::ShellError::Http(t) => AgentError::Transport(t),
                other => AgentError::Transport(crate::clip_public(other.to_string())),
            })
    }
    fn frozen(&self) -> Option<Arc<dyn Backend>> {
        Some(Arc::new(BusBackend { inner: Arc::clone(&self.inner), bus: Arc::clone(&self.bus), user_id: self.user_id.clone(), force_local: Some(self.bus.local_only()) }))
    }
    fn whoami(&self) -> Result<(String, String), AgentError> {
        self.inner.whoami()
    }
    fn keep_prefix(&self) -> bool {
        self.inner.keep_prefix()
    }
    fn wait_for_news(&self, timeout: Duration) -> Result<News, AgentError> {
        self.inner.wait_for_news(timeout)
    }
}
