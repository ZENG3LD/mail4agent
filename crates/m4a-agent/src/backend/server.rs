//! Tier 2: our server through its own product API (no Matrix).

use std::sync::Arc;

use zeroize::Zeroizing;

use super::wire::{HttpWire, Wire};
use super::{Backend, BackendKind, Capabilities, Session};
use crate::error::{AgentError, Result};
use crate::identity::{IdentityStore, SessionIdentity};
use crate::keyauth;

pub struct ServerBackend {
    base: String,
    wire: Arc<dyn Wire>,
    #[cfg(feature = "engine")]
    live: super::live::Live,
}

impl ServerBackend {
    pub fn new(base_url: &str) -> Result<Self> {
        Self::with_wire(base_url, Box::new(HttpWire::new(base_url)?))
    }

    /// Over any transport (tests).
    pub fn with_wire(base_url: &str, wire: Box<dyn Wire>) -> Result<Self> {
        Ok(Self {
            base: base_url.trim_end_matches('/').to_string(),
            wire: Arc::from(wire),
            #[cfg(feature = "engine")]
            live: super::live::Live::new(crate::engine::HttpExec::new(base_url)?),
        })
    }

    fn established(&self, token: &str) {
        #[cfg(feature = "engine")]
        {
            self.live.set_token(token);
            // The product's own proxy serves the Matrix paths without the spec prefix.
            self.live.with_exec(|e| e.set_keep_prefix(false));
        }
        let _ = token;
    }
}

impl Backend for ServerBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Server
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities { rooms: false, federation: false }
    }
    fn server_ref(&self) -> &str {
        &self.base
    }

    fn ensure_session(&self, ids: &IdentityStore, id: &mut SessionIdentity, invite: Option<&str>) -> Result<Session> {
        if id.tier != BackendKind::Server || id.server_ref != self.base {
            return Err(AgentError::Identity("identity belongs to another tier or server".into()));
        }
        if let Some(t) = keyauth::stored_token(ids, id)? {
            let (st, v) = self.wire.get("/product/v1/me", Some(&t))?;
            if st == 200 {
                let nick = v.get("nick").and_then(|n| n.as_str()).unwrap_or_default().to_string();
                self.established(&t);
                return Ok(Session { token: Zeroizing::new(t), nick, cred_ref: id.key_id.clone(), user_id: None, device_id: None });
            }
        }
        let (nick, token) = if id.enrolled {
            keyauth::login(&*self.wire, ids, id)?
        } else {
            keyauth::enroll(&*self.wire, ids, id, invite.ok_or(AgentError::NeedsInvite)?)?
        };
        self.established(&token);
        Ok(Session { token: Zeroizing::new(token), nick, cred_ref: id.key_id.clone(), user_id: None, device_id: None })
    }

    #[cfg(feature = "engine")]
    fn execute(&self, request: &mail4agent_messenger::OutgoingRequest) -> Result<mail4agent_messenger::HttpResponseDescriptor> {
        self.live.execute(request)
    }

    #[cfg(feature = "engine")]
    fn wait_for_news(&self, timeout: std::time::Duration) -> Result<crate::engine::News> {
        self.live.wait_for_news(timeout)
    }

    #[cfg(feature = "engine")]
    fn whoami(&self) -> Result<(String, String)> {
        self.live.whoami()
    }

    #[cfg(feature = "engine")]
    fn keep_prefix(&self) -> bool {
        self.live.keep_prefix()
    }
}
