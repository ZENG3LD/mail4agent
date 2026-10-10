//! Tier 2: our server through its own product API (no Matrix).

use zeroize::Zeroizing;

use super::wire::{HttpWire, Wire};
use super::{Backend, BackendKind, Capabilities, Session};
use crate::error::{AgentError, Result};
use crate::identity::{IdentityStore, SessionIdentity};
use crate::keyauth;

pub struct ServerBackend {
    base: String,
    wire: Box<dyn Wire>,
}

impl ServerBackend {
    pub fn new(base_url: &str) -> Result<Self> {
        Ok(Self { base: base_url.trim_end_matches('/').to_string(), wire: Box::new(HttpWire::new(base_url)?) })
    }

    /// Over any transport (tests).
    pub fn with_wire(base_url: &str, wire: Box<dyn Wire>) -> Self {
        Self { base: base_url.trim_end_matches('/').to_string(), wire }
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

    fn ensure_session(&mut self, ids: &IdentityStore, id: &mut SessionIdentity, invite: Option<&str>) -> Result<Session> {
        if id.tier != BackendKind::Server || id.server_ref != self.base {
            return Err(AgentError::Identity("identity belongs to another tier or server".into()));
        }
        if let Some(t) = keyauth::stored_token(ids, id)? {
            let (st, v) = self.wire.get("/product/v1/me", Some(&t))?;
            if st == 200 {
                let nick = v.get("nick").and_then(|n| n.as_str()).unwrap_or_default().to_string();
                return Ok(Session { token: Zeroizing::new(t), nick, cred_ref: id.key_id.clone(), user_id: None, device_id: None });
            }
        }
        let (nick, token) = if id.enrolled {
            keyauth::login(&*self.wire, ids, id)?
        } else {
            keyauth::enroll(&*self.wire, ids, id, invite.ok_or(AgentError::NeedsInvite)?)?
        };
        Ok(Session { token: Zeroizing::new(token), nick, cred_ref: id.key_id.clone(), user_id: None, device_id: None })
    }
}
