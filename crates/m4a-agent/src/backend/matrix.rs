//! Tier 3: the Matrix client API. Same key proof, carried by the custom login type
//! `org.m4a.login.signature`; enrollment (once) goes through the product's enroll endpoint, since
//! Matrix has no notion of an invite-bound key.

use m4a_seam::keyproof::LOGIN_TYPE;
use serde_json::json;
use zeroize::Zeroizing;

use super::wire::{field, HttpWire, Wire};
use super::{Backend, BackendKind, Capabilities, Session};
use crate::error::{AgentError, Result};
use crate::identity::{token_label, IdentityStore, SessionIdentity};
use crate::keyauth;

const LOGIN: &str = "/_matrix/client/v3/login";
const WHOAMI: &str = "/_matrix/client/v3/account/whoami";

pub struct MatrixBackend {
    base: String,
    wire: Box<dyn Wire>,
}

impl MatrixBackend {
    pub fn new(base_url: &str) -> Result<Self> {
        Ok(Self { base: base_url.trim_end_matches('/').to_string(), wire: Box::new(HttpWire::new(base_url)?) })
    }

    pub fn with_wire(base_url: &str, wire: Box<dyn Wire>) -> Self {
        Self { base: base_url.trim_end_matches('/').to_string(), wire }
    }

    /// The Matrix flow: ask with the key id, get the challenge in a 401, answer with the signature.
    fn matrix_login(&self, ids: &IdentityStore, id: &SessionIdentity) -> Result<Session> {
        let (st, v) = self.wire.post(LOGIN, &json!({ "type": LOGIN_TYPE, "key_id": id.key_id }), None)?;
        if st != 401 {
            return Err(keyauth::refused_or(st, "login challenge"));
        }
        let c = keyauth::parse_challenge(v.get(LOGIN_TYPE).ok_or_else(|| AgentError::Protocol("no challenge in the 401".into()))?)?;
        let signature = id.sign_login(ids.vault(), &c)?;
        let (st, v) = self.wire.post(LOGIN, &json!({ "type": LOGIN_TYPE, "key_id": id.key_id, "challenge_id": c.challenge_id, "signature": signature }), None)?;
        if st != 200 {
            return Err(keyauth::refused_or(st, "login"));
        }
        let token = field(&v, "access_token")?;
        ids.vault().put(&token_label(&id.session_id), token.as_bytes())?;
        let user_id = field(&v, "user_id")?;
        let nick = user_id.trim_start_matches('@').split(':').next().unwrap_or_default().to_string();
        Ok(Session { token: Zeroizing::new(token), nick, cred_ref: id.key_id.clone(), user_id: Some(user_id), device_id: v.get("device_id").and_then(|d| d.as_str()).map(str::to_string) })
    }
}

impl Backend for MatrixBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Matrix
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities { rooms: true, federation: true }
    }
    fn server_ref(&self) -> &str {
        &self.base
    }

    fn ensure_session(&mut self, ids: &IdentityStore, id: &mut SessionIdentity, invite: Option<&str>) -> Result<Session> {
        if id.tier != BackendKind::Matrix || id.server_ref != self.base {
            return Err(AgentError::Identity("identity belongs to another tier or server".into()));
        }
        if let Some(t) = keyauth::stored_token(ids, id)? {
            let (st, v) = self.wire.get(WHOAMI, Some(&t))?;
            if st == 200 {
                let user_id = field(&v, "user_id")?;
                let nick = user_id.trim_start_matches('@').split(':').next().unwrap_or_default().to_string();
                return Ok(Session { token: Zeroizing::new(t), nick, cred_ref: id.key_id.clone(), user_id: Some(user_id), device_id: v.get("device_id").and_then(|d| d.as_str()).map(str::to_string) });
            }
        }
        if !id.enrolled {
            keyauth::enroll(&*self.wire, ids, id, invite.ok_or(AgentError::NeedsInvite)?)?;
        }
        self.matrix_login(ids, id)
    }
}
