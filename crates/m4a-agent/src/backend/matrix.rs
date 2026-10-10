//! Tier 3: the Matrix client API. Same key proof, carried by the custom login type
//! `org.m4a.login.signature`; enrollment (once) goes through the product's enroll endpoint, since
//! Matrix has no notion of an invite-bound key.
//!
//! With the `engine` feature it also runs the engine: `.well-known` discovery of the real server
//! address, the spec prefix only when the server serves it, a token refresh by signature when the
//! server forgot the token, and sync by sliding sync (MSC4186) when the server offers it, falling
//! back to `/sync` v3.

use std::sync::Arc;

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

/// Which sync the engine's `/sync` calls become.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// Sliding sync when the server advertises it, `/sync` v3 otherwise (and after a refusal).
    Auto,
    /// Always `/sync` v3.
    V3,
}

pub struct MatrixBackend {
    base: String,
    wire: Arc<dyn Wire>,
    #[cfg(feature = "engine")]
    live: Arc<super::live::Live>,
    #[cfg(feature = "engine")]
    sliding: super::sliding::Sliding,
}

/// `GET /.well-known/matrix/client`: the server address the domain says clients should use.
/// `None` when there is no (usable) answer: the origin itself is then the server.
#[cfg(feature = "engine")]
pub fn discover_base(origin: &str) -> Option<String> {
    let exec = crate::engine::HttpExec::new(origin).ok()?;
    let (st, v) = exec.get_json("/.well-known/matrix/client").ok()?;
    if st != 200 {
        return None;
    }
    let found = v.get("m.homeserver")?.get("base_url")?.as_str()?.trim_end_matches('/').to_string();
    // Only a real origin is taken; anything else is ignored rather than trusted.
    crate::engine::http::parse_origin(&found).ok()?;
    Some(found)
}

impl MatrixBackend {
    /// No network. The origin is taken as the server.
    pub fn new(base_url: &str) -> Result<Self> {
        Self::with_wire(base_url, Box::new(HttpWire::new(base_url)?))
    }

    /// Asks the domain's `.well-known` for the real server address first, then connects there.
    #[cfg(feature = "engine")]
    pub fn discover(origin: &str) -> Result<Self> {
        let real = discover_base(origin).unwrap_or_else(|| origin.trim_end_matches('/').to_string());
        Self::new(&real)
    }

    pub fn with_wire(base_url: &str, wire: Box<dyn Wire>) -> Result<Self> {
        Ok(Self {
            base: base_url.trim_end_matches('/').to_string(),
            wire: Arc::from(wire),
            #[cfg(feature = "engine")]
            live: Arc::new(super::live::Live::new(crate::engine::HttpExec::new(base_url)?)),
            #[cfg(feature = "engine")]
            sliding: super::sliding::Sliding::new(),
        })
    }

    #[cfg(feature = "engine")]
    pub fn with_sync_mode(self, mode: SyncMode) -> Self {
        self.sliding.set_mode(mode);
        self
    }

    /// Whether `/sync` calls are currently served by sliding sync (after the first sync decided).
    #[cfg(feature = "engine")]
    pub fn uses_sliding_sync(&self) -> bool {
        self.sliding.active()
    }

    /// The server's real base URL (after discovery), without any fragment.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// The Matrix flow: ask with the key id, get the challenge in a 401, answer with the signature.
    fn login_by_signature(wire: &dyn Wire, ids: &IdentityStore, id: &SessionIdentity) -> Result<(String, Option<String>, String)> {
        let (st, v) = wire.post(LOGIN, &json!({ "type": LOGIN_TYPE, "key_id": id.key_id }), None)?;
        if st != 401 {
            return Err(keyauth::refused_or(st, "login challenge"));
        }
        let c = keyauth::parse_challenge(v.get(LOGIN_TYPE).ok_or_else(|| AgentError::Protocol("no challenge in the 401".into()))?)?;
        let signature = id.sign_login(ids.vault(), &c)?;
        let (st, v) = wire.post(LOGIN, &json!({ "type": LOGIN_TYPE, "key_id": id.key_id, "challenge_id": c.challenge_id, "signature": signature }), None)?;
        if st != 200 {
            return Err(keyauth::refused_or(st, "login"));
        }
        let token = field(&v, "access_token")?;
        ids.vault().put(&token_label(&id.session_id), token.as_bytes())?;
        Ok((token, v.get("device_id").and_then(|d| d.as_str()).map(str::to_string), field(&v, "user_id")?))
    }

    fn session_of(&self, id: &SessionIdentity, token: String, user_id: String, device_id: Option<String>) -> Session {
        let nick = user_id.trim_start_matches('@').split(':').next().unwrap_or_default().to_string();
        let _ = self;
        Session { token: Zeroizing::new(token), nick, cred_ref: id.key_id.clone(), user_id: Some(user_id), device_id }
    }

    #[allow(unused_variables)]
    fn established(&self, ids: &IdentityStore, id: &SessionIdentity, token: &str) {
        #[cfg(feature = "engine")]
        {
            self.live.set_token(token);
            // The server is asked whether it serves the spec prefix; ours does not need it.
            self.live.with_exec(|e| e.probe_prefix());
            let (ids, id, wire) = (ids.clone(), id.clone(), Arc::clone(&self.wire));
            let live = Arc::clone(&self.live);
            self.live.set_refresher(Arc::new(move || {
                let (token, _, _) = Self::login_by_signature(&*wire, &ids, &id)?;
                let _ = &live;
                Ok(token)
            }));
            self.sliding.decide(&self.live);
        }
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

    fn ensure_session(&self, ids: &IdentityStore, id: &mut SessionIdentity, invite: Option<&str>) -> Result<Session> {
        if id.tier != BackendKind::Matrix || id.server_ref != self.base {
            return Err(AgentError::Identity("identity belongs to another tier or server".into()));
        }
        if let Some(t) = keyauth::stored_token(ids, id)? {
            let (st, v) = self.wire.get(WHOAMI, Some(&t))?;
            if st == 200 {
                let user_id = field(&v, "user_id")?;
                self.established(ids, id, &t);
                return Ok(self.session_of(id, t, user_id, v.get("device_id").and_then(|d| d.as_str()).map(str::to_string)));
            }
        }
        if !id.enrolled {
            keyauth::enroll(&*self.wire, ids, id, invite.ok_or(AgentError::NeedsInvite)?)?;
        }
        let (token, device_id, user_id) = Self::login_by_signature(&*self.wire, ids, id)?;
        self.established(ids, id, &token);
        Ok(self.session_of(id, token, user_id, device_id))
    }

    #[cfg(feature = "engine")]
    fn execute(&self, request: &mail4agent_messenger::OutgoingRequest) -> Result<mail4agent_messenger::HttpResponseDescriptor> {
        if request.kind == mail4agent_messenger::OutgoingRequestKind::Sync {
            if let Some(answer) = self.sliding.sync(&self.live, request)? {
                return Ok(answer);
            }
        }
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
