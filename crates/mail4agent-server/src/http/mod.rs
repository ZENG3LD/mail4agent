//! Client-Server HTTP routes. Paths are relative; the process nests them
//! under `/_matrix` if it wants that prefix.
//!
//! A bearer is `Authorization: Bearer <raw>` or the `access_token` query
//! parameter. The stored credential is the SHA-256 hex of that raw token
//! ([`hash_token`]). `POST /client/v3/register` returns the raw bearer once,
//! in the response that creates the device. Nothing else returns it.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::error::MatrixError;
#[cfg(any(test, feature = "local-bearer"))]
use crate::keys::CredentialKind;
use crate::live::{ClaimRateLimiter, LiveRegistry};
use crate::typing::TypingRegistry;

mod account;
pub(crate) mod extras;
pub mod presence;
mod media;
mod compat;
pub mod edge_auth;
mod ephemeral;
mod federation;
pub mod fed_net;
mod keys;
mod messaging;
mod rooms;
mod push;
mod sync;
mod sliding;
pub mod identity;

pub struct Caller {
    pub user_id: i64,
    pub mxid: String,
    pub device_id: String,
    /// What the policy hook may know (`local` for device-bearer callers).
    pub claims: crate::policy::Claims,
}

pub struct Homeserver {
    /// The store: one writer, bounded parallel readers (tesserax-store). Reach it through
    /// [`Homeserver::conn_scope`] (blocking threads) or [`with_conn_pub`] (async).
    pub db: tesserax_store::Db,
    /// Parallel read-only connections (file-backed stores only; `None` for in-memory stores).
    pub readers: std::sync::OnceLock<tesserax_store::ReadPool>,
    pub live: LiveRegistry,
    pub typing: TypingRegistry,
    pub claim_rate: ClaimRateLimiter,
    pub push: crate::push::PushHub,
    /// Public client base URL for `/.well-known/matrix/client` (config, never hard-coded).
    pub public_base_url: std::sync::OnceLock<String>,
    /// `m.server` value for `/.well-known/matrix/server`; unset = federation off.
    pub federation_delegate: std::sync::OnceLock<String>,
    /// Federation F0 switch: when set, the key and federation routes answer.
    pub federation_enabled: std::sync::OnceLock<()>,
    /// Origins allowed to call federation routes; unset = any origin that proves its keys.
    pub federation_allow: std::sync::OnceLock<Vec<String>>,
    /// Set (`M4A_ANON_READ=on`) to honour the product's marked, assertion-less read-only forwards.
    pub anon_read: std::sync::OnceLock<()>,
    /// How remote servers' signing keys are fetched; unset = no remote verification.
    pub key_fetcher: std::sync::OnceLock<Arc<dyn crate::federation::RemoteKeys>>,
    /// Outgoing federation transport; unset = no outgoing federation.
    pub fed_transport: std::sync::OnceLock<Arc<dyn crate::federation::FedTransport>>,
    /// Wakes the outbox worker when new federation work exists.
    pub fed_notify: tokio::sync::Notify,
    /// Accounts, doors and issuer assertions; unset = legacy device-bearer behaviour only.
    pub seam: std::sync::OnceLock<Arc<identity::Seam>>,
    /// Policy hook; unset = allow everything.
    pub policy: std::sync::OnceLock<Arc<dyn crate::policy::PolicyHook>>,
}

impl Homeserver {
    /// A store over an already-open in-memory connection (tests, the client's local bus).
    /// File-backed stores come from [`Homeserver::from_db`].
    pub fn new(conn: Connection) -> Self {
        let db = tesserax_store::Db::open(&tesserax_store::DbConfig::in_memory()).expect("in-memory store");
        // Nothing else holds the fresh writer yet, so this never contends (and never blocks a runtime thread).
        db.blocking(|c| {
            *c = conn;
            Ok(())
        })
        .expect("install connection");
        Self::from_db(db)
    }

    /// A store over an opened tesserax-store writer.
    pub fn from_db(db: tesserax_store::Db) -> Self {
        Self {
            db,
            readers: std::sync::OnceLock::new(),
            live: LiveRegistry::new(),
            typing: TypingRegistry::new(),
            claim_rate: ClaimRateLimiter::new(),
            push: crate::push::PushHub::new(),
            public_base_url: std::sync::OnceLock::new(),
            federation_delegate: std::sync::OnceLock::new(),
            federation_enabled: std::sync::OnceLock::new(),
            federation_allow: std::sync::OnceLock::new(),
            anon_read: std::sync::OnceLock::new(),
            key_fetcher: std::sync::OnceLock::new(),
            fed_transport: std::sync::OnceLock::new(),
            fed_notify: tokio::sync::Notify::new(),
            seam: std::sync::OnceLock::new(),
            policy: std::sync::OnceLock::new(),
        }
    }

    /// Ask the policy hook (default: allow) about an action by `caller`.
    pub fn check_policy(&self, caller: &Caller, action: crate::policy::Action, room_kind: Option<crate::store::RoomKind>) -> Result<(), MatrixError> {
        match self.policy.get() {
            Some(h) => crate::policy::enforce(h.as_ref(), &caller.claims, action, room_kind),
            None => Ok(()),
        }
    }
}

pub fn hash_token(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn raw_token(headers: &HeaderMap, query_token: Option<&str>) -> Option<String> {
    if let Some(value) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(rest) = value.strip_prefix("Bearer ") {
            let rest = rest.trim();
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    query_token.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

impl Homeserver {
    /// Runs `f` on the single writer connection, waiting for it. For blocking threads only
    /// (`spawn_blocking`, plain threads); async code uses [`with_conn_pub`].
    /// Async form of [`Homeserver::conn_scope`] (runs on the blocking pool).
    pub async fn conn_async<T: Send + 'static>(&self, f: impl FnOnce(&mut Connection) -> T + Send + 'static) -> T {
        self.db.write(move |c| Ok(f(c))).await.expect("store writer")
    }

    pub fn conn_scope<T>(&self, f: impl FnOnce(&mut Connection) -> T) -> T {
        self.db.write_blocking(|c| Ok(f(c))).expect("store writer")
    }
}

pub async fn resolve_caller(
    state: &Arc<Homeserver>,
    headers: &HeaderMap,
    query_token: Option<&str>,
) -> Result<Caller, MatrixError> {
    if let Some((user_id, device_id, claims)) = identity::read_resolved(headers) {
        if user_id == identity::ANON_USER {
            // Anonymous read-only caller: no row, no device; only public data answers.
            return Ok(Caller { user_id, mxid: String::new(), device_id: String::new(), claims });
        }
        let state = Arc::clone(state);
        return tokio::task::spawn_blocking(move || -> Result<Caller, MatrixError> {
            state.conn_scope(|conn: &mut rusqlite::Connection| {
            let mxid = crate::store::mxid_of(&conn, user_id)?.ok_or_else(MatrixError::unknown_token)?;
            Ok(Caller { user_id, mxid, device_id, claims })
            })
        })
        .await
        .map_err(|_| MatrixError::internal())?;
    }
    #[cfg(not(any(test, feature = "local-bearer")))]
    {
        let _ = query_token;
        return Err(MatrixError::missing_token());
    }
    #[cfg(any(test, feature = "local-bearer"))]
    resolve_bearer(state, headers, query_token).await
}

#[cfg(any(test, feature = "local-bearer"))]
async fn resolve_bearer(state: &Arc<Homeserver>, headers: &HeaderMap, query_token: Option<&str>) -> Result<Caller, MatrixError> {
    let Some(raw) = raw_token(headers, query_token) else {
        return Err(MatrixError::missing_token());
    };
    let hash = hash_token(&raw);
    let state = Arc::clone(state);
    tokio::task::spawn_blocking(move || -> Result<Caller, MatrixError> {
        state.conn_scope(|conn: &mut rusqlite::Connection| {
        let device = crate::keys::device_for_credential(&conn, CredentialKind::Bearer, &hash)?
            .ok_or_else(MatrixError::unknown_token)?;
        let mxid = crate::store::mxid_of(&conn, device.user_id)?.ok_or_else(MatrixError::unknown_token)?;
        Ok(Caller { user_id: device.user_id, mxid, device_id: device.device_id, claims: crate::policy::Claims::new() })
        })
    })
    .await
    .map_err(|_| MatrixError::internal())?
}

/// Runs blocking DB work under the connection lock (shared by route modules).
pub(crate) async fn with_conn_pub<T, F>(state: &Arc<Homeserver>, work: F) -> Result<T, MatrixError>
where
    T: Send + 'static,
    F: FnOnce(&mut Connection) -> Result<T, MatrixError> + Send + 'static,
{
    let state = Arc::clone(state);
    state.db.write(move |conn| Ok(work(conn))).await.map_err(|_| MatrixError::internal())?
}

/// Read-only work on a pooled reader connection (the store's parallel WAL readers); falls back to
/// the writer when no read pool is attached (in-memory stores). `work` must not write.
pub async fn with_read_pub<T, F>(state: &Arc<Homeserver>, work: F) -> Result<T, MatrixError>
where
    T: Send + 'static,
    F: FnOnce(&Connection) -> Result<T, MatrixError> + Send + 'static,
{
    match state.readers.get() {
        Some(pool) => pool.read(move |conn| Ok(work(conn))).await.map_err(|_| MatrixError::internal())?,
        None => state.db.read(move |conn| Ok(work(conn))).await.map_err(|_| MatrixError::internal())?,
    }
}

pub fn wake_users(state: &Homeserver, ids: impl IntoIterator<Item = i64>) {
    state.live.wake_many(ids.into_iter().map(|id| format!("user:{id}")));
    // Every write that wakes sync may also owe a federation delivery.
    state.fed_notify.notify_one();
}

pub fn router(state: Arc<Homeserver>) -> Router {
    Router::new()
        .route("/client/versions", get(versions))
        .route("/client/v3/capabilities", get(capabilities))
        .merge(rooms::routes())
        .merge(messaging::routes())
        .merge(ephemeral::routes())
        .merge(account::routes())
        .merge(extras::routes())
        .merge(presence::routes())
        .merge(media::routes())
        .merge(sliding::routes())
                .merge(keys::routes())
        .merge(sync::routes())
        .merge(push::routes())
        .merge(compat::routes())
        .merge(federation::routes())
        .merge(identity::routes())
        .fallback(unrecognized)
        .layer(axum::middleware::from_fn_with_state(state.clone(), identity::assertion_layer))
        .layer(axum::middleware::from_fn(cors))
        .with_state(state)
}

/// Browser clients (Element, Cinny) call from another origin: answer preflights and allow it.
pub async fn cors(req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    use axum::http::{header, HeaderValue, Method, StatusCode};
    let preflight = req.method() == Method::OPTIONS;
    let mut resp = if preflight { axum::response::Response::builder().status(StatusCode::OK).body(axum::body::Body::empty()).unwrap() } else { next.run(req).await };
    let h = resp.headers_mut();
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"));
    h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("X-Requested-With, Content-Type, Authorization, Date"));
    resp
}

/// Every spec version up to the newest one supported (they are cumulative; clients test for the one a feature arrived in).
const SPEC_VERSIONS: [&str; 19] = ["v1.1", "v1.2", "v1.3", "v1.4", "v1.5", "v1.6", "v1.7", "v1.8", "v1.9", "v1.10", "v1.11", "v1.12", "v1.13", "v1.14", "v1.15", "v1.16", "v1.17", "v1.18", "v1.19"];

async fn versions() -> impl IntoResponse {
    Json(serde_json::json!({
        "versions": SPEC_VERSIONS,
        "unstable_features": { "org.matrix.simplified_msc3575": true, "org.matrix.msc4186": true },
    }))
}

async fn capabilities(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, MatrixError> {
    resolve_caller(&state, &headers, None).await?;
    let room_version = crate::store::MATRIX_ROOM_VERSION;
    Ok(Json(serde_json::json!({
        "capabilities": {
            "m.room_versions": {
                "default": room_version,
                "available": { room_version: "stable" },
            },
            "m.change_password": { "enabled": false },
        }
    })))
}

async fn unrecognized() -> MatrixError {
    MatrixError::unrecognized()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn versions_reports_v1_19() {
        let conn = Connection::open_in_memory().expect("memory");
        let app = router(Arc::new(Homeserver::new(conn)));
        let resp = app
            .oneshot(Request::get("/client/versions").body(Body::empty()).expect("request"))
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(value["versions"].as_array().unwrap().last().unwrap(), "v1.19");
        assert!(value["versions"].as_array().unwrap().iter().any(|v| v == "v1.1"));
    }

    #[tokio::test]
    async fn unknown_path_is_unrecognized() {
        let conn = Connection::open_in_memory().expect("memory");
        let app = router(Arc::new(Homeserver::new(conn)));
        let resp = app
            .oneshot(Request::get("/client/v3/nope").body(Body::empty()).expect("request"))
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(value["errcode"], "M_UNRECOGNIZED");
    }
}

