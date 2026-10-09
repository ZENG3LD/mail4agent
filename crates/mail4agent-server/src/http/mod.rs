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
use crate::keys::CredentialKind;
use crate::live::{ClaimRateLimiter, LiveRegistry};
use crate::typing::TypingRegistry;

mod account;
mod compat;
pub mod edge_auth;
mod ephemeral;
mod federation;
pub mod fed_net;
mod keys;
mod messaging;
mod register;
mod rooms;
mod push;
mod sync;

pub struct Caller {
    pub user_id: i64,
    pub mxid: String,
    pub device_id: String,
}

pub struct Homeserver {
    pub conn: std::sync::Mutex<Connection>,
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
    /// How remote servers' signing keys are fetched; unset = no remote verification.
    pub key_fetcher: std::sync::OnceLock<Arc<dyn crate::federation::RemoteKeys>>,
    /// Outgoing federation transport; unset = no outgoing federation.
    pub fed_transport: std::sync::OnceLock<Arc<dyn crate::federation::FedTransport>>,
    /// Wakes the outbox worker when new federation work exists.
    pub fed_notify: tokio::sync::Notify,
}

impl Homeserver {
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: std::sync::Mutex::new(conn),
            live: LiveRegistry::new(),
            typing: TypingRegistry::new(),
            claim_rate: ClaimRateLimiter::new(),
            push: crate::push::PushHub::new(),
            public_base_url: std::sync::OnceLock::new(),
            federation_delegate: std::sync::OnceLock::new(),
            federation_enabled: std::sync::OnceLock::new(),
            federation_allow: std::sync::OnceLock::new(),
            key_fetcher: std::sync::OnceLock::new(),
            fed_transport: std::sync::OnceLock::new(),
            fed_notify: tokio::sync::Notify::new(),
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

pub async fn resolve_caller(
    state: &Arc<Homeserver>,
    headers: &HeaderMap,
    query_token: Option<&str>,
) -> Result<Caller, MatrixError> {
    let Some(raw) = raw_token(headers, query_token) else {
        return Err(MatrixError::missing_token());
    };
    let hash = hash_token(&raw);
    let state = Arc::clone(state);
    tokio::task::spawn_blocking(move || -> Result<Caller, MatrixError> {
        let conn = state.conn.lock().unwrap_or_else(|e| e.into_inner());
        let device = crate::keys::device_for_credential(&conn, CredentialKind::Bearer, &hash)?
            .ok_or_else(MatrixError::unknown_token)?;
        let mxid = crate::store::mxid_of(&conn, device.user_id)?.ok_or_else(MatrixError::unknown_token)?;
        Ok(Caller { user_id: device.user_id, mxid, device_id: device.device_id })
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
    tokio::task::spawn_blocking(move || {
        let mut conn = state.conn.lock().unwrap_or_else(|e| e.into_inner());
        work(&mut conn)
    })
    .await
    .map_err(|_| MatrixError::internal())?
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
        .merge(register::routes())
        .merge(keys::routes())
        .merge(sync::routes())
        .merge(push::routes())
        .merge(compat::routes())
        .merge(federation::routes())
        .fallback(unrecognized)
        .with_state(state)
}

async fn versions() -> impl IntoResponse {
    Json(serde_json::json!({
        "versions": ["v1.19"],
        "unstable_features": {},
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
        assert_eq!(value, serde_json::json!({ "versions": ["v1.19"], "unstable_features": {} }));
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
