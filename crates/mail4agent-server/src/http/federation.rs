//! Federation F0 routes: this server's signing keys, a version probe, one
//! signed-request-protected query (profile existence), and the `X-Matrix`
//! authentication helper later federation routes call. Everything is off
//! (`M_UNRECOGNIZED`) unless federation is enabled in config.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{OriginalUri, Path, Query, State};
use axum::http::{header, HeaderMap, Uri};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

use super::{with_conn_pub, Homeserver};
use crate::error::MatrixError;
use crate::federation as fed;

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new()
        .route("/key/v2/server", get(own_keys))
        .route("/key/v2/server/{key_id}", get(own_keys_by_id))
        .route("/federation/v1/version", get(version))
        .route("/federation/v1/query/profile", get(profile))
}

fn require_enabled(state: &Homeserver) -> Result<(), MatrixError> {
    state.federation_enabled.get().map(|_| ()).ok_or_else(MatrixError::unrecognized)
}

async fn own_keys(State(state): State<Arc<Homeserver>>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let server = crate::store::matrix_server_name().to_string();
    let doc = with_conn_pub(&state, move |c| fed::server_keys_response(c, &server, fed::now_ms()).map_err(|_| MatrixError::internal())).await?;
    Ok(Json(doc))
}

async fn own_keys_by_id(State(state): State<Arc<Homeserver>>, Path(_key_id): Path<String>) -> Result<Json<Value>, MatrixError> {
    // The full document is returned whatever id is asked for (spec-permitted).
    own_keys(State(state)).await
}

async fn version(State(state): State<Arc<Homeserver>>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    Ok(Json(json!({ "server": { "name": "mail4agent", "version": env!("CARGO_PKG_VERSION") } })))
}

async fn profile(
    State(state): State<Arc<Homeserver>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    authenticate(&state, "GET", &uri, &headers, &[]).await?;
    let user_id = q.get("user_id").cloned().ok_or_else(|| MatrixError::invalid_param("user_id required"))?;
    let known = with_conn_pub(&state, move |c| {
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM matrix_users WHERE mxid = ?1", [&user_id], |r| r.get(0))
            .map_err(|_| MatrixError::internal())?;
        Ok(n > 0)
    })
    .await?;
    if known {
        Ok(Json(json!({})))
    } else {
        Err(MatrixError::not_found("user not found"))
    }
}

/// Path+query as the sender signed it: always with the `/_matrix` prefix,
/// which an edge in front of the core may have stripped.
fn signed_uri(uri: &Uri) -> String {
    let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    if pq.starts_with("/_matrix/") {
        pq.to_string()
    } else {
        format!("/_matrix{pq}")
    }
}

/// Authenticate a federation request from its `X-Matrix` header and return
/// the verified origin server name. `body` is the raw request body (empty for GET).
pub(crate) async fn authenticate(
    state: &Arc<Homeserver>,
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<String, MatrixError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| MatrixError::unauthorized("missing X-Matrix authorization"))?;
    let xm = fed::parse_x_matrix(value).map_err(|e| MatrixError::unauthorized(e.to_string()))?;
    let local = crate::store::matrix_server_name();
    if let Some(dest) = &xm.destination {
        if !crate::store::is_local_server_name(dest) {
            return Err(MatrixError::unauthorized("request is addressed to another server"));
        }
    }
    if fed::parse_server_name(&xm.origin).is_none() || crate::store::is_local_server_name(&xm.origin) {
        return Err(MatrixError::unauthorized("invalid origin"));
    }
    if let Some(allow) = state.federation_allow.get() {
        if !allow.iter().any(|a| a.eq_ignore_ascii_case(&xm.origin)) {
            return Err(MatrixError::forbidden("origin is not on the federation allowlist"));
        }
    }
    let content: Option<Value> = if body.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(body).map_err(|_| MatrixError::bad_json("body is not JSON"))?)
    };
    let public_key = remote_key(state, &xm.origin, &xm.key).await?;
    fed::verify_request_signature(&xm, method, &signed_uri(uri), local, content.as_ref(), &public_key)
        .map_err(|_| MatrixError::unauthorized("bad request signature"))?;
    Ok(xm.origin)
}

/// Public key of `server` for `key_id`: cache first, then one resolved fetch
/// (rate-limited per server), validated before it is stored.
async fn remote_key(state: &Arc<Homeserver>, server: &str, key_id: &str) -> Result<String, MatrixError> {
    let now = fed::now_ms();
    let (s, k) = (server.to_string(), key_id.to_string());
    let cached = with_conn_pub(state, move |c| fed::cached_remote_key(c, &s, &k, now).map_err(|_| MatrixError::internal())).await?;
    if let Some(pk) = cached {
        return Ok(pk);
    }
    let s = server.to_string();
    if !with_conn_pub(state, move |c| fed::may_refetch(c, &s, now).map_err(|_| MatrixError::internal())).await? {
        return Err(MatrixError::unauthorized("unknown signing key"));
    }
    let fetcher = state.key_fetcher.get().cloned().ok_or_else(|| MatrixError::unauthorized("remote key fetching is not configured"))?;
    let resp = fetcher.fetch_server_keys(server).await.map_err(|e| MatrixError::unauthorized(format!("cannot fetch keys: {e}")))?;
    let parsed = fed::parse_server_keys(&resp, server, now).map_err(|e| MatrixError::unauthorized(format!("invalid keys: {e}")))?;
    let found = parsed.keys.iter().find(|(id, _)| id == key_id).map(|(_, pk)| pk.clone());
    let (s, p) = (server.to_string(), parsed);
    with_conn_pub(state, move |c| fed::store_remote_keys(c, &s, &p, now).map_err(|_| MatrixError::internal())).await?;
    found.ok_or_else(|| MatrixError::unauthorized("unknown signing key"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::{FetchFuture, RemoteKeys};
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use rusqlite::Connection;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tower::ServiceExt;

    struct Mock {
        docs: Mutex<HashMap<String, Value>>,
        calls: AtomicUsize,
    }
    impl RemoteKeys for Mock {
        fn fetch_server_keys<'a>(&'a self, server: &'a str) -> FetchFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.docs.lock().unwrap().get(server).cloned().ok_or(fed::FedError::Network("unreachable".into()))
            })
        }
    }

    fn mem() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        crate::store::create_matrix_schema(&c).unwrap();
        crate::keys::create_matrix_keys_schema(&c).unwrap();
        c
    }

    /// A "receiving" homeserver plus a remote sender `a.example` whose key document the mock serves.
    fn setup() -> (Arc<Homeserver>, Arc<Mock>, rusqlite::Connection, String, ed25519_dalek::SigningKey) {
        let c = mem();
        crate::store::ensure_matrix_user(&c, 1, "alice000000000000000000000000a1", "2026-10-09T00:00:00+00:00").unwrap();
        let hs = Arc::new(Homeserver::new(c));
        hs.federation_enabled.set(()).unwrap();
        let sender = mem();
        let (kid, key) = fed::active_signing_key(&sender, 0).unwrap();
        let doc = fed::server_keys_response(&sender, "a.example", fed::now_ms()).unwrap();
        let mock = Arc::new(Mock { docs: Mutex::new(HashMap::from([("a.example".to_string(), doc)])), calls: AtomicUsize::new(0) });
        let _ = hs.key_fetcher.set(mock.clone());
        (hs, mock, sender, kid, key)
    }

    async fn call(hs: &Arc<Homeserver>, req: Request<Body>) -> (StatusCode, Value) {
        let resp = crate::http::router(Arc::clone(hs)).oneshot(req).await.unwrap();
        let st = resp.status();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (st, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    fn signed_get(uri: &str, origin: &str, dest: &str, kid: &str, key: &ed25519_dalek::SigningKey, signed_uri: &str) -> Request<Body> {
        let h = fed::build_x_matrix_header(origin, dest, kid, key, "GET", signed_uri, None);
        Request::get(uri).header(header::AUTHORIZATION, h).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn federation_is_off_until_enabled() {
        let hs = Arc::new(Homeserver::new(mem()));
        assert_eq!(call(&hs, Request::get("/key/v2/server").body(Body::empty()).unwrap()).await.0, StatusCode::NOT_FOUND);
        assert_eq!(call(&hs, Request::get("/federation/v1/version").body(Body::empty()).unwrap()).await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn own_key_document_is_served_and_valid() {
        let (hs, _, _, _, _) = setup();
        let (st, doc) = call(&hs, Request::get("/key/v2/server").body(Body::empty()).unwrap()).await;
        assert_eq!(st, StatusCode::OK);
        let me = crate::store::matrix_server_name();
        assert_eq!(doc["server_name"], me);
        assert!(fed::parse_server_keys(&doc, me, fed::now_ms()).is_ok());
        let (st2, doc2) = call(&hs, Request::get("/key/v2/server/ed25519:whatever").body(Body::empty()).unwrap()).await;
        assert_eq!((st2, doc2["verify_keys"].clone()), (StatusCode::OK, doc["verify_keys"].clone()), "stable key");
        assert_eq!(call(&hs, Request::get("/federation/v1/version").body(Body::empty()).unwrap()).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn signed_request_is_verified_with_fetched_then_cached_keys() {
        let (hs, mock, _, kid, key) = setup();
        let me = crate::store::matrix_server_name();
        let uri = "/federation/v1/query/profile?user_id=%40alice000000000000000000000000a1%3Aexample.org";
        let signed = format!("/_matrix{uri}");
        let (st, _) = call(&hs, signed_get(uri, "a.example", me, &kid, &key, &signed)).await;
        assert_eq!(st, StatusCode::OK);
        let (st, _) = call(&hs, signed_get(uri, "a.example", me, &kid, &key, &signed)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1, "second request served from the key cache");
        // The prefix is added once, whether or not an edge stripped it.
        assert_eq!(signed_uri(&"/federation/v1/x?a=1".parse().unwrap()), "/_matrix/federation/v1/x?a=1");
        assert_eq!(signed_uri(&"/_matrix/federation/v1/x?a=1".parse().unwrap()), "/_matrix/federation/v1/x?a=1");
    }

    #[tokio::test]
    async fn bad_requests_are_rejected() {
        let (hs, mock, _, kid, key) = setup();
        let me = crate::store::matrix_server_name();
        let uri = "/federation/v1/query/profile?user_id=%40alice000000000000000000000000a1%3Aexample.org";
        let signed = format!("/_matrix{uri}");
        // no header
        assert_eq!(call(&hs, Request::get(uri).body(Body::empty()).unwrap()).await.0, StatusCode::UNAUTHORIZED);
        // signature over another uri
        assert_eq!(call(&hs, signed_get(uri, "a.example", me, &kid, &key, "/_matrix/federation/v1/query/profile")).await.0, StatusCode::UNAUTHORIZED);
        // wrong destination
        assert_eq!(call(&hs, signed_get(uri, "a.example", "other.example", &kid, &key, &signed)).await.0, StatusCode::UNAUTHORIZED);
        // signed by a different key than the origin published
        let evil = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        assert_eq!(call(&hs, signed_get(uri, "a.example", me, &kid, &evil, &signed)).await.0, StatusCode::UNAUTHORIZED);
        // unknown key id
        assert_eq!(call(&hs, signed_get(uri, "a.example", me, "ed25519:nope", &key, &signed)).await.0, StatusCode::UNAUTHORIZED);
        // origin that cannot be reached
        assert_eq!(call(&hs, signed_get(uri, "ghost.example", me, &kid, &key, &signed)).await.0, StatusCode::UNAUTHORIZED);
        // claiming to be ourselves
        assert_eq!(call(&hs, signed_get(uri, me, me, &kid, &key, &signed)).await.0, StatusCode::UNAUTHORIZED);
        assert!(mock.calls.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn allowlist_and_unknown_user() {
        let (hs, _, _, kid, key) = setup();
        let me = crate::store::matrix_server_name();
        let uri = "/federation/v1/query/profile?user_id=%40nobody%3Aexample.org";
        let signed = format!("/_matrix{uri}");
        assert_eq!(call(&hs, signed_get(uri, "a.example", me, &kid, &key, &signed)).await.0, StatusCode::NOT_FOUND, "authenticated, user unknown");
        let (hs2, _, _, kid2, key2) = setup();
        hs2.federation_allow.set(vec!["b.example".into()]).unwrap();
        assert_eq!(call(&hs2, signed_get(uri, "a.example", me, &kid2, &key2, &signed)).await.0, StatusCode::FORBIDDEN);
    }
}
