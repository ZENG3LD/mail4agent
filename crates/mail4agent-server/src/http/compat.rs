//! Routes Element-class clients probe for: well-known, login discovery,
//! logout, push rules / pushers stubs, presence stub, media repo.
//!
//! What is deliberately NOT here: password login (this server has no
//! passwords; sessions come from `POST /register` unless a product disables it), OIDC, sliding sync.
//! Push rules and pushers are accepted and not stored because notification
//! delivery is the metadata-only `/push` WebSocket (push v1).

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::error::MatrixError;

use super::{resolve_caller, Homeserver};

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new()
        .route("/.well-known/matrix/client", get(well_known_client))
        .route("/.well-known/matrix/server", get(well_known_server))
        .route("/client/v3/login", get(login_flows).post(login))
        .route("/client/v3/logout", post(logout))
        .route("/client/v3/logout/all", post(logout_all))
        .route("/client/v3/pushrules", get(pushrules))
        .route("/client/v3/pushrules/", get(pushrules))
        .route("/client/v3/pushrules/{scope}/{kind}/{rule_id}", put(ok_empty).delete(ok_empty).get(ok_empty))
        .route("/client/v3/pushrules/{scope}/{kind}/{rule_id}/enabled", put(ok_empty).get(rule_enabled))
        .route("/client/v3/pushrules/{scope}/{kind}/{rule_id}/actions", put(ok_empty).get(rule_actions))
        .route("/client/v3/thirdparty/protocols", get(no_protocols))
        .route("/client/v3/voip/turnServer", get(no_turn_server))
        .route("/client/v3/pushers", get(pushers))
        .route("/client/v3/pushers/set", post(ok_empty))
        .route("/client/v3/notifications", get(notifications))
}

async fn ok_empty() -> Json<Value> {
    Json(json!({}))
}

async fn well_known_client(State(state): State<Arc<Homeserver>>) -> Result<Json<Value>, MatrixError> {
    let base = state.public_base_url.get().ok_or_else(|| MatrixError::not_found("no public base url configured"))?;
    Ok(Json(json!({ "m.homeserver": { "base_url": base } })))
}

/// Federation delegation. Served only when a federation name is configured;
/// federation itself is not implemented (see the matrix-compat plan).
async fn well_known_server(State(state): State<Arc<Homeserver>>) -> Result<Json<Value>, MatrixError> {
    let target = state.federation_delegate.get().ok_or_else(|| MatrixError::not_found("federation is not enabled"))?;
    Ok(Json(json!({ "m.server": target })))
}

/// Login is the product server's; this server lists no flows and mints no sessions.
/// No bridges: an empty protocol list, which is what clients read as "none".
async fn no_protocols() -> Json<Value> {
    Json(json!({}))
}

/// No TURN server configured: an empty answer (clients then place calls without relays).
async fn no_turn_server(State(state): State<Arc<Homeserver>>, headers: HeaderMap) -> Result<Json<Value>, MatrixError> {
    resolve_caller(&state, &headers, None).await?;
    Ok(Json(json!({})))
}

async fn login_flows() -> Json<Value> {
    Json(json!({ "flows": [] }))
}

async fn login() -> Result<Json<Value>, MatrixError> {
    Err(MatrixError::forbidden("login is not offered by the messenger server; sign in at the product server"))
}

async fn logout(State(state): State<Arc<Homeserver>>, headers: HeaderMap) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    super::with_conn_pub(&state, move |conn| {
        crate::keys::delete_device(conn, caller.user_id, &caller.device_id, &chrono::Utc::now().to_rfc3339())?;
        Ok(())
    })
    .await?;
    Ok(Json(json!({})))
}

async fn logout_all(State(state): State<Arc<Homeserver>>, headers: HeaderMap) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    super::with_conn_pub(&state, move |conn| {
        let now = chrono::Utc::now().to_rfc3339();
        for d in crate::keys::list_devices(conn, caller.user_id)? {
            crate::keys::delete_device(conn, caller.user_id, &d.device_id, &now)?;
        }
        Ok(())
    })
    .await?;
    Ok(Json(json!({})))
}

async fn pushrules(State(state): State<Arc<Homeserver>>, headers: HeaderMap) -> Result<Json<Value>, MatrixError> {
    resolve_caller(&state, &headers, None).await?;
    Ok(Json(json!({ "global": { "override": [], "content": [], "room": [], "sender": [], "underride": [] } })))
}

async fn rule_enabled() -> Json<Value> {
    Json(json!({ "enabled": true }))
}

async fn rule_actions() -> Json<Value> {
    Json(json!({ "actions": ["notify"] }))
}

async fn pushers(State(state): State<Arc<Homeserver>>, headers: HeaderMap) -> Result<Json<Value>, MatrixError> {
    resolve_caller(&state, &headers, None).await?;
    Ok(Json(json!({ "pushers": [] })))
}

async fn notifications(State(state): State<Arc<Homeserver>>, headers: HeaderMap) -> Result<Json<Value>, MatrixError> {
    resolve_caller(&state, &headers, None).await?;
    Ok(Json(json!({ "notifications": [] })))
}


#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
    use rusqlite::Connection;
    use tower::ServiceExt;

    const TOKEN: &str = "compat-token";
    const NOW: &str = "2026-10-09T00:00:00+00:00";

    fn hs() -> Arc<Homeserver> {
        let conn = Connection::open_in_memory().unwrap();
        crate::store::create_matrix_schema(&conn).unwrap();
        crate::keys::create_matrix_keys_schema(&conn).unwrap();
        crate::store::ensure_matrix_user(&conn, 1, "alice000000000000000000000000a1", NOW).unwrap();
        crate::keys::create_device(&conn, 1, crate::keys::CredentialKind::Bearer, &crate::http::hash_token(TOKEN), NOW).unwrap();
        Arc::new(Homeserver::new(conn))
    }

    async fn call(state: &Arc<Homeserver>, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let resp = crate::http::router(Arc::clone(state)).oneshot(req).await.unwrap();
        let (status, headers) = (resp.status(), resp.headers().clone());
        (status, headers, to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec())
    }

    fn authed(method: &str, uri: &str, body: Body) -> Request<Body> {
        Request::builder().method(method).uri(uri).header(header::AUTHORIZATION, format!("Bearer {TOKEN}")).body(body).unwrap()
    }

    #[tokio::test]
    async fn well_known_is_config_driven() {
        let state = hs();
        assert_eq!(call(&state, Request::get("/.well-known/matrix/client").body(Body::empty()).unwrap()).await.0, StatusCode::NOT_FOUND);
        state.public_base_url.set("https://chat.example".into()).unwrap();
        let (st, _, body) = call(&state, Request::get("/.well-known/matrix/client").body(Body::empty()).unwrap()).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["m.homeserver"]["base_url"], "https://chat.example");
        assert_eq!(call(&state, Request::get("/.well-known/matrix/server").body(Body::empty()).unwrap()).await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn login_stubs_push_stubs_and_logout() {
        let state = hs();
        let (st, _, body) = call(&state, Request::get("/client/v3/login").body(Body::empty()).unwrap()).await;
        assert_eq!((st, serde_json::from_slice::<Value>(&body).unwrap()["flows"].as_array().unwrap().len()), (StatusCode::OK, 0));
        assert_eq!(call(&state, Request::post("/client/v3/login").header(header::CONTENT_TYPE, "application/json").body(Body::from("{}")).unwrap()).await.0, StatusCode::FORBIDDEN);
        assert_eq!(call(&state, authed("GET", "/client/v3/pushrules/", Body::empty())).await.0, StatusCode::OK);
        assert_eq!(call(&state, authed("GET", "/client/v3/pushers", Body::empty())).await.0, StatusCode::OK);
        assert_eq!(call(&state, Request::get("/client/v3/pushers").body(Body::empty()).unwrap()).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(&state, authed("POST", "/client/v3/logout", Body::empty())).await.0, StatusCode::OK);
        assert_eq!(call(&state, authed("GET", "/client/v3/pushers", Body::empty())).await.0, StatusCode::UNAUTHORIZED, "token dies on logout");
    }

    #[tokio::test]
    async fn media_roundtrip_is_authenticated_and_download_only() {
        let state = hs();
        let blob = vec![7u8; 1000];
        let (st, _, body) = call(&state, authed("POST", "/media/v3/upload?filename=a.bin", Body::from(blob.clone()))).await;
        assert_eq!(st, StatusCode::OK);
        let uri = serde_json::from_slice::<Value>(&body).unwrap()["content_uri"].as_str().unwrap().to_string();
        let path = uri.strip_prefix("mxc://").unwrap();
        let (st, h, got) = call(&state, authed("GET", &format!("/client/v1/media/download/{path}"), Body::empty())).await;
        assert_eq!((st, got), (StatusCode::OK, blob));
        assert!(h[header::CONTENT_DISPOSITION].to_str().unwrap().starts_with("attachment"));
        assert_eq!(call(&state, Request::get(format!("/client/v1/media/download/{path}")).body(Body::empty()).unwrap()).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(&state, authed("GET", "/client/v1/media/download/other.example/abc", Body::empty())).await.0, StatusCode::NOT_FOUND);
    }
}
