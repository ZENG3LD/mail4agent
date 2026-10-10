//! HTTP surface of the example product server. `/product/v1/*` is the
//! product's own API; everything else goes through the signing link.

use std::sync::Arc;

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post, put};
use axum::{Json, Router};
use m4a_product_kit::door::{DoorError, LoginDoor};
use m4a_product_kit::model::UserStore;
use m4a_product_kit::service::{AuthUser, ServiceError, UserService};
use m4a_product_kit::{EdgeLink, EventPublisher};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::store::SqliteStore;

pub struct ProductApp {
    pub users: UserService<SqliteStore>,
    pub link: EdgeLink,
    pub events: EventPublisher,
    /// Bearer for `/product/v1/admin/*`; empty disables the admin API.
    pub admin_token: String,
    pub doors: Vec<Arc<dyn LoginDoor>>,
}

type App = Arc<ProductApp>;

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

struct ApiError(StatusCode, Value);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}

fn err(status: StatusCode, code: &str, msg: &str) -> ApiError {
    ApiError(status, json!({ "errcode": code, "error": msg }))
}

impl From<ServiceError> for ApiError {
    fn from(e: ServiceError) -> Self {
        match e {
            ServiceError::InvalidNick(m) => err(StatusCode::BAD_REQUEST, "M4A_INVALID_NICK", &m),
            ServiceError::NickTaken => err(StatusCode::CONFLICT, "M4A_NICK_TAKEN", "nick is taken"),
            ServiceError::Cooldown { retry_after_ms } => ApiError(StatusCode::TOO_MANY_REQUESTS, json!({ "errcode": "M4A_NICK_COOLDOWN", "error": "nick was changed recently", "retry_after_ms": retry_after_ms })),
            ServiceError::NotFound => err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "not found"),
            ServiceError::Unauthorized => err(StatusCode::UNAUTHORIZED, "M_UNKNOWN_TOKEN", "unknown or revoked token"),
            ServiceError::Internal(m) => {
                tracing::error!("internal: {m}");
                err(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", "internal error")
            }
        }
    }
}

fn bearer(h: &HeaderMap) -> Option<String> {
    h.get("authorization")?.to_str().ok()?.strip_prefix("Bearer ").map(|t| t.trim().to_string())
}

fn auth(app: &App, h: &HeaderMap) -> Result<Option<AuthUser>, ApiError> {
    match bearer(h) {
        None => Ok(None),
        Some(t) => app.users.authenticate(&t)?.map(Some).ok_or_else(|| ServiceError::Unauthorized.into()),
    }
}

fn hash_secret(secret: &str) -> Result<String, ApiError> {
    Argon2::default().hash_password(secret.as_bytes(), &SaltString::generate(&mut OsRng)).map(|h| h.to_string()).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", "hash failed"))
}

fn check_secret(hash: &str, secret: &str) -> bool {
    PasswordHash::new(hash).map(|h| Argon2::default().verify_password(secret.as_bytes(), &h).is_ok()).unwrap_or(false)
}

fn session_json(nick: &str, token: &str) -> Json<Value> {
    Json(json!({ "nick": nick, "token": token }))
}

pub fn router(app: App) -> Router {
    Router::new()
        .route("/product/v1/register", post(register))
        .route("/product/v1/login", post(login))
        .route("/product/v1/doors", get(doors))
        .route("/product/v1/login/door/{id}", post(door_login))
        .route("/product/v1/logout", post(logout))
        .route("/product/v1/me", get(me))
        .route("/product/v1/nick", put(set_nick))
        .route("/client/v3/push", get(push))
        .route("/_matrix/client/v3/push", get(push))
        .route("/product/v1/admin/revoke", post(admin_revoke))
        .route("/product/v1/admin/delete", post(admin_delete))
        .route("/product/v1/admin/tier", post(admin_tier))
        .fallback(any(proxy))
        .with_state(app)
}

async fn register(State(app): State<App>, Json(body): Json<Value>) -> Result<Json<Value>, ApiError> {
    let pw = body.get("password").and_then(Value::as_str).unwrap_or("");
    if pw.len() < 8 {
        return Err(err(StatusCode::BAD_REQUEST, "M_WEAK_PASSWORD", "password must have at least 8 characters"));
    }
    let hash = tokio::task::spawn_blocking({
        let pw = pw.to_string();
        move || hash_secret(&pw)
    })
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", "task failed"))??;
    let u = app.users.create_user(Some(&hash), now_ms())?;
    let s = app.users.issue_session(&u, now_ms())?;
    Ok(session_json(&u.nick, &s.token))
}

async fn login(State(app): State<App>, Json(body): Json<Value>) -> Result<Json<Value>, ApiError> {
    let nick = body.get("nick").and_then(Value::as_str).unwrap_or("").to_string();
    let pw = body.get("password").and_then(Value::as_str).unwrap_or("").to_string();
    let bad = || err(StatusCode::FORBIDDEN, "M_FORBIDDEN", "invalid credentials");
    let u = app.users.store.user_by_nick(&nick).map_err(ServiceError::from)?.ok_or_else(bad)?;
    let hash = app.users.store.secret_hash(u.id).map_err(ServiceError::from)?.ok_or_else(bad)?;
    if !tokio::task::spawn_blocking(move || check_secret(&hash, &pw)).await.unwrap_or(false) {
        return Err(bad());
    }
    let s = app.users.issue_session(&u, now_ms())?;
    Ok(session_json(&u.nick, &s.token))
}

async fn doors(State(app): State<App>) -> Json<Value> {
    Json(json!({ "doors": app.doors.iter().map(|d| d.id()).collect::<Vec<_>>() }))
}

async fn door_login(State(app): State<App>, Path(id): Path<String>, Json(proof): Json<Value>) -> Result<Json<Value>, ApiError> {
    let door = app.doors.iter().find(|d| d.id() == id).ok_or_else(|| err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "no such door"))?;
    let (source, subject) = door.verify(&proof).await.map_err(|e| match e {
        DoorError::BadProof(m) => err(StatusCode::BAD_REQUEST, "M_BAD_JSON", &m),
        DoorError::Refused(m) => err(StatusCode::FORBIDDEN, "M_FORBIDDEN", &m),
        DoorError::Unverified(m) => err(StatusCode::UNAUTHORIZED, "M_UNAUTHORIZED", &m),
    })?;
    let u = app.users.user_for_door(&source, &subject, now_ms())?;
    let s = app.users.issue_session(&u, now_ms())?;
    Ok(session_json(&u.nick, &s.token))
}

fn need(app: &App, h: &HeaderMap) -> Result<AuthUser, ApiError> {
    auth(app, h)?.ok_or_else(|| ServiceError::Unauthorized.into())
}

async fn logout(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let who = need(&app, &headers)?;
    app.events.publish(app.users.revoke(&who.cred_ref)?);
    Ok(Json(json!({})))
}

async fn me(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let who = need(&app, &headers)?;
    Ok(Json(json!({ "nick": who.nick, "flag": who.flag })))
}

async fn set_nick(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Result<Json<Value>, ApiError> {
    let who = need(&app, &headers)?;
    let new = body.get("nick").and_then(Value::as_str).unwrap_or("");
    let u = app.users.store.user_by_nick(&who.nick).map_err(ServiceError::from)?.ok_or(ServiceError::Unauthorized)?;
    let (u, evs) = app.users.set_nick(&u, new, now_ms())?;
    app.events.publish(evs);
    Ok(Json(json!({ "nick": u.nick })))
}

fn admin(app: &App, h: &HeaderMap) -> Result<(), ApiError> {
    let ok = !app.admin_token.is_empty() && bearer(h).map(|t| Sha256::digest(t.as_bytes()) == Sha256::digest(app.admin_token.as_bytes())).unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(err(StatusCode::FORBIDDEN, "M_FORBIDDEN", "admin token required"))
    }
}

async fn admin_revoke(State(app): State<App>, headers: HeaderMap, Json(b): Json<Value>) -> Result<Json<Value>, ApiError> {
    admin(&app, &headers)?;
    let evs = app.users.revoke(b.get("cred_ref").and_then(Value::as_str).unwrap_or(""))?;
    let n = evs.len();
    app.events.publish(evs);
    Ok(Json(json!({ "revoked": n })))
}

async fn admin_delete(State(app): State<App>, headers: HeaderMap, Json(b): Json<Value>) -> Result<Json<Value>, ApiError> {
    admin(&app, &headers)?;
    app.events.publish(app.users.delete(b.get("nick").and_then(Value::as_str).unwrap_or(""))?);
    Ok(Json(json!({})))
}

async fn admin_tier(State(app): State<App>, headers: HeaderMap, Json(b): Json<Value>) -> Result<Json<Value>, ApiError> {
    admin(&app, &headers)?;
    let tier = b.get("tier").and_then(Value::as_str).unwrap_or("");
    if !app.users.tiers.knows(tier) {
        return Err(err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "unknown tier"));
    }
    let u = app.users.store.user_by_nick(b.get("nick").and_then(Value::as_str).unwrap_or("")).map_err(ServiceError::from)?.ok_or(ServiceError::NotFound)?;
    app.users.store.set_tier(u.id, tier).map_err(ServiceError::from)?;
    Ok(Json(json!({})))
}

/// Everything else: authenticate, sign, forward to the edge. A bad token is
/// refused here; no token forwards unasserted (the messenger decides what an
/// unasserted caller may do).
async fn proxy(State(app): State<App>, req: Request) -> Response {
    let who = match auth(&app, req.headers()) {
        Ok(w) => w,
        Err(e) => return e.into_response(),
    };
    app.link.forward(who.as_ref(), req).await
}

/// Push socket: the handshake is authenticated here (Bearer header or `access_token`
/// query), signed, and relayed to the messenger; anonymous sockets are refused.
async fn push(State(app): State<App>, headers: HeaderMap, axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>, ws: axum::extract::WebSocketUpgrade) -> Response {
    let token = bearer(&headers).or_else(|| q.get("access_token").cloned());
    let who = match token.map(|t| app.users.authenticate(&t)) {
        Some(Ok(Some(w))) => w,
        _ => return m4a_product_kit::push_relay::unauthorized(),
    };
    app.link.relay_push(who, ws)
}
