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
    /// Serve unauthenticated reads of public rooms through the marked read-only mode
    /// (`M4A_PRODUCT_ANON_READ=on`; the core must have `M4A_ANON_READ=on` too).
    pub anon_read: bool,
    /// One-time login tokens for `login/get_token`.
    pub tokens: m4a_product_kit::LoginTokens,
    /// Lifetime of an access token handed out with a refresh token (0 turns refresh tokens off).
    pub access_ttl_ms: i64,
}

/// A refresh token lives this long.
const REFRESH_TTL_MS: i64 = 30 * 24 * 3600 * 1000;
/// A login token (`login/get_token`) lives this long.
const LOGIN_TOKEN_TTL_MS: i64 = 120_000;

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

/// Authenticates on the blocking pool: database work never runs on the async request
/// thread, and no store lock is held while the request waits on the edge.
async fn auth_blocking(app: &App, h: &HeaderMap) -> Result<Option<AuthUser>, ApiError> {
    let Some(t) = bearer(h) else { return Ok(None) };
    let app = Arc::clone(app);
    tokio::task::spawn_blocking(move || app.users.authenticate(&t))
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", "task failed"))??
        .map(Some)
        .ok_or_else(|| ServiceError::Unauthorized.into())
}

/// Runs store-touching work on the blocking pool (the store's writer must never be waited on
/// from the async runtime).
async fn blk<T: Send + 'static>(app: &App, f: impl FnOnce(&ProductApp) -> T + Send + 'static) -> Result<T, ApiError> {
    let app = Arc::clone(app);
    tokio::task::spawn_blocking(move || f(&app)).await.map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", "task failed"))
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
        .route("/client/v3/login", get(matrix_login_flows).post(matrix_login))
        .route("/_matrix/client/v3/login", get(matrix_login_flows).post(matrix_login))
        .route("/client/v3/refresh", post(matrix_refresh))
        .route("/_matrix/client/v3/refresh", post(matrix_refresh))
        .route("/client/v1/login/get_token", post(get_login_token))
        .route("/_matrix/client/v1/login/get_token", post(get_login_token))
        .route("/client/v3/capabilities", get(capabilities))
        .route("/_matrix/client/v3/capabilities", get(capabilities))
        .route("/client/v3/account/password", post(account_password))
        .route("/_matrix/client/v3/account/password", post(account_password))
        .route("/client/v3/account/deactivate", post(account_deactivate))
        .route("/_matrix/client/v3/account/deactivate", post(account_deactivate))
        .route("/client/v3/account/3pid", get(threepids))
        .route("/_matrix/client/v3/account/3pid", get(threepids))
        .route("/client/v3/account/3pid/add", post(threepid_denied))
        .route("/_matrix/client/v3/account/3pid/add", post(threepid_denied))
        .route("/client/v3/account/3pid/bind", post(threepid_denied))
        .route("/_matrix/client/v3/account/3pid/bind", post(threepid_denied))
        .route("/client/v3/account/3pid/email/requestToken", post(threepid_denied))
        .route("/_matrix/client/v3/account/3pid/email/requestToken", post(threepid_denied))
        .route("/client/v3/account/3pid/msisdn/requestToken", post(threepid_denied))
        .route("/_matrix/client/v3/account/3pid/msisdn/requestToken", post(threepid_denied))
        .route("/client/v3/account/password/email/requestToken", post(threepid_denied))
        .route("/_matrix/client/v3/account/password/email/requestToken", post(threepid_denied))
        .route("/client/v3/account/password/msisdn/requestToken", post(threepid_denied))
        .route("/_matrix/client/v3/account/password/msisdn/requestToken", post(threepid_denied))
        .route("/client/v3/register/email/requestToken", post(threepid_denied))
        .route("/_matrix/client/v3/register/email/requestToken", post(threepid_denied))
        .route("/client/v3/register/msisdn/requestToken", post(threepid_denied))
        .route("/_matrix/client/v3/register/msisdn/requestToken", post(threepid_denied))
        .route("/client/v3/account/3pid/delete", post(threepid_unbind))
        .route("/_matrix/client/v3/account/3pid/delete", post(threepid_unbind))
        .route("/client/v3/account/3pid/unbind", post(threepid_unbind))
        .route("/_matrix/client/v3/account/3pid/unbind", post(threepid_unbind))
        .route("/client/v3/register", post(matrix_register))
        .route("/_matrix/client/v3/register", post(matrix_register))
        .route("/client/v3/register/available", get(matrix_available))
        .route("/_matrix/client/v3/register/available", get(matrix_available))
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
        .layer(axum::middleware::from_fn(cors))
        .with_state(app)
}

/// Browser clients call from another origin: answer preflights and allow it.
async fn cors(req: Request, next: axum::middleware::Next) -> Response {
    use axum::http::{header, HeaderValue, Method};
    let preflight = req.method() == Method::OPTIONS;
    let mut resp = if preflight { Response::builder().status(StatusCode::OK).body(axum::body::Body::empty()).unwrap() } else { next.run(req).await };
    let h = resp.headers_mut();
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"));
    h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("X-Requested-With, Content-Type, Authorization, Date"));
    resp
}

/// The Matrix client login flow list: a nick and a password, or a one-time login token.
async fn matrix_login_flows() -> Json<Value> {
    Json(json!({ "flows": [{ "type": "m.login.password" }, { "type": "m.login.token", "get_login_token": true }] }))
}

/// Matrix login on top of the product login: `m.login.password` (the nick is the user) or
/// `m.login.token` (a token from `login/get_token`). The product session token is the access
/// token; the user and device ids come from the messenger's own answer. A client that asks for
/// `refresh_token: true` gets an expiring access token and a refresh token.
async fn matrix_login(State(app): State<App>, Json(body): Json<Value>) -> Result<Json<Value>, ApiError> {
    let bad = || err(StatusCode::FORBIDDEN, "M_FORBIDDEN", "invalid credentials");
    let user = if body.get("type").and_then(Value::as_str) == Some("m.login.token") {
        let t = body.get("token").and_then(Value::as_str).unwrap_or("");
        let nick = app.tokens.redeem(t, now_ms()).ok_or_else(|| err(StatusCode::FORBIDDEN, "M_FORBIDDEN", "invalid or expired login token"))?;
        blk(&app, move |a| -> Result<_, ServiceError> { Ok(a.users.store.user_by_nick(&nick)?) }).await??.ok_or_else(bad)?
    } else {
        let user = body.pointer("/identifier/user").or_else(|| body.get("user")).and_then(Value::as_str).unwrap_or("");
        let user = user.strip_prefix('@').unwrap_or(user);
        let nick = user.split(':').next().unwrap_or("").to_string();
        let pw = body.get("password").and_then(Value::as_str).unwrap_or("").to_string();
        verify_password(&app, nick, pw).await?
    };
    let want_refresh = body.get("refresh_token").and_then(Value::as_bool) == Some(true) && app.access_ttl_ms > 0;
    let ttl = app.access_ttl_ms;
    let (session, refresh) = blk(&app, move |a| -> Result<_, ServiceError> {
        if want_refresh && a.users.store.supports_refresh() {
            let (s, r) = a.users.issue_refreshable_session(&user, now_ms(), ttl, REFRESH_TTL_MS)?;
            Ok((s, Some(r)))
        } else {
            Ok((a.users.issue_session(&user, now_ms())?, None))
        }
    })
    .await??;
    let Json(mut out) = matrix_session(&app, session.token).await?;
    if let Some(r) = refresh {
        out["refresh_token"] = json!(r);
        out["expires_in_ms"] = json!(ttl);
    }
    Ok(Json(out))
}

/// `POST /refresh`: a new access token and a new refresh token for the same session.
async fn matrix_refresh(State(app): State<App>, Json(body): Json<Value>) -> Result<Json<Value>, ApiError> {
    let t = body.get("refresh_token").and_then(Value::as_str).unwrap_or("").to_string();
    let ttl = app.access_ttl_ms;
    let r = if ttl > 0 { blk(&app, move |a| a.users.refresh(&t, now_ms(), ttl, REFRESH_TTL_MS)).await?? } else { None };
    let (s, refresh) = r.ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, json!({ "errcode": "M_UNKNOWN_TOKEN", "error": "unknown or expired refresh token", "soft_logout": false })))?;
    Ok(Json(json!({ "access_token": s.token, "refresh_token": refresh, "expires_in_ms": ttl })))
}

/// Matrix user-interactive auth with the account password (re-authentication for sensitive
/// calls). `Ok` when the request carries a valid `m.login.password` auth; otherwise the 401 that
/// tells the client what to send.
async fn uia_password(app: &App, who: &AuthUser, body: &Value) -> Result<(), Response> {
    let pw = body.pointer("/auth/password").and_then(Value::as_str);
    if body.pointer("/auth/type").and_then(Value::as_str) != Some("m.login.password") || pw.is_none() {
        let v = json!({ "flows": [{ "stages": ["m.login.password"] }], "params": {}, "session": "reauth" });
        return Err((StatusCode::UNAUTHORIZED, Json(v)).into_response());
    }
    if let Some(u) = body.pointer("/auth/identifier/user").and_then(Value::as_str) {
        if u.trim_start_matches('@').split(':').next().map(str::to_lowercase) != Some(who.nick.to_lowercase()) {
            return Err(err(StatusCode::FORBIDDEN, "M_FORBIDDEN", "that is not your account").into_response());
        }
    }
    verify_password(app, who.nick.clone(), pw.unwrap_or("").to_string()).await.map(|_| ()).map_err(|_| err(StatusCode::UNAUTHORIZED, "M_FORBIDDEN", "wrong password").into_response())
}

/// `POST /login/get_token` (spec v1.7): a signed-in client, re-authenticating with its password,
/// gets a one-time token that another client can log in with.
async fn get_login_token(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Result<Response, ApiError> {
    let who = need(&app, &headers).await?;
    if let Err(r) = uia_password(&app, &who, &body).await {
        return Ok(r);
    }
    let t = app.tokens.issue(&who.nick, now_ms(), LOGIN_TOKEN_TTL_MS);
    Ok(Json(json!({ "login_token": t, "expires_in_ms": LOGIN_TOKEN_TTL_MS })).into_response())
}

/// The messenger's capabilities, plus what the product itself provides.
async fn capabilities(State(app): State<App>, req: Request) -> Response {
    let who = match auth_blocking(&app, req.headers()).await {
        Ok(Some(w)) => w,
        Ok(None) => return err(StatusCode::UNAUTHORIZED, "M_MISSING_TOKEN", "missing access token").into_response(),
        Err(e) => return e.into_response(),
    };
    let resp = app.link.forward(Some(&who), req).await;
    let (parts, body) = resp.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 1 << 20).await else { return err(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "messenger unavailable").into_response() };
    let Ok(mut v) = serde_json::from_slice::<Value>(&bytes) else { return Response::from_parts(parts, axum::body::Body::from(bytes)) };
    if parts.status.is_success() {
        v["capabilities"]["m.get_login_token"] = json!({ "enabled": true });
        v["capabilities"]["m.change_password"] = json!({ "enabled": true });
        v["capabilities"]["m.3pid_changes"] = json!({ "enabled": false });
    }
    (parts.status, Json(v)).into_response()
}

/// `POST /account/password`: re-authenticate, set the new password, and (default) sign every
/// other session out.
async fn account_password(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Result<Response, ApiError> {
    let who = need(&app, &headers).await?;
    if let Err(r) = uia_password(&app, &who, &body).await {
        return Ok(r);
    }
    let new = body.get("new_password").and_then(Value::as_str).unwrap_or("").to_string();
    if new.len() < 8 {
        return Err(err(StatusCode::BAD_REQUEST, "M_WEAK_PASSWORD", "password must have at least 8 characters"));
    }
    let hash = tokio::task::spawn_blocking(move || hash_secret(&new)).await.map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", "task failed"))??;
    let logout_others = body.get("logout_devices").and_then(Value::as_bool).unwrap_or(true);
    let (nick, mine) = (who.nick.clone(), who.cred_ref.clone());
    let evs = blk(&app, move |a| -> Result<_, ServiceError> {
        let u = a.users.store.user_by_nick(&nick)?.ok_or(ServiceError::Unauthorized)?;
        a.users.store.set_secret_hash(u.id, &hash)?;
        let mut evs = Vec::new();
        if logout_others {
            for c in a.users.store.credentials_of(u.id)?.into_iter().filter(|c| *c != mine) {
                evs.extend(a.users.revoke(&c)?);
            }
        }
        Ok(evs)
    })
    .await??;
    app.events.publish(evs);
    Ok(Json(json!({})).into_response())
}

/// `POST /account/deactivate`: re-authenticate, then delete the account (every session is
/// revoked and the messenger retires the identity).
async fn account_deactivate(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Result<Response, ApiError> {
    let who = need(&app, &headers).await?;
    if let Err(r) = uia_password(&app, &who, &body).await {
        return Ok(r);
    }
    let nick = who.nick.clone();
    let evs = blk(&app, move |a| a.users.delete(&nick)).await??;
    app.events.publish(evs);
    Ok(Json(json!({ "id_server_unbind_result": "no-support" })).into_response())
}

/// This product has no third-party identifiers: the list is empty, adding is refused.
async fn threepids(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    need(&app, &headers).await?;
    Ok(Json(json!({ "threepids": [] })))
}

async fn threepid_denied() -> ApiError {
    err(StatusCode::FORBIDDEN, "M_THREEPID_DENIED", "this server does not use third-party identifiers")
}

async fn threepid_unbind() -> Json<Value> {
    Json(json!({ "id_server_unbind_result": "no-support" }))
}

/// The password check shared by login and re-authentication.
async fn verify_password(app: &App, nick: String, pw: String) -> Result<m4a_product_kit::User, ApiError> {
    let bad = || err(StatusCode::FORBIDDEN, "M_FORBIDDEN", "invalid credentials");
    let (u, hash) = blk(app, move |a| -> Result<_, ServiceError> {
        let u = a.users.store.user_by_nick(&nick)?;
        let hash = match &u {
            Some(u) => a.users.store.secret_hash(u.id)?,
            None => None,
        };
        Ok((u, hash))
    })
    .await??;
    let (u, hash) = match (u, hash) {
        (Some(u), Some(h)) => (u, h),
        _ => return Err(bad()),
    };
    if !tokio::task::spawn_blocking(move || check_secret(&hash, &pw)).await.unwrap_or(false) {
        return Err(bad());
    }
    Ok(u)
}

/// The Matrix login answer for a product session token: user and device ids come from the messenger.
async fn matrix_session(app: &App, token: String) -> Result<Json<Value>, ApiError> {
    let t2 = token.clone();
    let who = blk(app, move |a| a.users.authenticate(&t2)).await??.ok_or_else(|| err(StatusCode::FORBIDDEN, "M_FORBIDDEN", "invalid credentials"))?;
    let req = Request::builder().method("GET").uri("/client/v3/account/whoami").body(axum::body::Body::empty()).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", "request"))?;
    let resp = app.link.forward(Some(&who), req).await;
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16).await.map_err(|_| err(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "messenger unavailable"))?;
    let w: Value = serde_json::from_slice(&bytes).map_err(|_| err(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "messenger unavailable"))?;
    let user_id = w["user_id"].as_str().ok_or_else(|| err(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "messenger refused the session"))?.to_string();
    let home = user_id.split_once(':').map(|(_, d)| d.to_string()).unwrap_or_default();
    Ok(Json(json!({ "user_id": user_id, "access_token": token, "device_id": w["device_id"], "home_server": home })))
}

/// Matrix `register` on the product: the username becomes the nick, one dummy auth stage.
async fn matrix_register(State(app): State<App>, Json(body): Json<Value>) -> Result<Response, ApiError> {
    if body.pointer("/auth/type").and_then(Value::as_str) != Some("m.login.dummy") {
        let v = json!({ "flows": [{ "stages": ["m.login.dummy"] }], "params": {}, "session": "register" });
        return Ok((StatusCode::UNAUTHORIZED, Json(v)).into_response());
    }
    let username = body.get("username").and_then(Value::as_str).unwrap_or("").to_string();
    if username.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "M_INVALID_USERNAME", "a username is required"));
    }
    let taken = {
        let n = username.clone();
        blk(&app, move |a| -> Result<_, ServiceError> { Ok(a.users.store.user_by_nick(&n)?) }).await??.is_some()
    };
    if taken {
        return Err(err(StatusCode::BAD_REQUEST, "M_USER_IN_USE", "that username is taken"));
    }
    let Json(sess) = register(State(app.clone()), Json(json!({ "password": body.get("password").cloned().unwrap_or_default() }))).await?;
    let token = sess["token"].as_str().unwrap_or_default().to_string();
    let (t2, nick) = (token.clone(), username.clone());
    let who = blk(&app, move |a| a.users.authenticate(&t2)).await??.ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", "session"))?;
    let (u, evs) = blk(&app, move |a| -> Result<_, ServiceError> {
        let u = a.users.store.user_by_nick(&who.nick)?.ok_or(ServiceError::Unauthorized)?;
        a.users.set_nick(&u, &nick, now_ms())
    })
    .await??;
    let _ = u;
    app.events.publish(evs);
    if body.get("inhibit_login").and_then(Value::as_bool) == Some(true) {
        return Ok(Json(json!({ "user_id": username })).into_response());
    }
    Ok(matrix_session(&app, token).await?.into_response())
}

async fn matrix_available(State(app): State<App>, axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let n = q.get("username").cloned().unwrap_or_default();
    if n.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "M_INVALID_USERNAME", "a username is required"));
    }
    if blk(&app, move |a| -> Result<_, ServiceError> { Ok(a.users.store.user_by_nick(&n)?) }).await??.is_some() {
        return Err(err(StatusCode::BAD_REQUEST, "M_USER_IN_USE", "that username is taken"));
    }
    Ok(Json(json!({ "available": true })))
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
    let (u, s) = blk(&app, move |a| -> Result<_, ServiceError> {
        let u = a.users.create_user(Some(&hash), now_ms())?;
        let s = a.users.issue_session(&u, now_ms())?;
        Ok((u, s))
    })
    .await??;
    Ok(session_json(&u.nick, &s.token))
}

async fn login(State(app): State<App>, Json(body): Json<Value>) -> Result<Json<Value>, ApiError> {
    let nick = body.get("nick").and_then(Value::as_str).unwrap_or("").to_string();
    let pw = body.get("password").and_then(Value::as_str).unwrap_or("").to_string();
    let u = verify_password(&app, nick, pw).await?;
    let (u, s) = blk(&app, move |a| -> Result<_, ServiceError> {
        let s = a.users.issue_session(&u, now_ms())?;
        Ok((u, s))
    })
    .await??;
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
    let (u, s) = blk(&app, move |a| -> Result<_, ServiceError> {
        let u = a.users.user_for_door(&source, &subject, now_ms())?;
        let s = a.users.issue_session(&u, now_ms())?;
        Ok((u, s))
    })
    .await??;
    Ok(session_json(&u.nick, &s.token))
}

async fn need(app: &App, h: &HeaderMap) -> Result<AuthUser, ApiError> {
    auth_blocking(app, h).await?.ok_or_else(|| ServiceError::Unauthorized.into())
}

async fn logout(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let who = need(&app, &headers).await?;
    let cred = who.cred_ref.clone();
    let evs = blk(&app, move |a| a.users.revoke(&cred)).await??;
    app.events.publish(evs);
    Ok(Json(json!({})))
}

async fn me(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let who = need(&app, &headers).await?;
    Ok(Json(json!({ "nick": who.nick, "flag": who.flag })))
}

async fn set_nick(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Result<Json<Value>, ApiError> {
    let who = need(&app, &headers).await?;
    let new = body.get("nick").and_then(Value::as_str).unwrap_or("");
    let (nick, new) = (who.nick.clone(), new.to_string());
    let (u, evs) = blk(&app, move |a| -> Result<_, ServiceError> {
        let u = a.users.store.user_by_nick(&nick)?.ok_or(ServiceError::Unauthorized)?;
        a.users.set_nick(&u, &new, now_ms())
    })
    .await??;
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
    let cred = b.get("cred_ref").and_then(Value::as_str).unwrap_or("").to_string();
    let evs = blk(&app, move |a| a.users.revoke(&cred)).await??;
    let n = evs.len();
    app.events.publish(evs);
    Ok(Json(json!({ "revoked": n })))
}

async fn admin_delete(State(app): State<App>, headers: HeaderMap, Json(b): Json<Value>) -> Result<Json<Value>, ApiError> {
    admin(&app, &headers)?;
    let nick = b.get("nick").and_then(Value::as_str).unwrap_or("").to_string();
    let evs = blk(&app, move |a| a.users.delete(&nick)).await??;
    app.events.publish(evs);
    Ok(Json(json!({})))
}

async fn admin_tier(State(app): State<App>, headers: HeaderMap, Json(b): Json<Value>) -> Result<Json<Value>, ApiError> {
    admin(&app, &headers)?;
    let tier = b.get("tier").and_then(Value::as_str).unwrap_or("");
    if !app.users.tiers.knows(tier) {
        return Err(err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "unknown tier"));
    }
    let (nick, tier) = (b.get("nick").and_then(Value::as_str).unwrap_or("").to_string(), tier.to_string());
    blk(&app, move |a| -> Result<(), ServiceError> {
        let u = a.users.store.user_by_nick(&nick)?.ok_or(ServiceError::NotFound)?;
        a.users.store.set_tier(u.id, &tier)?;
        Ok(())
    })
    .await??;
    Ok(Json(json!({})))
}

/// Everything else: authenticate, sign, forward to the edge. A bad token is
/// refused here; no token forwards unasserted (the messenger decides what an
/// unasserted caller may do).
async fn proxy(State(app): State<App>, req: Request) -> Response {
    let who = match auth_blocking(&app, req.headers()).await {
        Ok(w) => w,
        Err(e) => return e.into_response(),
    };
    if who.is_none() && app.anon_read && m4a_seam::anon_read_path_ok(req.method().as_str(), req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("")) {
        return app.link.forward_anon(req).await;
    }
    app.link.forward(who.as_ref(), req).await
}

/// Push socket: the handshake is authenticated here (Bearer header or `access_token`
/// query), signed, and relayed to the messenger; anonymous sockets are refused.
async fn push(State(app): State<App>, headers: HeaderMap, axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>, ws: axum::extract::WebSocketUpgrade) -> Response {
    let token = bearer(&headers).or_else(|| q.get("access_token").cloned());
    let Some(token) = token else { return m4a_product_kit::push_relay::unauthorized() };
    let who = {
        let app = Arc::clone(&app);
        match tokio::task::spawn_blocking(move || app.users.authenticate(&token)).await {
            Ok(Ok(Some(w))) => w,
            _ => return m4a_product_kit::push_relay::unauthorized(),
        }
    };
    app.link.relay_push(who, ws)
}
