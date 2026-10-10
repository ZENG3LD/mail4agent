//! The messenger side of the seam: the signed-assertion middleware and the
//! lifecycle events endpoint. Verification and wire formats live in
//! [`m4a_seam`]; this file only applies them. Inert until the deployment sets
//! [`Homeserver::seam`].
//!
//! The middleware verifies the assertion header against the method and the
//! path as this router receives it, resolves the identity (creating it, which
//! is first contact), and hands the result to [`super::resolve_caller`]
//! through an internal header that is stripped from every incoming request
//! first.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use m4a_seam::{Event, EventKind, NonceCache, SeamError};
use serde_json::{json, Value};

use crate::error::MatrixError;
use crate::identities;
use crate::policy::{claims_from, Claims};

use super::{wake_users, Homeserver};

/// Internal hand-over header; never trusted from the wire.
pub(super) const RESOLVED_HEADER: &str = "x-m4a-resolved";
/// Pseudo user id of an anonymous read-only caller (never a row).
pub(super) const ANON_USER: i64 = -1;

/// Seam configuration of this server.
pub struct Seam {
    /// Shared secrets, current first (a second one is accepted during rotation).
    pub secrets: Vec<Vec<u8>>,
    pub skew_ms: i64,
    pub assertion_header: String,
    pub event_sig_header: String,
    nonces: NonceCache,
}

impl Seam {
    pub fn new(secrets: Vec<Vec<u8>>, skew_s: i64, assertion_header: Option<String>, event_sig_header: Option<String>) -> Self {
        Self {
            secrets,
            skew_ms: skew_s * 1000,
            assertion_header: assertion_header.unwrap_or_else(|| m4a_seam::DEFAULT_ASSERTION_HEADER.to_string()).to_ascii_lowercase(),
            event_sig_header: event_sig_header.unwrap_or_else(|| m4a_seam::DEFAULT_EVENT_SIG_HEADER.to_string()).to_ascii_lowercase(),
            nonces: NonceCache::new(),
        }
    }

    /// `M4A_ASSERTION_SECRET` (>= 16 chars; `M4A_ASSERTION_SECRET_PREV` accepted too),
    /// `M4A_ASSERTION_SKEW_S` (30), `M4A_ASSERTION_HEADER`, `M4A_EVENT_SIG_HEADER`.
    /// `Ok(None)` when no secret is configured.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Ok(secret) = std::env::var("M4A_ASSERTION_SECRET") else { return Ok(None) };
        if secret.len() < 16 {
            return Err("M4A_ASSERTION_SECRET must be at least 16 characters".into());
        }
        let mut secrets = vec![secret.into_bytes()];
        if let Ok(prev) = std::env::var("M4A_ASSERTION_SECRET_PREV") {
            if !prev.is_empty() {
                secrets.push(prev.into_bytes());
            }
        }
        let skew: i64 = std::env::var("M4A_ASSERTION_SKEW_S").ok().and_then(|v| v.parse().ok()).unwrap_or(30);
        let name = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Ok(Some(Self::new(secrets, skew, name("M4A_ASSERTION_HEADER"), name("M4A_EVENT_SIG_HEADER"))))
    }
}

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new().route("/account-source/v1/events", post(lifecycle_event)).route("/account-source/v1/reconcile", post(reconcile_snapshot))
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Parsed internal header: `(user_id, device_id, claims)`.
pub(super) fn read_resolved(headers: &HeaderMap) -> Option<(i64, String, Claims)> {
    let v = headers.get(RESOLVED_HEADER)?.to_str().ok()?;
    let mut it = v.splitn(3, '|');
    let uid = it.next()?.parse().ok()?;
    let device = it.next()?.to_string();
    let flag: u8 = it.next()?.parse().ok()?;
    let mut claims = claims_from(flag);
    if uid == ANON_USER {
        claims.insert("anon".into(), "1".into());
    }
    Some((uid, device, claims))
}

fn seam_error(e: SeamError) -> MatrixError {
    match e {
        SeamError::Malformed(m) => MatrixError::unauthorized(format!("assertion rejected: {m}")),
        SeamError::BadSignature => MatrixError::unauthorized("assertion rejected: bad signature"),
        SeamError::Expired => MatrixError::unauthorized("assertion expired"),
        SeamError::Replay => MatrixError::unauthorized("assertion replayed"),
    }
}

/// Strip the internal header, then honour a valid signed assertion.
pub(super) async fn assertion_layer(State(state): State<Arc<Homeserver>>, mut req: Request, next: Next) -> Response {
    req.headers_mut().remove(RESOLVED_HEADER);
    let anon_marked = req.headers_mut().remove(m4a_seam::ANON_READ_HEADER).is_some_and(|v| v == "1");
    let Some(seam) = state.seam.get().cloned() else { return next.run(req).await };
    let Some(value) = req.headers().get(seam.assertion_header.as_str()).and_then(|v| v.to_str().ok()).map(str::to_string) else {
        if anon_marked && state.anon_read.get().is_some() {
            let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("");
            if !m4a_seam::anon_read_path_ok(req.method().as_str(), path) {
                return MatrixError::unauthorized("anonymous read is limited to public read-only paths").into_response();
            }
            req.headers_mut().insert(RESOLVED_HEADER, HeaderValue::from_static("-1|anon|0"));
        }
        return next.run(req).await;
    };
    let method = req.method().as_str().to_string();
    let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
    let now = now_ms();
    let a = match m4a_seam::verify_assertion(&seam.secrets, &value, &method, &path, now, seam.skew_ms) {
        Ok(a) => a,
        Err(e) => return seam_error(e).into_response(),
    };
    if method != "GET" && method != "HEAD" {
        if let Err(e) = seam.nonces.check_and_insert(&a, now, seam.skew_ms) {
            return seam_error(e).into_response();
        }
    }
    let st = Arc::clone(&state);
    let done = tokio::task::spawn_blocking(move || -> Result<String, MatrixError> {
        st.conn_scope(|conn: &mut rusqlite::Connection| {
        let r = identities::resolve_assertion(&mut *conn, &a.nick, &a.cred_ref, now)?;
        Ok(format!("{}|{}|{}", r.identity.id, r.device_id, a.paid))
        })
    })
    .await;
    match done {
        Ok(Ok(v)) => {
            if let Ok(hv) = HeaderValue::from_str(&v) {
                req.headers_mut().insert(RESOLVED_HEADER, hv);
            }
            next.run(req).await
        }
        Ok(Err(e)) => e.into_response(),
        Err(_) => MatrixError::internal().into_response(),
    }
}

/// Re-stamp the identity's current nick into its member events; returns users to wake.
fn restamp(conn: &mut rusqlite::Connection, id: i64) -> Result<Vec<i64>, MatrixError> {
    let Some(idn) = identities::identity_by_id(conn, id)? else { return Ok(vec![]) };
    let r = crate::store::refresh_member_displayname(conn, id, &idn.nick, &chrono::Utc::now().to_rfc3339(), now_ms())?;
    Ok(r.affected_user_ids.into_iter().collect())
}

/// Product -> messenger lifecycle events. Body is a [`m4a_seam::Event`]; the
/// signature header carries the hex HMAC of the raw body.
/// Product's startup snapshot of live credentials; see [`m4a_seam::Reconcile`].
async fn reconcile_snapshot(State(state): State<Arc<Homeserver>>, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, MatrixError> {
    let seam = state.seam.get().cloned().ok_or_else(MatrixError::unrecognized)?;
    let sig = headers.get(seam.event_sig_header.as_str()).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !m4a_seam::verify_body(&seam.secrets, &body, sig) {
        return Err(MatrixError::unauthorized("bad event signature"));
    }
    let snap: m4a_seam::Reconcile = serde_json::from_slice(&body).map_err(|_| MatrixError::bad_json("malformed reconcile body"))?;
    let out = super::with_conn_pub(&state, move |conn| identities::reconcile(conn, &snap, now_ms())).await?;
    wake_users(&state, out.wake.clone());
    for u in &out.closed {
        state.push.close_user(*u);
    }
    Ok(Json(json!({ "ok": true, "devices_removed": out.devices_removed, "identities_retired": out.identities_retired })))
}

async fn lifecycle_event(State(state): State<Arc<Homeserver>>, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, MatrixError> {
    let seam = state.seam.get().cloned().ok_or_else(MatrixError::unrecognized)?;
    let sig = headers.get(seam.event_sig_header.as_str()).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !m4a_seam::verify_body(&seam.secrets, &body, sig) {
        return Err(MatrixError::unauthorized("bad event signature"));
    }
    let ev: Event = serde_json::from_slice(&body).map_err(|_| MatrixError::bad_json("unknown event type or missing field"))?;
    if ev.id.is_empty() {
        return Err(MatrixError::bad_json("missing id"));
    }
    let closed = Arc::new(std::sync::Mutex::new(Vec::<i64>::new()));
    let closed_in = Arc::clone(&closed);
    let (applied, woke) = super::with_conn_pub(&state, move |conn| {
        let closed = closed_in;
        let now = now_ms();
        let fresh = conn.execute("INSERT OR IGNORE INTO account_events_seen (event_id, at_ms) VALUES (?1, ?2)", rusqlite::params![ev.id, now])?;
        if fresh == 0 {
            return Ok((false, vec![])); // replay of an applied event: success, nothing to do
        }
        let res: Result<(bool, Vec<i64>), MatrixError> = match &ev.kind {
            EventKind::CredentialRevoked { cred_ref } => identities::apply_credential_revoked(conn, cred_ref).map(|u| {
                closed.lock().unwrap().extend(u);
                (u.is_some(), u.into_iter().collect())
            }),
            EventKind::AccountDeleted { nick } => {
                let id = identities::identity_by_nick(conn, nick)?.map(|i| i.id);
                identities::apply_account_deleted(conn, nick, now).map(|b| {
                    closed.lock().unwrap().extend(id);
                    (b, vec![])
                })
            }
            EventKind::NickChanged { old, new } => identities::apply_nick_changed(conn, old, new).and_then(|id| match id {
                Some(id) => Ok((true, restamp(conn, id)?)),
                None => Ok((false, vec![])),
            }),
        };
        if res.is_err() {
            // Not applied: allow a corrected retry with the same id.
            conn.execute("DELETE FROM account_events_seen WHERE event_id = ?1", rusqlite::params![ev.id])?;
        }
        res
    })
    .await?;
    wake_users(&state, woke);
    for u in closed.lock().unwrap().iter() {
        state.push.close_user(*u);
    }
    Ok(Json(json!({ "ok": true, "applied": applied })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request as Req, StatusCode};
    use m4a_seam::{sign_assertion, sign_body, Assertion};
    use tower::ServiceExt;

    const SECRET: &[u8] = b"0123456789abcdef0123";

    fn state() -> Arc<Homeserver> {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        crate::store::create_matrix_schema(&c).unwrap();
        crate::keys::create_matrix_keys_schema(&c).unwrap();
        let hs = Arc::new(Homeserver::new(c));
        let _ = hs.seam.set(Arc::new(Seam::new(vec![SECRET.to_vec()], 30, None, None)));
        hs
    }

    async fn call(hs: &Arc<Homeserver>, req: Req<Body>) -> (StatusCode, Value) {
        let resp = crate::http::router(hs.clone()).oneshot(req).await.unwrap();
        let st = resp.status();
        let b = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (st, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    fn assertion(nick: &str, cred: &str, nonce: &str, paid: u8) -> Assertion {
        let now = chrono::Utc::now().timestamp();
        Assertion { nick: nick.into(), cred_ref: cred.into(), authenticated: 1, paid, iat: now, exp: now + 60, nonce: nonce.into() }
    }

    fn signed_req(method: &str, path: &str, a: &Assertion, body: Body) -> Req<Body> {
        Req::builder().method(method).uri(path).header(m4a_seam::DEFAULT_ASSERTION_HEADER, sign_assertion(SECRET, method, path, a))
            .header("content-type", "application/json").body(body).unwrap()
    }

    #[tokio::test]
    async fn assertion_creates_identity_contact_and_device_and_forged_header_is_ignored() {
        let hs = state();
        let p = "/client/v3/profile/@ivy:example.org/displayname";
        let (st, body) = call(&hs, signed_req("GET", p, &assertion("ivy", "c1", "n1", 0), Body::empty())).await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert_eq!(body["displayname"], "ivy");
        hs.conn_async(|c| {
            let a = identities::identity_by_nick(c, "ivy").unwrap().unwrap();
            assert_eq!(crate::store::mxid_of(c, a.id).unwrap().as_deref(), Some("@ivy:example.org"));
            assert_eq!(crate::keys::list_devices(c, a.id).unwrap().len(), 1);
        })
        .await;
        let forged = Req::builder().uri(p).header(RESOLVED_HEADER, "1|X|1").body(Body::empty()).unwrap();
        assert_eq!(call(&hs, forged).await.0, StatusCode::UNAUTHORIZED, "no token, forged hand-over is stripped");
        let mut r = signed_req("GET", p, &assertion("ivy", "c1", "n2", 0), Body::empty());
        *r.uri_mut() = "/client/v3/profile/@other:example.org/displayname".parse().unwrap();
        assert_eq!(call(&hs, r).await.0, StatusCode::UNAUTHORIZED);
        // no assertion at all never creates anything
        let none = Req::builder().uri("/client/v3/capabilities").body(Body::empty()).unwrap();
        assert_eq!(call(&hs, none).await.0, StatusCode::UNAUTHORIZED);
        let n: i64 = hs.conn_async(|c| c.query_row("SELECT COUNT(*) FROM identities", [], |r| r.get(0)).unwrap()).await;
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn replayed_nonce_on_a_write_is_refused_and_nick_conflict_has_a_stable_shape() {
        let hs = state();
        let a = assertion("jay", "c2", "n-write", 0);
        let (st, _) = call(&hs, signed_req("PUT", "/client/v3/profile/@jay:example.org/displayname", &a, Body::from("{}"))).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "displayname is the product's, the core never sets it");
        let (st, _) = call(&hs, signed_req("PUT", "/client/v3/profile/@jay:example.org/displayname", &a, Body::from("{}"))).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "same nonce again");
        hs.conn_async(|c| c.execute_batch("INSERT INTO matrix_users (user_id, mxid, created_at) VALUES (77, '@taken:example.org', 't')").unwrap()).await;
        let (st, body) = call(&hs, signed_req("GET", "/client/v3/capabilities", &assertion("taken", "c3", "n9", 0), Body::empty())).await;
        assert_eq!((st, body["errcode"].as_str()), (StatusCode::CONFLICT, Some("M4A_NICK_CONFLICT")));
    }

    #[tokio::test]
    async fn login_is_closed_and_flows_are_empty() {
        let hs = state();
        let r = Req::builder().method("POST").uri("/client/v3/login").header("content-type", "application/json").body(Body::from("{}")).unwrap();
        assert_eq!(call(&hs, r).await.0, StatusCode::FORBIDDEN);
        let (_, flows) = call(&hs, Req::builder().uri("/client/v3/login").body(Body::empty()).unwrap()).await;
        assert_eq!(flows["flows"], json!([]));
    }

    #[tokio::test]
    async fn lifecycle_events_are_signed_idempotent_and_revoke_wakes() {
        let hs = state();
        let (st, _) = call(&hs, signed_req("GET", "/client/v3/capabilities", &assertion("lee", "c9", "n7", 0), Body::empty())).await;
        assert_eq!(st, StatusCode::OK);
        let post = |body: &str, sig: Option<String>| {
            let sig = sig.unwrap_or_else(|| sign_body(SECRET, body.as_bytes()));
            Req::builder().method("POST").uri("/account-source/v1/events").header(m4a_seam::DEFAULT_EVENT_SIG_HEADER, sig).body(Body::from(body.to_string())).unwrap()
        };
        let rev = r#"{"id":"e1","type":"credential.revoked","cred_ref":"c9"}"#;
        assert_eq!(call(&hs, post(rev, Some("00".into()))).await.0, StatusCode::UNAUTHORIZED);
        let (st, b) = call(&hs, post(rev, None)).await;
        assert_eq!((st, b["applied"].clone()), (StatusCode::OK, json!(true)));
        assert_eq!(call(&hs, post(rev, None)).await.1["applied"], json!(false), "replayed id is a no-op success");
        let ren = r#"{"id":"e2","type":"nick.changed","old":"lee","new":"leigh"}"#;
        assert_eq!(call(&hs, post(ren, None)).await.1["applied"], json!(true));
        let del = r#"{"id":"e3","type":"account.deleted","nick":"leigh"}"#;
        assert_eq!(call(&hs, post(del, None)).await.1["applied"], json!(true));
        assert_eq!(call(&hs, post(r#"{"id":"e4","type":"bogus"}"#, None)).await.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn policy_hook_is_consulted_with_claims_for_every_action() {
        use crate::policy::{Action, Decision, PolicyContext, PolicyHook};
        struct Rec(std::sync::Mutex<Vec<(Action, String)>>);
        impl PolicyHook for Rec {
            fn decide(&self, c: &PolicyContext<'_>) -> Decision {
                self.0.lock().unwrap().push((c.action, c.claims.get("flag").cloned().unwrap_or_default()));
                Decision::Deny("closed".into())
            }
        }
        let hs = state();
        let rec = Arc::new(Rec(Default::default()));
        let _ = hs.policy.set(rec.clone());
        let routes: [(&str, &str, &str); 5] = [
            ("POST", "/client/v3/createRoom", "{}"),
            ("POST", "/client/v3/rooms/!r:example.org/join", "{}"),
            ("POST", "/client/v3/rooms/!r:example.org/invite", "{\"user_id\":\"@a:example.org\"}"),
            ("PUT", "/client/v3/rooms/!r:example.org/send/m.room.message/t1", "{}"),
            ("POST", "/media/v3/upload", "x"),
        ];
        for (i, (m, p, b)) in routes.iter().enumerate() {
            let (st, body) = call(&hs, signed_req(m, p, &assertion("pol", "cp", &format!("np{i}"), 1), Body::from(*b))).await;
            assert_eq!((st, body["errcode"].as_str()), (StatusCode::FORBIDDEN, Some("M4A_POLICY_DENIED")), "{m} {p}: {body}");
        }
        let seen = rec.0.lock().unwrap().clone();
        for a in [Action::CreateRoom, Action::JoinRoom, Action::Invite, Action::SendEvent, Action::UploadMedia] {
            assert!(seen.iter().any(|(x, f)| *x == a && f == "1"), "{a:?} not consulted with the flag claim: {seen:?}");
        }
    }
}
