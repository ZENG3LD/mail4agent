//! Identity wiring: signed-assertion middleware, the external-login door
//! (`POST /client/v3/login`), the display-name -> `set_nick` mapping and the
//! issuer lifecycle endpoint. Everything is inert until the deployment sets
//! [`Homeserver::identity`].
//!
//! The assertion middleware verifies `X-M4A-Assertion` (+ `-Sig`) against the
//! method and the path as this router receives it, resolves the account,
//! performs first contact and the device lookup, and hands the result to
//! [`super::resolve_caller`] through an internal header that the middleware
//! strips from every incoming request first.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::account_source::{AccountFacts, AccountSource, RequestParts, SignedHeaderSource, EVENT_SIG_HEADER};
use crate::accounts::{self, AccountsConfig};
use crate::error::MatrixError;
use crate::external_login::{door_assertion, ExternalLogin};

use super::{wake_users, Homeserver};

/// Internal hand-over header; never trusted from the wire.
pub(super) const RESOLVED_HEADER: &str = "x-m4a-resolved";

/// Deployment identity configuration.
pub struct Identity {
    pub cfg: AccountsConfig,
    pub signed: Option<Arc<SignedHeaderSource>>,
    pub doors: Vec<Arc<dyn ExternalLogin>>,
}

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new().route("/account-source/v1/events", post(lifecycle_event))
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Parsed internal header: `(user_id, device_id, facts)`.
pub(super) fn read_resolved(headers: &HeaderMap) -> Option<(i64, String, AccountFacts)> {
    let v = headers.get(RESOLVED_HEADER)?.to_str().ok()?;
    let mut it = v.splitn(5, '|');
    let uid = it.next()?.parse().ok()?;
    let device = it.next()?.to_string();
    let authenticated = it.next()? == "1";
    let paid = it.next()? == "1";
    let source = it.next()?.to_string();
    Some((uid, device, AccountFacts { source, authenticated, paid }))
}

/// Strip the internal header, then honour a valid signed assertion.
pub(super) async fn assertion_layer(State(state): State<Arc<Homeserver>>, mut req: Request, next: Next) -> Response {
    req.headers_mut().remove(RESOLVED_HEADER);
    let Some(identity) = state.identity.get() else { return next.run(req).await };
    let Some(signed) = identity.signed.clone() else { return next.run(req).await };
    if !req.headers().contains_key(crate::account_source::ASSERTION_HEADER) {
        return next.run(req).await;
    }
    let method = req.method().as_str().to_string();
    let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
    let asserted = match signed.authenticate(&RequestParts { method: &method, path: &path, headers: req.headers(), now_ms: now_ms() }) {
        Ok(Some(a)) => a,
        Ok(None) => return next.run(req).await,
        Err(e) => return MatrixError::from(e).into_response(),
    };
    let st = Arc::clone(&state);
    let done = tokio::task::spawn_blocking(move || -> Result<String, MatrixError> {
        let mut conn = st.conn.lock().unwrap_or_else(|e| e.into_inner());
        let cfg = &st.identity.get().expect("checked above").cfg;
        let now = now_ms();
        let r = accounts::resolve_account(&mut conn, &asserted, cfg, now)?;
        accounts::first_contact(&mut conn, r.account.id, now)?;
        let device = accounts::device_for_assertion(&conn, r.account.id, &asserted)?;
        Ok(format!("{}|{}|{}|{}|{}", r.account.id, device, asserted.authenticated as u8, asserted.paid as u8, asserted.source))
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

/// `POST /client/v3/login` for `m4a.login.<door>` types.
pub(super) async fn door_login(state: &Arc<Homeserver>, body: Value) -> Result<Value, MatrixError> {
    let identity = state.identity.get().ok_or_else(|| MatrixError::forbidden("login is not enabled: this server has no passwords; sessions are created by register"))?;
    let kind = body.get("type").and_then(Value::as_str).unwrap_or("");
    let door = identity
        .doors
        .iter()
        .find(|d| format!("m4a.login.{}", d.id()) == kind)
        .ok_or_else(|| MatrixError::invalid_param("unknown login type"))?
        .clone();
    let (source, subject) = door.verify(&body).await?;
    let wanted = body.get("nick").and_then(Value::as_str).map(str::to_string);
    let st = Arc::clone(state);
    super::with_conn_pub(state, move |conn| {
        let identity = state_identity(&st)?;
        let now = now_ms();
        let r = accounts::resolve_account(conn, &door_assertion(&source, &subject, "", 0), &identity.cfg, now)?;
        // A nick wanted at login is honoured before first contact (it then becomes the localpart).
        if let Some(n) = wanted {
            if !r.account.localpart_frozen && n != r.account.nick {
                accounts::set_nick(conn, r.account.id, &n, &identity.cfg, now)?;
            }
        }
        let mxid = accounts::first_contact(conn, r.account.id, now)?;
        let raw = super::register::mint_bearer_pub();
        let hash = super::hash_token(&raw);
        let device_id = crate::keys::create_device(conn, r.account.id, crate::keys::CredentialKind::Bearer, &hash, &chrono::Utc::now().to_rfc3339())?;
        Ok(json!({ "user_id": mxid, "access_token": raw, "device_id": device_id, "home_server": crate::store::matrix_server_name() }))
    })
    .await
}

fn state_identity(st: &Arc<Homeserver>) -> Result<&Identity, MatrixError> {
    st.identity.get().map(|i| i.as_ref()).ok_or_else(MatrixError::internal)
}

/// Re-stamp the account's current nick into its member events; returns users to wake.
fn restamp(conn: &mut rusqlite::Connection, account_id: i64) -> Result<Vec<i64>, MatrixError> {
    let Some(acc) = accounts::account_by_id(conn, account_id)? else { return Ok(vec![]) };
    let r = crate::store::refresh_member_displayname(conn, account_id, &acc.nick, &chrono::Utc::now().to_rfc3339(), now_ms())?;
    Ok(r.affected_user_ids.into_iter().collect())
}

/// `PUT /profile/{user}/displayname` for account-backed callers.
pub(super) async fn set_display_name(state: &Arc<Homeserver>, user_id: i64, new: String) -> Result<Option<()>, MatrixError> {
    let st = Arc::clone(state);
    let woke = super::with_conn_pub(state, move |conn| {
        if accounts::account_by_id(conn, user_id)?.is_none() {
            return Ok(None);
        }
        let default = AccountsConfig::default();
        let cfg = st.identity.get().map(|i| &i.cfg).unwrap_or(&default);
        accounts::set_nick(conn, user_id, &new, cfg, now_ms())?;
        Ok(Some(restamp(conn, user_id)?))
    })
    .await?;
    Ok(woke.map(|ids| wake_users(state, ids)))
}

/// Issuer lifecycle events: `credential.revoked{cred_ref}`, `account.deleted{nick}`,
/// `nick.changed{old,new}`. Body is JSON with a unique `id` (idempotency key) and `type`;
/// `X-M4A-Event-Sig` is hex HMAC-SHA256 of the raw body.
async fn lifecycle_event(State(state): State<Arc<Homeserver>>, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, MatrixError> {
    let identity = state.identity.get().ok_or_else(MatrixError::unrecognized)?;
    let signed = identity.signed.clone().ok_or_else(MatrixError::unrecognized)?;
    let sig = headers.get(EVENT_SIG_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !signed.verify_body(&body, sig) {
        return Err(MatrixError::unauthorized("bad event signature"));
    }
    let ev: Value = serde_json::from_slice(&body).map_err(|_| MatrixError::bad_json("event is not JSON"))?;
    let id = ev.get("id").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| MatrixError::bad_json("missing id"))?.to_string();
    let kind = ev.get("type").and_then(Value::as_str).unwrap_or("").to_string();
    let field = |k: &str| ev.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let (cred, nick, old, new) = (field("cred_ref"), field("nick"), field("old"), field("new"));
    let source = signed.id().to_string();
    let st = Arc::clone(&state);
    let (applied, woke, extra) = super::with_conn_pub(&state, move |conn| {
        let mut wake: Vec<i64> = Vec::new();
        let cfg = &state_identity(&st)?.cfg;
        let now = now_ms();
        let seen = conn.execute("INSERT OR IGNORE INTO account_events_seen (event_id, at_ms) VALUES (?1, ?2)", rusqlite::params![id, now])?;
        if seen == 0 {
            return Ok((false, None, vec![])); // replay of an applied event: success, nothing to do
        }
        let res = match kind.as_str() {
            "credential.revoked" if !cred.is_empty() => accounts::apply_credential_revoked(conn, &source, &cred).map(|u| (u.is_some(), u)),
            "account.deleted" if !nick.is_empty() => accounts::apply_account_deleted(conn, &source, &nick, now).map(|b| (b, None)),
            "nick.changed" if !old.is_empty() && !new.is_empty() => accounts::apply_nick_changed(conn, &source, &old, &new, cfg).and_then(|b| {
                if let (true, Some(a)) = (b, accounts::account_by_nick(conn, &new)?) {
                    wake.extend(restamp(conn, a.id)?);
                }
                Ok((b, None))
            }),
            _ => Err(MatrixError::bad_json("unknown event type or missing field")),
        };
        if res.is_err() {
            // Not applied: allow a corrected retry with the same id.
            conn.execute("DELETE FROM account_events_seen WHERE event_id = ?1", rusqlite::params![id])?;
        }
        res.map(|(a, w)| (a, w, wake))
    })
    .await?;
    wake_users(&state, woke.into_iter().chain(extra));
    Ok(Json(json!({ "ok": true, "applied": applied })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_source::{build_assertion, ASSERTION_HEADER, ASSERTION_SIG_HEADER};
    use crate::external_login::{MatrixOpenIdLogin, OpenIdUserinfo, UserinfoFuture};
    use crate::federation::FedError;
    use axum::body::Body;
    use axum::http::{Request as Req, StatusCode};
    use tower::ServiceExt;

    struct Fake;
    impl OpenIdUserinfo for Fake {
        fn userinfo<'a>(&'a self, server: &'a str, tok: &'a str) -> UserinfoFuture<'a> {
            Box::pin(async move {
                if tok == "good" { Ok(json!({"sub": format!("@zed:{server}")})) } else { Err(FedError::Network("no".into())) }
            })
        }
    }

    fn state() -> Arc<Homeserver> {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        crate::store::create_matrix_schema(&c).unwrap();
        crate::keys::create_matrix_keys_schema(&c).unwrap();
        let hs = Arc::new(Homeserver::new(c));
        let signed = Arc::new(SignedHeaderSource::new("issuer:test", vec![b"0123456789abcdef0123".to_vec()], 30_000));
        let _ = hs.identity.set(Arc::new(Identity {
            cfg: AccountsConfig::default(),
            signed: Some(signed),
            doors: vec![Arc::new(MatrixOpenIdLogin::new(Arc::new(Fake)))],
        }));
        hs
    }

    async fn call(hs: &Arc<Homeserver>, req: Req<Body>) -> (StatusCode, Value) {
        let resp = crate::http::router(hs.clone()).oneshot(req).await.unwrap();
        let st = resp.status();
        let b = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (st, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    fn signed_req(hs: &Arc<Homeserver>, method: &str, path: &str, nick: &str, cred: &str, nonce: &str, body: Body) -> Req<Body> {
        let signed = hs.identity.get().unwrap().signed.clone().unwrap();
        let now = chrono::Utc::now().timestamp();
        let j = json!({"v":1,"nick":nick,"placeholder":false,"authenticated":true,"paid":false,"cred_ref":cred,"iat":now,"exp":now+60,"nonce":nonce});
        let (v, s) = build_assertion(&signed, method, path, &j);
        Req::builder().method(method).uri(path).header(ASSERTION_HEADER, v).header(ASSERTION_SIG_HEADER, s)
            .header("content-type", "application/json").body(body).unwrap()
    }

    #[tokio::test]
    async fn assertion_creates_account_contact_and_device_and_forged_header_is_ignored() {
        let hs = state();
        let (st, body) = call(&hs, signed_req(&hs, "GET", "/client/v3/profile/@ivy:example.org/displayname", "ivy", "c1", "n1", Body::empty())).await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert_eq!(body["displayname"], "ivy");
        let c = hs.conn.lock().unwrap();
        let a = accounts::account_by_nick(&c, "ivy").unwrap().unwrap();
        assert!(a.localpart_frozen && a.first_contact_ms.is_some());
        assert_eq!(crate::store::mxid_of(&c, a.id).unwrap().as_deref(), Some("@ivy:example.org"));
        assert_eq!(crate::keys::list_devices(&c, a.id).unwrap().len(), 1);
        drop(c);
        // client-supplied internal header and a tampered signature are not honoured
        let forged = Req::builder().method("GET").uri("/client/v3/profile/@ivy:example.org/displayname").header(RESOLVED_HEADER, "1|X|1|1|local").body(Body::empty()).unwrap();
        assert_eq!(call(&hs, forged).await.0, StatusCode::UNAUTHORIZED);
        let mut r = signed_req(&hs, "GET", "/client/v3/profile/@ivy:example.org/displayname", "ivy", "c1", "n2", Body::empty());
        *r.uri_mut() = "/client/v3/profile/@other:example.org/displayname".parse().unwrap();
        assert_eq!(call(&hs, r).await.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn issuer_cannot_use_displayname_and_policy_error_shape_is_stable() {
        let hs = state();
        let r = signed_req(&hs, "PUT", "/client/v3/profile/@jay:example.org/displayname", "jay", "c2", "n3", Body::from("{\"displayname\":\"newname\"}"));
        let (st, body) = call(&hs, r).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        assert_eq!(body["errcode"], "M_FORBIDDEN");
    }

    #[tokio::test]
    async fn door_login_mints_separate_account_and_honours_nick_before_contact() {
        let hs = state();
        let login = |tok: &str, nick: Option<&str>| {
            let mut b = json!({"type":"m4a.login.matrix","matrix_server_name":"other.example","access_token":tok});
            if let Some(n) = nick { b["nick"] = json!(n); }
            Req::builder().method("POST").uri("/client/v3/login").header("content-type", "application/json").body(Body::from(b.to_string())).unwrap()
        };
        assert_eq!(call(&hs, login("bad", None)).await.0, StatusCode::UNAUTHORIZED);
        let (st, b) = call(&hs, login("good", Some("kim"))).await;
        assert_eq!(st, StatusCode::OK, "{b}");
        assert_eq!(b["user_id"], "@kim:example.org");
        // the bearer works
        let tok = b["access_token"].as_str().unwrap();
        let (st, _) = call(&hs, Req::builder().uri("/client/v3/capabilities").header("authorization", format!("Bearer {tok}")).body(Body::empty()).unwrap()).await;
        assert_eq!(st, StatusCode::OK);
        // same foreign address returns to the same account; nick already frozen, name does not move
        let (st, b2) = call(&hs, login("good", Some("kimmy"))).await;
        assert_eq!(st, StatusCode::OK, "{b2}");
        assert_eq!(b2["user_id"], "@kim:example.org");
        // no account row was created for the foreign address as a remote user
        let c = hs.conn.lock().unwrap();
        let n: i64 = c.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
        let sub: String = c.query_row("SELECT subject FROM external_identities", [], |r| r.get(0)).unwrap();
        assert_eq!(sub, "@zed:other.example");
    }

    #[tokio::test]
    async fn lifecycle_events_are_signed_idempotent_and_revoke_wakes() {
        let hs = state();
        let (st, _) = call(&hs, signed_req(&hs, "GET", "/client/v3/capabilities", "lee", "c9", "n7", Body::empty())).await;
        assert_eq!(st, StatusCode::OK);
        let signed = hs.identity.get().unwrap().signed.clone().unwrap();
        let post = |body: &str, sig: Option<String>| {
            let sig = sig.unwrap_or_else(|| crate::account_source::sign_body_for_tests(&signed, body.as_bytes()));
            Req::builder().method("POST").uri("/account-source/v1/events").header(EVENT_SIG_HEADER, sig).body(Body::from(body.to_string())).unwrap()
        };
        let rev = r#"{"id":"e1","type":"credential.revoked","cred_ref":"c9"}"#;
        assert_eq!(call(&hs, post(rev, Some("00".into()))).await.0, StatusCode::UNAUTHORIZED);
        let (st, b) = call(&hs, post(rev, None)).await;
        assert_eq!((st, b["applied"].clone()), (StatusCode::OK, json!(true)));
        let (_, b) = call(&hs, post(rev, None)).await;
        assert_eq!(b["applied"], json!(false), "replayed id is a no-op success");
        let ren = r#"{"id":"e2","type":"nick.changed","old":"lee","new":"leigh"}"#;
        assert_eq!(call(&hs, post(ren, None)).await.1["applied"], json!(true));
        let del = r#"{"id":"e3","type":"account.deleted","nick":"leigh"}"#;
        assert_eq!(call(&hs, post(del, None)).await.1["applied"], json!(true));
        let bad = r#"{"id":"e4","type":"bogus"}"#;
        assert_eq!(call(&hs, post(bad, None)).await.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn displayname_put_changes_nick_not_localpart_and_restamps() {
        let hs = state();
        let b = {
            let b = json!({"type":"m4a.login.matrix","matrix_server_name":"other.example","access_token":"good"});
            let r = Req::builder().method("POST").uri("/client/v3/login").header("content-type", "application/json").body(Body::from(b.to_string())).unwrap();
            call(&hs, r).await.1
        };
        let mxid = b["user_id"].as_str().unwrap().to_string();
        let tok = b["access_token"].as_str().unwrap().to_string();
        let put = |name: &str| Req::builder().method("PUT").uri(format!("/client/v3/profile/{mxid}/displayname")).header("authorization", format!("Bearer {tok}"))
            .header("content-type", "application/json").body(Body::from(json!({"displayname": name}).to_string())).unwrap();
        let (st, body) = call(&hs, put("Mia")).await;
        assert_eq!(st, StatusCode::OK, "{body}");
        let (_, g) = call(&hs, Req::builder().uri(format!("/client/v3/profile/{mxid}/displayname")).header("authorization", format!("Bearer {tok}")).body(Body::empty()).unwrap()).await;
        assert_eq!(g["displayname"], "Mia");
        let (st, body) = call(&hs, put("Mia2")).await;
        assert_eq!((st, body["errcode"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("M4A_NICK_COOLDOWN")));
        let c = hs.conn.lock().unwrap();
        let a = accounts::account_by_nick(&c, "mia").unwrap().unwrap();
        assert_eq!(format!("@{}:example.org", a.localpart), mxid);
        assert_ne!(a.localpart, "mia");
    }

    #[tokio::test]
    async fn policy_hook_is_consulted_for_every_account_action() {
        use crate::policy::{Action, Decision, PolicyContext, PolicyHook};
        struct Rec(std::sync::Mutex<Vec<Action>>);
        impl PolicyHook for Rec {
            fn decide(&self, c: &PolicyContext<'_>) -> Decision {
                self.0.lock().unwrap().push(c.action);
                Decision::Deny("closed".into())
            }
        }
        let hs = state();
        let rec = Arc::new(Rec(Default::default()));
        let _ = hs.policy.set(rec.clone());
        let routes: [(&str, &str, &str); 6] = [
            ("POST", "/client/v3/createRoom", "{}"),
            ("POST", "/client/v3/rooms/!r:example.org/join", "{}"),
            ("POST", "/client/v3/rooms/!r:example.org/invite", "{\"user_id\":\"@a:example.org\"}"),
            ("PUT", "/client/v3/rooms/!r:example.org/send/m.room.message/t1", "{}"),
            ("POST", "/media/v3/upload", "x"),
            ("PUT", "/client/v3/profile/@pol:example.org/displayname", "{\"displayname\":\"abc\"}"),
        ];
        for (i, (m, p, b)) in routes.iter().enumerate() {
            let (st, body) = call(&hs, signed_req(&hs, m, p, "pol", "cp", &format!("np{i}"), Body::from(*b))).await;
            assert_eq!((st, body["errcode"].as_str()), (StatusCode::FORBIDDEN, Some("M4A_POLICY_DENIED")), "{m} {p}: {body}");
        }
        let seen = rec.0.lock().unwrap().clone();
        for a in [Action::CreateRoom, Action::JoinRoom, Action::Invite, Action::SendEvent, Action::UploadMedia, Action::SetNick] {
            assert!(seen.contains(&a), "{a:?} not consulted: {seen:?}");
        }
    }
}
