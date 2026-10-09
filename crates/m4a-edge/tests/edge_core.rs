//! In-process edge -> core: a real core router (with the shared-secret gate) on a
//! loopback port, a real edge router in front, real HTTP and WebSocket between them.

use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use mail4agent_server::http::{edge_auth::require_edge_secret, hash_token, router, Homeserver};
use rusqlite::Connection;
use serde_json::{json, Value};

const SECRET: &str = "0123456789abcdef0123456789abcdef-test-secret";
const NOW: &str = "2026-10-09T00:00:00+00:00";

async fn serve(app: axum::Router) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap() });
    a
}

fn core() -> axum::Router {
    let conn = Connection::open_in_memory().unwrap();
    mail4agent_server::store::create_matrix_schema(&conn).unwrap();
    mail4agent_server::keys::create_matrix_keys_schema(&conn).unwrap();
    for (uid, pid, tok, nick) in [(1, "alice000000000000000000000000a1", "tok-alice", "alice"), (2, "bob0000000000000000000000000b2", "tok-bob", "bob")] {
        mail4agent_server::store::ensure_matrix_user(&conn, uid, pid, NOW).unwrap();
        mail4agent_server::keys::create_device(&conn, uid, mail4agent_server::keys::CredentialKind::Bearer, &hash_token(tok), NOW).unwrap();
        mail4agent_server::nick::set_nick(&conn, uid, nick).unwrap();
    }
    require_edge_secret(router(Arc::new(Homeserver::new(conn))), SECRET.to_string())
}

#[tokio::test]
async fn edge_forwards_cs_api_push_and_media_and_core_refuses_direct_access() {
    let core_addr = serve(core()).await;
    let edge_addr = serve(m4a_edge::edge_router(m4a_edge::EdgeConfig { core_url: format!("http://{core_addr}"), secret: SECRET.into() })).await;
    let c = reqwest::Client::new();
    let edge = format!("http://{edge_addr}");

    // The core refuses anything without the secret; a client-supplied wrong secret through the edge is replaced.
    assert_eq!(c.get(format!("http://{core_addr}/client/versions")).send().await.unwrap().status(), 401);
    let r = c.get(format!("{edge}/_matrix/client/versions")).header("x-m4a-edge-secret", "forged").send().await.unwrap();
    assert_eq!(r.status(), 200, "edge strips /_matrix and supplies its own secret");
    assert!(c.get(format!("{edge}/edge/healthz")).send().await.unwrap().status().is_success());

    // Contract unchanged through the edge: create room, send, GET /messages.
    let a = |rb: reqwest::RequestBuilder| rb.header("authorization", "Bearer tok-alice");
    let b = |rb: reqwest::RequestBuilder| rb.header("authorization", "Bearer tok-bob");
    let room: Value = a(c.post(format!("{edge}/_matrix/client/v3/createRoom"))).json(&json!({"name":"edge-chan","visibility":"public"})).send().await.unwrap().json().await.unwrap();
    let room_id = room["room_id"].as_str().unwrap().to_string();
    assert_eq!(b(c.post(format!("{edge}/_matrix/client/v3/rooms/{room_id}/join"))).json(&json!({})).send().await.unwrap().status(), 200);

    // Push v1 relay: bob's socket is held at the edge, then alice's message arrives on it.
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{edge_addr}/_matrix/client/v3/push")).await.unwrap();
    ws.send(tokio_tungstenite::tungstenite::Message::text(json!({"type":"register","tokens":["tok-bob"]}).to_string())).await.unwrap();
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next()).await.unwrap().unwrap().unwrap();
    assert!(first.to_text().unwrap().contains("registered"), "registered ack relayed: {first:?}");

    let sent = a(c.put(format!("{edge}/_matrix/client/v3/rooms/{room_id}/send/m.room.message/t1"))).json(&json!({"msgtype":"m.text","body":"through the edge"})).send().await.unwrap();
    assert_eq!(sent.status(), 200);
    let msgs: Value = b(c.get(format!("{edge}/_matrix/client/v3/rooms/{room_id}/messages?dir=b&limit=5"))).send().await.unwrap().json().await.unwrap();
    assert!(msgs["chunk"].as_array().unwrap().iter().any(|e| e["content"]["body"] == "through the edge"), "{msgs}");
    let pushed = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next()).await.expect("push frame").unwrap().unwrap();
    assert!(!pushed.to_text().unwrap().is_empty());

    // Media (binary body, auth) and well-known pass through.
    let up: Value = a(c.post(format!("{edge}/_matrix/media/v3/upload"))).body(vec![9u8; 4096]).send().await.unwrap().json().await.unwrap();
    let path = up["content_uri"].as_str().unwrap().strip_prefix("mxc://").unwrap().to_string();
    let got = b(c.get(format!("{edge}/_matrix/client/v1/media/download/{path}"))).send().await.unwrap().bytes().await.unwrap();
    assert_eq!(got.len(), 4096);
    assert_eq!(c.get(format!("{edge}/.well-known/matrix/client")).send().await.unwrap().status(), 404, "config-driven on the core");
}

#[tokio::test]
async fn edge_rate_limits_register_per_client_and_reports_core_down() {
    let dead = m4a_edge::edge_router(m4a_edge::EdgeConfig { core_url: "http://127.0.0.1:9".into(), secret: SECRET.into() });
    let addr = serve(dead).await;
    let c = reqwest::Client::new();
    assert_eq!(c.get(format!("http://{addr}/_matrix/client/versions")).send().await.unwrap().status(), 502);
    assert_eq!(c.get(format!("http://{addr}/edge/healthz")).send().await.unwrap().status(), 502);
    let mut limited = false;
    for _ in 0..30 {
        let r = c.post(format!("http://{addr}/_matrix/client/v3/register")).header("x-forwarded-for", "203.0.113.9").body("{}").send().await.unwrap();
        if r.status() == 429 {
            limited = true;
            break;
        }
    }
    assert!(limited, "register is rate limited per client ip");
}

#[tokio::test]
async fn edge_passes_the_assertion_header_and_the_signed_path_is_the_core_path() {
    use m4a_seam::{sign_assertion, Assertion, DEFAULT_ASSERTION_HEADER};
    let secret = b"0123456789abcdef0123".to_vec();
    let conn = Connection::open_in_memory().unwrap();
    mail4agent_server::store::create_matrix_schema(&conn).unwrap();
    mail4agent_server::keys::create_matrix_keys_schema(&conn).unwrap();
    let hs = Arc::new(Homeserver::new(conn));
    let _ = hs.seam.set(Arc::new(mail4agent_server::http::identity::Seam::new(vec![secret.clone()], 30, None, None)));
    let core_addr = serve(require_edge_secret(router(hs), SECRET.to_string())).await;
    let edge_addr = serve(m4a_edge::edge_router(m4a_edge::EdgeConfig { core_url: format!("http://{core_addr}"), secret: SECRET.into() })).await;
    let c = reqwest::Client::new();
    let now = chrono_now();
    let a = |nonce: &str| Assertion { nick: "nora".into(), cred_ref: "c1".into(), authenticated: 1, paid: 0, iat: now, exp: now + 60, nonce: nonce.into() };
    // The product signs over the core-side path (no `/_matrix` prefix, query kept).
    let core_path = "/client/v3/capabilities?x=1";
    let v = sign_assertion(&secret, "GET", core_path, &a("n-edge"));
    let ok = c.get(format!("http://{edge_addr}/_matrix{core_path}")).header(DEFAULT_ASSERTION_HEADER, &v).send().await.unwrap();
    assert_eq!(ok.status(), 200, "{}", ok.text().await.unwrap());
    // Signed over the prefixed path does not match what the core sees.
    let v2 = sign_assertion(&secret, "GET", &format!("/_matrix{core_path}"), &a("n-edge2"));
    let bad = c.get(format!("http://{edge_addr}/_matrix{core_path}")).header(DEFAULT_ASSERTION_HEADER, &v2).send().await.unwrap();
    assert_eq!(bad.status(), 401);
    // A client cannot inject the internal hand-over header through the edge.
    let forged = c.get(format!("http://{edge_addr}/_matrix/client/v3/capabilities")).header("x-m4a-resolved", "1|dev|1").send().await.unwrap();
    assert_eq!(forged.status(), 401);
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}
