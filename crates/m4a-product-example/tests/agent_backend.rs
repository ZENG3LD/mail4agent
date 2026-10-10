//! The Backend of the agent client in identity mode, against the product and the core: login by
//! signature, sliding sync (and plain /sync on request), and the push socket as the news channel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use m4a_product_example::{router, ProductApp, SqliteStore};
use m4a_product_kit::nick_rules::NickRules;
use m4a_product_kit::tiers::TierTable;
use m4a_product_kit::{EdgeLink, EventPublisher, UserService};
use mail4agent_server::http::{edge_auth::require_edge_secret, identity::Seam, Homeserver};
use tesserax_store::rusqlite::Connection;
use serde_json::{json, Value};

const EDGE_SECRET: &str = "0123456789abcdef0123456789abcdef-edge";
const ADMIN: &str = "admin-token-for-tests";
const SEAM_SECRET: &[u8] = b"seam-secret-0123456789abcdef";

async fn serve(app: axum::Router) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap() });
    a
}

async fn product() -> String {
    let conn = Connection::open_in_memory().unwrap();
    mail4agent_server::store::create_matrix_schema(&conn).unwrap();
    mail4agent_server::keys::create_matrix_keys_schema(&conn).unwrap();
    let core = Arc::new(Homeserver::new(conn));
    let _ = core.seam.set(Arc::new(Seam::new(vec![SEAM_SECRET.to_vec()], 30, None, None)));
    let core_addr = serve(require_edge_secret(mail4agent_server::http::router(core), EDGE_SECRET.to_string())).await;
    let edge_addr = serve(m4a_edge::edge_router(m4a_edge::EdgeConfig { core_url: format!("http://{core_addr}"), secret: EDGE_SECRET.into(), link_token: None })).await;
    let link = EdgeLink::new(&format!("http://{edge_addr}"), SEAM_SECRET.to_vec(), None);
    let app = Arc::new(ProductApp {
        users: UserService::new(Arc::new(SqliteStore::memory().unwrap()), NickRules::default(), TierTable::default()),
        events: EventPublisher::spawn(link.clone(), None, Duration::from_millis(50)),
        link,
        admin_token: ADMIN.into(),
        doors: vec![],
        anon_read: false,
        tokens: Default::default(),
        access_ttl_ms: 3_600_000,
        challenges: m4a_product_kit::ChallengeBook::new("test-product"),
    });
    format!("http://{}", serve(router(app)).await)
}


use m4a_agent::backend::matrix::{MatrixBackend, SyncMode};
use m4a_agent::engine::News;
use m4a_agent::{Backend, BackendKind, IdentityStore, MemoryVault};
use mail4agent_messenger::{HttpMethod, OutgoingRequest, OutgoingRequestKind, RequestId};

async fn invite(base: &str) -> (String, String) {
    let b: Value = reqwest::Client::new().post(format!("{base}/product/v1/admin/invite")).bearer_auth(ADMIN).json(&json!({})).send().await.unwrap().json().await.unwrap();
    (b["invite"].as_str().unwrap().to_string(), b["nick"].as_str().unwrap().to_string())
}

fn req(seed: u64, method: HttpMethod, path: &str, query: &[(&str, &str)], body: Option<Value>, kind: OutgoingRequestKind) -> OutgoingRequest {
    OutgoingRequest { id: RequestId::next(seed), method, path: path.into(), query: query.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(), body, kind }
}

fn login(base: &str, sid: &str, invite: &str, mode: SyncMode) -> (Arc<MatrixBackend>, String) {
    let ids = IdentityStore::new(Arc::new(MemoryVault::new()));
    let backend = MatrixBackend::discover(base).expect("backend").with_sync_mode(mode);
    let mut id = ids.resolve(sid, BackendKind::Matrix, backend.server_ref()).expect("identity");
    let session = backend.ensure_session(&ids, &mut id, Some(invite)).expect("enroll and login by signature");
    (Arc::new(backend), session.user_id.expect("user id"))
}

#[tokio::test]
async fn sliding_sync_v3_fallback_and_push_in_identity_mode() {
    let base = product().await;
    let ((inv_a, _), (inv_b, _)) = (invite(&base).await, invite(&base).await);
    tokio::task::spawn_blocking(move || {
        let (alice, alice_id) = login(&base, "a-sess", &inv_a, SyncMode::Auto);
        let (bob, bob_id) = login(&base, "b-sess", &inv_b, SyncMode::Auto);
        let (plain, _) = login(&base, "c-sess", &invite_blocking(&base), SyncMode::V3);
        assert!(alice.uses_sliding_sync(), "the server offers MSC4186, so it is used");
        assert!(!plain.uses_sliding_sync(), "V3 was asked for");

        // Sync as the engine would ask for it: a v3 request, a v3-shaped answer, tokens carried on.
        for backend in [&alice, &plain] {
            let first = backend.execute(&req(1, HttpMethod::Get, "/_matrix/client/v3/sync", &[("timeout", "0")], None, OutgoingRequestKind::Sync)).expect("sync");
            assert_eq!(first.status, 200);
            let v: Value = serde_json::from_slice(&first.body).unwrap();
            let next = v["next_batch"].as_str().expect("next_batch").to_string();
            assert!(v.get("rooms").is_some());
            let second = backend.execute(&req(2, HttpMethod::Get, "/_matrix/client/v3/sync", &[("timeout", "0"), ("since", &next)], None, OutgoingRequestKind::Sync)).expect("sync 2");
            assert_eq!(second.status, 200);
        }

        // The push socket: bob waits, alice makes a room, bob joins, alice writes.
        let bob_wait = Arc::clone(&bob);
        let waiter = std::thread::spawn(move || {
            // Opens the socket, then waits for news.
            assert_eq!(bob_wait.wait_for_news(Duration::from_millis(300)).expect("wait"), News::Idle, "nothing yet");
            bob_wait.wait_for_news(Duration::from_secs(20)).expect("wait")
        });
        std::thread::sleep(Duration::from_millis(600));
        let made = alice.execute(&req(3, HttpMethod::Post, "/_matrix/client/v3/createRoom", &[], Some(json!({ "preset": "private_chat", "invite": [bob_id] })), OutgoingRequestKind::CreateRoom)).expect("create");
        assert_eq!(made.status, 200, "{}", String::from_utf8_lossy(&made.body));
        let room = serde_json::from_slice::<Value>(&made.body).unwrap()["room_id"].as_str().unwrap().to_string();
        let enc = |s: &str| s.replace('!', "%21").replace(':', "%3A");
        let joined = bob.execute(&req(4, HttpMethod::Post, &format!("/_matrix/client/v3/rooms/{}/join", enc(&room)), &[], Some(json!({})), OutgoingRequestKind::JoinRoom)).expect("join");
        assert_eq!(joined.status, 200, "{}", String::from_utf8_lossy(&joined.body));
        let sent = alice.execute(&req(5, HttpMethod::Put, &format!("/_matrix/client/v3/rooms/{}/send/m.room.encrypted/t1", enc(&room)), &[], Some(json!({ "algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "opaque", "sender_key": "k", "session_id": "s", "device_id": "D" })), OutgoingRequestKind::RoomSend)).expect("send");
        assert_eq!(sent.status, 200, "{}", String::from_utf8_lossy(&sent.body));
        match waiter.join().expect("waiter") {
            News::Pushed(events) => {
                assert!(events.iter().any(|e| e.room == room && e.sender == alice_id), "pushed: {events:?}");
                assert!(events.iter().all(|e| e.body.is_empty()), "push carries no plaintext");
            }
            News::Idle => panic!("the push socket delivered nothing"),
        }
    })
    .await
    .unwrap();
}

fn invite_blocking(base: &str) -> String {
    let b: Value = reqwest::blocking::Client::new().post(format!("{base}/product/v1/admin/invite")).bearer_auth(ADMIN).json(&json!({})).send().unwrap().json().unwrap();
    b["invite"].as_str().unwrap().to_string()
}
