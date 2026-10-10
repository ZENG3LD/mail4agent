//! The messenger shell client in IDENTITY mode: no password, no token handed to anyone. The
//! client generates the identity, enrolls with the operator's invite, logs in by signature, keeps
//! its store key random in its vault, and two such sessions exchange an encrypted DM, on tier 2
//! (product API) and tier 3 (Matrix API).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use m4a_product_example::{router, ProductApp, SqliteStore};
use m4a_product_kit::nick_rules::NickRules;
use m4a_product_kit::tiers::TierTable;
use m4a_product_kit::{EdgeLink, EventPublisher, UserService};
use mail4agent_messenger_shell::{
    CreateRoomKind, MessageKind, MessengerCommand, OpenedStore, OutgoingMessage, RoomId, SessionConfig, UserId,
};
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

fn texts(shell: &OpenedStore) -> Vec<String> {
    shell.texts().iter().map(|t| format!("{}|{}", t.outcome, t.body)).collect()
}

fn settle(s: &mut OpenedStore, now: &mut i64) {
    for _ in 0..8 {
        *now += 2_000;
        s.drive(*now, false).expect("drive");
        std::thread::sleep(Duration::from_millis(40));
    }

}


async fn invite(base: &str) -> (String, String) {
    let b: Value = reqwest::Client::new().post(format!("{base}/product/v1/admin/invite")).bearer_auth(ADMIN).json(&json!({})).send().await.unwrap().json().await.unwrap();
    (b["invite"].as_str().unwrap().to_string(), b["nick"].as_str().unwrap().to_string())
}

async fn dm_by_identity(tier: m4a_agent::BackendKind, tag: &str) {
    let base = product().await;
    let root = std::env::temp_dir().join(format!("m4a-ident-shell-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let ((inv_a, n_a), (inv_b, n_b)) = (invite(&base).await, invite(&base).await);
    let versions = reqwest::get(format!("{base}/_matrix/client/versions")).await.unwrap().status().as_u16();
    assert_eq!(versions, 200, "the Matrix server serves its spec prefix");
    let result = tokio::task::spawn_blocking(move || {
        let cfg = |sid: &str, inv: Option<&str>| SessionConfig::new_identity(base.clone(), tier, sid, &root, inv.map(str::to_string)).unwrap();
        let mut alice = OpenedStore::connect(&cfg("sess-alice", Some(&inv_a))).expect("alice enrolls and connects");
        let mut bob = OpenedStore::connect(&cfg("sess-bob", Some(&inv_b))).expect("bob enrolls and connects");
        assert_eq!(alice.nick(), Some(n_a.as_str()), "the nick the operator assigned");
        assert_eq!(bob.nick(), Some(n_b.as_str()));
        let (mut an, mut bn) = (1_000_000_i64, 1_000_000_i64);
        settle(&mut alice, &mut an);
        settle(&mut bob, &mut bn);
        alice.dispatch(MessengerCommand::CreateRoom { kind: CreateRoomKind::Dm { peer: UserId::parse(&format!("@{n_b}:example.org")).unwrap() } }, an).expect("create dm");
        for _ in 0..3 {
            settle(&mut alice, &mut an);
            settle(&mut bob, &mut bn);
        }
        let invite = bob.rooms().into_iter().find(|r| r.membership == "invite").expect("bob has an invite");
        bob.dispatch(MessengerCommand::JoinRoom { room_id: RoomId::parse(&invite.room_id).unwrap() }, bn).expect("join");
        for _ in 0..3 {
            settle(&mut bob, &mut bn);
            settle(&mut alice, &mut an);
        }
        let room = alice.rooms().into_iter().find(|r| r.membership == "join").expect("alice joined");
        assert!(room.encrypted);
        let send = |s: &mut OpenedStore, now: i64, body: &str| {
            s.dispatch(MessengerCommand::SendMessage { room_id: RoomId::parse(&room.room_id).unwrap(), message: OutgoingMessage { kind: MessageKind::Text, body: body.into(), reply_to: None, edit_of: None }, txn_id: None }, now).expect("send");
        };
        send(&mut alice, an, "hello by signature");
        for _ in 0..6 {
            settle(&mut alice, &mut an);
            settle(&mut bob, &mut bn);
            if texts(&bob).iter().any(|t| t.ends_with("|hello by signature")) {
                break;
            }
        }
        assert!(texts(&bob).iter().any(|t| t.ends_with("|hello by signature")), "bob never decrypted: {:?} {:?}", texts(&bob), bob.http_trace());
        send(&mut bob, bn, "and back");
        for _ in 0..6 {
            settle(&mut bob, &mut bn);
            settle(&mut alice, &mut an);
            if texts(&alice).iter().any(|t| t.ends_with("|and back")) {
                break;
            }
        }
        assert!(texts(&alice).iter().any(|t| t.ends_with("|and back")), "alice never decrypted: {:?}", texts(&alice));
        // Restart (the same session ids, no invite any more): the identity logs in by signature,
        // the sealed store opens under the vault key, and the nick is the same.
        let sid_dir = alice.store_dir().to_path_buf();
        drop(alice);
        let again = OpenedStore::connect(&cfg("sess-alice", None)).expect("a restart needs no invite");
        assert_eq!(again.nick(), Some(n_a.as_str()));
        assert_eq!(again.store_dir(), sid_dir);
        assert!(texts(&again).iter().any(|t| t.ends_with("|hello by signature")), "history survives the restart: {:?}", texts(&again));
        // The vault, not the session id, guards the store: no key material in the clear on disk.
        let raw: Vec<u8> = std::fs::read(root.join(".m4a-agent").join("vault.enc")).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("identity-key"));
        // A session that was never invited cannot connect.
        assert!(OpenedStore::connect(&cfg("sess-stranger", None)).is_err());
        assert!(OpenedStore::connect(&cfg("sess-stranger", Some("forged-invite"))).is_err());
        let _ = std::fs::remove_dir_all(&root);
    })
    .await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn identity_sessions_exchange_encrypted_texts_on_the_product_tier() {
    dm_by_identity(m4a_agent::BackendKind::Server, "server").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn identity_sessions_exchange_encrypted_texts_on_the_matrix_tier() {
    dm_by_identity(m4a_agent::BackendKind::Matrix, "matrix").await;
}
