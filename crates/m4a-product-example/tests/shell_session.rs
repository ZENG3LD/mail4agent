//! The messenger shell client in product-session mode: login at the product,
//! whoami through the product proxy, then an encrypted direct message both
//! ways. Core runs without any legacy session code.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use m4a_product_example::{router, ProductApp, SqliteStore};
use m4a_product_kit::nick_rules::NickRules;
use m4a_product_kit::tiers::TierTable;
use m4a_product_kit::{EdgeLink, EventPublisher, UserService};
use mail4agent_messenger_shell::{
    CreateRoomKind, MessageKind, MessengerCommand, OpenedStore, OutgoingMessage, ProductSecret, RoomId, SessionConfig, UserId,
};
use mail4agent_server::http::{edge_auth::require_edge_secret, identity::Seam, Homeserver};
use tesserax_store::rusqlite::Connection;
use serde_json::{json, Value};

const EDGE_SECRET: &str = "0123456789abcdef0123456789abcdef-edge";
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
        admin_token: String::new(),
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

#[tokio::test(flavor = "multi_thread")]
async fn shells_log_in_at_the_product_and_exchange_encrypted_texts_through_its_proxy() {
    let base = product().await;
    let root = std::env::temp_dir().join(format!("m4a-prod-shell-{}", std::process::id()));
    let c = reqwest::Client::new();
    let mut nicks = vec![];
    for _ in 0..2 {
        let b: Value = c.post(format!("{base}/product/v1/register")).json(&json!({"password":"correct horse"})).send().await.unwrap().json().await.unwrap();
        nicks.push(b["nick"].as_str().unwrap().to_string());
    }
    let (n_a, n_b) = (nicks[0].clone(), nicks[1].clone());
    let result = tokio::task::spawn_blocking(move || {
        let cfg = |nick: &str, sid: &str| SessionConfig::new_product(base.clone(), nick, ProductSecret::Password("correct horse".to_string().into()), sid, &root).unwrap();
        let mut alice = OpenedStore::connect(&cfg(&n_a, "sess-alice")).expect("alice connects through the product");
        let mut bob = OpenedStore::connect(&cfg(&n_b, "sess-bob")).expect("bob connects through the product");
        assert_eq!(alice.nick(), Some(n_a.as_str()));
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
        assert!(room.encrypted, "direct rooms are encrypted");
        let send = |s: &mut OpenedStore, now: i64, body: &str| {
            s.dispatch(
                MessengerCommand::SendMessage {
                    room_id: RoomId::parse(&room.room_id).unwrap(),
                    message: OutgoingMessage { kind: MessageKind::Text, body: body.into(), reply_to: None, edit_of: None },
                    txn_id: None,
                },
                now,
            )
            .expect("send");
        };
        send(&mut alice, an, "hello through the product");
        for _ in 0..6 {
            settle(&mut alice, &mut an);
            settle(&mut bob, &mut bn);
            if texts(&bob).iter().any(|t| t.ends_with("|hello through the product")) {
                break;
            }
        }
        assert!(texts(&bob).iter().any(|t| t.ends_with("|hello through the product")), "bob never decrypted: {:?} bobtrace {:?} alice {:?} alicetrace {:?}", texts(&bob), bob.http_trace(), texts(&alice), alice.http_trace());
        send(&mut bob, bn, "and back");
        for _ in 0..6 {
            settle(&mut bob, &mut bn);
            settle(&mut alice, &mut an);
            if texts(&alice).iter().any(|t| t.ends_with("|and back")) {
                break;
            }
        }
        assert!(texts(&alice).iter().any(|t| t.ends_with("|and back")), "alice never decrypted: {:?}", texts(&alice));
        // A wrong password never reaches the messenger.
        let bad = SessionConfig::new_product(cfg(&n_a, "sess-x").homeserver_url().to_string(), &n_a, ProductSecret::Password("nope".to_string().into()), "sess-y", &std::env::temp_dir()).unwrap();
        assert!(OpenedStore::connect(&bad).is_err());
    })
    .await;
    result.unwrap();
}
