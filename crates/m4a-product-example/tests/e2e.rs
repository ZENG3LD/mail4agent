//! Product server -> edge -> core, all real HTTP on loopback, in one process.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use m4a_product_example::{router, ProductApp, SqliteStore};
use m4a_product_kit::door::{DoorFuture, LoginDoor};
use m4a_product_kit::nick_rules::NickRules;
use m4a_product_kit::tiers::TierTable;
use m4a_product_kit::{EdgeLink, EventPublisher, UserService};
use mail4agent_server::http::{edge_auth::require_edge_secret, identity::Seam, Homeserver};
use rusqlite::Connection;
use serde_json::{json, Value};

const EDGE_SECRET: &str = "0123456789abcdef0123456789abcdef-edge";
const SEAM_SECRET: &[u8] = b"seam-secret-0123456789abcdef";
const LINK: &str = "link-token-0123456789abcdef";
const ADMIN: &str = "admin-token-for-tests";

async fn serve(app: axum::Router) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap() });
    a
}

fn serve_unix(app: axum::Router, path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let l = tokio::net::UnixListener::bind(path).unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
}

struct FakeDoor;
impl LoginDoor for FakeDoor {
    fn id(&self) -> &str {
        "fake"
    }
    fn verify<'a>(&'a self, proof: &'a Value) -> DoorFuture<'a> {
        Box::pin(async move { Ok(("fake".to_string(), proof["who"].as_str().unwrap_or("x").to_string())) })
    }
}

struct Stack {
    link: EdgeLink,
    edge: String,
    core: Arc<Homeserver>,
    product: String,
    c: reqwest::Client,
}

async fn stack() -> Stack {
    stack_with(None).await
}

/// With `unix_dir`, product -> edge and edge -> core run over unix sockets in that directory.
async fn stack_with(unix_dir: Option<&std::path::Path>) -> Stack {
    let conn = Connection::open_in_memory().unwrap();
    mail4agent_server::store::create_matrix_schema(&conn).unwrap();
    mail4agent_server::keys::create_matrix_keys_schema(&conn).unwrap();
    let core = Arc::new(Homeserver::new(conn));
    let _ = core.anon_read.set(());
    let _ = core.seam.set(Arc::new(Seam::new(vec![SEAM_SECRET.to_vec()], 30, None, None)));
    let core_app = require_edge_secret(mail4agent_server::http::router(core.clone()), EDGE_SECRET.to_string());
    let (core_url, edge_url) = match unix_dir {
        Some(d) => {
            serve_unix(core_app, &d.join("core.sock"));
            (format!("unix:{}", d.join("core.sock").display()), format!("unix:{}", d.join("edge.sock").display()))
        }
        None => (format!("http://{}", serve(core_app).await), String::new()),
    };
    let edge_app = m4a_edge::edge_router(m4a_edge::EdgeConfig { core_url, secret: EDGE_SECRET.into(), link_token: Some(LINK.into()) });
    let edge_url = match unix_dir {
        Some(d) => {
            serve_unix(edge_app, &d.join("edge.sock"));
            edge_url
        }
        None => format!("http://{}", serve(edge_app).await),
    };
    let link = EdgeLink::new(&edge_url, SEAM_SECRET.to_vec(), None).with_link_token(Some(LINK.into()));
    let app = Arc::new(ProductApp {
        users: UserService::new(Arc::new(SqliteStore::memory().unwrap()), NickRules::default(), TierTable::default()),
        events: EventPublisher::spawn_with(link.clone(), None, Duration::from_millis(50), Arc::new(m4a_product_kit::SqliteOutbox::memory().unwrap())),
        link: link.clone(),
        admin_token: ADMIN.into(),
        doors: vec![Arc::new(FakeDoor)],
        anon_read: true,
    });
    let product = format!("http://{}", serve(router(app)).await);
    Stack { link, edge: edge_url, core, product, c: reqwest::Client::new() }
}

impl Stack {
    async fn post(&self, path: &str, token: Option<&str>, body: Value) -> (u16, Value) {
        self.send("POST", path, token, Some(body)).await
    }
    async fn send(&self, method: &str, path: &str, token: Option<&str>, body: Option<Value>) -> (u16, Value) {
        let mut rb = self.c.request(method.parse().unwrap(), format!("{}{}", self.product, path));
        if let Some(t) = token {
            rb = rb.bearer_auth(t);
        }
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let r = rb.send().await.unwrap();
        (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
    }
    async fn register(&self) -> (String, String) {
        let (st, b) = self.post("/product/v1/register", None, json!({"password":"correct horse"})).await;
        assert_eq!(st, 200, "{b}");
        (b["nick"].as_str().unwrap().to_string(), b["token"].as_str().unwrap().to_string())
    }
    /// Poll the core until `f` holds (events are delivered asynchronously).
    async fn until(&self, what: &str, f: impl Fn(&Connection) -> bool) {
        for _ in 0..100 {
            if f(&self.core.conn.lock().unwrap()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("timed out waiting for: {what}");
    }
}

#[tokio::test]
async fn register_contact_room_message_rename_logout_and_delete_through_the_whole_stack() {
    let s = stack().await;
    let (a_nick, a_tok) = s.register().await;
    let (b_nick, b_tok) = s.register().await;
    assert_eq!((a_nick.len(), b_nick.len()), (8, 8), "placeholder nicks");

    // Registration alone does not touch the messenger.
    assert_eq!(s.core.conn.lock().unwrap().query_row::<i64, _, _>("SELECT COUNT(*) FROM identities", [], |r| r.get(0)).unwrap(), 0);

    // Nick before first contact: free, and the messenger's localpart becomes the short nick.
    let (st, b) = s.send("PUT", "/product/v1/nick", Some(&a_tok), Some(json!({"nick":"alice"}))).await;
    assert_eq!((st, b["nick"].as_str()), (200, Some("alice")));
    let (st, b) = s.send("PUT", "/product/v1/nick", Some(&a_tok), Some(json!({"nick":"alice2"}))).await;
    assert_eq!((st, b["errcode"].as_str()), (429, Some("M4A_NICK_COOLDOWN")));
    assert!(b["retry_after_ms"].as_i64().unwrap() > 0);
    let (st, b) = s.send("PUT", "/product/v1/nick", Some(&b_tok), Some(json!({"nick":"Alice"}))).await;
    assert_eq!((st, b["errcode"].as_str()), (409, Some("M4A_NICK_TAKEN")));
    let (st, _) = s.send("PUT", "/product/v1/nick", Some(&b_tok), Some(json!({"nick":"a:b"}))).await;
    assert_eq!(st, 400);
    let (st, _) = s.send("PUT", "/product/v1/nick", Some(&b_tok), Some(json!({"nick":"bobby"}))).await;
    assert_eq!(st, 200);

    // First messenger requests are first contact.
    for t in [&a_tok, &b_tok] {
        let (st, b) = s.send("GET", "/_matrix/client/v3/capabilities", Some(t), None).await;
        assert_eq!(st, 200, "{b}");
    }
    {
        let c = s.core.conn.lock().unwrap();
        let ids: Vec<String> = c.prepare("SELECT localpart FROM identities ORDER BY id").unwrap().query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
        assert_eq!(ids, vec!["alice", "bobby"]);
    }

    // Room, invite, join, message, read: a normal Matrix flow through the proxy.
    let (st, b) = s.post("/_matrix/client/v3/createRoom", Some(&a_tok), json!({"name":"hello","preset":"private_chat"})).await;
    assert_eq!(st, 200, "{b}");
    let room = b["room_id"].as_str().unwrap().to_string();
    let (st, b) = s.post(&format!("/_matrix/client/v3/rooms/{room}/invite"), Some(&a_tok), json!({"user_id":"@bobby:example.org"})).await;
    assert_eq!(st, 200, "{b}");
    let (st, b) = s.post(&format!("/_matrix/client/v3/rooms/{room}/join"), Some(&b_tok), json!({})).await;
    assert_eq!(st, 200, "{b}");
    let (st, b) = s.send("PUT", &format!("/_matrix/client/v3/rooms/{room}/send/m.room.encrypted/t1"), Some(&a_tok), Some(json!({"algorithm":"m.megolm.v1.aes-sha2","ciphertext":"hi bob (opaque)","sender_key":"k","session_id":"s","device_id":"d"}))).await;
    assert_eq!(st, 200, "{b}");
    let (st, b) = s.send("GET", &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=10"), Some(&b_tok), None).await;
    assert_eq!(st, 200, "{b}");
    assert!(b.to_string().contains("hi bob"), "{b}");

    // Without a token or with a forged assertion header nothing is asserted.
    let (st, _) = s.send("GET", "/_matrix/client/v3/capabilities", None, None).await;
    assert_eq!(st, 401);
    let r = s.c.get(format!("{}/_matrix/client/v3/capabilities", s.product)).header("x-m4a-assertion", "v1.e30.00").header("x-m4a-resolved", "1|X|1").send().await.unwrap();
    assert_eq!(r.status().as_u16(), 401);
    let (st, _) = s.send("GET", "/_matrix/client/v3/capabilities", Some("not-a-token"), None).await;
    assert_eq!(st, 401, "unknown token is refused by the product");

    // Rename after contact: the product publishes nick.changed; the localpart stays.
    let (c_nick, c_tok) = s.register().await;
    assert_eq!(s.send("GET", "/_matrix/client/v3/capabilities", Some(&c_tok), None).await.0, 200);
    let (st, b) = s.send("PUT", "/product/v1/nick", Some(&c_tok), Some(json!({"nick":"carla"}))).await;
    assert_eq!((st, b["nick"].as_str()), (200, Some("carla")));
    s.until("identity renamed", |c| c.query_row("SELECT nick FROM identities WHERE localpart = ?1", [&c_nick], |r| r.get::<_, String>(0)).map(|n| n == "carla").unwrap_or(false)).await;
    let (st, b) = s.send("GET", &format!("/_matrix/client/v3/profile/@{c_nick}:example.org/displayname"), Some(&c_tok), None).await;
    assert_eq!((st, b["displayname"].as_str()), (200, Some("carla")));
    // Same credential keeps working under the new nick, same identity.
    assert_eq!(s.send("GET", "/_matrix/client/v3/capabilities", Some(&c_tok), None).await.0, 200);
    assert_eq!(s.core.conn.lock().unwrap().query_row::<i64, _, _>("SELECT COUNT(*) FROM identities", [], |r| r.get(0)).unwrap(), 3);

    // Logout: product refuses the token at once; the core drops the device.
    let devs = |c: &Connection, n: &str| c.query_row::<i64, _, _>("SELECT COUNT(*) FROM devices d JOIN identities i ON i.id = d.user_id WHERE i.nick = ?1", [n], |r| r.get(0)).unwrap();
    assert_eq!(devs(&s.core.conn.lock().unwrap(), "bobby"), 1);
    assert_eq!(s.post("/product/v1/logout", Some(&b_tok), json!({})).await.0, 200);
    assert_eq!(s.send("GET", "/_matrix/client/v3/capabilities", Some(&b_tok), None).await.0, 401);
    s.until("device removed", |c| devs(c, "bobby") == 0).await;

    // Admin API is closed without the admin token; delete retires the identity in the core.
    assert_eq!(s.post("/product/v1/admin/delete", Some("nope"), json!({"nick":"alice"})).await.0, 403);
    assert_eq!(s.post("/product/v1/admin/delete", Some(ADMIN), json!({"nick":"alice"})).await.0, 200);
    s.until("identity retired", |c| c.query_row::<i64, _, _>("SELECT COUNT(*) FROM identities WHERE nick = 'alice'", [], |r| r.get(0)).unwrap() == 0).await;
    assert_eq!(s.core.conn.lock().unwrap().query_row::<i64, _, _>("SELECT COUNT(*) FROM reserved_localparts WHERE localpart = 'alice'", [], |r| r.get(0)).unwrap(), 1);
    assert_eq!(s.send("GET", "/_matrix/client/v3/capabilities", Some(&a_tok), None).await.0, 401);
}

#[tokio::test]
async fn login_password_doors_and_tier_flag() {
    let s = stack().await;
    let (nick, _) = s.register().await;
    let (st, b) = s.post("/product/v1/login", None, json!({"nick":nick,"password":"correct horse"})).await;
    assert_eq!(st, 200, "{b}");
    assert_eq!(s.post("/product/v1/login", None, json!({"nick":nick,"password":"wrong"})).await.0, 403);
    assert_eq!(s.post("/product/v1/login", None, json!({"nick":"nobody1","password":"x"})).await.0, 403);
    assert_eq!(s.post("/product/v1/register", None, json!({"password":"short"})).await.0, 400);

    let (_, d) = s.send("GET", "/product/v1/doors", None, None).await;
    assert_eq!(d["doors"], json!(["fake"]));
    let (st, one) = s.post("/product/v1/login/door/fake", None, json!({"who":"@x:other.example"})).await;
    assert_eq!(st, 200, "{one}");
    let (_, two) = s.post("/product/v1/login/door/fake", None, json!({"who":"@x:other.example"})).await;
    assert_eq!(one["nick"], two["nick"], "same foreign address, same user; nick is a placeholder, not the address");
    assert_eq!(one["nick"].as_str().unwrap().len(), 8);
    assert_eq!(s.post("/product/v1/login/door/none", None, json!({})).await.0, 404);

    let tok = one["token"].as_str().unwrap();
    assert_eq!(s.send("GET", "/product/v1/me", Some(tok), None).await.1["flag"], 0);
    let n = one["nick"].as_str().unwrap();
    assert_eq!(s.post("/product/v1/admin/tier", Some(ADMIN), json!({"nick":n,"tier":"paid"})).await.0, 200);
    assert_eq!(s.send("GET", "/product/v1/me", Some(tok), None).await.1["flag"], 1);
    assert_eq!(s.post("/product/v1/admin/tier", Some(ADMIN), json!({"nick":n,"tier":"gold"})).await.0, 400);
}

#[tokio::test]
async fn push_socket_is_signed_by_the_product_relayed_through_the_edge_and_registered_by_identity() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
    let s = stack().await;
    let (_, a_tok) = s.register().await;
    let (_, b_tok) = s.register().await;
    let ws = s.product.replacen("http", "ws", 1);
    // No token: refused before the upgrade. Wrong token: refused too.
    assert!(tokio_tungstenite::connect_async(format!("{ws}/client/v3/push")).await.is_err());
    let mut bad = format!("{ws}/_matrix/client/v3/push").into_client_request().unwrap();
    bad.headers_mut().insert("authorization", "Bearer nope".parse().unwrap());
    assert!(tokio_tungstenite::connect_async(bad).await.is_err());
    // Valid token: registered at once, no token frame needed.
    let mut req = format!("{ws}/client/v3/push").into_client_request().unwrap();
    req.headers_mut().insert("authorization", format!("Bearer {a_tok}").parse().unwrap());
    let (mut sock, _) = tokio_tungstenite::connect_async(req).await.expect("handshake");
    let first = tokio::time::timeout(Duration::from_secs(5), sock.next()).await.expect("registered in time").unwrap().unwrap();
    assert_eq!(first.into_text().unwrap().as_str(), r#"{"type":"registered"}"#);
    // The registration is by verified identity: an event for alice reaches the socket.
    s.send("GET", "/_matrix/client/v3/capabilities", Some(&b_tok), None).await;
    let a_nick = s.send("GET", "/product/v1/me", Some(&a_tok), None).await.1["nick"].as_str().unwrap().to_string();
    let (_, b) = s.post("/_matrix/client/v3/createRoom", Some(&b_tok), json!({"preset":"private_chat","name":"pub"})).await;
    let room = b["room_id"].as_str().unwrap().to_string();
    let (st, b) = s.post(&format!("/_matrix/client/v3/rooms/{room}/invite"), Some(&b_tok), json!({"user_id": format!("@{a_nick}:example.org")})).await;
    assert_eq!(st, 200, "{b}");
    let (st, _) = s.post(&format!("/_matrix/client/v3/rooms/{room}/join"), Some(&a_tok), json!({})).await;
    assert_eq!(st, 200);
    let (st, b) = s.send("PUT", &format!("/_matrix/client/v3/rooms/{room}/send/m.room.encrypted/p1"), Some(&b_tok), Some(json!({"algorithm":"m.megolm.v1.aes-sha2","ciphertext":"x","sender_key":"k","session_id":"s","device_id":"d"}))).await;
    assert_eq!(st, 200, "{b}");
    let got = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(Message::Text(t))) = sock.next().await {
            if t.contains("\"event\"") {
                return t.to_string();
            }
        }
        String::new()
    })
    .await
    .expect("push event in time");
    assert!(got.contains(&room), "{got}");
    let _ = sock.close(None).await;
}

#[tokio::test]
async fn barrier_token_gates_the_edge_but_not_the_public_protocol_surfaces() {
    let s = stack().await;
    let c = &s.c;
    // Without the token (or with a wrong one) the edge refuses client paths, even with a valid-looking header.
    let r = c.get(format!("{}/_matrix/client/v3/capabilities", s.edge)).send().await.unwrap();
    assert_eq!((r.status().as_u16(), r.json::<Value>().await.unwrap()["errcode"].as_str().map(str::to_string)), (401, Some("M4A_LINK_TOKEN_REQUIRED".into())));
    let r = c.get(format!("{}/_matrix/client/v3/capabilities", s.edge)).header("x-m4a-link-token", "wrong-token-0123456789").send().await.unwrap();
    assert_eq!(r.status().as_u16(), 401);
    // Public surfaces stay open (they are not product traffic).
    for p in ["/_matrix/client/versions", "/.well-known/matrix/client", "/edge/healthz"] {
        let r = c.get(format!("{}{p}", s.edge)).send().await.unwrap();
        assert_ne!(r.status().as_u16(), 401, "{p}");
    }
    // Through the product, with its token configured, everything works; a client-supplied token header is dropped.
    let (_, tok) = s.register().await;
    let r = c.get(format!("{}/_matrix/client/v3/capabilities", s.product)).bearer_auth(&tok).header("x-m4a-link-token", "client-forged-0123456789").send().await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
}

#[tokio::test]
async fn unix_sockets_carry_product_to_edge_to_core_including_the_push_socket() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let dir = std::env::temp_dir().join(format!("m4a-unix-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let s = stack_with(Some(&dir)).await;
    let (_, tok) = s.register().await;
    // A normal request crosses both unix hops and the core answers for the asserted identity.
    let (st, who) = s.send("GET", "/_matrix/client/v3/account/whoami", Some(&tok), None).await;
    assert_eq!(st, 200, "{who}");
    assert!(who["user_id"].as_str().unwrap().ends_with(":example.org"));
    // The push socket is relayed over both hops as well.
    let mut req = format!("{}/client/v3/push", s.product.replacen("http", "ws", 1)).into_client_request().unwrap();
    req.headers_mut().insert("authorization", format!("Bearer {tok}").parse().unwrap());
    let (mut sock, _) = tokio_tungstenite::connect_async(req).await.expect("handshake");
    let first = tokio::time::timeout(Duration::from_secs(5), sock.next()).await.expect("registered in time").unwrap().unwrap();
    assert_eq!(first.into_text().unwrap().as_str(), r#"{"type":"registered"}"#);
    // The barrier still applies: a request that skips the product link token is refused by the edge.
    let c = reqwest::Client::builder().unix_socket(dir.join("edge.sock")).build().unwrap();
    let r = c.get("http://edge.local/_matrix/client/v3/capabilities").send().await.unwrap();
    assert_eq!(r.status().as_u16(), 401);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn anonymous_read_serves_public_rooms_only_and_never_writes() {
    let s = stack().await;
    let (_, tok) = s.register().await;
    // A public channel with one plaintext post, and a private room with one encrypted event.
    let (_, ch) = s.post("/_matrix/client/v3/createRoom", Some(&tok), json!({"visibility":"public","name":"open"})).await;
    let chan = ch["room_id"].as_str().unwrap().to_string();
    let (st, b) = s.send("PUT", &format!("/_matrix/client/v3/rooms/{chan}/send/m.room.message/a1"), Some(&tok), Some(json!({"msgtype":"m.text","body":"hello world"}))).await;
    assert_eq!(st, 200, "{b}");
    let (_, pr) = s.post("/_matrix/client/v3/createRoom", Some(&tok), json!({"preset":"private_chat","name":"closed"})).await;
    let closed = pr["room_id"].as_str().unwrap().to_string();
    // No token at all.
    let (st, b) = s.send("GET", &format!("/_matrix/client/v3/rooms/{chan}/messages?dir=b"), None, None).await;
    assert_eq!(st, 200, "{b}");
    assert!(b["chunk"].to_string().contains("hello world"), "{b}");
    let (st, _) = s.send("GET", "/_matrix/client/v3/publicRooms", None, None).await;
    assert_eq!(st, 200);
    // Closed rooms stay closed to anonymous readers.
    let (st, _) = s.send("GET", &format!("/_matrix/client/v3/rooms/{closed}/messages?dir=b"), None, None).await;
    assert_eq!(st, 403);
    // Anonymous writes and non-allowlisted reads never reach the core with an identity.
    let (st, _) = s.send("PUT", &format!("/_matrix/client/v3/rooms/{chan}/send/m.room.message/a2"), None, Some(json!({"msgtype":"m.text","body":"x"}))).await;
    assert_eq!(st, 401);
    let (st, _) = s.send("GET", "/_matrix/client/v3/sync", None, None).await;
    assert_eq!(st, 401);
    let (st, _) = s.send("GET", "/_matrix/client/v3/account/whoami", None, None).await;
    assert_eq!(st, 401);
    // The core refuses the marker itself outside the allowlist, even from a holder of the link token.
    let r = s.c.get(format!("{}/_matrix/client/v3/account/whoami", s.edge)).header("x-m4a-link-token", LINK).header("x-m4a-anon-read", "1").send().await.unwrap();
    assert_eq!(r.status().as_u16(), 401);
    // A user's token is not downgraded: an authenticated read still sees its own membership.
    let (st, b) = s.send("GET", &format!("/_matrix/client/v3/rooms/{closed}/messages?dir=b"), Some(&tok), None).await;
    assert_eq!(st, 200, "{b}");
}

#[tokio::test]
async fn startup_reconcile_applies_revocations_and_deletions_the_messenger_never_heard_of() {
    let s = stack().await;
    let (a_nick, a_tok) = s.register().await;
    let (b_nick, b_tok) = s.register().await;
    for t in [&a_tok, &b_tok] {
        assert_eq!(s.send("GET", "/_matrix/client/v3/account/whoami", Some(t), None).await.0, 200);
    }
    let count = |sql: &'static str| move |c: &Connection| c.query_row::<i64, _, _>(sql, [], |r| r.get(0)).unwrap();
    assert_eq!(count("SELECT COUNT(*) FROM identities")(&s.core.conn.lock().unwrap()), 2);
    // The product lost track of b entirely and of a's only credential, without any event having been sent.
    let snap = m4a_seam::Reconcile { id: "r1".into(), complete: true, nicks: vec![m4a_seam::LiveNick { nick: a_nick.clone(), creds: vec![] }] };
    m4a_product_kit::send_reconcile(&s.link, None, &snap, Duration::from_millis(20), 3).await.unwrap();
    s.until("b retired and a's device gone", |c| count("SELECT COUNT(*) FROM identities")(c) == 1 && count("SELECT COUNT(*) FROM devices")(c) == 0).await;
    let c = s.core.conn.lock().unwrap();
    let left: String = c.query_row("SELECT nick FROM identities", [], |r| r.get(0)).unwrap();
    assert_eq!(left, a_nick);
    assert_ne!(left, b_nick);
    drop(c);
    // A partial snapshot never retires anyone.
    let partial = m4a_seam::Reconcile { id: "r2".into(), complete: false, nicks: vec![] };
    m4a_product_kit::send_reconcile(&s.link, None, &partial, Duration::from_millis(20), 3).await.unwrap();
    assert_eq!(count("SELECT COUNT(*) FROM identities")(&s.core.conn.lock().unwrap()), 1);
    // A forged snapshot is refused.
    let forged = s.c.post(format!("{}/_matrix/account-source/v1/reconcile", s.edge)).header("x-m4a-link-token", LINK).header(m4a_seam::DEFAULT_EVENT_SIG_HEADER, "00").body("{\"id\":\"x\",\"complete\":true,\"nicks\":[]}").send().await.unwrap();
    assert_eq!(forged.status().as_u16(), 401);
}

async fn open_push(s: &Stack, tok: &str) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = format!("{}/client/v3/push", s.product.replacen("http", "ws", 1)).into_client_request().unwrap();
    req.headers_mut().insert("authorization", format!("Bearer {tok}").parse().unwrap());
    let (mut sock, _) = tokio_tungstenite::connect_async(req).await.expect("handshake");
    let first = tokio::time::timeout(Duration::from_secs(5), sock.next()).await.expect("registered").unwrap().unwrap();
    assert!(first.into_text().unwrap().contains("registered"));
    sock
}

/// The socket must end (close frame, error or EOF) soon after the event is applied.
async fn assert_closes(sock: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>) {
    use futures_util::StreamExt;
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match sock.next().await {
                None | Some(Err(_)) | Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "push socket stayed open");
}

#[tokio::test]
async fn push_sockets_close_when_the_credential_is_revoked_or_the_account_deleted_or_reconcile_removes_it() {
    let s = stack().await;
    // Logout revokes the credential: that user's socket ends; another user's stays up.
    let (_, a_tok) = s.register().await;
    let (b_nick, b_tok) = s.register().await;
    let mut a = open_push(&s, &a_tok).await;
    let mut b = open_push(&s, &b_tok).await;
    assert_eq!(s.send("POST", "/product/v1/logout", Some(&a_tok), None).await.0, 200);
    assert_closes(&mut a).await;
    // Admin delete: the account's socket ends.
    let (st, _) = s.send("POST", "/product/v1/admin/delete", Some(ADMIN), Some(json!({"nick": b_nick}))).await;
    assert_eq!(st, 200);
    assert_closes(&mut b).await;
    // Reconcile removal: the product forgot the credential without any event.
    let (c_nick, c_tok) = s.register().await;
    let mut c = open_push(&s, &c_tok).await;
    let snap = m4a_seam::Reconcile { id: "rp".into(), complete: false, nicks: vec![m4a_seam::LiveNick { nick: c_nick, creds: vec![] }] };
    m4a_product_kit::send_reconcile(&s.link, None, &snap, Duration::from_millis(20), 3).await.unwrap();
    assert_closes(&mut c).await;
}
