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
const ADMIN: &str = "admin-token-for-tests";

async fn serve(app: axum::Router) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap() });
    a
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
    core: Arc<Homeserver>,
    product: String,
    c: reqwest::Client,
}

async fn stack() -> Stack {
    let conn = Connection::open_in_memory().unwrap();
    mail4agent_server::store::create_matrix_schema(&conn).unwrap();
    mail4agent_server::keys::create_matrix_keys_schema(&conn).unwrap();
    let core = Arc::new(Homeserver::new(conn));
    let _ = core.seam.set(Arc::new(Seam::new(vec![SEAM_SECRET.to_vec()], 30, None, None)));
    let core_addr = serve(require_edge_secret(mail4agent_server::http::router(core.clone()), EDGE_SECRET.to_string())).await;
    let edge_addr = serve(m4a_edge::edge_router(m4a_edge::EdgeConfig { core_url: format!("http://{core_addr}"), secret: EDGE_SECRET.into() })).await;
    let link = EdgeLink::new(&format!("http://{edge_addr}"), SEAM_SECRET.to_vec(), None);
    let app = Arc::new(ProductApp {
        users: UserService::new(Arc::new(SqliteStore::memory().unwrap()), NickRules::default(), TierTable::default()),
        events: EventPublisher::spawn(link.clone(), None, Duration::from_millis(50)),
        link,
        admin_token: ADMIN.into(),
        doors: vec![Arc::new(FakeDoor)],
    });
    let product = format!("http://{}", serve(router(app)).await);
    Stack { core, product, c: reqwest::Client::new() }
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
