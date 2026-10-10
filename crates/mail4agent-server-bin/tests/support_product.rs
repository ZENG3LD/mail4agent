//! Test fixture: an in-process product server (example crate) in front of a
//! spawned core. Not a test target itself; included with `#[path]`.
#![allow(dead_code)]

use std::sync::{mpsc, Arc};
use std::time::Duration;

use m4a_product_example::{router, ProductApp, SqliteStore};
use m4a_product_kit::nick_rules::NickRules;
use m4a_product_kit::tiers::TierTable;
use m4a_product_kit::{EdgeLink, EventPublisher, UserService};

pub const ADMIN_TOKEN: &str = "admin-token-for-tests";
pub const SEAM_SECRET: &str = "seam-secret-0123456789abcdef";

pub struct Product {
    pub url: String,
}

/// Start the product in a background thread; it forwards to `core_url` (the spawned core).
pub fn start_product(core_url: &str) -> Product {
    let (tx, rx) = mpsc::channel();
    let core = core_url.to_string();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime");
        rt.block_on(async move {
            let link = EdgeLink::new(&core, SEAM_SECRET.as_bytes().to_vec(), None);
            let app = Arc::new(ProductApp {
                users: UserService::new(Arc::new(SqliteStore::memory().expect("db")), NickRules::default(), TierTable::default()),
                events: EventPublisher::spawn(link.clone(), None, Duration::from_millis(50)),
                link,
                admin_token: ADMIN_TOKEN.into(),
                doors: vec![],
                anon_read: false,
        tokens: Default::default(),
        access_ttl_ms: 3_600_000,
        challenges: m4a_product_kit::ChallengeBook::new("test-product"),
            });
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
            tx.send(format!("http://{}", l.local_addr().expect("addr"))).expect("send");
            axum::serve(l, router(app)).await.expect("serve");
        });
    });
    Product { url: rx.recv().expect("product url") }
}

/// Register a user at the product, give it `nick` (first change is free, before
/// messenger contact), and return its session token.
pub fn product_user(p: &Product, nick: &str) -> String {
    let c = reqwest::blocking::Client::new();
    let r: serde_json::Value = c.post(format!("{}/product/v1/register", p.url)).json(&serde_json::json!({"password":"correct horse"})).send().expect("register").json().expect("json");
    let token = r["token"].as_str().expect("token").to_string();
    let st = c.put(format!("{}/product/v1/nick", p.url)).bearer_auth(&token).json(&serde_json::json!({ "nick": nick })).send().expect("nick").status();
    assert!(st.is_success(), "set nick {nick}: {st}");
    token
}

/// The operator's one-time invite for an agent session that will be called `nick`.
pub fn product_invite(p: &Product, nick: &str) -> String {
    let r: serde_json::Value = reqwest::blocking::Client::new()
        .post(format!("{}/product/v1/admin/invite", p.url))
        .bearer_auth(ADMIN_TOKEN)
        .json(&serde_json::json!({ "nick": nick }))
        .send()
        .expect("invite")
        .json()
        .expect("json");
    r["invite"].as_str().expect("invite code").to_string()
}
