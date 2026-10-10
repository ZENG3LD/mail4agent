//! Two real server processes with different server names (`a.example`,
//! `b.example`) federate over loopback HTTP: public room join and posts,
//! cross-server DM invite, key query/claim, to-device, both directions.
//! The two servers find each other through the staging override map; no DNS.
//! Opaque blobs stand in for Olm ciphertext: clients' key exchange is
//! unchanged and runs on top of exactly these routes.

#[path = "support_product.rs"]
mod support_product;

use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mail4agent_server::federation::enc;
use reqwest::blocking::Client;
use serde_json::{json, Value};

struct Srv {
    name: &'static str,
    addr: String,
    token: String,
    /// Product server in front of this core; clients talk to it.
    purl: String,
    device: String,
    user: String,
    dir: PathBuf,
    child: Option<Child>,
}

impl Drop for Srv {
    fn drop(&mut self) {
        if let Some(c) = self.child.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn key_hex() -> String {
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut b).unwrap();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Srv {
    fn call(&self, c: &Client, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let url = format!("{}{}", self.purl, path);
        let mut r = c.request(method.parse().unwrap(), url).bearer_auth(&self.token);
        if let Some(b) = body {
            r = r.json(&b);
        }
        let resp = r.send().unwrap();
        (resp.status().as_u16(), resp.json().unwrap_or(Value::Null))
    }
}

fn poll<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let t = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(t.elapsed() < Duration::from_secs(25), "timed out waiting for: {what}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn bodies(a: &Srv, c: &Client, room: &str) -> Vec<String> {
    let (_, v) = a.call(c, "GET", &format!("/client/v3/rooms/{}/messages?dir=b&limit=50", enc(room)), None);
    v["chunk"].as_array().cloned().unwrap_or_default().iter().filter_map(|e| e["content"]["body"].as_str().or_else(|| e["content"]["ciphertext"].as_str()).map(str::to_string)).collect()
}

fn send(a: &Srv, c: &Client, room: &str, ty: &str, txn: &str, content: Value) -> Value {
    let (st, v) = a.call(c, "PUT", &format!("/client/v3/rooms/{}/send/{}/{}", enc(room), ty, txn), Some(content));
    assert_eq!(st, 200, "send {txn}: {v}");
    v
}

#[test]
fn two_servers_federate_public_room_dm_keys_and_to_device() {
    // Each server needs the other's port for the staging override map, so reserve both first.
    let (ra, rb) = (free_port(), free_port());
    let a = start_with_ports("a.example", "alice", ra, ("b.example", rb));
    let b = start_with_ports("b.example", "bob", rb, ("a.example", ra));
    let c = Client::builder().timeout(Duration::from_secs(10)).build().unwrap();

    // F0 over the wire.
    let (st, kd) = a.call(&c, "GET", "/_matrix/key/v2/server", None);
    assert_eq!((st, kd["server_name"].as_str()), (200, Some("a.example")));
    // Unsigned federation call is refused.
    let unsigned = c.put(format!("http://{}/_matrix/federation/v1/send/x", b.addr)).json(&json!({"origin":"a.example","pdus":[]})).send().unwrap();
    assert_eq!(unsigned.status().as_u16(), 401);

    // ---- public room: join, history, posts both ways
    let (st, v) = a.call(&c, "POST", "/client/v3/createRoom", Some(json!({"visibility":"public","name":"town"})));
    assert_eq!(st, 200, "{v}");
    let town = v["room_id"].as_str().unwrap().to_string();
    send(&a, &c, &town, "m.room.message", "e1", json!({"msgtype":"m.text","body":"early from a"}));
    let (st, v) = b.call(&c, "POST", &format!("/client/v3/rooms/{}/join", enc(&town)), Some(json!({})));
    assert_eq!(st, 200, "federated join: {v}");
    let (_, joined) = b.call(&c, "GET", "/client/v3/joined_rooms", None);
    assert!(joined["joined_rooms"].as_array().unwrap().iter().any(|r| r == &json!(town)), "bob joined on b");
    let hist = bodies(&b, &c, &town);
    assert!(hist.iter().any(|x| x == "early from a"), "history delivered with the join: {hist:?}");
    send(&a, &c, &town, "m.room.message", "e2", json!({"msgtype":"m.text","body":"hello from a"}));
    poll("b sees a's post", || bodies(&b, &c, &town).iter().any(|x| x == "hello from a").then_some(()));
    // Channels are read-only below level 50: alice promotes bob (a state event that must replicate to b).
    let pl_path = format!("/client/v3/rooms/{}/state/m.room.power_levels", enc(&town));
    let (_, mut pl) = a.call(&c, "GET", &pl_path, None);
    pl["users"][&b.user] = json!(50);
    assert_eq!(a.call(&c, "PUT", &pl_path, Some(pl)).0, 200);
    poll("b sees the new power levels", || (b.call(&c, "GET", &pl_path, None).1["users"][&b.user] == json!(50)).then_some(()));
    send(&b, &c, &town, "m.room.message", "e3", json!({"msgtype":"m.text","body":"hello from b"}));
    poll("a sees b's post", || bodies(&a, &c, &town).iter().any(|x| x == "hello from b").then_some(()));
    let (_, members) = a.call(&c, "GET", &format!("/client/v3/rooms/{}/joined_members", enc(&town)), None);
    assert!(members["joined"].get(&b.user).is_some(), "a lists bob as a member: {members}");

    // ---- DM across servers
    let (st, v) = a.call(&c, "POST", "/client/v3/createRoom", Some(json!({"is_direct":true,"invite":[b.user],"visibility":"private"})));
    assert_eq!(st, 200, "dm create: {v}");
    let dm = v["room_id"].as_str().unwrap().to_string();
    poll("bob has the invite", || {
        let (_, s) = b.call(&c, "GET", "/client/v3/sync?timeout=0", None);
        s["rooms"]["invite"].get(&dm).map(|_| ())
    });
    let (st, v) = b.call(&c, "POST", &format!("/client/v3/rooms/{}/join", enc(&dm)), Some(json!({})));
    assert_eq!(st, 200, "bob joins dm: {v}");
    poll("alice sees bob joined", || {
        let (_, m) = a.call(&c, "GET", &format!("/client/v3/rooms/{}/joined_members", enc(&dm)), None);
        m["joined"].get(&b.user).map(|_| ())
    });

    // ---- keys across servers (clients' key exchange is unchanged on top of this)
    let dev = |s: &Srv, curve: &str| {
        json!({"device_keys":{"user_id":s.user,"device_id":s.device,"algorithms":["m.olm.v1.curve25519-aes-sha2"],
            "keys":{format!("curve25519:{}",s.device):curve, format!("ed25519:{}",s.device):format!("ed-{curve}")},
            "signatures":{s.user.clone():{format!("ed25519:{}",s.device):"sig"}}},
          "one_time_keys":{"signed_curve25519:AAAAAA":{"key":format!("otk-{curve}"),"signatures":{}}}})
    };
    assert_eq!(a.call(&c, "POST", "/client/v3/keys/upload", Some(dev(&a, "curveA"))).0, 200);
    assert_eq!(b.call(&c, "POST", "/client/v3/keys/upload", Some(dev(&b, "curveB"))).0, 200);
    let (st, q) = b.call(&c, "POST", "/client/v3/keys/query", Some(json!({"device_keys":{a.user.clone():[]}})));
    assert_eq!(st, 200);
    assert_eq!(q["device_keys"][&a.user][&a.device]["keys"][format!("curve25519:{}", a.device)], "curveA", "bob queried alice's keys through federation: {q}");
    let (_, cl) = b.call(&c, "POST", "/client/v3/keys/claim", Some(json!({"one_time_keys":{a.user.clone():{a.device.clone():"signed_curve25519"}}})));
    assert_eq!(cl["one_time_keys"][&a.user][&a.device]["signed_curve25519:AAAAAA"]["key"], "otk-curveA", "claim across servers: {cl}");
    let (_, q2) = a.call(&c, "POST", "/client/v3/keys/query", Some(json!({"device_keys":{b.user.clone():[]}})));
    assert_eq!(q2["device_keys"][&b.user][&b.device]["keys"][format!("curve25519:{}", b.device)], "curveB", "reverse direction: {q2}");
    let (_, cl2) = a.call(&c, "POST", "/client/v3/keys/claim", Some(json!({"one_time_keys":{b.user.clone():{b.device.clone():"signed_curve25519"}}})));
    assert_eq!(cl2["one_time_keys"][&b.user][&b.device]["signed_curve25519:AAAAAA"]["key"], "otk-curveB");
    // a stranger who shares no room is not visible
    let (_, none) = b.call(&c, "POST", "/client/v3/keys/query", Some(json!({"device_keys":{"@ghost:a.example":[]}})));
    assert!(none["device_keys"].get("@ghost:a.example").is_none() || none["device_keys"]["@ghost:a.example"] == json!({}));

    // ---- E2E DM payloads (opaque ciphertext) both ways
    let ct = |tag: &str| json!({"algorithm":"m.olm.v1.curve25519-aes-sha2","sender_key":"k","ciphertext":format!("ct-{tag}")});
    send(&a, &c, &dm, "m.room.encrypted", "d1", ct("a-to-b"));
    poll("bob receives alice's ciphertext", || bodies(&b, &c, &dm).iter().any(|x| x == "ct-a-to-b").then_some(()));
    send(&b, &c, &dm, "m.room.encrypted", "d2", ct("b-to-a"));
    poll("alice receives bob's ciphertext", || bodies(&a, &c, &dm).iter().any(|x| x == "ct-b-to-a").then_some(()));

    // ---- to-device across servers
    let (st, _) = b.call(&c, "PUT", "/client/v3/sendToDevice/m.room.encrypted/t1", Some(json!({"messages":{a.user.clone():{a.device.clone():{"algorithm":"m.olm.v1.curve25519-aes-sha2","ciphertext":"td-b-to-a"}}}})));
    assert_eq!(st, 200);
    poll("alice gets the to-device message", || {
        let (_, s) = a.call(&c, "GET", "/client/v3/sync?timeout=0", None);
        s["to_device"]["events"].as_array().and_then(|e| e.iter().find(|x| x["content"]["ciphertext"] == "td-b-to-a").map(|_| ()))
    });
    let _ = (a.name, b.name);
}

/// Event ids of one room as one server lists them (newest first).
fn event_ids(a: &Srv, c: &Client, room: &str) -> Vec<String> {
    let (_, v) = a.call(c, "GET", &format!("/client/v3/rooms/{}/messages?dir=b&limit=100", enc(room)), None);
    v["chunk"].as_array().cloned().unwrap_or_default().iter().filter_map(|e| e["event_id"].as_str().map(str::to_string)).collect()
}

fn is_hash_id(id: &str) -> bool {
    id.len() == 44 && id.starts_with('$') && !id.contains(['+', '/', '='])
}

/// Closed rooms are DAG rooms when the feature is on: every event of the room, on both servers,
/// carries the same reference-hash id; the public channel stays legacy; m4a-fed-1 carries both.
#[cfg(feature = "f3-hash-ids")]
#[test]
fn two_servers_federate_f3_closed_rooms_and_keep_public_rooms_legacy() {
    let (ra, rb) = (free_port(), free_port());
    let a = start_with_ports("a.example", "alice", ra, ("b.example", rb));
    let b = start_with_ports("b.example", "bob", rb, ("a.example", ra));
    let c = Client::builder().timeout(Duration::from_secs(10)).build().unwrap();
    let ct = |tag: &str| json!({"algorithm":"m.megolm.v1.aes-sha2","sender_key":"k","session_id":"s","device_id":"D","ciphertext":format!("ct-{tag}")});

    // A closed group: invite across servers, join, messages both ways.
    let (st, v) = a.call(&c, "POST", "/client/v3/createRoom", Some(json!({"visibility":"private","name":"closed","invite":[b.user]})));
    assert_eq!(st, 200, "create: {v}");
    let room = v["room_id"].as_str().unwrap().to_string();
    poll("bob has the invite", || b.call(&c, "GET", "/client/v3/sync?timeout=0", None).1["rooms"]["invite"].get(&room).map(|_| ()));
    let (st, v) = b.call(&c, "POST", &format!("/client/v3/rooms/{}/join", enc(&room)), Some(json!({})));
    assert_eq!(st, 200, "bob joins the f3 room: {v}");
    poll("alice sees bob joined", || a.call(&c, "GET", &format!("/client/v3/rooms/{}/joined_members", enc(&room)), None).1["joined"].get(&b.user).map(|_| ()));

    let m1 = send(&a, &c, &room, "m.room.encrypted", "m1", ct("a1"))["event_id"].as_str().unwrap().to_string();
    assert!(is_hash_id(&m1), "sender gets the computed id back: {m1}");
    poll("bob receives alice's message", || bodies(&b, &c, &room).iter().any(|x| x == "ct-a1").then_some(()));
    let m2 = send(&b, &c, &room, "m.room.encrypted", "m2", ct("b1"))["event_id"].as_str().unwrap().to_string();
    assert!(is_hash_id(&m2), "{m2}");
    poll("alice receives bob's message", || bodies(&a, &c, &room).iter().any(|x| x == "ct-b1").then_some(()));

    // Both servers hold the same events under the same ids.
    let (ea, eb) = (event_ids(&a, &c, &room), event_ids(&b, &c, &room));
    for id in [&m1, &m2] {
        assert!(ea.contains(id) && eb.contains(id), "{id} is on both servers: a={ea:?} b={eb:?}");
    }
    assert!(ea.iter().all(|i| is_hash_id(i)), "every event of the room on a is hash-id: {ea:?}");
    assert!(eb.iter().all(|i| is_hash_id(i)), "every event of the room on b is hash-id: {eb:?}");

    // State written on one side shows on the other: power levels (a), then a rename by bob (b), both checked by the DAG's auth rules.
    let pl_path = format!("/client/v3/rooms/{}/state/m.room.power_levels", enc(&room));
    let (_, mut pl) = a.call(&c, "GET", &pl_path, None);
    pl["users"][&b.user] = json!(50);
    assert_eq!(a.call(&c, "PUT", &pl_path, Some(pl)).0, 200);
    poll("b sees the new power levels", || (b.call(&c, "GET", &pl_path, None).1["users"][&b.user] == json!(50)).then_some(()));
    let name_path = format!("/client/v3/rooms/{}/state/m.room.name", enc(&room));
    let (st, _) = b.call(&c, "PUT", &name_path, Some(json!({"name":"renamed by bob"})));
    assert_eq!(st, 200);
    poll("a sees bob's rename", || (a.call(&c, "GET", &name_path, None).1["name"] == json!("renamed by bob")).then_some(()));

    // Bob leaves; alice sees it.
    assert_eq!(b.call(&c, "POST", &format!("/client/v3/rooms/{}/leave", enc(&room)), Some(json!({}))).0, 200);
    poll("alice sees bob left", || a.call(&c, "GET", &format!("/client/v3/rooms/{}/joined_members", enc(&room)), None).1["joined"].get(&b.user).is_none().then_some(()));

    // A public channel is not part of the layer: it still federates with legacy ids (the m4a-fed-1 test above covers its flow).
    let (_, v) = a.call(&c, "POST", "/client/v3/createRoom", Some(json!({"visibility":"public","name":"town"})));
    let town = v["room_id"].as_str().unwrap().to_string();
    let e = send(&a, &c, &town, "m.room.message", "p1", json!({"msgtype":"m.text","body":"public"}))["event_id"].as_str().unwrap().to_string();
    assert!(!is_hash_id(&e), "public channel keeps legacy ids: {e}");
    let (st, _) = b.call(&c, "POST", &format!("/client/v3/rooms/{}/join", enc(&town)), Some(json!({})));
    assert_eq!(st, 200);
    poll("bob sees the public post", || bodies(&b, &c, &town).iter().any(|x| x == "public").then_some(()));
}

fn start_with_ports(name: &'static str, localpart: &str, port: u16, peer: (&str, u16)) -> Srv {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = PathBuf::from(format!("/tmp/m4a-fed-{}-{}-{}", name, std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)));
    let key = key_hex();
    std::fs::create_dir_all(&dir).unwrap();
    let addr = format!("127.0.0.1:{port}");
    let exe = std::env::var("CARGO_BIN_EXE_mail4agent_server_bin").or_else(|_| std::env::var("CARGO_BIN_EXE_mail4agent-server-bin")).expect("bin");
    let child = Command::new(exe)
        .args(["--bind", &addr, "--db", dir.join("messenger.db").to_str().unwrap(), "--server-name", name])
        .env("M4A_DB_KEY_HEX", &key)
        .env("M4A_FEDERATION", "1")
        .env("M4A_FEDERATION_PEER_OVERRIDE", format!("{}=http://127.0.0.1:{}", peer.0, peer.1))
        .env("M4A_ASSERTION_SECRET", support_product::SEAM_SECRET)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let t = Instant::now();
    while TcpStream::connect(&addr).is_err() {
        assert!(t.elapsed() < Duration::from_secs(20), "server {name} did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    // The product server in front of this core; the user's first call is its first contact.
    let product = support_product::start_product(&format!("http://{addr}"));
    let token = support_product::product_user(&product, localpart);
    let who: Value = Client::new().get(format!("{}/client/v3/account/whoami", product.url)).bearer_auth(&token).send().unwrap().json().unwrap();
    let (user, device) = (who["user_id"].as_str().unwrap().to_string(), who["device_id"].as_str().unwrap().to_string());
    assert_eq!(user, format!("@{localpart}:{name}"));
    Srv { name, addr, token, purl: product.url, device, user, dir, child: Some(child) }
}
