//! Interop with a real Synapse: key discovery, Synapse verifying our signed events, and a
//! Synapse user joining and talking in one of our public DAG rooms.
//!
//! Needs a Synapse install, named by `M4A_SYNAPSE_PYTHON` (the python of a venv with
//! `matrix-synapse`) and the `openssl` command; without them the test says so and passes.
//! Everything runs on localhost: Synapse listens in plain HTTP (our side reaches it through the
//! peer override), and a small TLS hop in front of our server stands in for the HTTPS Synapse
//! insists on. The server names are `localhost:<port>`.
#![cfg(feature = "f3-hash-ids")]

#[path = "support_product.rs"]
mod support_product;
#[path = "support/fed.rs"]
mod support_fed;

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use mail4agent_server::federation::enc;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use support_fed::{free_port, poll, start_node};

/// Synapse is heavy to start: the tests of this file take turns.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Terminates TLS for our server: a hop is all Synapse needs to reach plain HTTP.
const TLS_HOP: &str = r#"
import socket, ssl, sys, threading
cert, key, lp, tp = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", lp))
s.listen(64)
def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except Exception:
        pass
    for x in (a, b):
        try:
            x.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
def serve(c):
    try:
        t = ctx.wrap_socket(c, server_side=True)
        u = socket.create_connection(("127.0.0.1", tp))
    except Exception:
        c.close()
        return
    threading.Thread(target=pipe, args=(t, u), daemon=True).start()
    pipe(u, t)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
"#;

struct Procs(Vec<Child>, PathBuf);
impl Drop for Procs {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn wait_http(url: &str) {
    let c = Client::builder().danger_accept_invalid_certs(true).timeout(Duration::from_secs(3)).build().unwrap();
    poll(url, || c.get(url).send().ok().filter(|r| r.status().is_success()).map(|_| ()));
}

struct Env {
    _procs: Procs,
    dir: PathBuf,
    ours: support_fed::Srv,
    plain: Client,
    any_cert: Client,
    syn_port: u16,
    tls_port: u16,
    syn_name: String,
    our_name: &'static str,
    tok: String,
}

impl Env {
    fn syn(&self, m: &str, p: &str, b: Option<Value>) -> (u16, Value) {
        let url = format!("http://127.0.0.1:{}/_matrix/client/v3{p}", self.syn_port);
        let mut r = match m { "GET" => self.plain.get(url), "PUT" => self.plain.put(url), _ => self.plain.post(url) }.bearer_auth(&self.tok);
        if let Some(b) = b {
            r = r.json(&b);
        }
        let resp = r.send().unwrap();
        (resp.status().as_u16(), resp.json().unwrap_or(Value::Null))
    }
    fn log_tail(&self) -> String {
        std::fs::read_to_string(self.dir.join("syn.log")).unwrap_or_default().lines().rev().take(15).collect::<Vec<_>>().join("\n")
    }
}

/// Synapse plus our server, wired together on localhost; `None` when Synapse is not available.
fn setup() -> Option<Env> {
    let Ok(py) = std::env::var("M4A_SYNAPSE_PYTHON") else {
        eprintln!("skipped: M4A_SYNAPSE_PYTHON is not set");
        return None;
    };
    let dir = PathBuf::from(format!("/tmp/m4a-synapse-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut procs = Procs(vec![], dir.clone());
    let d = |f: &str| dir.join(f).to_str().unwrap().to_string();

    let (syn_port, tls_port, bind_port) = (free_port(), free_port(), free_port());
    let syn_name = format!("localhost:{syn_port}");
    let our_name: &'static str = Box::leak(format!("localhost:{tls_port}").into_boxed_str());

    // Synapse: plain-HTTP listener, no certificate checks, loopback allowed, no rate limits.
    std::fs::write(d("log.yaml"), "version: 1\nformatters:\n  p:\n    format: '%(levelname)s %(name)s %(message)s'\nhandlers:\n  c:\n    class: logging.FileHandler\n    filename: ".to_string() + &d("syn.log") + "\n    formatter: p\nroot:\n  level: INFO\n  handlers: [c]\ndisable_existing_loggers: false\n").unwrap();
    std::fs::write(
        d("hs.yaml"),
        format!(
            "server_name: \"{syn_name}\"\npid_file: {pid}\nlisteners:\n  - port: {syn_port}\n    bind_addresses: ['127.0.0.1']\n    type: http\n    tls: false\n    resources:\n      - names: [client, federation]\ndatabase:\n  name: sqlite3\n  args:\n    database: {db}\nlog_config: {log}\nmedia_store_path: {media}\nsigning_key_path: {key}\nregistration_shared_secret: interop-secret\nreport_stats: false\ntrusted_key_servers: []\nsuppress_key_server_warning: true\nfederation_verify_certificates: false\nfederation_ip_range_blacklist: []\nip_range_blacklist: []\nallow_public_rooms_over_federation: true\nrc_message: {{per_second: 1000, burst_count: 1000}}\nrc_joins:\n  local: {{per_second: 1000, burst_count: 1000}}\n  remote: {{per_second: 1000, burst_count: 1000}}\nrc_federation: {{window_size: 1000, sleep_limit: 1000, sleep_delay: 1, reject_limit: 1000, concurrent: 1000}}\n",
            pid = d("syn.pid"), db = d("syn.db"), log = d("log.yaml"), media = d("media"), key = d("syn.key")
        ),
    )
    .unwrap();
    let gen = Command::new(&py).args(["-m", "synapse.app.homeserver", "-c", &d("hs.yaml"), "--generate-keys"]).output().unwrap();
    assert!(gen.status.success(), "synapse keys: {}", String::from_utf8_lossy(&gen.stderr));
    procs.0.push(Command::new(&py).args(["-m", "synapse.app.homeserver", "-c", &d("hs.yaml")]).stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().unwrap());
    wait_http(&format!("http://127.0.0.1:{syn_port}/_matrix/client/versions"));
    let reg = Command::new(&py).args(["-m", "synapse._scripts.register_new_matrix_user", "-c", &d("hs.yaml"), "-u", "syn", "-p", "pw-interop-1", "--no-admin", &format!("http://127.0.0.1:{syn_port}")]).output().unwrap();
    assert!(reg.status.success(), "register: {}{}", String::from_utf8_lossy(&reg.stdout), String::from_utf8_lossy(&reg.stderr));

    // Our server, reachable as `localhost:<tls_port>` through the TLS hop.
    let cert = Command::new("openssl").args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", &d("k.pem"), "-out", &d("c.pem"), "-subj", "/CN=localhost", "-days", "1"]).output().unwrap();
    assert!(cert.status.success(), "openssl");
    procs.0.push(Command::new(&py).args(["-c", TLS_HOP, &d("c.pem"), &d("k.pem"), &tls_port.to_string(), &bind_port.to_string()]).spawn().unwrap());
    let ours = start_node(our_name, "alice", bind_port, &[(&syn_name, syn_port)]);
    wait_http(&format!("https://127.0.0.1:{tls_port}/_matrix/key/v2/server"));


    let any_cert = Client::builder().danger_accept_invalid_certs(true).timeout(Duration::from_secs(10)).build().unwrap();
    let plain = Client::builder().timeout(Duration::from_secs(10)).build().unwrap();
    let login: Value = plain.post(format!("http://127.0.0.1:{syn_port}/_matrix/client/v3/login")).json(&json!({"type":"m.login.password","identifier":{"type":"m.id.user","user":"syn"},"password":"pw-interop-1"})).send().unwrap().json().unwrap();
    let tok = login["access_token"].as_str().unwrap().to_string();
    Some(Env { _procs: procs, dir, ours, plain, any_cert, syn_port, tls_port, syn_name, our_name, tok })
}

#[test]
fn synapse_verifies_our_keys_and_events_and_a_synapse_user_joins_a_public_dag_room() {
    let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(env) = setup() else { return };
    let Env { ours, plain, any_cert, syn_port, tls_port, syn_name, our_name, .. } = &env;
    let (syn_port, tls_port, our_name) = (*syn_port, *tls_port, *our_name);
    // Key discovery in both directions.
    let our_keys: Value = any_cert.get(format!("https://127.0.0.1:{tls_port}/_matrix/key/v2/server")).send().unwrap().json().unwrap();
    assert_eq!(our_keys["server_name"], our_name);
    assert!(our_keys["verify_keys"].as_object().is_some_and(|k| !k.is_empty()) && our_keys["signatures"][our_name].is_object());
    let syn_keys: Value = plain.get(format!("http://127.0.0.1:{syn_port}/_matrix/key/v2/server")).send().unwrap().json().unwrap();
    assert_eq!(syn_keys["server_name"], syn_name.as_str());

    // Our public DAG room, and Synapse's user in it.
    let (st, v) = ours.call(plain, "POST", "/client/v3/createRoom", Some(json!({"visibility":"private","name":"open house"})));
    assert_eq!(st, 200, "{v}");
    let room = v["room_id"].as_str().unwrap().to_string();
    let (st, v) = ours.call(plain, "PUT", &format!("/client/v3/rooms/{}/state/m.room.join_rules", enc(&room)), Some(json!({"join_rule":"public"})));
    assert_eq!(st, 200, "join rules: {v}");
    let (st, v) = env.syn("POST", &format!("/join/{}?server_name={}", enc(&room), enc(our_name)), Some(json!({})));
    assert_eq!(st, 200, "synapse joins our room: {v}\n{}", env.log_tail());

    // Our events reach Synapse and pass its signature and hash checks, under our ids.
    let (st, v) = ours.call(plain, "PUT", &format!("/client/v3/rooms/{}/send/m.room.encrypted/t1", enc(&room)), Some(json!({"algorithm":"m.megolm.v1.aes-sha2","sender_key":"k","session_id":"s","device_id":"D","ciphertext":"hello-from-us"})));
    assert_eq!(st, 200, "send: {v}");
    let ours_id = v["event_id"].as_str().unwrap().to_string();
    assert!(ours_id.starts_with('$') && ours_id.len() == 44, "reference-hash id: {ours_id}");
    poll("synapse has our message", || {
        let (_, m) = env.syn("GET", &format!("/rooms/{}/messages?dir=b&limit=20", enc(&room)), None);
        m["chunk"].as_array()?.iter().find(|e| e["event_id"] == ours_id.as_str() && e["content"]["ciphertext"] == "hello-from-us").map(|_| ())
    });

    // And Synapse's events reach us.
    let (st, v) = env.syn("PUT", &format!("/rooms/{}/send/m.room.encrypted/s1", enc(&room)), Some(json!({"algorithm":"m.megolm.v1.aes-sha2","sender_key":"k2","session_id":"s2","device_id":"E","ciphertext":"hello-from-synapse"})));
    assert_eq!(st, 200, "synapse send: {v}");
    let syn_id = v["event_id"].as_str().unwrap().to_string();
    poll("we have synapse's message", || {
        let (_, m) = ours.call(plain, "GET", &format!("/client/v3/rooms/{}/messages?dir=b&limit=20", enc(&room)), None);
        m["chunk"].as_array()?.iter().find(|e| e["event_id"] == syn_id.as_str()).map(|_| ())
    });
}

/// Our user joins a public room that lives on Synapse (room version 11), over federation: their
/// make_join template, our signature, their send_join answer verified in full, then messages both ways.
#[test]
fn our_user_joins_a_public_room_on_synapse_and_talks() {
    let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(env) = setup() else { return };
    let (ours, plain) = (&env.ours, &env.plain);
    let (st, v) = env.syn("POST", "/createRoom", Some(json!({"preset":"public_chat","name":"synapse side","room_version":"11"})));
    assert_eq!(st, 200, "{v}");
    let room = v["room_id"].as_str().unwrap().to_string();
    let (st, _) = env.syn("PUT", &format!("/rooms/{}/send/m.room.message/old1", enc(&room)), Some(json!({"msgtype":"m.text","body":"before you came"})));
    assert_eq!(st, 200);

    let (st, v) = ours.call(plain, "POST", &format!("/client/v3/join/{}", enc(&room)), Some(json!({})));
    assert_eq!(st, 200, "we join: {v}\n{}", env.log_tail());
    let (_, members) = env.syn("GET", &format!("/rooms/{}/joined_members", enc(&room)), None);
    assert!(members["joined"].get(&ours.user).is_some(), "synapse lists our user as joined: {members}");

    // Both ways, under the hash ids.
    let (st, v) = ours.call(plain, "PUT", &format!("/client/v3/rooms/{}/send/m.room.message/o1", enc(&room)), Some(json!({"msgtype":"m.text","body":"from us"})));
    assert_eq!(st, 200, "send: {v}");
    let our_id = v["event_id"].as_str().unwrap().to_string();
    poll("synapse has our message", || {
        let (_, m) = env.syn("GET", &format!("/rooms/{}/messages?dir=b&limit=20", enc(&room)), None);
        m["chunk"].as_array()?.iter().find(|e| e["event_id"] == our_id.as_str() && e["content"]["body"] == "from us").map(|_| ())
    });
    let (st, v) = env.syn("PUT", &format!("/rooms/{}/send/m.room.message/s1", enc(&room)), Some(json!({"msgtype":"m.text","body":"from synapse"})));
    assert_eq!(st, 200, "{v}");
    let syn_id = v["event_id"].as_str().unwrap().to_string();
    poll("we have synapse's message and the earlier history", || {
        let (_, m) = ours.call(plain, "GET", &format!("/client/v3/rooms/{}/messages?dir=b&limit=50", enc(&room)), None);
        let chunk = m["chunk"].as_array()?;
        let has = |id: &str| chunk.iter().any(|e| e["event_id"] == id);
        (has(&syn_id) && chunk.iter().any(|e| e["content"]["body"] == "before you came")).then_some(())
    });
}

#[test]
fn synapse_invites_our_user_to_a_closed_room_and_keys_device_lists_and_directories_work() {
    let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(env) = setup() else { return };
    let Env { ours, plain, syn_name, our_name, .. } = &env;
    let our_name = *our_name;
    let (alice, syn_user) = (ours.user.clone(), format!("@syn:{syn_name}"));
    let (_, who) = env.syn("GET", "/account/whoami", None);
    let syn_dev = who["device_id"].as_str().unwrap().to_string();
    let dev_keys = |user: &str, dev: &str, tag: &str| {
        json!({"user_id": user, "device_id": dev, "algorithms": ["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],
               "keys": {format!("curve25519:{dev}"): format!("c-{tag}"), format!("ed25519:{dev}"): format!("e-{tag}")},
               "signatures": {user: {format!("ed25519:{dev}"): "c2ln"}}})
    };

    // Both sides publish device keys and a one-time key.
    let (st, v) = ours.call(plain, "POST", "/client/v3/keys/upload", Some(json!({"device_keys": dev_keys(&alice, &ours.device, "a1"), "one_time_keys": {"signed_curve25519:AAAAAA": {"key": "otk-alice", "signatures": {&alice: {format!("ed25519:{}", ours.device): "c2ln"}}}}})));
    assert_eq!(st, 200, "our upload: {v}");
    let (st, v) = env.syn("POST", "/keys/upload", Some(json!({"device_keys": dev_keys(&syn_user, &syn_dev, "s1"), "one_time_keys": {"signed_curve25519:AAAAAA": {"key": "otk-syn", "signatures": {&syn_user: {format!("ed25519:{syn_dev}"): "c2ln"}}}}})));
    assert_eq!(st, 200, "synapse upload: {v}");

    // A closed, encrypted room on Synapse; our user is invited and sees it with its stripped state.
    let (st, v) = env.syn("POST", "/createRoom", Some(json!({"preset":"private_chat","name":"secret","room_version":"11","invite":[alice],"initial_state":[{"type":"m.room.encryption","state_key":"","content":{"algorithm":"m.megolm.v1.aes-sha2"}}]})));
    assert_eq!(st, 200, "synapse createRoom: {v}\n{}", env.log_tail());
    let room = v["room_id"].as_str().unwrap().to_string();
    let inv = poll("we have the invite", || ours.call(plain, "GET", "/client/v3/sync?timeout=0", None).1["rooms"]["invite"].get(&room).cloned());
    let evs = inv["invite_state"]["events"].as_array().unwrap();
    assert!(evs.iter().any(|e| e["type"] == "m.room.name" && e["content"]["name"] == "secret"), "stripped state shows the name: {inv}");
    let (st, v) = ours.call(plain, "POST", &format!("/client/v3/join/{}", enc(&room)), Some(json!({})));
    assert_eq!(st, 200, "we accept the invite: {v}\n{}", env.log_tail());
    poll("synapse sees us joined", || {
        let (_, m) = env.syn("GET", &format!("/rooms/{}/joined_members", enc(&room)), None);
        m["joined"].get(&alice).map(|_| ())
    });

    // Messages both ways.
    let ct = |t: &str| json!({"algorithm":"m.megolm.v1.aes-sha2","sender_key":"k","session_id":"s","device_id":"D","ciphertext":t});
    let (st, v) = env.syn("PUT", &format!("/rooms/{}/send/m.room.encrypted/q1", enc(&room)), Some(ct("from-synapse")));
    assert_eq!(st, 200, "{v}");
    let sid = v["event_id"].as_str().unwrap().to_string();
    poll("we have synapse's message", || {
        let (_, m) = ours.call(plain, "GET", &format!("/client/v3/rooms/{}/messages?dir=b&limit=20", enc(&room)), None);
        m["chunk"].as_array()?.iter().find(|e| e["event_id"] == sid.as_str()).map(|_| ())
    });
    let (st, v) = ours.call(plain, "PUT", &format!("/client/v3/rooms/{}/send/m.room.encrypted/q2", enc(&room)), Some(ct("from-us")));
    assert_eq!(st, 200, "{v}\n{}", env.log_tail());
    let oid = v["event_id"].as_str().unwrap().to_string();
    poll("synapse has our message", || {
        let (_, m) = env.syn("GET", &format!("/rooms/{}/messages?dir=b&limit=20", enc(&room)), None);
        m["chunk"].as_array()?.iter().find(|e| e["event_id"] == oid.as_str()).map(|_| ())
    });

    // E2E: we query and claim Synapse's user's keys; Synapse queries and claims ours.
    let (st, q) = ours.call(plain, "POST", "/client/v3/keys/query", Some(json!({"device_keys": {&syn_user: []}})));
    assert_eq!(st, 200, "{q}");
    assert!(q["device_keys"][&syn_user][&syn_dev]["keys"].is_object(), "we see synapse's device: {q}");
    let (_, cl) = ours.call(plain, "POST", "/client/v3/keys/claim", Some(json!({"one_time_keys": {&syn_user: {&syn_dev: "signed_curve25519"}}})));
    assert!(cl["one_time_keys"][&syn_user][&syn_dev].is_object(), "we claim synapse's one-time key: {cl}");
    let (_, q) = env.syn("POST", "/keys/query", Some(json!({"device_keys": {&alice: []}})));
    assert!(q["device_keys"][&alice][&ours.device]["keys"].is_object(), "synapse sees our device: {q}\n{}", env.log_tail());
    let (_, cl) = env.syn("POST", "/keys/claim", Some(json!({"one_time_keys": {&alice: {&ours.device: "signed_curve25519"}}})));
    assert!(cl["one_time_keys"][&alice][&ours.device].is_object(), "synapse claims our one-time key: {cl}");

    // Device-list updates: a changed device on either side is announced to the other.
    let mut since = ours.call(plain, "GET", "/client/v3/sync?timeout=0", None).1["next_batch"].as_str().unwrap().to_string();
    let (_, s0) = env.syn("GET", "/sync?timeout=0", None);
    let mut syn_since = s0["next_batch"].as_str().unwrap().to_string();
    let (st, _) = env.syn("POST", "/keys/upload", Some(json!({"device_keys": dev_keys(&syn_user, &syn_dev, "s2")})));
    assert_eq!(st, 200);
    poll("we learn synapse's device list changed", || {
        let (_, s) = ours.call(plain, "GET", &format!("/client/v3/sync?timeout=500&since={since}"), None);
        since = s["next_batch"].as_str().unwrap().to_string();
        s["device_lists"]["changed"].as_array()?.iter().any(|u| *u == json!(syn_user)).then_some(())
    });
    let (st, _) = ours.call(plain, "POST", "/client/v3/keys/upload", Some(json!({"device_keys": dev_keys(&alice, &ours.device, "a2")})));
    assert_eq!(st, 200);
    poll("synapse learns our device list changed", || {
        let (_, s) = env.syn("GET", &format!("/sync?timeout=500&since={syn_since}"), None);
        syn_since = s["next_batch"].as_str().unwrap().to_string();
        s["device_lists"]["changed"].as_array()?.iter().any(|u| *u == json!(alice)).then_some(())
    });

    // Directories: Synapse resolves our alias, reads our profile and our public room list.
    let (_, v) = ours.call(plain, "POST", "/client/v3/createRoom", Some(json!({"visibility":"public","name":"lobby"})));
    let lobby = v["room_id"].as_str().unwrap().to_string();
    let alias = format!("#lobby:{our_name}");
    assert_eq!(ours.call(plain, "PUT", &format!("/client/v3/directory/room/{}", enc(&alias)), Some(json!({"room_id": lobby}))).0, 200);
    let (st, r) = env.syn("GET", &format!("/directory/room/{}", enc(&alias)), None);
    assert_eq!((st, r["room_id"].as_str()), (200, Some(lobby.as_str())), "synapse resolves our alias: {r}\n{}", env.log_tail());
    assert_eq!(ours.call(plain, "PUT", &format!("/client/v3/profile/{}/avatar_url", enc(&alice)), Some(json!({"avatar_url": format!("mxc://{our_name}/me")}))).0, 200);
    let (st, p) = env.syn("GET", &format!("/profile/{}", enc(&alice)), None);
    assert_eq!(st, 200, "{p}");
    assert_eq!(p["avatar_url"], format!("mxc://{our_name}/me"));
    let (st, pr) = env.syn("GET", &format!("/publicRooms?server={}", enc(our_name)), None);
    assert_eq!(st, 200, "{pr}");
    assert!(pr["chunk"].as_array().is_some_and(|c| c.iter().any(|r| r["room_id"] == lobby.as_str())), "our public rooms through synapse: {pr}");

    // Notary: we hand out our own key document, and Synapse's, counter-signed.
    let doc: Value = env.plain.post(format!("http://127.0.0.1:{}/_matrix/key/v2/query", env.ours.addr.rsplit(':').next().unwrap())).json(&json!({"server_keys": {syn_name.as_str(): {}}})).send().unwrap().json().unwrap();
    assert!(doc["server_keys"][0]["signatures"][our_name].is_object() && doc["server_keys"][0]["signatures"][syn_name.as_str()].is_object(), "notary doc: {doc}");
}

#[test]
fn media_presence_and_user_lookup_work_with_synapse() {
    let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(env) = setup() else { return };
    let Env { ours, plain, syn_name, our_name, .. } = &env;
    let our_name = *our_name;
    let (alice, syn_user) = (ours.user.clone(), format!("@syn:{syn_name}"));

    // A shared room (so presence is visible): Synapse creates it, invites us, we join.
    let (st, v) = env.syn("POST", "/createRoom", Some(json!({"preset":"private_chat","name":"shared","room_version":"11","invite":[alice]})));
    assert_eq!(st, 200, "{v}\n{}", env.log_tail());
    let room = v["room_id"].as_str().unwrap().to_string();
    poll("we have the invite", || ours.call(plain, "GET", "/client/v3/sync?timeout=0", None).1["rooms"]["invite"].get(&room).cloned());
    assert_eq!(ours.call(plain, "POST", &format!("/client/v3/join/{}", enc(&room)), Some(json!({}))).0, 200, "{}", env.log_tail());
    poll("synapse sees us joined", || env.syn("GET", &format!("/rooms/{}/joined_members", enc(&room)), None).1["joined"].get(&alice).map(|_| ()));

    // Presence, Synapse -> us: Synapse's user goes online with a status; our sync and GET show it.
    let (st, v) = env.syn("PUT", &format!("/presence/{}/status", enc(&syn_user)), Some(json!({"presence":"online","status_msg":"on synapse"})));
    assert_eq!(st, 200, "{v}");
    poll("our server learns synapse's presence", || {
        let (st, v) = ours.call(plain, "GET", &format!("/client/v3/presence/{}/status", enc(&syn_user)), None);
        (st == 200 && v["presence"] == "online" && v["status_msg"] == "on synapse").then_some(())
    });
    // Presence, us -> Synapse.
    let (st, v) = ours.call(plain, "PUT", &format!("/client/v3/presence/{}/status", enc(&alice)), Some(json!({"presence":"unavailable","status_msg":"on ours"})));
    assert_eq!(st, 200, "{v}");
    // Synapse batches incoming presence before applying it.
    std::thread::sleep(Duration::from_secs(3));
    poll("synapse learns our presence", || {
        let (st, v) = env.syn("GET", &format!("/presence/{}/status", enc(&alice)), None);
        (st == 200 && v["presence"] == "unavailable" && v["status_msg"] == "on ours").then_some(())
    });

    // Media, ours -> Synapse: Synapse's user downloads our file through Synapse (authenticated media).
    let blob: Vec<u8> = (0..20_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8).collect();
    let up = plain.post(format!("{}/media/v3/upload", ours.purl)).bearer_auth(&ours.token).header("content-type", "application/octet-stream").body(blob.clone()).send().unwrap();
    let mxc = up.json::<Value>().unwrap()["content_uri"].as_str().unwrap().to_string();
    let path = mxc.strip_prefix("mxc://").unwrap().to_string();
    poll("synapse fetches our media", || {
        let r = plain.get(format!("http://127.0.0.1:{}/_matrix/client/v1/media/download/{path}", env.syn_port)).bearer_auth(&env.tok).send().ok()?;
        (r.status().as_u16() == 200 && r.bytes().ok()?.to_vec() == blob).then_some(())
    });
    // Media, Synapse -> ours: we download Synapse's file (federation media fetch, cached).
    let sblob = b"synapse's file, as opaque bytes".to_vec();
    let up = plain.post(format!("http://127.0.0.1:{}/_matrix/media/v3/upload", env.syn_port)).bearer_auth(&env.tok).header("content-type", "application/octet-stream").body(sblob.clone()).send().unwrap();
    let smxc = up.json::<Value>().unwrap()["content_uri"].as_str().unwrap().to_string();
    let sid = smxc.rsplit('/').next().unwrap();
    for _ in 0..2 {
        let r = plain.get(format!("{}/client/v1/media/download/{syn_name}/{sid}", ours.purl)).bearer_auth(&ours.token).send().unwrap();
        assert_eq!(r.status().as_u16(), 200, "{}", env.log_tail());
        assert_eq!(r.bytes().unwrap().to_vec(), sblob);
    }

    // Federated user lookup: Synapse's user, found by full id, with the profile Synapse holds.
    let (st, v) = env.syn("PUT", &format!("/profile/{}/displayname", enc(&syn_user)), Some(json!({"displayname":"Syn Display"})));
    assert_eq!(st, 200, "{v}");
    let (st, v) = ours.call(plain, "POST", "/client/v3/user_directory/search", Some(json!({"search_term": syn_user})));
    assert_eq!(st, 200, "{v}");
    assert_eq!((v["results"][0]["user_id"].as_str(), v["results"][0]["display_name"].as_str()), (Some(syn_user.as_str()), Some("Syn Display")), "{v}");
    let _ = our_name;

    // Declining an invite: we invite Synapse's user to a closed room; Synapse refuses through
    // make_leave / send_leave on our server, and we show them as having left.
    let (st, v) = ours.call(plain, "POST", "/client/v3/createRoom", Some(json!({"visibility":"private","name":"declined","invite":[syn_user]})));
    assert_eq!(st, 200, "{v}");
    let ours_room = v["room_id"].as_str().unwrap().to_string();
    // Synapse caches identical sync requests for two minutes: vary the timeout on every try.
    let mut n = 0;
    poll("synapse has the invite", || {
        n += 1;
        env.syn("GET", &format!("/sync?timeout={n}"), None).1["rooms"]["invite"].get(&ours_room).map(|_| ())
    });
    let (st, v) = env.syn("POST", &format!("/rooms/{}/leave", enc(&ours_room)), Some(json!({})));
    assert_eq!(st, 200, "{v}\n{}", env.log_tail());
    poll("we show the invitee as left", || {
        let (_, m) = ours.call(plain, "GET", &format!("/client/v3/rooms/{}/members?membership=leave", enc(&ours_room)), None);
        m["chunk"].as_array()?.iter().any(|e| e["state_key"] == syn_user.as_str()).then_some(())
    });
}
