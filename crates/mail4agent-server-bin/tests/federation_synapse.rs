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

#[test]
fn synapse_verifies_our_keys_and_events_and_a_synapse_user_joins_a_public_dag_room() {
    let Ok(py) = std::env::var("M4A_SYNAPSE_PYTHON") else {
        eprintln!("skipped: M4A_SYNAPSE_PYTHON is not set");
        return;
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

    // Key discovery in both directions.
    let our_keys: Value = any_cert.get(format!("https://127.0.0.1:{tls_port}/_matrix/key/v2/server")).send().unwrap().json().unwrap();
    assert_eq!(our_keys["server_name"], our_name);
    assert!(our_keys["verify_keys"].as_object().is_some_and(|k| !k.is_empty()) && our_keys["signatures"][our_name].is_object());
    let syn_keys: Value = plain.get(format!("http://127.0.0.1:{syn_port}/_matrix/key/v2/server")).send().unwrap().json().unwrap();
    assert_eq!(syn_keys["server_name"], syn_name);

    // Our public DAG room, and Synapse's user in it.
    let (st, v) = ours.call(&plain, "POST", "/client/v3/createRoom", Some(json!({"visibility":"private","name":"open house"})));
    assert_eq!(st, 200, "{v}");
    let room = v["room_id"].as_str().unwrap().to_string();
    let (st, v) = ours.call(&plain, "PUT", &format!("/client/v3/rooms/{}/state/m.room.join_rules", enc(&room)), Some(json!({"join_rule":"public"})));
    assert_eq!(st, 200, "join rules: {v}");
    let login: Value = plain.post(format!("http://127.0.0.1:{syn_port}/_matrix/client/v3/login")).json(&json!({"type":"m.login.password","identifier":{"type":"m.id.user","user":"syn"},"password":"pw-interop-1"})).send().unwrap().json().unwrap();
    let tok = login["access_token"].as_str().unwrap().to_string();
    let syn = |m: &str, p: &str, b: Option<Value>| -> (u16, Value) {
        let url = format!("http://127.0.0.1:{syn_port}/_matrix/client/v3{p}");
        let mut r = match m { "GET" => plain.get(url), "PUT" => plain.put(url), _ => plain.post(url) }.bearer_auth(&tok);
        if let Some(b) = b { r = r.json(&b); }
        let resp = r.send().unwrap();
        (resp.status().as_u16(), resp.json().unwrap_or(Value::Null))
    };
    let (st, v) = syn("POST", &format!("/join/{}?server_name={}", enc(&room), enc(our_name)), Some(json!({})));
    assert_eq!(st, 200, "synapse joins our room: {v}\n{}", std::fs::read_to_string(d("syn.log")).unwrap_or_default().lines().rev().take(15).collect::<Vec<_>>().join("\n"));

    // Our events reach Synapse and pass its signature and hash checks, under our ids.
    let (st, v) = ours.call(&plain, "PUT", &format!("/client/v3/rooms/{}/send/m.room.encrypted/t1", enc(&room)), Some(json!({"algorithm":"m.megolm.v1.aes-sha2","sender_key":"k","session_id":"s","device_id":"D","ciphertext":"hello-from-us"})));
    assert_eq!(st, 200, "send: {v}");
    let ours_id = v["event_id"].as_str().unwrap().to_string();
    assert!(ours_id.starts_with('$') && ours_id.len() == 44, "reference-hash id: {ours_id}");
    poll("synapse has our message", || {
        let (_, m) = syn("GET", &format!("/rooms/{}/messages?dir=b&limit=20", enc(&room)), None);
        m["chunk"].as_array()?.iter().find(|e| e["event_id"] == ours_id.as_str() && e["content"]["ciphertext"] == "hello-from-us").map(|_| ())
    });

    // And Synapse's events reach us.
    let (st, v) = syn("PUT", &format!("/rooms/{}/send/m.room.encrypted/s1", enc(&room)), Some(json!({"algorithm":"m.megolm.v1.aes-sha2","sender_key":"k2","session_id":"s2","device_id":"E","ciphertext":"hello-from-synapse"})));
    assert_eq!(st, 200, "synapse send: {v}");
    let syn_id = v["event_id"].as_str().unwrap().to_string();
    poll("we have synapse's message", || {
        let (_, m) = ours.call(&plain, "GET", &format!("/client/v3/rooms/{}/messages?dir=b&limit=20", enc(&room)), None);
        m["chunk"].as_array()?.iter().find(|e| e["event_id"] == syn_id.as_str()).map(|_| ())
    });
}
