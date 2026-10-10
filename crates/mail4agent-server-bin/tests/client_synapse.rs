//! The client against a stock Synapse as the homeserver: two accounts hold an end-to-end encrypted
//! DM through the shell's store and the engine driver, once with sliding sync (when Synapse offers
//! it) and once with plain `/sync`.
//!
//! Needs a Synapse install named by `M4A_SYNAPSE_PYTHON` (the python of a venv with
//! `matrix-synapse`); without it the test says so and passes. Everything is on localhost. The
//! accounts are made by the test harness (shared-secret registration, password login): the agent
//! client itself never sees a password; its logins are by key signature (see the other tests).

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use m4a_agent::backend::attached::AttachedBackend;
use m4a_agent::BackendKind;
use mail4agent_messenger_shell::{CreateRoomKind, DeviceId, MessageKind, MessengerCommand, OpenedStore, OutgoingMessage, RoomId, UserId};
use reqwest::blocking::Client;
use serde_json::{json, Value};

struct Syn(Child, PathBuf);
impl Drop for Syn {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn start(py: &str) -> (Syn, u16) {
    let dir = PathBuf::from(format!("/tmp/m4a-client-synapse-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let d = |f: &str| dir.join(f).to_str().unwrap().to_string();
    let port = free_port();
    std::fs::write(d("log.yaml"), format!("version: 1\nformatters:\n  p:\n    format: '%(levelname)s %(name)s %(message)s'\nhandlers:\n  c:\n    class: logging.FileHandler\n    filename: {}\n    formatter: p\nroot:\n  level: INFO\n  handlers: [c]\ndisable_existing_loggers: false\n", d("syn.log"))).unwrap();
    std::fs::write(
        d("hs.yaml"),
        format!(
            "server_name: \"localhost:{port}\"\npid_file: {pid}\nlisteners:\n  - port: {port}\n    bind_addresses: ['127.0.0.1']\n    type: http\n    tls: false\n    resources:\n      - names: [client]\ndatabase:\n  name: sqlite3\n  args:\n    database: {db}\nlog_config: {log}\nmedia_store_path: {media}\nsigning_key_path: {key}\nregistration_shared_secret: interop-secret\nreport_stats: false\ntrusted_key_servers: []\nsuppress_key_server_warning: true\ndefault_room_version: \"11\"\nexperimental_features:\n  msc4186_enabled: true\nrc_message: {{per_second: 1000, burst_count: 1000}}\nrc_joins:\n  local: {{per_second: 1000, burst_count: 1000}}\nrc_login:\n  address: {{per_second: 1000, burst_count: 1000}}\n  account: {{per_second: 1000, burst_count: 1000}}\n  failed_attempts: {{per_second: 1000, burst_count: 1000}}\nrc_invites:\n  per_room: {{per_second: 1000, burst_count: 1000}}\n  per_user: {{per_second: 1000, burst_count: 1000}}\n",
            pid = d("syn.pid"), db = d("syn.db"), log = d("log.yaml"), media = d("media"), key = d("syn.key")
        ),
    )
    .unwrap();
    let gen = Command::new(py).args(["-m", "synapse.app.homeserver", "-c", &d("hs.yaml"), "--generate-keys"]).output().unwrap();
    assert!(gen.status.success(), "synapse keys: {}", String::from_utf8_lossy(&gen.stderr));
    let child = Command::new(py).args(["-m", "synapse.app.homeserver", "-c", &d("hs.yaml")]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let syn = Syn(child, dir.clone());
    let c = Client::builder().timeout(Duration::from_secs(3)).build().unwrap();
    let url = format!("http://127.0.0.1:{port}/_matrix/client/versions");
    let mut up = false;
    for _ in 0..120 {
        if c.get(&url).send().ok().is_some_and(|r| r.status().is_success()) {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(up, "synapse did not start: {}", std::fs::read_to_string(d("syn.log")).unwrap_or_default());
    for user in ["alice", "bob"] {
        let reg = Command::new(py).args(["-m", "synapse._scripts.register_new_matrix_user", "-c", &d("hs.yaml"), "-u", user, "-p", "pw-harness-only", "--no-admin", &format!("http://127.0.0.1:{port}")]).output().unwrap();
        assert!(reg.status.success(), "register: {}{}", String::from_utf8_lossy(&reg.stdout), String::from_utf8_lossy(&reg.stderr));
    }
    (syn, port)
}

/// `(user_id, device_id, token)` as the harness obtains them.
fn harness_login(port: u16, user: &str) -> (String, String, String) {
    let v: Value = Client::new()
        .post(format!("http://127.0.0.1:{port}/_matrix/client/v3/login"))
        .json(&json!({"type":"m.login.password","identifier":{"type":"m.id.user","user":user},"password":"pw-harness-only","initial_device_display_name":"harness"}))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let s = |k: &str| v[k].as_str().unwrap_or_else(|| panic!("login: {v}")).to_string();
    (s("user_id"), s("device_id"), s("access_token"))
}

fn settle(s: &mut OpenedStore, now: &mut i64) {
    for _ in 0..6 {
        *now += 2_000;
        s.drive(*now, false).expect("drive");
        std::thread::sleep(Duration::from_millis(60));
    }
}

fn texts(s: &OpenedStore) -> Vec<String> {
    s.texts().iter().map(|t| format!("{}|{}", t.outcome, t.body)).collect()
}

fn run(port: u16, sliding: bool, tag: &str) {
    let root = std::env::temp_dir().join(format!("m4a-client-synapse-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let base = format!("http://127.0.0.1:{port}");
    let open = |user: &str| {
        let (user_id, device_id, token) = harness_login(port, user);
        let backend = AttachedBackend::new(BackendKind::Matrix, &base, &token).expect("backend");
        let backend = if sliding { backend } else { backend.without_sliding_sync() };
        let on = backend.uses_sliding_sync();
        let store = OpenedStore::open(&root.join(user), &format!("sess-{user}-{tag}"), DeviceId::parse(&device_id).unwrap(), &user_id, &format!("localhost:{port}"), Arc::new(backend), &token).expect("open");
        (store, user_id, on)
    };
    let (mut alice, _, a_sliding) = open("alice");
    let (mut bob, bob_id, _) = open("bob");
    eprintln!("sliding sync in use for {tag}: {a_sliding}");
    if !sliding {
        assert!(!a_sliding);
    }
    let (mut an, mut bn) = (1_000_000_i64, 1_000_000_i64);
    settle(&mut alice, &mut an);
    settle(&mut bob, &mut bn);
    alice.dispatch(MessengerCommand::CreateRoom { kind: CreateRoomKind::Dm { peer: UserId::parse(&bob_id).unwrap() } }, an).expect("create dm");
    for _ in 0..3 {
        settle(&mut alice, &mut an);
        settle(&mut bob, &mut bn);
    }
    let invite = bob.rooms().into_iter().find(|r| r.membership == "invite").unwrap_or_else(|| panic!("bob has no invite: {:?} {:?}", bob.http_trace(), alice.http_trace()));
    bob.dispatch(MessengerCommand::JoinRoom { room_id: RoomId::parse(&invite.room_id).unwrap() }, bn).expect("join");
    for _ in 0..3 {
        settle(&mut bob, &mut bn);
        settle(&mut alice, &mut an);
    }
    let room = alice.rooms().into_iter().find(|r| r.membership == "join").expect("alice in the room");
    let send = |s: &mut OpenedStore, now: i64, body: &str| {
        s.dispatch(MessengerCommand::SendMessage { room_id: RoomId::parse(&room.room_id).unwrap(), message: OutgoingMessage { kind: MessageKind::Text, body: body.into(), reply_to: None, edit_of: None }, txn_id: None }, now).expect("send");
    };
    send(&mut alice, an, "hello through synapse");
    for _ in 0..8 {
        settle(&mut alice, &mut an);
        settle(&mut bob, &mut bn);
        if texts(&bob).iter().any(|t| t.ends_with("|hello through synapse")) {
            break;
        }
    }
    assert!(texts(&bob).iter().any(|t| t.ends_with("|hello through synapse")), "bob never decrypted: {:?} {:?}", texts(&bob), bob.http_trace());
    send(&mut bob, bn, "and back");
    for _ in 0..8 {
        settle(&mut bob, &mut bn);
        settle(&mut alice, &mut an);
        if texts(&alice).iter().any(|t| t.ends_with("|and back")) {
            break;
        }
    }
    assert!(texts(&alice).iter().any(|t| t.ends_with("|and back")), "alice never decrypted: {:?}", texts(&alice));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn encrypted_dm_through_stock_synapse_with_sliding_sync_and_with_v3() {
    let Ok(py) = std::env::var("M4A_SYNAPSE_PYTHON") else {
        eprintln!("skipped: M4A_SYNAPSE_PYTHON is not set");
        return;
    };
    let (_syn, port) = start(&py);
    let v: Value = Client::new().get(format!("http://127.0.0.1:{port}/_matrix/client/versions")).send().unwrap().json().unwrap();
    eprintln!("synapse unstable_features: {}", v["unstable_features"]);
    run(port, true, "auto");
    // Fresh accounts' stores are separate by tag; the same Synapse serves the v3 run too.
    run(port, false, "v3");
}
