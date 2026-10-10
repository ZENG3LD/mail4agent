//! Two messenger shells exchange one private-room text through
//! `mail4agent-server-bin` on 127.0.0.1. The shells perform the HTTP the
//! engine releases, including key setup when the room is encrypted.
//! The database key and the bearer tokens are fixtures generated or named
//! here and are not printed.

#[path = "support_product.rs"]
mod support_product;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mail4agent_messenger_shell::{
    session_store_dir, CreateRoomKind, DeviceId, MessageKind, MessengerCommand, OpenedStore,
    OutgoingMessage, RoomId, SessionWake,
};
use mail4agent_server::store::init_messenger_db;

const TEXT: &str = "shell-two-device-hello";
const GROUP_TEXT: &str = "shell-group-hello";
const CHANNEL_TEXT: &str = "shell-channel-hello";

struct StopServer(Option<Child>);

impl Drop for StopServer {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct TempDb {
    dir: PathBuf,
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let db = self.dir.join("messenger.db");
        let path = db.display().to_string();
        let _ = std::fs::remove_file(&db);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn random_key_hex() -> String {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .expect("urandom")
        .read_exact(&mut bytes)
        .expect("urandom read");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A product user with the given nick whose first contact has happened; returns (token, device id).
fn login(product: &support_product::Product, nick: &str) -> (String, String) {
    let token = support_product::product_user(product, nick);
    let who: serde_json::Value = reqwest::blocking::Client::new()
        .get(format!("{}/client/v3/account/whoami", product.url))
        .bearer_auth(&token)
        .send()
        .expect("whoami")
        .json()
        .expect("whoami json");
    (token, who["device_id"].as_str().expect("device id").to_string())
}

fn server_bin() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_mail4agent_server_bin") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    let exe = std::env::current_exe().expect("test executable");
    let mut path = exe
        .parent()
        .and_then(|dir| dir.parent())
        .expect("target profile dir")
        .to_path_buf();
    path.push("mail4agent-server-bin");
    assert!(
        path.is_file(),
        "mail4agent-server-bin was not built next to the test harness"
    );
    path
}

struct RoutineCapture {
    url: String,
    hits: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
    done: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for RoutineCapture {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn start_routine() -> RoutineCapture {
    let listener = TcpListener::bind("127.0.0.1:0").expect("routine bind");
    let addr = listener.local_addr().expect("routine addr");
    listener.set_nonblocking(true).expect("nonblocking");
    let hits = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&hits);
    let done = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&done);
    let thread = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(90);
        while !flag.load(Ordering::Relaxed) && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut sock, _)) => {
                    let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 2048];
                    loop {
                        let n = sock.read(&mut tmp).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        let marker = b"\r\n\r\n";
                        if let Some(end) = buf.windows(4).position(|window| window == marker) {
                            let headers = String::from_utf8_lossy(&buf[..end]).to_string();
                            let length = headers
                                .lines()
                                .find_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    if name.eq_ignore_ascii_case("content-length") {
                                        value.trim().parse::<usize>().ok()
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or(0);
                            if buf.len() >= end + 4 + length {
                                let body = buf[end + 4..end + 4 + length].to_vec();
                                recorded.lock().expect("hits").push((headers, body));
                                let _ = sock.write_all(
                                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                );
                                break;
                            }
                        }
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    RoutineCapture {
        url: format!("http://{addr}/routine"),
        hits,
        done,
        thread: Some(thread),
    }
}

fn wait_until_accepts(addr: &str) {
    let start = Instant::now();
    loop {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        if start.elapsed() > Duration::from_secs(15) {
            panic!("server did not accept {addr}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn open_shell(
    dir: &std::path::Path,
    session: &str,
    device_id: &str,
    user_id: &str,
    base_url: &str,
    token: &str,
) -> OpenedStore {
    let device = DeviceId::parse(device_id).expect("device id");
    OpenedStore::open(dir, session, device, user_id, "localhost", base_url, token)
        .expect("open shell")
}

fn settle(shell: &mut OpenedStore, now: &mut i64) {
    for _ in 0..8 {
        *now += 2_000;
        shell.drive(*now, false).expect("drive");
    }
}

fn catch_up(shell: &mut OpenedStore, now: &mut i64) {
    *now += 2_000;
    shell.drive(*now, true).expect("catch up");
}

fn describe(shell: &OpenedStore) -> String {
    let rooms: Vec<String> = shell
        .rooms()
        .iter()
        .map(|room| {
            format!(
                "{} membership={} encrypted={}",
                room.room_id, room.membership, room.encrypted
            )
        })
        .collect();
    let texts: Vec<String> = shell
        .texts()
        .iter()
        .map(|text| {
            format!(
                "{} outcome={} body_len={}",
                text.room_id,
                text.outcome,
                text.body.len()
            )
        })
        .collect();
    format!(
        "inflight={} rooms=[{}] texts=[{}] http=[{}]",
        shell.sync_inflight(),
        rooms.join(", "),
        texts.join(", "),
        shell.http_trace().join(" | ")
    )
}

#[test]
fn two_shells_exchange_one_text_over_loopback() {
    let temp = TempDb {
        dir: PathBuf::from(format!(
            "/tmp/mail4agent-shell-two-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis()
        )),
    };
    std::fs::create_dir_all(&temp.dir).expect("tmpdir");
    let db = temp.dir.join("messenger.db");
    let key_hex = random_key_hex();

    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
    let port = probe.local_addr().expect("addr").port();
    drop(probe);
    let addr = format!("127.0.0.1:{port}");
    let base = format!("http://{addr}");

    let exe = server_bin();
    let child = Command::new(exe)
        .args([
            "--bind",
            &addr,
            "--db",
            db.to_str().expect("utf-8"),
            "--server-name",
            "localhost",
        ])
        .env("M4A_DB_KEY_HEX", &key_hex)
        .env("M4A_ASSERTION_SECRET", support_product::SEAM_SECRET)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");
    let mut server = StopServer(Some(child));
    wait_until_accepts(&addr);
    let product = support_product::start_product(&base);
    let base = product.url.clone();
    let (alice_token, alice_device) = login(&product, "alice");
    let (bob_token, bob_device) = login(&product, "bob");

    let alice_dir = temp.dir.join("alice");
    let bob_dir = temp.dir.join("bob");
    let mut alice = open_shell(
        &alice_dir,
        "session-alice",
        &alice_device,
        "@alice:localhost",
        &base,
        &alice_token,
    );
    let mut bob = open_shell(
        &bob_dir,
        "session-bob",
        &bob_device,
        "@bob:localhost",
        &base,
        &bob_token,
    );
    let routine = start_routine();
    bob.set_wake(SessionWake {
        routine_url: Some(routine.url.clone()),
        ..SessionWake::default()
    });
    let mut alice_now = 1_000_000_i64;
    let mut bob_now = 1_000_000_i64;
    settle(&mut alice, &mut alice_now);
    settle(&mut bob, &mut bob_now);

    alice
        .dispatch(
            MessengerCommand::CreateRoom {
                kind: CreateRoomKind::Dm {
                    peer: mail4agent_messenger_shell::UserId::parse("@bob:localhost")
                        .expect("bob"),
                },
            },
            alice_now,
        )
        .expect("create dm");
    settle(&mut alice, &mut alice_now);
    catch_up(&mut alice, &mut alice_now);
    catch_up(&mut bob, &mut bob_now);

    let invite = bob
        .rooms()
        .into_iter()
        .find(|room| room.membership == "invite")
        .unwrap_or_else(|| {
            panic!(
                "bob saw no invite; bob {} alice {}",
                describe(&bob),
                describe(&alice)
            )
        });
    bob.dispatch(
        MessengerCommand::JoinRoom {
            room_id: RoomId::parse(&invite.room_id).expect("room id"),
        },
        bob_now,
    )
    .expect("join");
    settle(&mut bob, &mut bob_now);
    catch_up(&mut bob, &mut bob_now);
    catch_up(&mut alice, &mut alice_now);

    let room = alice
        .rooms()
        .into_iter()
        .find(|room| room.membership == "join")
        .unwrap_or_else(|| panic!("alice has no joined room; {}", describe(&alice)));
    assert!(
        room.encrypted,
        "private room was not encrypted; refusing a plaintext send; {}",
        describe(&alice)
    );
    alice
        .dispatch(
            MessengerCommand::SendMessage {
                room_id: RoomId::parse(&room.room_id).expect("room"),
                message: OutgoingMessage {
                    kind: MessageKind::Text,
                    body: TEXT.to_string(),
                    reply_to: None,
                    edit_of: None,
                },
                txn_id: None,
            },
            alice_now,
        )
        .expect("send");

    let mut sent = false;
    for _ in 0..12 {
        settle(&mut alice, &mut alice_now);
        if alice
            .texts()
            .iter()
            .any(|text| text.body == TEXT && text.outcome == "sent")
        {
            sent = true;
            break;
        }
        let texts = alice.texts();
        if let Some(failed) = texts
            .iter()
            .find(|text| text.body == TEXT && text.outcome.starts_with("failed"))
        {
            panic!(
                "alice send failed ({}); {}",
                failed.outcome,
                describe(&alice)
            );
        }
    }
    assert!(
        sent,
        "alice ciphertext was not accepted; {}",
        describe(&alice)
    );

    let mut saw = false;
    for _ in 0..4 {
        catch_up(&mut bob, &mut bob_now);
        settle(&mut bob, &mut bob_now);
        if bob.texts().iter().any(|text| text.body == TEXT) {
            saw = true;
            break;
        }
        if bob
            .texts()
            .iter()
            .any(|text| text.outcome.starts_with("undecryptable"))
        {
            panic!("bob could not decrypt; {}", describe(&bob));
        }
    }
    assert!(
        saw,
        "second device did not see the text; {}",
        describe(&bob)
    );
    let hits = routine.hits.lock().expect("hits");
    assert_eq!(
        hits.len(),
        1,
        "decrypted room text did not hit the routine once; {}",
        describe(&bob)
    );
    assert!(
        !hits[0].0.to_ascii_lowercase().contains("authorization"),
        "routine post added a bearer"
    );
    let trace = format!("{} || ALICE {}", describe(&bob), describe(&alice));
    assert!(
        trace.contains("SigningKeysUpload 200") && trace.contains("SignaturesUpload 200"),
        "M3: automatic cross-signing did not upload keys and the device signature; {trace}"
    );
    assert!(!hits[0].0.contains("/mail/send"));
    drop(hits);
    let ids = wake_event_ids(&routine, TEXT, "@alice:localhost");
    assert_eq!(ids.len(), 1, "dm wake should be one json object");

    drop(alice);
    drop(bob);
    if let Some(child) = server.0.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    server.0 = None;
}

struct ThreeShells {
    temp: TempDb,
    key_hex: String,
    alice_device: String,
    bob_device: String,
    carol_device: String,
    alice_token: String,
    bob_token: String,
    carol_token: String,
    base: String,
    server: StopServer,
    store_root: PathBuf,
}

fn start_three_shells() -> ThreeShells {
    let temp = TempDb {
        dir: PathBuf::from(format!(
            "/tmp/mail4agent-shell-group-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis()
        )),
    };
    std::fs::create_dir_all(&temp.dir).expect("tmpdir");
    let db = temp.dir.join("messenger.db");
    let key_hex = random_key_hex();

    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
    let port = probe.local_addr().expect("addr").port();
    drop(probe);
    let addr = format!("127.0.0.1:{port}");
    let base = format!("http://{addr}");

    let exe = server_bin();
    let child = Command::new(exe)
        .args([
            "--bind",
            &addr,
            "--db",
            db.to_str().expect("utf-8"),
            "--server-name",
            "localhost",
        ])
        .env("M4A_DB_KEY_HEX", &key_hex)
        .env("M4A_ASSERTION_SECRET", support_product::SEAM_SECRET)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");
    let server = StopServer(Some(child));
    wait_until_accepts(&addr);
    let product = support_product::start_product(&base);
    let base = product.url.clone();
    let (alice_token, alice_device) = login(&product, "alice");
    let (bob_token, bob_device) = login(&product, "bob");
    let (carol_token, carol_device) = login(&product, "carol");

    // One root, the directory M4A_STORE_ROOT names. session_store_dir
    // gives each session id its own child. The shells are not pointed
    // at one path.
    let store_root = temp.dir.join("m4a-store-root");
    std::fs::create_dir_all(&store_root).expect("store root");
    ThreeShells {
        temp,
        key_hex,
        alice_device,
        bob_device,
        carol_device,
        alice_token,
        bob_token,
        carol_token,
        base,
        server,
        store_root,
    }
}

fn open_session(
    boot: &ThreeShells,
    session: &str,
    device: &str,
    user: &str,
    token: &str,
) -> OpenedStore {
    let dir = session_store_dir(&boot.store_root, session);
    open_shell(&dir, session, device, user, &boot.base, token)
}

fn distinct_session_dirs(boot: &ThreeShells) {
    let alice = session_store_dir(&boot.store_root, "session-alice");
    let bob = session_store_dir(&boot.store_root, "session-bob");
    let carol = session_store_dir(&boot.store_root, "session-carol");
    assert_ne!(alice, bob);
    assert_ne!(alice, carol);
    assert_ne!(bob, carol);
    assert!(alice.starts_with(&boot.store_root));
    assert!(bob.starts_with(&boot.store_root));
    assert!(carol.starts_with(&boot.store_root));
}

fn wait_membership(
    shell: &mut OpenedStore,
    now: &mut i64,
    membership: &str,
    encrypted: Option<bool>,
) -> String {
    for _ in 0..5 {
        if let Some(room) = shell.rooms().into_iter().find(|room| {
            room.membership == membership && encrypted.is_none_or(|flag| room.encrypted == flag)
        }) {
            return room.room_id;
        }
        catch_up(shell, now);
    }
    panic!(
        "no room membership={membership} encrypted={encrypted:?}; {}",
        describe(shell)
    );
}

fn join_room(shell: &mut OpenedStore, now: &mut i64, room_id: &str) {
    shell
        .dispatch(
            MessengerCommand::JoinRoom {
                room_id: RoomId::parse(room_id).expect("room id"),
            },
            *now,
        )
        .unwrap_or_else(|err| panic!("join {room_id}: {err}; {}", describe(shell)));
    settle(shell, now);
}

fn send_text(shell: &mut OpenedStore, now: &mut i64, room_id: &str, text: &str) {
    shell
        .dispatch(
            MessengerCommand::SendMessage {
                room_id: RoomId::parse(room_id).expect("room"),
                message: OutgoingMessage {
                    kind: MessageKind::Text,
                    body: text.to_string(),
                    reply_to: None,
                    edit_of: None,
                },
                txn_id: None,
            },
            *now,
        )
        .unwrap_or_else(|err| panic!("send: {err}; {}", describe(shell)));
    let mut sent = false;
    for _ in 0..12 {
        settle(shell, now);
        if shell
            .texts()
            .iter()
            .any(|row| row.body == text && row.outcome == "sent")
        {
            sent = true;
            break;
        }
        if let Some(failed) = shell
            .texts()
            .iter()
            .find(|row| row.body == text && row.outcome.starts_with("failed"))
        {
            panic!("send failed ({}); {}", failed.outcome, describe(shell));
        }
    }
    assert!(
        sent,
        "ciphertext or plaintext was not accepted; {}",
        describe(shell)
    );
}

fn wait_text(shell: &mut OpenedStore, now: &mut i64, text: &str) {
    for _ in 0..4 {
        catch_up(shell, now);
        settle(shell, now);
        if shell.texts().iter().any(|row| row.body == text) {
            return;
        }
        if shell
            .texts()
            .iter()
            .any(|row| row.outcome.starts_with("undecryptable"))
        {
            panic!("could not decrypt; {}", describe(shell));
        }
    }
    panic!("did not see the text; {}", describe(shell));
}

fn wake_event_ids(routine: &RoutineCapture, body: &str, from: &str) -> Vec<String> {
    let hits = routine.hits.lock().expect("hits");
    assert!(
        !hits.is_empty(),
        "decrypted room text did not hit the routine"
    );
    let mut ids = Vec::new();
    for (headers, bytes) in hits.iter() {
        assert!(
            !headers.to_ascii_lowercase().contains("authorization"),
            "routine post added a bearer"
        );
        assert!(!headers.contains("/mail/send"));
        let parsed: serde_json::Value = serde_json::from_slice(bytes).expect("wake json");
        assert_eq!(parsed["body"], body, "wake body: {parsed}");
        assert_eq!(parsed["from"], from, "wake from: {parsed}");
        let event_id = parsed["event_id"].as_str().unwrap_or("").to_string();
        assert!(event_id.starts_with('$'), "wake event_id missing: {parsed}");
        ids.push(event_id);
    }
    ids
}

fn stop_server(server: &mut StopServer) {
    if let Some(mut child) = server.0.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn timeline_messages(
    db: &std::path::Path,
    key_hex: &str,
    room_id: &str,
) -> Vec<(String, String, String)> {
    let conn = init_messenger_db(db.to_str().expect("utf-8"), key_hex).expect("reopen db");
    let mut stmt = conn
        .prepare(
            "SELECT event_id, event_type, content FROM events \
             WHERE room_id = ?1 AND state_key IS NULL \
             AND event_type IN ('m.room.message', 'm.room.encrypted') \
             ORDER BY stream_id",
        )
        .expect("prepare");
    stmt.query_map([room_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })
    .expect("query")
    .collect::<Result<Vec<_>, _>>()
    .expect("rows")
}

fn open_trio(boot: &ThreeShells) -> (OpenedStore, OpenedStore, OpenedStore) {
    distinct_session_dirs(boot);
    let alice = open_session(
        boot,
        "session-alice",
        &boot.alice_device,
        "@alice:localhost",
        &boot.alice_token,
    );
    let bob = open_session(
        boot,
        "session-bob",
        &boot.bob_device,
        "@bob:localhost",
        &boot.bob_token,
    );
    let carol = open_session(
        boot,
        "session-carol",
        &boot.carol_device,
        "@carol:localhost",
        &boot.carol_token,
    );
    (alice, bob, carol)
}

#[test]
fn three_local_shells_exchange_one_text_in_an_encrypted_group() {
    let mut boot = start_three_shells();
    let routine = start_routine();
    let (mut alice, mut bob, mut carol) = open_trio(&boot);
    bob.set_wake(SessionWake {
        routine_url: Some(routine.url.clone()),
        ..SessionWake::default()
    });
    carol.set_wake(SessionWake {
        routine_url: Some(routine.url.clone()),
        ..SessionWake::default()
    });
    let mut alice_now = 1_000_000_i64;
    let mut bob_now = 1_000_000_i64;
    let mut carol_now = 1_000_000_i64;
    settle(&mut alice, &mut alice_now);
    settle(&mut bob, &mut bob_now);
    settle(&mut carol, &mut carol_now);

    alice
        .dispatch(
            MessengerCommand::CreateRoom {
                kind: CreateRoomKind::Group {
                    name: "shell-group".to_string(),
                    invite: vec![
                        mail4agent_messenger_shell::UserId::parse("@bob:localhost")
                            .expect("bob"),
                        mail4agent_messenger_shell::UserId::parse("@carol:localhost")
                            .expect("carol"),
                    ],
                    members_can_invite: false,
                },
            },
            alice_now,
        )
        .expect("create group");
    settle(&mut alice, &mut alice_now);
    let room_id = wait_membership(&mut alice, &mut alice_now, "join", Some(true));
    let bob_invite = wait_membership(&mut bob, &mut bob_now, "invite", None);
    let carol_invite = wait_membership(&mut carol, &mut carol_now, "invite", None);
    assert_eq!(bob_invite, room_id);
    assert_eq!(carol_invite, room_id);
    join_room(&mut bob, &mut bob_now, &room_id);
    join_room(&mut carol, &mut carol_now, &room_id);
    let _ = wait_membership(&mut bob, &mut bob_now, "join", Some(true));
    let _ = wait_membership(&mut carol, &mut carol_now, "join", Some(true));
    catch_up(&mut alice, &mut alice_now);

    let room = alice
        .rooms()
        .into_iter()
        .find(|room| room.room_id == room_id)
        .expect("alice room");
    assert!(
        room.encrypted,
        "group room was not encrypted; {}",
        describe(&alice)
    );
    for _ in 0..4 {
        settle(&mut alice, &mut alice_now);
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    send_text(&mut alice, &mut alice_now, &room_id, GROUP_TEXT);
    wait_text(&mut bob, &mut bob_now, GROUP_TEXT);
    wait_text(&mut carol, &mut carol_now, GROUP_TEXT);

    let ids = wake_event_ids(&routine, GROUP_TEXT, "@alice:localhost");
    assert_eq!(
        ids.len(),
        2,
        "each other member should wake once; {}",
        describe(&bob)
    );
    assert_eq!(ids[0], ids[1]);

    drop(alice);
    drop(bob);
    drop(carol);
    stop_server(&mut boot.server);
    let events = timeline_messages(&boot.temp.dir.join("messenger.db"), &boot.key_hex, &room_id);
    assert!(
        events.iter().any(|(event_id, event_type, content)| {
            event_id == &ids[0] && event_type == "m.room.encrypted" && !content.contains(GROUP_TEXT)
        }),
        "group timeline was not m.room.encrypted: {:?}",
        events
            .iter()
            .map(|(id, kind, _)| format!("{id} {kind}"))
            .collect::<Vec<_>>()
    );
    assert!(
        events
            .iter()
            .all(|(_, event_type, _)| event_type != "m.room.message"),
        "encrypted group stored a plaintext m.room.message"
    );
}

#[test]
fn three_local_shells_exchange_one_text_in_a_public_plaintext_channel() {
    let mut boot = start_three_shells();
    let routine = start_routine();
    let (mut alice, mut bob, mut carol) = open_trio(&boot);
    bob.set_wake(SessionWake {
        routine_url: Some(routine.url.clone()),
        ..SessionWake::default()
    });
    carol.set_wake(SessionWake {
        routine_url: Some(routine.url.clone()),
        ..SessionWake::default()
    });
    let mut alice_now = 2_000_000_i64;
    let mut bob_now = 2_000_000_i64;
    let mut carol_now = 2_000_000_i64;
    settle(&mut alice, &mut alice_now);
    settle(&mut bob, &mut bob_now);
    settle(&mut carol, &mut carol_now);

    alice
        .dispatch(
            MessengerCommand::CreateRoom {
                kind: CreateRoomKind::Channel {
                    name: "shell-channel".to_string(),
                    topic: None,
                },
            },
            alice_now,
        )
        .expect("create channel");
    settle(&mut alice, &mut alice_now);
    let room_id = wait_membership(&mut alice, &mut alice_now, "join", Some(false));
    join_room(&mut bob, &mut bob_now, &room_id);
    join_room(&mut carol, &mut carol_now, &room_id);
    let _ = wait_membership(&mut bob, &mut bob_now, "join", Some(false));
    let _ = wait_membership(&mut carol, &mut carol_now, "join", Some(false));

    let room = alice
        .rooms()
        .into_iter()
        .find(|room| room.room_id == room_id)
        .expect("alice room");
    assert!(
        !room.encrypted,
        "channel is public plaintext; {}",
        describe(&alice)
    );
    // Alice must see both joins (and query their devices) before she encrypts.
    for _ in 0..4 {
        settle(&mut alice, &mut alice_now);
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    send_text(&mut alice, &mut alice_now, &room_id, CHANNEL_TEXT);
    wait_text(&mut bob, &mut bob_now, CHANNEL_TEXT);
    wait_text(&mut carol, &mut carol_now, CHANNEL_TEXT);

    let ids = wake_event_ids(&routine, CHANNEL_TEXT, "@alice:localhost");
    assert_eq!(
        ids.len(),
        2,
        "each other member should wake once; {}",
        describe(&bob)
    );
    assert_eq!(ids[0], ids[1]);

    drop(alice);
    drop(bob);
    drop(carol);
    stop_server(&mut boot.server);
    // Public plaintext store: the post lives in pub_events, never in the closed events table.
    let closed = timeline_messages(&boot.temp.dir.join("messenger.db"), &boot.key_hex, &room_id);
    assert!(
        closed.iter().all(|(_, event_type, _)| event_type != "m.room.message" && event_type != "m.room.encrypted"),
        "public channel post leaked into the closed events table: {closed:?}"
    );
    let conn = init_messenger_db(boot.temp.dir.join("messenger.db").to_str().expect("utf-8"), &boot.key_hex).expect("reopen db");
    let public: i64 = conn
        .query_row("SELECT COUNT(*) FROM pub_events WHERE room_id = ?1 AND content LIKE ?2", rusqlite::params![room_id, format!("%{CHANNEL_TEXT}%")], |r| r.get(0))
        .expect("pub_events");
    assert_eq!(public, 1, "public post must live in pub_events");
}

#[test]
fn m4_late_joiner_decrypts_history_from_an_existing_member() {
    const LATE_TEXT: &str = "history before carol joined";
    let mut boot = start_three_shells();
    let (mut alice, mut bob, mut carol) = open_trio(&boot);
    let mut alice_now = 3_000_000_i64;
    let mut bob_now = 3_000_000_i64;
    let mut carol_now = 3_000_000_i64;
    settle(&mut alice, &mut alice_now);
    settle(&mut bob, &mut bob_now);
    settle(&mut carol, &mut carol_now);
    alice
        .dispatch(
            MessengerCommand::CreateRoom {
                kind: CreateRoomKind::Group {
                    name: "history".to_string(),
                    invite: vec![mail4agent_messenger_shell::UserId::parse("@bob:localhost").expect("bob")],
                    members_can_invite: true,
                },
            },
            alice_now,
        )
        .expect("create channel");
    settle(&mut alice, &mut alice_now);
    let room_id = wait_membership(&mut alice, &mut alice_now, "join", Some(true));
    join_room(&mut bob, &mut bob_now, &room_id);
    let _ = wait_membership(&mut bob, &mut bob_now, "join", Some(true));
    for _ in 0..4 {
        settle(&mut alice, &mut alice_now);
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    send_text(&mut alice, &mut alice_now, &room_id, LATE_TEXT);
    wait_text(&mut bob, &mut bob_now, LATE_TEXT);

    // Carol is invited and joins only now: the text predates her membership.
    alice
        .dispatch(
            MessengerCommand::Invite {
                room_id: RoomId::parse(&room_id).expect("room id"),
                user_id: mail4agent_messenger_shell::UserId::parse("@carol:localhost").expect("carol"),
            },
            alice_now,
        )
        .expect("invite carol");
    settle(&mut alice, &mut alice_now);
    join_room(&mut carol, &mut carol_now, &room_id);
    let _ = wait_membership(&mut carol, &mut carol_now, "join", Some(true));
    let mut saw = false;
    for _ in 0..30 {
        settle(&mut alice, &mut alice_now);
        settle(&mut carol, &mut carol_now);
        if carol.texts().iter().any(|text| text.body == LATE_TEXT) {
            saw = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    assert!(saw, "M4: late joiner never decrypted history; {}", describe(&carol));
    drop(alice);
    drop(bob);
    drop(carol);
    stop_server(&mut boot.server);
}

#[test]
fn m5_rich_commands_roundtrip() {
    use mail4agent_messenger_shell::CmdRequest;
    let mut boot = start_three_shells();
    let (mut alice, mut bob, mut carol) = open_trio(&boot);
    let mut alice_now = 4_000_000_i64;
    let mut bob_now = 4_000_000_i64;
    let mut carol_now = 4_000_000_i64;
    settle(&mut alice, &mut alice_now);
    settle(&mut bob, &mut bob_now);
    settle(&mut carol, &mut carol_now);
    let cmd = |name: &str, args: serde_json::Value| CmdRequest {
        cmd: name.to_string(),
        as_nick: "x".to_string(),
        args,
    };
    let made = alice.run_command(&cmd("rooms.create", serde_json::json!({"name": "m5chan", "kind": "group", "invite": ["@bob:localhost"]})), alice_now);
    assert!(made.ok, "create: {:?}", made.error);
    alice_now += 10_000;
    let room_id = made.data["room"].as_str().unwrap_or_else(|| panic!("room id; {}", describe(&alice))).to_string();
    let joined = bob.run_command(&cmd("rooms.join", serde_json::json!({"room": room_id})), bob_now);
    assert!(joined.ok, "join: {:?}", joined.error);
    bob_now += 10_000;
    for _ in 0..4 {
        settle(&mut alice, &mut alice_now);
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    let listed = alice.run_command(&cmd("rooms.list", serde_json::json!({})), alice_now);
    assert!(listed.data["rooms"].as_array().unwrap().iter().any(|r| r["title"] == "m5chan"), "list: {}", listed.data);
    let sent = alice.run_command(&cmd("rooms.send", serde_json::json!({"room": "#m5chan", "text": "hello @bob"})), alice_now);
    assert!(sent.ok, "send: {:?}", sent.error);
    let event = sent.data["event_id"].as_str().expect("event id").to_string();
    wait_text(&mut bob, &mut bob_now, "hello @bob");
    let read = bob.run_command(&cmd("rooms.read", serde_json::json!({"room": "#m5chan", "limit": 5})), bob_now);
    assert!(read.ok, "read: {:?}", read.error);
    let rows = read.data["messages"].as_array().unwrap();
    assert!(rows.iter().any(|r| r["body"] == "hello @bob" && r["event_id"] == event.as_str()), "read: {}", read.data);
    drop(alice);
    drop(bob);
    drop(carol);
    stop_server(&mut boot.server);
}
