//! One client, two local sessions, and a third session that exists only on
//! the homeserver. Mail between the local pair does not call the homeserver.
//! Mail to the third session does. Loopback only. No bearer is printed.

use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[path = "support_product.rs"]
mod support_product;

use mail4agent_messenger_shell::{
    load_session_records, session_store_dir, CreateRoomKind, MachineClient, MessageKind,
    MessengerCommand, OpenedStore, OutgoingMessage, RoomId, SessionConfig,
};

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
    assert!(path.is_file(), "mail4agent-server-bin was not built");
    path
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

fn bearer_is_absent(dir: &std::path::Path, secret: &str) -> bool {
    if secret.is_empty() || !dir.exists() {
        return false;
    }
    let needle = secret.as_bytes();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = match std::fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(_) => return false,
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                return false;
            };
            if bytes.windows(needle.len()).any(|window| window == needle) {
                return false;
            }
        }
    }
    true
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
        .map(|text| format!("{} outcome={}", text.room_id, text.outcome))
        .collect();
    format!(
        "user={} nick={} rooms=[{}] texts=[{}] http=[{}] hits={}",
        shell.user_id(),
        shell.nick().unwrap_or(""),
        rooms.join(", "),
        texts.join(", "),
        shell.http_trace().join(" | "),
        shell.homeserver_hits()
    )
}

fn drive(shell: &mut OpenedStore, now: &mut i64, wait: bool) {
    *now += 1_000;
    shell
        .drive(*now, wait)
        .unwrap_or_else(|err| panic!("drive: {err}; {}", describe(shell)));
}

/// Sender and peer are both inside `client`. Local delivery is already on.
fn exchange_local(client: &mut MachineClient, from: &str, to: &str, plaintext: &str) -> String {
    let mut now = 50_000_i64;
    let room_id = {
        let sender = client.session_mut(from).expect("sender");
        sender
            .ensure_dm(to, now)
            .unwrap_or_else(|err| panic!("ensure dm: {err}; {}", describe(sender)))
    };
    let mut saw_invite = false;
    for _ in 0..8 {
        drive(client.session_mut(to).expect("peer"), &mut now, true);
        saw_invite = client
            .session_mut(to)
            .expect("peer")
            .rooms()
            .iter()
            .any(|room| {
                room.room_id == room_id
                    && (room.membership == "invite" || room.membership == "join")
            });
        if saw_invite {
            break;
        }
    }
    assert!(
        saw_invite,
        "local peer never saw the dm; {}",
        describe(client.session_mut(to).expect("peer"))
    );
    if client
        .session_mut(to)
        .expect("peer")
        .rooms()
        .iter()
        .any(|room| room.room_id == room_id && room.membership == "invite")
    {
        client
            .session_mut(to)
            .expect("peer")
            .accept_direct_invites(now)
            .unwrap_or_else(|err| panic!("join: {err}"));
    }
    let peer_user = client.session_mut(to).expect("peer").user_id().to_string();
    let mut sender_sees_join = false;
    for _ in 0..8 {
        drive(client.session_mut(from).expect("sender"), &mut now, true);
        if client
            .session_mut(from)
            .expect("sender")
            .member_joined(&room_id, &peer_user)
        {
            sender_sees_join = true;
            break;
        }
    }
    assert!(
        sender_sees_join,
        "sender did not see the local peer join; {}",
        describe(client.session_mut(from).expect("sender"))
    );
    client
        .session_mut(from)
        .expect("sender")
        .write_to_nick(to, plaintext, now)
        .unwrap_or_else(|err| {
            panic!(
                "local send: {err}; {}",
                describe(client.session_mut(from).expect("sender"))
            )
        });
    for _ in 0..12 {
        drive(client.session_mut(to).expect("peer"), &mut now, true);
        if let Some(row) = client
            .session_mut(to)
            .expect("peer")
            .texts()
            .iter()
            .find(|text| text.room_id == room_id && text.body == plaintext)
        {
            return row
                .event_id
                .clone()
                .unwrap_or_else(|| panic!("local row has no event id"));
        }
    }
    panic!(
        "local peer did not decrypt; {}",
        describe(client.session_mut(to).expect("peer"))
    );
}

fn exchange_remote(
    sender: &mut OpenedStore,
    peer: &mut OpenedStore,
    peer_nick: &str,
    plaintext: &str,
) -> String {
    let mut sender_now = 80_000_i64;
    let mut peer_now = 80_000_i64;
    let room_id = sender
        .ensure_dm(peer_nick, sender_now)
        .unwrap_or_else(|err| panic!("remote ensure: {err}; {}", describe(sender)));
    let mut saw_invite = false;
    for _ in 0..8 {
        drive(peer, &mut peer_now, true);
        saw_invite = peer.rooms().iter().any(|room| {
            room.room_id == room_id && (room.membership == "invite" || room.membership == "join")
        });
        if saw_invite {
            break;
        }
    }
    assert!(
        saw_invite,
        "remote peer never saw the dm; {}",
        describe(peer)
    );
    if peer
        .rooms()
        .iter()
        .any(|room| room.room_id == room_id && room.membership == "invite")
    {
        peer.accept_direct_invites(peer_now)
            .unwrap_or_else(|err| panic!("remote join: {err}; {}", describe(peer)));
    }
    let peer_user = peer.user_id().to_string();
    let mut sender_sees_join = false;
    for _ in 0..8 {
        drive(sender, &mut sender_now, true);
        if sender.member_joined(&room_id, &peer_user) {
            sender_sees_join = true;
            break;
        }
    }
    assert!(
        sender_sees_join,
        "sender did not see the remote peer join; {}",
        describe(sender)
    );
    sender
        .write_to_nick(peer_nick, plaintext, sender_now)
        .unwrap_or_else(|err| panic!("remote send: {err}; {}", describe(sender)));
    for _ in 0..12 {
        drive(peer, &mut peer_now, true);
        if let Some(row) = peer
            .texts()
            .iter()
            .find(|text| text.room_id == room_id && text.body == plaintext)
        {
            return row
                .event_id
                .clone()
                .unwrap_or_else(|| panic!("remote row has no event id"));
        }
    }
    panic!("remote peer did not decrypt; {}", describe(peer));
}

fn sealed_bytes(dir: &std::path::Path) -> Vec<u8> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path).expect("read dir") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    let mut out = Vec::new();
    for path in files {
        out.extend(std::fs::read(&path).expect("read"));
    }
    out
}

/// Unique per call inside one test process: parallel tests must never share a temp dir.
fn uniq() -> u128 {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_nanos();
    nanos.wrapping_add(N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u128)
}

#[test]
fn one_client_local_dm_skips_homeserver_remote_session_uses_it() {
    let temp = TempDb {
        dir: PathBuf::from(format!(
            "/tmp/mail4agent-machine-{}-{}",
            std::process::id(),
            uniq()
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

    let child = Command::new(server_bin())
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

    let root = temp.dir.join("stores");
    let sessions_dir = temp.dir.join("sessions");
    std::fs::create_dir_all(&root).expect("store root");
    std::fs::create_dir_all(&sessions_dir).expect("sessions");
    std::fs::write(
        sessions_dir.join("alice.json"),
        r#"{"bot_name":"Alice","session_id":"web-alice"}"#,
    )
    .expect("alice record");
    std::fs::write(
        sessions_dir.join("chief.json"),
        "{\"bot_name\":\"Привет мир\",\"session_id\":\"web-chief\"}",
    )
    .expect("chief record");

    let product = support_product::start_product(&base);
    let invites = [("alice", support_product::product_invite(&product, "alice")), ("privet-mir", support_product::product_invite(&product, "privet-mir"))];
    let courier_invite = support_product::product_invite(&product, "courier");
    let base = product.url.clone();
    let mut sessions = load_session_records(&sessions_dir).expect("discover");
    assert_eq!(sessions.len(), 2);
    for session in &mut sessions {
        let nick = if session.bot_name == "Alice" { "alice" } else { "privet-mir" };
        session.invite = invites.iter().find(|t| t.0 == nick).map(|t| t.1.clone());
    }
    let routine_bearer = "mem-only-routine-bearer";
    for session in &mut sessions {
        if session.bot_name == "Alice" {
            session.routine_bearer = Some(routine_bearer.to_string());
        }
    }
    assert!(sessions.iter().all(|session| session.routine_url.is_none()));

    let mut client = MachineClient::open(&base, &root, sessions).expect("one client");
    assert!(client.holds("Alice"));
    assert!(client.holds("privet-mir"));
    assert!(!client.holds("courier"));
    let alice_dir = client.store_dir("alice").expect("alice dir");
    let chief_dir = client.store_dir("Привет мир").expect("chief dir");
    assert_eq!(alice_dir, session_store_dir(&root, "web-alice"));
    assert_eq!(chief_dir, session_store_dir(&root, "web-chief"));
    assert_ne!(alice_dir, chief_dir);
    assert_ne!(sealed_bytes(&alice_dir), sealed_bytes(&chief_dir));

    let alice_bearer = client
        .session_mut("alice")
        .expect("alice")
        .device_bearer()
        .to_string();
    let chief_bearer = client
        .session_mut("privet-mir")
        .expect("chief")
        .device_bearer()
        .to_string();
    assert!(bearer_is_absent(&alice_dir, &alice_bearer));
    assert!(bearer_is_absent(&chief_dir, &chief_bearer));
    assert!(bearer_is_absent(&root, routine_bearer));
    assert!(bearer_is_absent(&sessions_dir, routine_bearer));
    drop(alice_bearer);
    drop(chief_bearer);

    let hits_before_local = client.homeserver_hits();
    assert!(
        hits_before_local > 0,
        "registration drive never called the homeserver"
    );
    client.set_local_delivery(true);
    let local_event = exchange_local(
        &mut client,
        "alice",
        "privet-mir",
        "local-dm-plaintext",
    );
    // The way back: the peer answers into the same encrypted room and the first sender decrypts it.
    let back = {
        let mut now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
        client.session_mut("privet-mir").expect("chief").write_to_nick("alice", "local-dm-answer", now).unwrap_or_else(|err| panic!("local answer: {err}"));
        let mut found = None;
        for _ in 0..12 {
            // As the daemon does: its tick drives every session without waiting.
            now += 1_000;
            let _ = client.tick(now, 0);
            std::thread::sleep(std::time::Duration::from_millis(200));
            let alice = client.session_mut("alice").expect("alice");
            if let Some(row) = alice.texts().iter().find(|t| t.body == "local-dm-answer") {
                found = row.event_id.clone();
                break;
            }
        }
        found.unwrap_or_else(|| panic!("the way back did not decrypt; {}", describe(client.session_mut("alice").expect("alice"))))
    };
    println!("local_answer_event_id={back}");
    let hits_after_local = client.homeserver_hits();
    client.set_local_delivery(false);
    assert_eq!(
        hits_before_local, hits_after_local,
        "local dm called the homeserver"
    );
    assert!(!local_event.is_empty());

    let mut courier = OpenedStore::connect(
        &SessionConfig::new_identity(&base, m4a_agent::BackendKind::Server, "web-courier", &root, Some(courier_invite.clone())).expect("courier config"),
    )
    .expect("courier is only on the homeserver");
    assert_eq!(courier.nick(), Some("courier"));
    assert_ne!(
        courier.store_dir(),
        alice_dir.as_path(),
        "courier store collided"
    );
    let courier_nick = courier.nick().unwrap().to_string();
    let hits_before_remote = client.homeserver_hits();
    assert_eq!(
        hits_after_local, hits_before_remote,
        "a request from the local exchange reached the homeserver after it"
    );
    let remote_event = {
        let sender = client.session_mut("alice").expect("alice");
        exchange_remote(sender, &mut courier, &courier_nick, "remote-dm-plaintext")
    };
    let hits_after_remote = client.homeserver_hits();
    assert!(
        hits_after_remote > hits_before_remote,
        "remote dm did not call the homeserver"
    );
    assert!(!remote_event.is_empty());
    assert!(courier
        .texts()
        .iter()
        .all(|text| text.body != "local-dm-plaintext"));

    println!(
        "local_hits_before={hits_before_local} local_hits_after={hits_after_local} remote_hits_before={hits_before_remote} remote_hits_after={hits_after_remote} local_event_id={local_event} remote_event_id={remote_event}"
    );

    if let Some(child) = server.0.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    server.0 = None;
}

fn drive_quiet(shell: &mut OpenedStore, now: &mut i64) {
    *now += 2_000;
    shell
        .drive(*now, false)
        .unwrap_or_else(|err| panic!("drive: {err}; {}", describe(shell)));
}

fn stable_hits(client: &MachineClient) -> u64 {
    let start = Instant::now();
    let mut last = client.homeserver_hits();
    let mut since = Instant::now();
    loop {
        thread::sleep(Duration::from_millis(40));
        let hits = client.homeserver_hits();
        if hits != last {
            last = hits;
            since = Instant::now();
        }
        if since.elapsed() >= Duration::from_millis(300)
            && start.elapsed() >= Duration::from_millis(300)
        {
            return last;
        }
        if start.elapsed() > Duration::from_secs(5) {
            return client.homeserver_hits();
        }
    }
}

/// Server accepts a channel send; push v1 metadata reaches session B's
/// socket (no plaintext body). Session A does not. The client does not POST.
#[test]
fn one_socket_pushes_session_b_and_not_session_a() {
    let temp = TempDb {
        dir: PathBuf::from(format!(
            "/tmp/mail4agent-push-{}-{}",
            std::process::id(),
            uniq()
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

    let child = Command::new(server_bin())
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

    let root = temp.dir.join("stores");
    std::fs::create_dir_all(&root).expect("store root");
    let product = support_product::start_product(&base);
    let base = product.url.clone();
    let sessions = vec![
        mail4agent_messenger_shell::HostSession::new("Alice", "web-alice").with_invite(support_product::product_invite(&product, "alice")),
        mail4agent_messenger_shell::HostSession::new("Привет мир", "web-chief").with_invite(support_product::product_invite(&product, "privet-mir")),
    ];
    let courier_invite = support_product::product_invite(&product, "courier");
    let mut client =
        MachineClient::open(&base, &root, sessions).expect("one client opens one socket");
    assert!(client.holds("alice"));
    assert!(client.holds("privet-mir"));

    let mut courier = OpenedStore::connect(
        &SessionConfig::new_identity(&base, m4a_agent::BackendKind::Server, "web-courier", &root, Some(courier_invite.clone())).expect("courier config"),
    )
    .expect("courier");
    let mut courier_now = 10_000_i64;
    for _ in 0..6 {
        drive_quiet(&mut courier, &mut courier_now);
    }
    courier
        .dispatch(
            MessengerCommand::CreateRoom {
                kind: CreateRoomKind::Channel {
                    name: "push-channel".to_string(),
                    topic: None,
                },
            },
            courier_now,
        )
        .expect("create channel");
    let mut room_id = None;
    for _ in 0..8 {
        drive_quiet(&mut courier, &mut courier_now);
        courier
            .drive(courier_now, true)
            .unwrap_or_else(|err| panic!("catch up: {err}; {}", describe(&courier)));
        room_id = courier
            .rooms()
            .into_iter()
            .find(|room| room.membership == "join")
            .map(|room| room.room_id);
        if room_id.is_some() {
            break;
        }
    }
    let room_id = room_id.unwrap_or_else(|| panic!("channel missing; {}", describe(&courier)));
    let mut chief_now = 20_000_i64;
    client
        .session_mut("privet-mir")
        .expect("session b")
        .dispatch(
            MessengerCommand::JoinRoom {
                room_id: RoomId::parse(&room_id).expect("room id"),
            },
            chief_now,
        )
        .expect("session b joins");
    let mut joined = false;
    for _ in 0..8 {
        chief_now += 2_000;
        client
            .session_mut("privet-mir")
            .expect("session b")
            .drive(chief_now, true)
            .unwrap_or_else(|err| panic!("session b sync: {err}"));
        joined = client
            .session_mut("privet-mir")
            .expect("session b")
            .rooms()
            .iter()
            .any(|room| room.room_id == room_id && room.membership == "join");
        if joined {
            break;
        }
    }
    assert!(
        joined,
        "session b did not join; {}",
        describe(client.session_mut("privet-mir").expect("b"))
    );

    let hits = stable_hits(&client);
    let trace_a = client
        .session_mut("alice")
        .expect("a")
        .http_trace()
        .len();
    let trace_b = client
        .session_mut("privet-mir")
        .expect("b")
        .http_trace()
        .len();
    let sender = courier.user_id().to_string();
    let body = "push-for-session-b";
    courier
        .dispatch(
            MessengerCommand::SendMessage {
                room_id: RoomId::parse(&room_id).expect("room"),
                message: OutgoingMessage {
                    kind: MessageKind::Text,
                    body: body.to_string(),
                    reply_to: None,
                    edit_of: None,
                },
                txn_id: None,
            },
            courier_now,
        )
        .expect("send");
    let mut sent = false;
    for _ in 0..12 {
        drive_quiet(&mut courier, &mut courier_now);
        if courier
            .texts()
            .iter()
            .any(|row| row.body == body && row.outcome == "sent")
        {
            sent = true;
            break;
        }
    }
    assert!(
        sent,
        "channel send was not accepted; {}",
        describe(&courier)
    );

    let start = Instant::now();
    loop {
        client.deliver_pushed();
        let got = client
            .session_mut("privet-mir")
            .expect("b")
            .pushed_room_events()
            .iter()
            .any(|event| event.event_id.starts_with('$') && event.body.is_empty());
        if got || start.elapsed() > Duration::from_secs(5) {
            break;
        }
        thread::sleep(Duration::from_millis(30));
    }
    let pushed_b: Vec<_> = client
        .session_mut("privet-mir")
        .expect("b")
        .pushed_room_events()
        .to_vec();
    let pushed_a: Vec<_> = client
        .session_mut("alice")
        .expect("a")
        .pushed_room_events()
        .to_vec();
    assert!(
        pushed_a.is_empty(),
        "session a received a push: {pushed_a:?}"
    );
    assert_eq!(pushed_b.len(), 1, "session b push count: {pushed_b:?}");
    let event = &pushed_b[0];
    assert_eq!(event.room, room_id);
    assert_eq!(event.sender, sender);
    assert!(
        event.body.is_empty(),
        "push v1 must not carry plaintext body, got {:?}",
        event.body
    );
    assert!(
        event.wire_type == "m.room.encrypted" || event.wire_type == "m.room.message",
        "wire_type {}",
        event.wire_type
    );
    assert!(
        event.event_id.starts_with('$'),
        "event id {}",
        event.event_id
    );
    let _ = body; // sent plaintext; push carries metadata only
    assert_eq!(
        client.homeserver_hits(),
        hits,
        "the machine client posted during push"
    );
    assert_eq!(
        client
            .session_mut("alice")
            .expect("a")
            .http_trace()
            .len(),
        trace_a
    );
    assert_eq!(
        client
            .session_mut("privet-mir")
            .expect("b")
            .http_trace()
            .len(),
        trace_b
    );
    assert!(
        client
            .session_mut("privet-mir")
            .expect("b")
            .texts()
            .iter()
            .all(|text| text.body != body),
        "session b learned the text from sync, not from the push"
    );

    if let Some(child) = server.0.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    server.0 = None;
}
