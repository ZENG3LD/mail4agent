//! Two Grok Bot web sessions register themselves on loopback and one finds
//! the other by the nick derived from the bot display name. Neither is
//! handed the other's bearer or a routine URL.

use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mail4agent_messenger_shell::{
    session_store_dir, OpenedStore, SessionConfig, BOT_NAME_ENV, DEVICE_TOKEN_ENV,
    HOMESERVER_URL_ENV, SESSION_ID_ENV, STORE_ROOT_ENV,
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

#[test]
fn two_web_sessions_register_and_one_finds_the_other_by_nick() {
    let temp = TempDb {
        dir: PathBuf::from(format!(
            "/tmp/mail4agent-web-reg-{}-{}",
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
        .env_remove("M4A_BOOTSTRAP_PUBLIC_ID")
        .env_remove("M4A_BOOTSTRAP_NICK")
        .env_remove("M4A_BOOTSTRAP_TOKEN")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");
    let mut server = StopServer(Some(child));
    wait_until_accepts(&addr);

    let root = temp.dir.join("stores");
    std::fs::create_dir_all(&root).expect("store root");
    let alice_cfg = SessionConfig::new(&base, "Alice", "web-alice", &root, None)
        .expect("alice config");
    let chief_cfg = SessionConfig::new(&base, "Привет мир", "web-chief", &root, None)
        .expect("chief config");
    assert_eq!(alice_cfg.nick(), "alice");
    assert_eq!(chief_cfg.nick(), "privet-mir");
    assert_ne!(chief_cfg.nick(), "nachshtab");
    let alice_dir = alice_cfg.store_dir();
    let chief_dir = chief_cfg.store_dir();
    assert_eq!(alice_dir, session_store_dir(&root, "web-alice"));
    assert_eq!(chief_dir, session_store_dir(&root, "web-chief"));
    assert_ne!(alice_dir, chief_dir);

    let mut alice = connect_web(&base, "Alice", "web-alice", &root);
    let mut chief = connect_web(&base, "Привет мир", "web-chief", &root);
    assert_eq!(alice.nick(), Some("alice"));
    assert_eq!(chief.nick(), Some("privet-mir"));
    assert!(
        bearer_is_absent(&alice_dir, alice.device_bearer()),
        "alice bearer was written under the store"
    );
    assert!(
        bearer_is_absent(&chief_dir, chief.device_bearer()),
        "chief bearer was written under the store"
    );

    let found = alice
        .find_nick("Привет мир", 3_000)
        .expect("alice finds the chief by display name");
    assert_eq!(found.nick, "privet-mir");
    assert_eq!(found.user_id, "@privet-mir:localhost");
    let found = chief
        .find_nick("alice", 4_000)
        .expect("chief finds alice by nick");
    assert_eq!(found.nick, "alice");
    assert_eq!(found.user_id, "@alice:localhost");

    let chief_nick = chief.nick().unwrap().to_string();
    let event_id = exchange_encrypted_dm(
        &mut alice,
        &mut chief,
        &chief_nick,
        "web-session-dm-plaintext",
    );
    println!(
        "local_sender_user={} local_sender_nick={} local_peer_user={} local_peer_nick={} local_event_id={}",
        alice.user_id(),
        alice.nick().unwrap_or(""),
        chief.user_id(),
        chief_nick,
        event_id
    );

    let alice_bearer = alice.device_bearer().to_string();
    drop(alice);
    drop(chief);
    assert!(
        OpenedStore::connect(&alice_cfg).is_err(),
        "reopen without the keychain bearer must fail"
    );
    let mut alice = OpenedStore::connect(
        &SessionConfig::new(
            &base,
            "Alice",
            "web-alice",
            &root,
            Some(alice_bearer),
        )
        .expect("reopen config"),
    )
    .expect("same session reopens");
    assert_eq!(alice.nick(), Some("alice"));
    let found = alice
        .find_nick("privet-mir", 5_000)
        .expect("reopened session still finds the chief by nick");
    assert_eq!(found.user_id, "@privet-mir:localhost");
    assert!(bearer_is_absent(&alice_dir, alice.device_bearer()));

    if let Some(child) = server.0.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    server.0 = None;
}

fn connect_web(
    base: &str,
    bot_name: &str,
    session_id: &str,
    store_root: &std::path::Path,
) -> OpenedStore {
    std::env::set_var(HOMESERVER_URL_ENV, base);
    std::env::set_var(BOT_NAME_ENV, bot_name);
    std::env::set_var(SESSION_ID_ENV, session_id);
    std::env::set_var(STORE_ROOT_ENV, store_root);
    std::env::remove_var(DEVICE_TOKEN_ENV);
    std::env::remove_var("M4A_NICK");
    let opened = OpenedStore::connect_from_env();
    for key in [
        HOMESERVER_URL_ENV,
        BOT_NAME_ENV,
        SESSION_ID_ENV,
        STORE_ROOT_ENV,
        DEVICE_TOKEN_ENV,
    ] {
        std::env::remove_var(key);
    }
    opened.unwrap_or_else(|err| panic!("connect {bot_name}: {err}"))
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
        "user={} nick={} rooms=[{}] texts=[{}] http=[{}]",
        shell.user_id(),
        shell.nick().unwrap_or(""),
        rooms.join(", "),
        texts.join(", "),
        shell.http_trace().join(" | ")
    )
}

fn drive(shell: &mut OpenedStore, now: &mut i64, wait: bool) {
    *now += 1_000;
    shell
        .drive(*now, wait)
        .unwrap_or_else(|err| panic!("drive: {err}; {}", describe(shell)));
}

/// Sender looks the peer up by the derived nick, the peer joins, the sender
/// sends one encrypted DM, and the peer decrypts it. Returns the event id
/// the peer read. No bearer is printed.
fn exchange_encrypted_dm(
    sender: &mut OpenedStore,
    peer: &mut OpenedStore,
    peer_nick: &str,
    plaintext: &str,
) -> String {
    let mut sender_now = 10_000_i64;
    let mut peer_now = 10_000_i64;
    let room_id = sender
        .ensure_dm(peer_nick, sender_now)
        .unwrap_or_else(|err| panic!("ensure dm: {err}; {}", describe(sender)));
    let mut encrypted = sender
        .rooms()
        .iter()
        .any(|room| room.room_id == room_id && room.encrypted && room.membership == "join");
    for _ in 0..6 {
        if encrypted {
            break;
        }
        drive(sender, &mut sender_now, true);
        encrypted = sender
            .rooms()
            .iter()
            .any(|room| room.room_id == room_id && room.encrypted && room.membership == "join");
    }
    assert!(
        encrypted,
        "dm was not an encrypted join; {}",
        describe(sender)
    );

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
    assert!(saw_invite, "peer never saw the dm; {}", describe(peer));
    if peer
        .rooms()
        .iter()
        .any(|room| room.room_id == room_id && room.membership == "invite")
    {
        peer.accept_direct_invites(peer_now)
            .unwrap_or_else(|err| panic!("join: {err}; {}", describe(peer)));
        for _ in 0..4 {
            if peer
                .rooms()
                .iter()
                .any(|room| room.room_id == room_id && room.membership == "join")
            {
                break;
            }
            drive(peer, &mut peer_now, true);
        }
    }
    assert!(
        peer.rooms()
            .iter()
            .any(|room| room.room_id == room_id && room.membership == "join"),
        "peer did not join; {}",
        describe(peer)
    );

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
        "sender did not see the peer join; {}",
        describe(sender)
    );

    let sent = sender
        .write_to_nick(peer_nick, plaintext, sender_now)
        .unwrap_or_else(|err| panic!("send: {err}; {}", describe(sender)));
    assert_eq!(sent, room_id, "send used a different room");

    for _ in 0..12 {
        drive(peer, &mut peer_now, true);
        if let Some(row) = peer
            .texts()
            .iter()
            .find(|text| text.room_id == room_id && text.body == plaintext)
        {
            let event_id = row
                .event_id
                .clone()
                .unwrap_or_else(|| panic!("decrypted row has no event id; {}", describe(peer)));
            assert!(!event_id.is_empty(), "decrypted event id was empty");
            return event_id;
        }
    }
    panic!("peer did not decrypt the dm; {}", describe(peer));
}

#[test]
#[ignore = "existing homeserver named by M4A_HOMESERVER_URL"]
fn two_web_sessions_dm_against_existing_homeserver() {
    let base = std::env::var(HOMESERVER_URL_ENV).expect("M4A_HOMESERVER_URL");
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis();
    let temp = TempDb {
        dir: PathBuf::from(format!("/tmp/mail4agent-web-proof-{stamp}")),
    };
    std::fs::create_dir_all(&temp.dir).expect("tmpdir");
    let root = temp.dir.join("stores");
    std::fs::create_dir_all(&root).expect("store root");
    let alice_name = format!("Alice {stamp}");
    let chief_name = format!("Проба {stamp}");
    let alice_session = format!("proof-h-{stamp}");
    let chief_session = format!("proof-c-{stamp}");
    let mut alice = connect_web(&base, &alice_name, &alice_session, &root);
    let mut chief = connect_web(&base, &chief_name, &chief_session, &root);
    let chief_nick = chief.nick().unwrap().to_string();
    assert_ne!(chief_nick, "nachshtab");
    assert_ne!(alice.nick(), Some("alice"));
    assert_ne!(
        session_store_dir(&root, &alice_session),
        session_store_dir(&root, &chief_session)
    );
    let event_id = exchange_encrypted_dm(
        &mut alice,
        &mut chief,
        &chief_nick,
        "production-web-session-dm-plaintext",
    );
    println!(
        "prod_sender_user={} prod_sender_nick={} prod_peer_user={} prod_peer_nick={} prod_event_id={}",
        alice.user_id(),
        alice.nick().unwrap_or(""),
        chief.user_id(),
        chief_nick,
        event_id
    );
}
