//! Two messenger shells exchange one private-room text through
//! `mail4agent-server-bin` on 127.0.0.1. The shells perform the HTTP the
//! engine releases, including key setup when the room is encrypted.
//! The database key and the bearer tokens are fixtures generated or named
//! here and are not printed.

use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mail4agent_messenger_shell::{
    CreateRoomKind, DeviceId, MessageKind, MessengerCommand, OpenedStore, OutgoingMessage, RoomId,
};
use mail4agent_server::http::hash_token;
use mail4agent_server::keys::{self, CredentialKind};
use mail4agent_server::nick;
use mail4agent_server::store::{self, init_messenger_db};

const ALICE_TOKEN: &str = "fake-alice-token";
const BOB_TOKEN: &str = "fake-bob-token";
const TEXT: &str = "shell-two-device-hello";
const NOW: &str = "2026-10-05T00:00:00+00:00";

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

fn seed(db: &std::path::Path, key_hex: &str) -> (String, String) {
    store::set_matrix_server_name("localhost").expect("server name");
    let conn = init_messenger_db(db.to_str().expect("utf-8"), key_hex).expect("open db");
    store::ensure_matrix_user(&conn, 1, "alicepub", NOW).expect("alice");
    store::ensure_matrix_user(&conn, 2, "bobpub", NOW).expect("bob");
    nick::set_nick(&conn, 1, "alice_nick").expect("alice nick");
    nick::set_nick(&conn, 2, "bob_nick").expect("bob nick");
    let alice_device = keys::create_device(
        &conn,
        1,
        CredentialKind::Bearer,
        &hash_token(ALICE_TOKEN),
        NOW,
    )
    .expect("alice device");
    let bob_device = keys::create_device(
        &conn,
        2,
        CredentialKind::Bearer,
        &hash_token(BOB_TOKEN),
        NOW,
    )
    .expect("bob device");
    conn.execute_batch("PRAGMA wal_checkpoint(FULL);")
        .expect("checkpoint");
    (alice_device, bob_device)
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
    let (alice_device, bob_device) = seed(&db, &key_hex);

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
        .env_remove("M4A_BOOTSTRAP_PUBLIC_ID")
        .env_remove("M4A_BOOTSTRAP_NICK")
        .env_remove("M4A_BOOTSTRAP_TOKEN")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");
    let mut server = StopServer(Some(child));
    wait_until_accepts(&addr);

    let alice_dir = temp.dir.join("alice");
    let bob_dir = temp.dir.join("bob");
    let mut alice = open_shell(
        &alice_dir,
        "session-alice",
        &alice_device,
        "@alicepub:localhost",
        &base,
        ALICE_TOKEN,
    );
    let mut bob = open_shell(
        &bob_dir,
        "session-bob",
        &bob_device,
        "@bobpub:localhost",
        &base,
        BOB_TOKEN,
    );
    let mut alice_now = 1_000_000_i64;
    let mut bob_now = 1_000_000_i64;
    settle(&mut alice, &mut alice_now);
    settle(&mut bob, &mut bob_now);

    alice
        .dispatch(
            MessengerCommand::CreateRoom {
                kind: CreateRoomKind::Dm {
                    peer: mail4agent_messenger_shell::UserId::parse("@bobpub:localhost")
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

    drop(alice);
    drop(bob);
    if let Some(child) = server.0.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    server.0 = None;
}
