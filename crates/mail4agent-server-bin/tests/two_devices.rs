//! Two fake bearer devices exchange one private-room event through the
//! real `mail4agent-server-bin` process. The binary can bootstrap only one
//! user, so this test seeds both devices in a throwaway SQLCipher file
//! first. Tokens below are fixtures, not operator credentials. The raw
//! database key is generated at runtime and is not printed.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mail4agent_server::http::hash_token;
use mail4agent_server::keys::{self, CredentialKind};
use mail4agent_server::nick;
use mail4agent_server::store::{self, init_messenger_db};
use tungstenite::{stream::MaybeTlsStream, Message};

const ALICE_TOKEN: &str = "fake-alice-token";
const BOB_TOKEN: &str = "fake-bob-token";
const TEXT: &str = "two-device-hello";
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
        let _ = std::fs::remove_dir(&self.dir);
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

fn seed(db: &std::path::Path, key_hex: &str) {
    match store::set_matrix_server_name("localhost") {
        Ok(()) => {}
        Err(_) if store::matrix_server_name() == "localhost" => {}
        Err(err) => panic!("server name: {err}"),
    }
    let conn = init_messenger_db(db.to_str().expect("utf-8"), key_hex).expect("open db");
    store::ensure_matrix_user(&conn, 1, "alicepub", NOW).expect("alice");
    store::ensure_matrix_user(&conn, 2, "bobpub", NOW).expect("bob");
    nick::set_nick(&conn, 1, "alice_nick").expect("alice nick");
    nick::set_nick(&conn, 2, "bob_nick").expect("bob nick");
    keys::create_device(
        &conn,
        1,
        CredentialKind::Bearer,
        &hash_token(ALICE_TOKEN),
        NOW,
    )
    .expect("alice device");
    keys::create_device(
        &conn,
        2,
        CredentialKind::Bearer,
        &hash_token(BOB_TOKEN),
        NOW,
    )
    .expect("bob device");
    conn.execute_batch("PRAGMA wal_checkpoint(FULL);")
        .expect("checkpoint");
}

fn encode_path(segment: &str) -> String {
    let mut out = String::new();
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn http(addr: &str, method: &str, path: &str, token: &str, json: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("write timeout");
    let body = json.unwrap_or("");
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n"
    );
    if json.is_some() {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes()).expect("write");
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, text)
}

fn response_body(raw: &str) -> &str {
    raw.split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("")
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

#[test]
fn two_devices_exchange_one_private_room_message() {
    let temp = TempDb {
        dir: PathBuf::from(format!(
            "/tmp/mail4agent-two-devices-{}",
            std::process::id()
        )),
    };
    std::fs::create_dir_all(&temp.dir).expect("tmpdir");
    let db = temp.dir.join("messenger.db");
    let key_hex = random_key_hex();
    seed(&db, &key_hex);

    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
    let port = probe.local_addr().expect("addr").port();
    drop(probe);
    let addr = format!("127.0.0.1:{port}");

    let exe = std::env::var("CARGO_BIN_EXE_mail4agent_server_bin")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_mail4agent-server-bin"))
        .unwrap_or_else(|_| {
            let keys: Vec<_> = std::env::vars()
                .map(|(k, _)| k)
                .filter(|k| k.starts_with("CARGO_BIN"))
                .collect();
            panic!("server binary env missing; CARGO_BIN keys: {keys:?}");
        });
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
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn server");
    let mut server = StopServer(Some(child));
    wait_until_accepts(&addr);

    let (create_status, create_raw) = http(
        &addr,
        "POST",
        "/client/v3/createRoom",
        ALICE_TOKEN,
        Some(
            r#"{"visibility":"private","is_direct":false,"invite":["@bobpub:localhost"],"name":"private"}"#,
        ),
    );
    assert_eq!(create_status, 200, "createRoom: {create_raw}");
    let created: serde_json::Value =
        serde_json::from_str(response_body(&create_raw)).expect("create json");
    let room_id = created["room_id"].as_str().expect("room_id").to_string();
    let room_path = encode_path(&room_id);

    let (join_status, join_raw) = http(
        &addr,
        "POST",
        &format!("/client/v3/rooms/{room_path}/join"),
        BOB_TOKEN,
        Some("{}"),
    );
    assert_eq!(join_status, 200, "join: {join_raw}");

    let (since_status, since_raw) =
        http(&addr, "GET", "/client/v3/sync?timeout=0", BOB_TOKEN, None);
    assert_eq!(since_status, 200, "bob sync before send: {since_raw}");
    let since_json: serde_json::Value =
        serde_json::from_str(response_body(&since_raw)).expect("since json");
    let since = since_json["next_batch"]
        .as_str()
        .expect("next_batch")
        .to_string();

    let send_body = format!(
        r#"{{"algorithm":"m.megolm.v1.aes-sha2","sender_key":"fake-sender","session_id":"fake-session","ciphertext":"fake-ciphertext","body":"{TEXT}"}}"#
    );
    let (send_status, send_raw) = http(
        &addr,
        "PUT",
        &format!("/client/v3/rooms/{room_path}/send/m.room.encrypted/txn-two-devices"),
        ALICE_TOKEN,
        Some(&send_body),
    );
    assert_eq!(send_status, 200, "send: {send_raw}");
    let sent: serde_json::Value =
        serde_json::from_str(response_body(&send_raw)).expect("send json");
    let event_id = sent["event_id"].as_str().expect("event_id").to_string();

    let (sync_status, sync_raw) = http(
        &addr,
        "GET",
        &format!("/client/v3/sync?timeout=0&since={since}"),
        BOB_TOKEN,
        None,
    );
    assert_eq!(sync_status, 200, "bob sync after send: {sync_raw}");
    let sync_body = response_body(&sync_raw);
    assert!(
        sync_body.contains(&event_id),
        "event id missing: {sync_body}"
    );
    assert!(sync_body.contains(TEXT), "text missing: {sync_body}");
    println!("listening {addr}");
    println!("room {room_id}");
    println!("send_status {send_status} event_id {event_id}");
    println!("bob_sync_status {sync_status}");
    println!("bob_sync {sync_body}");

    if let Some(child) = server.0.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    server.0 = None;
}

/// Session A stores one `m.room.encrypted` event. The one push socket,
/// registered for both sessions, delivers that event to session B only.
/// The frame has the wire type and no plaintext body, even when the
/// stored content contains a `body` field.
#[test]
fn encrypted_event_is_pushed_to_session_b_and_not_session_a() {
    let temp = TempDb {
        dir: PathBuf::from(format!(
            "/tmp/mail4agent-push-encrypted-{}-{}",
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
    seed(&db, &key_hex);

    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
    let port = probe.local_addr().expect("addr").port();
    drop(probe);
    let addr = format!("127.0.0.1:{port}");

    let exe = std::env::var("CARGO_BIN_EXE_mail4agent_server_bin")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_mail4agent-server-bin"))
        .expect("server binary");
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

    let (create_status, create_raw) = http(
        &addr,
        "POST",
        "/client/v3/createRoom",
        ALICE_TOKEN,
        Some(
            r#"{"visibility":"private","is_direct":false,"invite":["@bobpub:localhost"],"name":"encrypted-push"}"#,
        ),
    );
    assert_eq!(create_status, 200, "createRoom: {create_raw}");
    let created: serde_json::Value =
        serde_json::from_str(response_body(&create_raw)).expect("create json");
    let room_id = created["room_id"].as_str().expect("room_id").to_string();
    let room_path = encode_path(&room_id);

    let (join_status, join_raw) = http(
        &addr,
        "POST",
        &format!("/client/v3/rooms/{room_path}/join"),
        BOB_TOKEN,
        Some("{}"),
    );
    assert_eq!(join_status, 200, "join: {join_raw}");

    let (mut socket, _) =
        tungstenite::connect(format!("ws://{addr}/client/v3/push")).expect("push socket");
    match socket.get_mut() {
        MaybeTlsStream::Plain(tcp) => {
            tcp.set_read_timeout(Some(Duration::from_millis(800)))
                .expect("timeout");
        }
        _ => panic!("loopback push socket was not plain"),
    }
    let register = format!(r#"{{"type":"register","tokens":["{ALICE_TOKEN}","{BOB_TOKEN}"]}}"#);
    socket
        .send(Message::text(register))
        .expect("register frame");
    let registered = read_ws_text(&mut socket).expect("registered frame");
    assert!(
        registered.contains(r#""type":"registered""#),
        "socket did not register: {registered}"
    );

    let planted = "not-the-push-body";
    let send_body = format!(
        r#"{{"algorithm":"m.megolm.v1.aes-sha2","sender_key":"curve","session_id":"sess","ciphertext":"aabb","body":"{planted}"}}"#
    );
    let (send_status, send_raw) = http(
        &addr,
        "PUT",
        &format!("/client/v3/rooms/{room_path}/send/m.room.encrypted/txn-encrypted-push"),
        ALICE_TOKEN,
        Some(&send_body),
    );
    assert_eq!(send_status, 200, "send: {send_raw}");
    let sent: serde_json::Value =
        serde_json::from_str(response_body(&send_raw)).expect("send json");
    let event_id = sent["event_id"].as_str().expect("event_id").to_string();

    let frame = read_ws_text(&mut socket).expect("push frame");
    assert!(!frame.contains(planted), "push invented a plaintext body");
    assert!(!frame.contains("ciphertext"), "push carried ciphertext");
    assert!(!frame.contains("access_token") && !frame.contains("bearer"));
    let value: serde_json::Value = serde_json::from_str(&frame).expect("push json");
    assert_eq!(value["type"], "event");
    assert_eq!(value["event"]["room"], room_id);
    assert_eq!(value["event"]["sender"], "@alicepub:localhost");
    assert_eq!(value["event"]["recipient"], "@bobpub:localhost");
    assert_eq!(value["event"]["event_id"], event_id);
    assert_eq!(value["event"]["wire_type"], "m.room.encrypted");
    assert!(
        value["event"].get("body").is_none(),
        "body key on encrypted push"
    );

    match read_ws_text(&mut socket) {
        Err(err) if err == "timeout" => {}
        Ok(extra) => panic!("session A also received a push: {extra}"),
        Err(err) => panic!("second read: {err}"),
    }

    let (sync_status, sync_raw) = http(&addr, "GET", "/client/v3/sync?timeout=0", BOB_TOKEN, None);
    assert_eq!(sync_status, 200, "sync: {sync_raw}");
    let sync_body = response_body(&sync_raw);
    assert!(
        sync_body.contains(&event_id),
        "stored event id missing from sync"
    );
    assert!(
        sync_body.contains("m.room.encrypted"),
        "stored row was not m.room.encrypted"
    );

    if let Some(child) = server.0.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    server.0 = None;
}

fn read_ws_text(
    socket: &mut tungstenite::WebSocket<MaybeTlsStream<std::net::TcpStream>>,
) -> Result<String, String> {
    loop {
        match socket.read() {
            Ok(Message::Text(text)) => return Ok(text.to_string()),
            Ok(Message::Ping(payload)) => {
                socket
                    .send(Message::Pong(payload))
                    .map_err(|err| err.to_string())?;
            }
            Ok(Message::Close(_)) => return Err("closed".into()),
            Ok(_) => {}
            Err(tungstenite::Error::Io(err))
                if matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
            {
                return Err("timeout".into());
            }
            Err(err) => return Err(err.to_string()),
        }
    }
}
