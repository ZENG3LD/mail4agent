//! `m4a-send` path: a request on the client's local socket becomes an
//! encrypted DM from the `as` session, and the recipient's wake JSON
//! carries room, sender nick, recipient nick, event id, body, and the reply
//! command. Loopback only. No bearer is printed.

#[path = "support_product.rs"]
mod support_product;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use mail4agent_messenger_shell::{send_via_socket, HostSession, MachineClient, SendRequest};

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

fn routine_mock() -> (String, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("routine bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let Ok(n) = stream.read(&mut chunk) else {
                    break;
                };
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                    let length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if buf.len() >= end + 4 + length {
                        let body = buf[end + 4..end + 4 + length].to_vec();
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        let _ = tx.send(body);
                        break;
                    }
                }
            }
        }
    });
    (format!("http://{addr}/routine"), rx)
}

/// Unique per call inside one test process: parallel tests must never share a temp dir.
fn uniq() -> u128 {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_nanos();
    nanos.wrapping_add(N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u128)
}

#[test]
fn send_socket_dm_wakes_the_recipient_with_a_reply_hint() {
    let stamp = uniq();
    let temp = TempDb {
        dir: PathBuf::from(format!(
            "/tmp/mail4agent-send-{}-{stamp}",
            std::process::id()
        )),
    };
    std::fs::create_dir_all(&temp.dir).expect("tmpdir");
    let db = temp.dir.join("messenger.db");
    let key_hex = random_key_hex();
    let probe = TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
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
    let _server = StopServer(Some(child));
    wait_until_accepts(&addr);

    let (routine_url, routine_rx) = routine_mock();
    let root = temp.dir.join("stores");
    let product = support_product::start_product(&base);
    let base = product.url.clone();
    let alice_invite = support_product::product_invite(&product, "alice");
    let sessions = vec![
        HostSession::new("Alice", "web-alice").with_invite(alice_invite),
        HostSession::new("Привет мир", "web-chief")
            .with_invite(support_product::product_invite(&product, "privet-mir"))
            .with_routine(routine_url, Some("test-routine-key".to_string())),
    ];
    let mut client = MachineClient::open(&base, &root, sessions).expect("client opens");
    // A second client cannot open the same sealed stores.
    assert!(MachineClient::open(
        &base,
        &root,
        vec![HostSession::new("Alice", "web-alice").with_invite("spent-elsewhere")]
    )
    .is_err());
    let sock = temp.dir.join("web-client.sock");
    client.listen_for_sends(&sock).expect("listen");

    let text = "Alice -> privet-mir: test reply path";
    let request = SendRequest {
        as_nick: "alice".to_string(),
        to: "privet-mir".to_string(),
        text: text.to_string(),
    };
    let sock_for_thread = sock.clone();
    let sender =
        thread::spawn(move || send_via_socket(&sock_for_thread, &request, Duration::from_secs(90)));

    let start = Instant::now();
    let mut now = 50_000_i64;
    let mut served = None;
    let mut wake = None;
    while start.elapsed() < Duration::from_secs(90) && (served.is_none() || wake.is_none()) {
        now += 1_000;
        let report = client.tick(now, 1);
        if let Some(sent) = report.sent.into_iter().next() {
            served = Some(sent);
        }
        if let Ok(body) = routine_rx.try_recv() {
            wake = Some(body);
        }
        thread::sleep(Duration::from_millis(100));
    }
    let (from, to, reply) = served.expect("the client answered the send");
    assert_eq!(
        (from.as_str(), to.as_str()),
        ("alice", "privet-mir")
    );
    assert!(reply.ok, "send failed: {:?}", reply.error);
    let answer = sender
        .join()
        .expect("sender thread")
        .expect("socket answer");
    assert!(answer.ok);
    let event_id = answer.event_id.clone().expect("event id");
    assert!(event_id.starts_with('$'));

    let wake: serde_json::Value =
        serde_json::from_slice(&wake.expect("recipient routine was woken")).expect("wake json");
    assert_eq!(wake["body"], text);
    assert_eq!(wake["event_id"], event_id.as_str());
    assert_eq!(wake["room"], answer.room.clone().expect("room").as_str());
    assert_eq!(wake["from_nick"], "alice");
    assert_eq!(wake["to"], "privet-mir");
    assert!(wake["from"]
        .as_str()
        .expect("from")
        .starts_with("@alice:"));
    assert_eq!(
        wake["reply"],
        "m4a-send --as privet-mir --to alice '<your reply>'"
    );
    let raw = wake.to_string();
    assert!(!raw.contains("test-routine-key"));

    drop(client);
    assert!(!sock.exists(), "socket file removed on drop");
}
