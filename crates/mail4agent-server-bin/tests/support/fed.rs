#![allow(dead_code)]
//! Shared pieces of the multi-server federation tests: process handles, polling, and a
//! controllable link (partition, tampering) between servers.

use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::support_product;
use std::time::{Duration, Instant};

use mail4agent_server::federation::enc;
use reqwest::blocking::Client;
use serde_json::{json, Value};

pub struct Srv {
    pub name: &'static str,
    pub addr: String,
    pub token: String,
    /// Product server in front of this core; clients talk to it.
    pub purl: String,
    pub device: String,
    pub user: String,
    pub dir: PathBuf,
    pub child: Option<Child>,
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

pub fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

pub fn key_hex() -> String {
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut b).unwrap();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Srv {
    pub fn call(&self, c: &Client, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let url = format!("{}{}", self.purl, path);
        let mut r = c.request(method.parse().unwrap(), url).bearer_auth(&self.token);
        if let Some(b) = body {
            r = r.json(&b);
        }
        let resp = r.send().unwrap();
        (resp.status().as_u16(), resp.json().unwrap_or(Value::Null))
    }
}

pub fn poll<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let t = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(t.elapsed() < Duration::from_secs(25), "timed out waiting for: {what}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn bodies(a: &Srv, c: &Client, room: &str) -> Vec<String> {
    let (_, v) = a.call(c, "GET", &format!("/client/v3/rooms/{}/messages?dir=b&limit=50", enc(room)), None);
    v["chunk"].as_array().cloned().unwrap_or_default().iter().filter_map(|e| e["content"]["body"].as_str().or_else(|| e["content"]["ciphertext"].as_str()).map(str::to_string)).collect()
}

pub fn send(a: &Srv, c: &Client, room: &str, ty: &str, txn: &str, content: Value) -> Value {
    let (st, v) = a.call(c, "PUT", &format!("/client/v3/rooms/{}/send/{}/{}", enc(room), ty, txn), Some(content));
    assert_eq!(st, 200, "send {txn}: {v}");
    v
}

/// Event ids of one room as one server lists them (newest first).
pub fn event_ids(a: &Srv, c: &Client, room: &str) -> Vec<String> {
    let (_, v) = a.call(c, "GET", &format!("/client/v3/rooms/{}/messages?dir=b&limit=100", enc(room)), None);
    v["chunk"].as_array().cloned().unwrap_or_default().iter().filter_map(|e| e["event_id"].as_str().map(str::to_string)).collect()
}

pub fn is_hash_id(id: &str) -> bool {
    id.len() == 44 && id.starts_with('$') && !id.contains(['+', '/', '='])
}

pub fn start_node(name: &'static str, localpart: &str, port: u16, peers: &[(&str, u16)]) -> Srv {
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
        .env("M4A_FEDERATION_PEER_OVERRIDE", peers.iter().map(|(n, p)| format!("{n}=http://127.0.0.1:{p}")).collect::<Vec<_>>().join(","))
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

/// A controllable TCP/HTTP hop between two servers: while down it drops connections (a network
/// partition); while `tamper` is set it alters the first event of every get_missing_events answer.
pub struct Link {
    pub port: u16,
    up: Arc<AtomicBool>,
    tamper: Arc<AtomicBool>,
}

impl Link {
    pub fn new(target_port: u16) -> Link {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (up, tamper) = (Arc::new(AtomicBool::new(true)), Arc::new(AtomicBool::new(false)));
        let (u2, t2) = (up.clone(), tamper.clone());
        std::thread::spawn(move || {
            for conn in l.incoming().flatten() {
                if !u2.load(Ordering::SeqCst) {
                    continue; // dropped: the sender sees a failed request
                }
                let t3 = t2.clone();
                std::thread::spawn(move || {
                    let _ = relay(conn, target_port, t3.load(Ordering::SeqCst));
                });
            }
        });
        Link { port, up, tamper }
    }
    pub fn set_up(&self, up: bool) {
        self.up.store(up, Ordering::SeqCst);
    }
    pub fn set_tamper(&self, on: bool) {
        self.tamper.store(on, Ordering::SeqCst);
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn relay(mut client: TcpStream, target: u16, tamper: bool) -> std::io::Result<()> {
    use std::io::Write;
    client.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut req = Vec::new();
    let mut buf = [0u8; 8192];
    let (head_end, body_len) = loop {
        let n = client.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        req.extend_from_slice(&buf[..n]);
        if let Some(p) = find(&req, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&req[..p]).to_ascii_lowercase();
            let len = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse::<usize>().ok()).unwrap_or(0);
            break (p + 4, len);
        }
    };
    while req.len() < head_end + body_len {
        let n = client.read(&mut buf)?;
        if n == 0 {
            break;
        }
        req.extend_from_slice(&buf[..n]);
    }
    let head = String::from_utf8_lossy(&req[..head_end]).to_string();
    let request_line = head.lines().next().unwrap_or("").to_string();
    let mut up = TcpStream::connect(("127.0.0.1", target))?;
    let mut fwd: Vec<String> = head.trim_end().lines().filter(|l| !l.to_ascii_lowercase().starts_with("connection:")).map(str::to_string).collect();
    fwd.push("Connection: close".into());
    up.write_all(format!("{}\r\n\r\n", fwd.join("\r\n")).as_bytes())?;
    up.write_all(&req[head_end..])?;
    let mut resp = Vec::new();
    up.read_to_end(&mut resp)?;
    if tamper && request_line.contains("get_missing_events") {
        if let Some(p) = find(&resp, b"\r\n\r\n") {
            let (h, body) = (String::from_utf8_lossy(&resp[..p]).to_string(), &resp[p + 4..]);
            if let Ok(mut v) = serde_json::from_slice::<Value>(body) {
                if let Some(e) = v["events"].get_mut(0) {
                    let ts = e["origin_server_ts"].as_u64().unwrap_or(1);
                    e["origin_server_ts"] = json!(ts + 1);
                    let nb = serde_json::to_vec(&v).unwrap();
                    let mut lines: Vec<String> = h.lines().filter(|l| !l.to_ascii_lowercase().starts_with("content-length:")).map(str::to_string).collect();
                    lines.push(format!("content-length: {}", nb.len()));
                    resp = format!("{}\r\n\r\n", lines.join("\r\n")).into_bytes();
                    resp.extend_from_slice(&nb);
                }
            }
        }
    }
    client.write_all(&resp)
}
