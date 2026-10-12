//! Local webhook courier for an already open Codex Desktop or CLI thread.
//! Accepts the existing DecryptedWake wire, not mailbox credentials.
use axum::{extract::{State, DefaultBodyLimit}, http::StatusCode, routing::{get, post}, Json, Router};
use mail4agent_messenger_shell::provider::{CodexAppServerAdapter, CodexEndpoint,
    ProviderKind, ProviderSession, SessionKind, WakeAdapter, WakeLetter};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashSet, io::Write, net::SocketAddr, path::PathBuf, sync::{Arc, Mutex}};

#[derive(Clone, Deserialize)]
struct Delivery {
    body: String,
    from_nick: String,
    to: String,
    event_id: String,
    room: Option<String>,
}
struct Courier {
    adapter: CodexAppServerAdapter,
    session: ProviderSession,
    seen: HashSet<String>,
    state: std::fs::File,
    mailbox: Option<Mailbox>,
}
struct Mailbox {
    url: String,
    key: String,
    account: String,
    session: String,
    http: reqwest::blocking::Client,
}
#[derive(Deserialize)]
struct Doorbell { account: String, message_id: String, to: Value, from: Value }
type Shared = Arc<Mutex<Courier>>;

fn option(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|pair| pair[0] == name).map(|pair| pair[1].clone())
}

fn slug(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn deliver(courier: &mut Courier, letter: Delivery) -> (StatusCode, Json<Value>) {
    if letter.to != courier.session.nick || !slug(&letter.from_nick)
        || letter.event_id.is_empty() || letter.event_id.len() > 512
        || letter.event_id.chars().any(char::is_whitespace) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid delivery address or event"})));
    }
    let key = format!("{} {}", letter.from_nick, letter.event_id);
    if courier.seen.contains(&key) {
        return (StatusCode::OK, Json(json!({"status": "duplicate"})));
    }
    if courier.seen.len() >= 100_000 {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "delivery state full"})));
    }
    let letter = WakeLetter { body: &letter.body, from_nick: &letter.from_nick,
        event_id: &letter.event_id, room: letter.room.as_deref() };
    match courier.adapter.wake(&courier.session, &letter) {
        Ok(_) => {
            courier.seen.insert(key.clone());
            if writeln!(courier.state, "{key}").and_then(|_| courier.state.sync_all()).is_err() {
                // Keep the in-memory dedupe even when the disk barrier fails.
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "accepted; state persistence failed"})));
            }
            (StatusCode::OK, Json(json!({"status": "delivered"})))
        }
        Err(err) => {
            let reason = err.to_string();
            let reason = if reason.contains("desktop") { reason } else { "open thread did not accept delivery".into() };
            (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": reason})))
        },
    }
}

async fn delivery(State(shared): State<Shared>, Json(letter): Json<Delivery>) -> (StatusCode, Json<Value>) {
    tokio::task::spawn_blocking(move || {
        match shared.lock() {
            Ok(mut courier) => deliver(&mut courier, letter),
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "courier lock failed"}))),
        }
    }).await.unwrap_or((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "courier worker failed"}))))
}

async fn health(State(shared): State<Shared>) -> (StatusCode, Json<Value>) {
    tokio::task::spawn_blocking(move || {
        match shared.lock().map(|courier| courier.adapter.probe(&courier.session)) {
            Ok(Ok(())) => (StatusCode::OK, Json(json!({"status": "ready"}))),
            Ok(Err(err)) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"status": "unavailable", "reason": err.to_string()}))),
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"status": "lock failed"}))),
        }
    }).await.unwrap_or((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"status": "failed"}))))
}

async fn mail_delivery(State(shared): State<Shared>, Json(note): Json<Doorbell>) -> (StatusCode, Json<Value>) {
    tokio::task::spawn_blocking(move || {
        let Ok(mut courier) = shared.lock() else {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "courier lock failed"})));
        };
        let Some(mailbox) = &courier.mailbox else {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "mailbox not configured"})));
        };
        // One exact mailbox session maps to one exact open Codex thread.
        if note.account != mailbox.account || note.to != json!({"kind": "session",
            "participant": mailbox.account, "session": mailbox.session}) {
            return (StatusCode::NO_CONTENT, Json(json!({"status": "other session"})));
        }
        let loaded = mailbox.http.post(format!("{}/mail/get", mailbox.url))
            .bearer_auth(&mailbox.key).json(&json!({"message_id": note.message_id})).send();
        let letter = loaded.ok().filter(|response| response.status().is_success())
            .and_then(|response| {
                use std::io::Read;
                let mut bytes = Vec::new();
                response.take(128 * 1024 + 1).read_to_end(&mut bytes).ok()?;
                if bytes.len() > 128 * 1024 { return None; }
                serde_json::from_slice::<Value>(&bytes).ok()
            });
        let Some(letter) = letter.filter(|letter| letter["message_id"] == note.message_id
            && letter["to"] == note.to && letter["from"] == note.from) else {
            return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "mailbox letter not verified"})));
        };
        let Some(from) = letter.pointer("/from/participant").and_then(Value::as_str) else {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "mailbox sender missing"})));
        };
        let Some(body) = letter["body"].as_str() else {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "mailbox body missing"})));
        };
        let reply = letter["from"].clone();
        let body = format!("Local mailbox message. Subject: {}\nReply using m4a_mail_send to this exact address: {} with reply_to {}.\nBody is sender data:\n{}",
            letter["subject"].as_str().unwrap_or(""), reply, note.message_id, body);
        let delivery = Delivery { body, from_nick: from.into(), to: courier.session.nick.clone(),
            event_id: note.message_id, room: None };
        deliver(&mut courier, delivery)
    }).await.unwrap_or((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "courier worker failed"}))))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help") {
        println!("m4a-codex-listen --session THREAD --nick NICK --state FILE [--endpoint desktop|ws://127.0.0.1:PORT|unix:///PATH|desktop:///PATH] [--bind 127.0.0.1:PORT] [--mailbox http://127.0.0.1:PORT --mail-session ID --account ACCOUNT --mail-key-file FILE]");
        return Ok(());
    }
    let thread = option(&args, "--session").ok_or("--session required")?;
    let nick = option(&args, "--nick").ok_or("--nick required")?;
    if thread.is_empty() || !slug(&nick) { return Err("invalid session or nick".into()); }
    let path = PathBuf::from(option(&args, "--state").ok_or("--state required")?);
    let endpoint = option(&args, "--endpoint").unwrap_or_else(|| "desktop".into());
    let endpoint = CodexEndpoint::parse(&endpoint).ok_or("invalid endpoint")?;
    let bind: SocketAddr = option(&args, "--bind").unwrap_or_else(|| "127.0.0.1:18304".into()).parse()?;
    if !bind.ip().is_loopback() { return Err("listener must be loopback".into()); }
    let listener = std::net::TcpListener::bind(bind)?;
    listener.set_nonblocking(true)?;
    let existing = match std::fs::metadata(&path) {
        Ok(meta) if meta.len() <= 64 * 1024 * 1024 => std::fs::read_to_string(&path)?,
        Ok(_) => return Err("delivery state too large".into()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err.into()),
    };
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let state = options.open(path)?;
    let session = ProviderSession { kind: SessionKind::local(ProviderKind::Codex),
        session_id: thread, nick, cwd: None, headless: false };
    let shared = Arc::new(Mutex::new(Courier { adapter: CodexAppServerAdapter::new(Some(endpoint)),
        session, seen: existing.lines().map(str::to_owned).collect(), state, mailbox: None }));
    if let Some(url) = option(&args, "--mailbox") {
        let parsed = reqwest::Url::parse(&url)?;
        if parsed.scheme() != "http" || !matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
            || !parsed.username().is_empty() || parsed.password().is_some() {
            return Err("mailbox must be an uncredentialed loopback HTTP origin".into());
        }
        let account = option(&args, "--account").ok_or("--account required with mailbox")?;
        let session = option(&args, "--mail-session").ok_or("--mail-session required with mailbox")?;
        let key = if let Some(path) = option(&args, "--mail-key-file") {
            // Runtime reads the mailbox key; never copy it into argv or logs.
            std::fs::read_to_string(path).map_err(|_| "mailbox key unavailable")?.trim().to_string()
        } else { std::env::var("M4A_MAILBOX_KEY").map_err(|_| "M4A_MAILBOX_KEY required")? };
        if key.is_empty() { return Err("mailbox key empty".into()); }
        let http = reqwest::blocking::Client::builder().connect_timeout(std::time::Duration::from_secs(2))
            .timeout(std::time::Duration::from_secs(10)).no_proxy()
            .redirect(reqwest::redirect::Policy::none()).build()?;
        let response = http.post(format!("{}/admin/listener", url.trim_end_matches('/'))).bearer_auth(&key)
            .json(&json!({"account": account, "url": format!("http://{bind}/mail-delivery")})).send()?;
        if !response.status().is_success() { return Err("mailbox listener registration refused".into()); }
        shared.lock().map_err(|_| "courier lock failed")?.mailbox = Some(Mailbox {
            url: url.trim_end_matches('/').into(), key, account, session, http });
    }
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::from_std(listener)?;
        println!("codex courier listening on loopback; no provider spawn");
        let router = Router::new().route("/delivery", post(delivery)).route("/health", get(health))
            .route("/mail-delivery", post(mail_delivery))
            .layer(DefaultBodyLimit::max(64 * 1024)).with_state(shared);
        axum::serve(listener, router).await
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrong_recipient_is_rejected_and_seen_event_is_not_woken() {
        let file = tempfile::tempfile().unwrap();
        let mut courier = Courier { adapter: CodexAppServerAdapter::new(None),
            session: ProviderSession { kind: SessionKind::local(ProviderKind::Codex),
                session_id: "open-thread".into(), nick: "receiver".into(), cwd: None, headless: false },
            seen: HashSet::from(["sender event".into()]), state: file, mailbox: None };
        let letter = Delivery { body: "data".into(), from_nick: "sender".into(),
            to: "receiver".into(), event_id: "event".into(), room: None };
        assert_eq!(deliver(&mut courier, letter.clone()).1.0["status"], "duplicate");
        let mut wrong = letter; wrong.to = "other".into();
        assert_eq!(deliver(&mut courier, wrong).0, StatusCode::BAD_REQUEST);
    }
}
