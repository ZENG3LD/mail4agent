//! The machine client's one socket. The client opens it against the
//! homeserver it already has. Room text for a session registered on this
//! connection is pushed here. The ack goes out before the text is handed
//! to that session. This path does not POST and it does not call `/sync`.

use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tungstenite::{stream::MaybeTlsStream, Message};

use crate::{clip_public, ShellError};

/// One room text the homeserver pushed for a single session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushedRoomEvent {
    /// Room id.
    pub room: String,
    /// Sender mxid.
    pub sender: String,
    /// Plaintext body. Ciphertext is not pushed on this socket.
    pub body: String,
    /// Matrix event id.
    pub event_id: String,
}

struct Incoming {
    recipient: String,
    event: PushedRoomEvent,
}

pub(crate) struct PushLink {
    inbox: Arc<Mutex<Vec<Incoming>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for PushLink {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl PushLink {
    pub(crate) fn open(base_url: &str, tokens: Vec<String>) -> Result<Self, ShellError> {
        if tokens.is_empty() {
            return Err(ShellError::Http("push socket has no session".into()));
        }
        let url = push_ws_url(base_url)?;
        let inbox = Arc::new(Mutex::new(Vec::new()));
        let ready = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let worker = thread::spawn({
            let inbox = Arc::clone(&inbox);
            let ready = Arc::clone(&ready);
            let failed = Arc::clone(&failed);
            let stop = Arc::clone(&stop);
            move || worker_main(url, tokens, inbox, ready, failed, stop)
        });
        let start = Instant::now();
        loop {
            if ready.load(Ordering::Acquire) {
                return Ok(Self {
                    inbox,
                    stop,
                    worker: Some(worker),
                });
            }
            if let Some(err) = failed.lock().unwrap_or_else(|err| err.into_inner()).clone() {
                stop.store(true, Ordering::Release);
                let _ = worker.join();
                return Err(ShellError::Http(err));
            }
            if start.elapsed() > Duration::from_secs(5) {
                stop.store(true, Ordering::Release);
                let _ = worker.join();
                return Err(ShellError::Http("push socket did not register".into()));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    pub(crate) fn drain(&self) -> Vec<(String, PushedRoomEvent)> {
        self.inbox
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .drain(..)
            .map(|incoming| (incoming.recipient, incoming.event))
            .collect()
    }
}

fn push_ws_url(base: &str) -> Result<String, ShellError> {
    let url = reqwest::Url::parse(base).map_err(|_| ShellError::BaseUrl)?;
    let scheme = match url.scheme() {
        "http" => "ws",
        "https" => {
            return Err(ShellError::Http(
                "push socket is opened from an http homeserver, not https".into(),
            ));
        }
        _ => return Err(ShellError::BaseUrl),
    };
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or(ShellError::BaseUrl)?;
    let mut raw = format!("{scheme}://{host}");
    if let Some(port) = url.port() {
        raw.push(':');
        raw.push_str(&port.to_string());
    }
    raw.push_str("/client/v3/push");
    Ok(raw)
}

fn worker_main(
    url: String,
    mut tokens: Vec<String>,
    inbox: Arc<Mutex<Vec<Incoming>>>,
    ready: Arc<AtomicBool>,
    failed: Arc<Mutex<Option<String>>>,
    stop: Arc<AtomicBool>,
) {
    let result = run_socket(&url, &mut tokens, &inbox, &ready, &stop);
    for token in &mut tokens {
        zeroize::Zeroize::zeroize(token);
    }
    if let Err(err) = result {
        if !stop.load(Ordering::Acquire) {
            *failed.lock().unwrap_or_else(|err| err.into_inner()) = Some(err);
        }
    }
}

fn run_socket(
    url: &str,
    tokens: &mut [String],
    inbox: &Mutex<Vec<Incoming>>,
    ready: &AtomicBool,
    stop: &AtomicBool,
) -> Result<(), String> {
    let (mut socket, _response) =
        tungstenite::connect(url).map_err(|err| clip_public(err.to_string()))?;
    match socket.get_mut() {
        MaybeTlsStream::Plain(tcp) => {
            let _ = tcp.set_read_timeout(Some(Duration::from_millis(200)));
        }
        _ => {}
    }
    let register = serde_json::json!({ "type": "register", "tokens": tokens }).to_string();
    for token in tokens.iter_mut() {
        zeroize::Zeroize::zeroize(token);
    }
    socket
        .send(Message::text(register))
        .map_err(|err| clip_public(err.to_string()))?;
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        let message = match socket.read() {
            Ok(message) => message,
            Err(tungstenite::Error::Io(err))
                if matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
            {
                continue;
            }
            Err(err) => return Err(clip_public(err.to_string())),
        };
        let text = match message {
            Message::Text(text) => text,
            Message::Close(_) => return Err("push socket closed".into()),
            _ => continue,
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(text.as_str()) else {
            continue;
        };
        match value.get("type").and_then(|item| item.as_str()) {
            Some("registered") => ready.store(true, Ordering::Release),
            Some("event") => {
                if let Some(envelope_id) = value.get("envelope_id").and_then(|item| item.as_str()) {
                    let ack = serde_json::json!({ "type": "ack", "envelope_id": envelope_id })
                        .to_string();
                    socket
                        .send(Message::text(ack))
                        .map_err(|err| clip_public(err.to_string()))?;
                }
                if let Some(incoming) = parse_event(&value) {
                    inbox
                        .lock()
                        .unwrap_or_else(|err| err.into_inner())
                        .push(incoming);
                }
            }
            _ => {}
        }
    }
}

fn parse_event(value: &serde_json::Value) -> Option<Incoming> {
    if value.get("access_token").is_some() || value.get("bearer").is_some() {
        return None;
    }
    let event = value.get("event")?;
    if event.get("access_token").is_some() || event.get("bearer").is_some() {
        return None;
    }
    let room = event.get("room")?.as_str()?.to_string();
    let sender = event.get("sender")?.as_str()?.to_string();
    let body = event.get("body")?.as_str()?.to_string();
    let event_id = event.get("event_id")?.as_str()?.to_string();
    let recipient = event.get("recipient")?.as_str()?.to_string();
    if room.is_empty() || sender.is_empty() || event_id.is_empty() || recipient.is_empty() {
        return None;
    }
    Some(Incoming {
        recipient,
        event: PushedRoomEvent {
            room,
            sender,
            body,
            event_id,
        },
    })
}
