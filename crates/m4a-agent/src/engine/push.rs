//! The client's push socket. The client opens it against the
//! homeserver it already has. Push contract **v1**: metadata only
//! (`room`, `sender`, `event_id`, `recipient`, `wire_type`) — never a
//! plaintext `body`. The ack goes out before the event is handed to that
//! session. This path does not POST. The client drives `/sync` and
//! decrypts after the push.

use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tungstenite::{stream::MaybeTlsStream, Message};

use super::http::clip_public;
use crate::error::AgentError;

/// One room event the homeserver pushed for a single session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushedRoomEvent {
    /// Room id.
    pub room: String,
    /// Sender mxid.
    pub sender: String,
    /// Always empty on push v1 (server never sends plaintext). Kept so
    /// call sites compiling against this struct stay stable; wake uses
    /// `/sync` + decrypt, not this field.
    pub body: String,
    /// Matrix event id.
    pub event_id: String,
    /// `m.room.message` or `m.room.encrypted`.
    pub wire_type: String,
}

struct Incoming {
    recipient: String,
    event: PushedRoomEvent,
}

pub struct PushLink {
    inbox: Arc<Mutex<Vec<Incoming>>>,
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl Drop for PushLink {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

impl PushLink {
    /// One socket for all `tokens`, or with `separate` (product mode: a handshake
    /// is vouched for one identity) one socket per token sharing one inbox.
    pub fn open(base_url: &str, keep_prefix: bool, tokens: Vec<String>, separate: bool) -> Result<Self, AgentError> {
        if tokens.is_empty() {
            return Err(AgentError::Transport("push socket has no session".into()));
        }
        let url = push_ws_url(base_url, keep_prefix)?;
        let inbox = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let groups: Vec<Vec<String>> = if separate { tokens.into_iter().map(|t| vec![t]).collect() } else { vec![tokens] };
        let mut link = Self { inbox: Arc::clone(&inbox), stop: Arc::clone(&stop), workers: Vec::new() };
        let mut readies = Vec::new();
        let mut faileds = Vec::new();
        for group in groups {
            let ready = Arc::new(AtomicBool::new(false));
            let failed = Arc::new(Mutex::new(None));
            let worker = thread::spawn({
                let (url, inbox, ready, failed, stop) = (url.clone(), Arc::clone(&inbox), Arc::clone(&ready), Arc::clone(&failed), Arc::clone(&stop));
                move || worker_main(url, group, inbox, ready, failed, stop)
            });
            link.workers.push(worker);
            readies.push(ready);
            faileds.push(failed);
        }
        let start = Instant::now();
        loop {
            if readies.iter().all(|r| r.load(Ordering::Acquire)) {
                return Ok(link);
            }
            for failed in &faileds {
                if let Some(err) = failed.lock().unwrap_or_else(|err| err.into_inner()).clone() {
                    return Err(AgentError::Transport(err)); // Drop stops and joins the workers
                }
            }
            if start.elapsed() > Duration::from_secs(5) {
                return Err(AgentError::Transport("push socket did not register".into()));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn drain(&self) -> Vec<(String, PushedRoomEvent)> {
        self.inbox
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .drain(..)
            .map(|incoming| (incoming.recipient, incoming.event))
            .collect()
    }
}

fn push_ws_url(base: &str, keep_prefix: bool) -> Result<String, AgentError> {
    let url = reqwest::Url::parse(base).map_err(|_| AgentError::Protocol("not a valid server URL".into()))?;
    let scheme = match url.scheme() {
        "http" => "ws",
        "https" => "wss",
        _ => return Err(AgentError::Protocol("not a valid server URL".into())),
    };
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or(AgentError::Protocol("not a valid server URL".into()))?;
    let mut raw = format!("{scheme}://{host}");
    if let Some(port) = url.port() {
        raw.push(':');
        raw.push_str(&port.to_string());
    }
    raw.push_str(if keep_prefix { "/_matrix/client/v3/push" } else { "/client/v3/push" });
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
    // The first token also rides the handshake as a bearer: a product proxy
    // authenticates the handshake with it and signs it; a plain server ignores it.
    let mut request = tungstenite::client::IntoClientRequest::into_client_request(url)
        .map_err(|err| clip_public(err.to_string()))?;
    if let Some(first) = tokens.first() {
        if let Ok(value) = tungstenite::http::HeaderValue::from_str(&format!("Bearer {first}")) {
            request.headers_mut().insert(tungstenite::http::header::AUTHORIZATION, value);
        }
    }
    let (mut socket, _response) =
        tungstenite::connect(request).map_err(|err| clip_public(err.to_string()))?;
    match socket.get_mut() {
        MaybeTlsStream::Plain(tcp) => {
            let _ = tcp.set_read_timeout(Some(Duration::from_millis(200)));
        }
        MaybeTlsStream::Rustls(tls) => {
            let _ = tls.sock.set_read_timeout(Some(Duration::from_millis(200)));
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
    let event_id = event.get("event_id")?.as_str()?.to_string();
    let recipient = event.get("recipient")?.as_str()?.to_string();
    let wire_type = event
        .get("wire_type")
        .and_then(|item| item.as_str())
        .unwrap_or("m.room.message")
        .to_string();
    // Push v1: never trust/require body. Always empty locally.
    let body = String::new();
    if room.is_empty() || sender.is_empty() || event_id.is_empty() || recipient.is_empty() || wire_type.is_empty()
    {
        return None;
    }
    Some(Incoming {
        recipient,
        event: PushedRoomEvent {
            room,
            sender,
            body,
            event_id,
            wire_type,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_homeserver_opens_the_push_socket_as_wss() {
        let url = push_ws_url("https://example.test/ignored", false).expect("url");
        assert_eq!(url, "wss://example.test/client/v3/push");
        let local = push_ws_url("http://127.0.0.1:9", false).expect("local");
        assert_eq!(local, "ws://127.0.0.1:9/client/v3/push");
    }

    #[test]
    fn encrypted_push_keeps_the_event_id_and_drops_any_body() {
        let value = serde_json::json!({
            "type": "event",
            "v": 1,
            "envelope_id": "p1",
            "event": {
                "room": "!room:example",
                "sender": "@a:example",
                "event_id": "$evt",
                "recipient": "@b:example",
                "wire_type": "m.room.encrypted",
                "body": "not-plaintext",
            }
        });
        let incoming = parse_event(&value).expect("parsed");
        assert_eq!(incoming.recipient, "@b:example");
        assert_eq!(incoming.event.event_id, "$evt");
        assert_eq!(incoming.event.wire_type, "m.room.encrypted");
        assert!(incoming.event.body.is_empty());
        assert_eq!(incoming.event.room, "!room:example");
        assert_eq!(incoming.event.sender, "@a:example");
    }

    #[test]
    fn v1_plaintext_wire_type_parses_without_body() {
        let value = serde_json::json!({
            "type": "event",
            "v": 1,
            "envelope_id": "p2",
            "event": {
                "room": "!room:example",
                "sender": "@a:example",
                "event_id": "$evt2",
                "recipient": "@b:example",
                "wire_type": "m.room.message",
            }
        });
        let incoming = parse_event(&value).expect("v1 without body must parse");
        assert!(incoming.event.body.is_empty());
        assert_eq!(incoming.event.wire_type, "m.room.message");
        assert_eq!(incoming.event.event_id, "$evt2");
    }
}
