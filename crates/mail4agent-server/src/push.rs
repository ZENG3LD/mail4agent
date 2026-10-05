//! Room push for the one socket a machine client opens.
//!
//! This is not `/sync` and it is not an outbound webhook. The client
//! connects. After it registers the device bearers it already holds, a
//! new `m.room.message` with a text `body`, or a new `m.room.encrypted`
//! event, is written down that socket for each other member whose device
//! is on it. History is not replayed. An encrypted event carries the
//! event id, room, sender, recipient, and wire type. This server does
//! not hold Megolm keys and does not invent a plaintext body. The client
//! that holds the keys decrypts after the push.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use tokio::sync::mpsc;

use crate::error::MatrixError;

struct Subscription {
    id: u64,
    users: HashSet<i64>,
    tx: mpsc::UnboundedSender<String>,
}

/// Sockets keyed by the Matrix user ids registered on them.
pub struct PushHub {
    next_sub: AtomicU64,
    next_envelope: AtomicU64,
    subs: Mutex<Vec<Subscription>>,
}

impl Default for PushHub {
    fn default() -> Self {
        Self::new()
    }
}

impl PushHub {
    pub fn new() -> Self {
        Self {
            next_sub: AtomicU64::new(1),
            next_envelope: AtomicU64::new(1),
            subs: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn subscribe(&self, users: Vec<i64>) -> (u64, mpsc::UnboundedReceiver<String>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let id = self.next_sub.fetch_add(1, Ordering::Relaxed);
        let users = users.into_iter().collect();
        self.subs
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push(Subscription { id, users, tx });
        (id, rx)
    }

    pub(crate) fn unsubscribe(&self, id: u64) {
        self.subs
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .retain(|sub| sub.id != id);
    }

    fn next_envelope_id(&self) -> String {
        let n = self.next_envelope.fetch_add(1, Ordering::Relaxed);
        format!("p{n}")
    }

    fn publish(&self, user_id: i64, frame: &str) {
        let mut subs = self.subs.lock().unwrap_or_else(|err| err.into_inner());
        subs.retain(|sub| {
            if !sub.users.contains(&user_id) {
                return true;
            }
            sub.tx.send(frame.to_string()).is_ok()
        });
    }

    pub(crate) fn publish_room_text(&self, text: &RoomTextPush) {
        for (user_id, mxid) in &text.recipients {
            let frame = if text.wire_type == "m.room.encrypted" {
                encrypted_event_frame(
                    &self.next_envelope_id(),
                    &text.room_id,
                    &text.sender,
                    &text.event_id,
                    mxid,
                )
            } else {
                event_frame(
                    &self.next_envelope_id(),
                    &text.room_id,
                    &text.sender,
                    text.body.as_deref().unwrap_or(""),
                    &text.event_id,
                    mxid,
                )
            };
            self.publish(*user_id, &frame);
        }
    }
}

/// One accepted room event for members other than the sender.
/// `body` is set only for plaintext `m.room.message`.
pub(crate) struct RoomTextPush {
    pub room_id: String,
    pub sender: String,
    pub body: Option<String>,
    pub wire_type: String,
    pub event_id: String,
    pub recipients: Vec<(i64, String)>,
}

pub(crate) fn recipients_for_room_text(
    conn: &rusqlite::Connection,
    event_type: &str,
    content_str: &str,
    room_id: &str,
    sender_user_id: i64,
    sender_mxid: &str,
    event_id: &str,
    wake_ids: &HashSet<i64>,
) -> Result<Option<RoomTextPush>, MatrixError> {
    let (wire_type, body) = if event_type == "m.room.message" {
        let Ok(content) = serde_json::from_str::<serde_json::Value>(content_str) else {
            return Ok(None);
        };
        let Some(body) = content
            .get("body")
            .and_then(|value| value.as_str())
            .filter(|body| !body.is_empty())
        else {
            return Ok(None);
        };
        ("m.room.message", Some(body.to_string()))
    } else if event_type == "m.room.encrypted" {
        // Ciphertext is not a body. A `body` field inside the encrypted
        // content is not plaintext and is not copied onto the frame.
        ("m.room.encrypted", None)
    } else {
        return Ok(None);
    };
    let mut recipients = Vec::new();
    let mut seen = HashSet::new();
    for user_id in wake_ids {
        if *user_id == sender_user_id || !seen.insert(*user_id) {
            continue;
        }
        let Some(mxid) = crate::store::mxid_of(conn, *user_id)? else {
            continue;
        };
        recipients.push((*user_id, mxid));
    }
    if recipients.is_empty() {
        return Ok(None);
    }
    Ok(Some(RoomTextPush {
        room_id: room_id.to_string(),
        sender: sender_mxid.to_string(),
        body,
        wire_type: wire_type.to_string(),
        event_id: event_id.to_string(),
        recipients,
    }))
}

/// Outer object says an event happened. The inner object is the room text.
/// `recipient` is which session on the shared socket the text is for.
pub(crate) fn event_frame(
    envelope_id: &str,
    room: &str,
    sender: &str,
    body: &str,
    event_id: &str,
    recipient: &str,
) -> String {
    serde_json::json!({
        "type": "event",
        "envelope_id": envelope_id,
        "event": {
            "room": room,
            "sender": sender,
            "body": body,
            "event_id": event_id,
            "recipient": recipient,
        },
    })
    .to_string()
}

/// Encrypted push. No `body`: the server cannot decrypt Megolm.
pub(crate) fn encrypted_event_frame(
    envelope_id: &str,
    room: &str,
    sender: &str,
    event_id: &str,
    recipient: &str,
) -> String {
    serde_json::json!({
        "type": "event",
        "envelope_id": envelope_id,
        "event": {
            "room": room,
            "sender": sender,
            "event_id": event_id,
            "recipient": recipient,
            "wire_type": "m.room.encrypted",
        },
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_frame_is_an_envelope_around_room_sender_body_and_event_id() {
        let frame = event_frame(
            "p1",
            "!room:example",
            "@sender:example",
            "hello",
            "$evt",
            "@b:example",
        );
        let value: serde_json::Value = serde_json::from_str(&frame).expect("json");
        assert_eq!(value["type"], "event");
        assert_eq!(value["envelope_id"], "p1");
        assert_eq!(value["event"]["room"], "!room:example");
        assert_eq!(value["event"]["sender"], "@sender:example");
        assert_eq!(value["event"]["body"], "hello");
        assert_eq!(value["event"]["event_id"], "$evt");
        assert_eq!(value["event"]["recipient"], "@b:example");
        assert!(value.get("access_token").is_none());
        assert!(value.get("bearer").is_none());
        assert!(value["event"].get("access_token").is_none());
    }

    #[test]
    fn encrypted_event_frame_names_the_wire_type_and_has_no_body() {
        let frame = encrypted_event_frame(
            "p2",
            "!room:example",
            "@sender:example",
            "$evt",
            "@b:example",
        );
        let value: serde_json::Value = serde_json::from_str(&frame).expect("json");
        assert_eq!(value["type"], "event");
        assert_eq!(value["envelope_id"], "p2");
        assert_eq!(value["event"]["room"], "!room:example");
        assert_eq!(value["event"]["sender"], "@sender:example");
        assert_eq!(value["event"]["event_id"], "$evt");
        assert_eq!(value["event"]["recipient"], "@b:example");
        assert_eq!(value["event"]["wire_type"], "m.room.encrypted");
        assert!(value["event"].get("body").is_none());
        assert!(value.get("access_token").is_none());
        assert!(value.get("bearer").is_none());
        assert!(!frame.contains("ciphertext"));
    }
}
