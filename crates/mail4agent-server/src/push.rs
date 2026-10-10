//! Room push for the one socket a machine client opens.
//!
//! This is not `/sync` and it is not an outbound webhook. The client
//! connects. After it registers the device bearers it already holds, a
//! new `m.room.message` or `m.room.encrypted` event is written down that
//! socket for each other member whose device is on it. History is not
//! replayed.
//!
//! # Push contract v1 (hard cutover)
//!
//! Frames carry `"v": 1` and **never** a plaintext `body` — only room,
//! sender, event_id, recipient, wire_type. The client that holds Megolm
//! keys (or can `/sync` the event) decrypts after the push. No legacy
//! flag; peers must update.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use tokio::sync::mpsc;

use crate::error::MatrixError;

/// Top-level push schema version.
pub const PUSH_VERSION: u32 = 1;

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

    /// Drop every push connection that speaks for `user_id` (credential revoked, account
    /// deleted): the sockets end, clients must reconnect and prove themselves again.
    pub(crate) fn close_user(&self, user_id: i64) {
        self.subs.lock().unwrap_or_else(|err| err.into_inner()).retain(|sub| !sub.users.contains(&user_id));
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
            let frame = metadata_event_frame(
                &self.next_envelope_id(),
                &text.room_id,
                &text.sender,
                &text.event_id,
                mxid,
                &text.wire_type,
            );
            self.publish(*user_id, &frame);
        }
    }
}

/// One accepted room event for members other than the sender.
/// Plaintext body of a stored message is never copied onto the push frame.
pub(crate) struct RoomTextPush {
    pub room_id: String,
    pub sender: String,
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
    let wire_type = if event_type == "m.room.message" {
        // Require a non-empty stored body so empty notices do not wake;
        // the body itself is never put on the push frame.
        let Ok(content) = serde_json::from_str::<serde_json::Value>(content_str) else {
            return Ok(None);
        };
        let Some(body) = content.get("body").and_then(|value| value.as_str()).filter(|b| !b.is_empty()) else {
            return Ok(None);
        };
        let _ = body;
        "m.room.message"
    } else if event_type == "m.room.encrypted" {
        "m.room.encrypted"
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
        wire_type: wire_type.to_string(),
        event_id: event_id.to_string(),
        recipients,
    }))
}

/// Push v1 metadata frame — never includes `body`.
pub(crate) fn metadata_event_frame(
    envelope_id: &str,
    room: &str,
    sender: &str,
    event_id: &str,
    recipient: &str,
    wire_type: &str,
) -> String {
    serde_json::json!({
        "type": "event",
        "v": PUSH_VERSION,
        "envelope_id": envelope_id,
        "event": {
            "room": room,
            "sender": sender,
            "event_id": event_id,
            "recipient": recipient,
            "wire_type": wire_type,
        },
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_frame_has_version_wire_type_and_never_a_body() {
        let frame = metadata_event_frame(
            "p1",
            "!room:example",
            "@sender:example",
            "$evt",
            "@b:example",
            "m.room.message",
        );
        let value: serde_json::Value = serde_json::from_str(&frame).expect("json");
        assert_eq!(value["type"], "event");
        assert_eq!(value["v"], 1);
        assert_eq!(value["envelope_id"], "p1");
        assert_eq!(value["event"]["room"], "!room:example");
        assert_eq!(value["event"]["sender"], "@sender:example");
        assert_eq!(value["event"]["event_id"], "$evt");
        assert_eq!(value["event"]["recipient"], "@b:example");
        assert_eq!(value["event"]["wire_type"], "m.room.message");
        assert!(value["event"].get("body").is_none());
        assert!(value.get("access_token").is_none());
        assert!(value.get("bearer").is_none());
    }

    #[test]
    fn encrypted_event_frame_names_the_wire_type_and_has_no_body() {
        let frame = metadata_event_frame("p2", "!room:example", "@sender:example", "$evt", "@b:example", "m.room.encrypted");
        let value: serde_json::Value = serde_json::from_str(&frame).expect("json");
        assert_eq!(value["v"], 1);
        assert_eq!(value["event"]["wire_type"], "m.room.encrypted");
        assert!(value["event"].get("body").is_none());
        assert!(!frame.contains("ciphertext"));
    }

    #[test]
    fn publish_room_text_never_puts_plaintext_on_the_wire() {
        let hub = PushHub::new();
        let (id, mut rx) = hub.subscribe(vec![2]);
        hub.publish_room_text(&RoomTextPush {
            room_id: "!r:ex".into(),
            sender: "@a:ex".into(),
            wire_type: "m.room.message".into(),
            event_id: "$e".into(),
            recipients: vec![(2, "@b:ex".into())],
        });
        let frame = rx.try_recv().expect("frame");
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["v"], 1);
        assert_eq!(v["event"]["wire_type"], "m.room.message");
        assert!(v["event"].get("body").is_none());
        hub.unsubscribe(id);
    }
}
