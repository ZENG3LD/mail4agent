//! Ephemeral data units between servers: typing, read receipts, device-list updates. (Presence is
//! not carried: this server has none, and an incoming `m.presence` is accepted and dropped.)
//! Outgoing ones go through the federation outbox like any other item; incoming ones are applied
//! only for users of the sending server who are members of a room here.

use std::collections::HashSet;
use std::time::Instant;

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::fed_rooms as fr;
use crate::store::{self, Membership};

fn now_ms() -> i64 {
    crate::federation::now_ms()
}

fn remote_servers_of_user(conn: &Connection, user_id: i64) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    for room in store::rooms_for_user(conn, user_id, Some(Membership::Join)).unwrap_or_default() {
        out.extend(fr::remote_domains(conn, &room).unwrap_or_default());
    }
    out.into_iter().collect()
}

fn queue(conn: &Connection, servers: impl IntoIterator<Item = String>, edu: &Value) {
    for d in servers {
        let _ = fr::enqueue(conn, &d, "edu", "", "", edu, now_ms());
    }
}

/// A local user's typing state in a room that has remote members.
pub fn enqueue_typing(conn: &Connection, room_id: &str, user_id: i64, typing: bool) {
    if user_id <= 0 {
        return;
    }
    let (Ok(servers), Ok(Some(mxid))) = (fr::remote_domains(conn, room_id), store::mxid_of(conn, user_id)) else { return };
    queue(conn, servers, &json!({ "edu_type": "m.typing", "content": { "room_id": room_id, "user_id": mxid, "typing": typing } }));
}

/// A local user's read receipt in a room that has remote members.
pub fn enqueue_receipt(conn: &Connection, room_id: &str, user_id: i64, event_id: &str, ts: i64) {
    if user_id <= 0 {
        return;
    }
    let (Ok(servers), Ok(Some(mxid))) = (fr::remote_domains(conn, room_id), store::mxid_of(conn, user_id)) else { return };
    let content = json!({ room_id: { "m.read": { mxid: { "event_ids": [event_id], "data": { "ts": ts } } } } });
    queue(conn, servers, &json!({ "edu_type": "m.receipt", "content": content }));
}

/// A local user's devices or keys changed: tell every server that shares a room with them.
pub fn enqueue_device_list(conn: &Connection, user_id: i64, stream_id: i64) {
    if user_id <= 0 {
        return;
    }
    let Ok(Some(mxid)) = store::mxid_of(conn, user_id) else { return };
    let servers = remote_servers_of_user(conn, user_id);
    queue(conn, servers, &json!({ "edu_type": "m.device_list_update", "content": { "user_id": mxid, "device_id": "*", "stream_id": stream_id, "prev_id": [] } }));
}

/// The newest device-list change of a user (0 when there is none).
pub fn device_list_stream(conn: &Connection, user_id: i64) -> i64 {
    conn.query_row("SELECT COALESCE(MAX(stream_id), 0) FROM device_list_changes WHERE user_id = ?1", [user_id], |r| r.get(0)).unwrap_or(0)
}

fn from_origin(mxid: &str, origin: &str) -> bool {
    fr::domain_of(mxid) == Some(origin)
}

/// Apply one incoming EDU from `origin`. Returns the local users to wake.
pub fn apply_inbound(conn: &mut Connection, typing: &crate::typing::TypingRegistry, origin: &str, edu: &Value) -> HashSet<i64> {
    let mut wake = HashSet::new();
    let content = edu.get("content").cloned().unwrap_or(Value::Null);
    match edu.get("edu_type").and_then(Value::as_str) {
        Some("m.typing") => {
            let (Some(room), Some(user), Some(on)) = (content.get("room_id").and_then(Value::as_str), content.get("user_id").and_then(Value::as_str), content.get("typing").and_then(Value::as_bool)) else { return wake };
            if !from_origin(user, origin) {
                return wake;
            }
            let Ok(Some(uid)) = store::user_id_of(conn, user) else { return wake };
            if store::room_member(conn, room, uid).ok().flatten().map(|m| m.membership) != Some(Membership::Join) {
                return wake;
            }
            if typing.set_typing(room, uid, on, 30_000, Instant::now()) {
                wake = crate::rooms::member_and_invited_ids(conn, room).unwrap_or_default();
            }
        }
        Some("m.receipt") => {
            for (room, by_type) in content.as_object().into_iter().flatten() {
                let Some(users) = by_type.get("m.read").and_then(Value::as_object) else { continue };
                for (user, data) in users {
                    if !from_origin(user, origin) {
                        continue;
                    }
                    let Ok(Some(uid)) = store::user_id_of(conn, user) else { continue };
                    if store::room_member(conn, room, uid).ok().flatten().map(|m| m.membership) != Some(Membership::Join) {
                        continue;
                    }
                    let ts = data.pointer("/data/ts").and_then(Value::as_i64).unwrap_or_else(now_ms);
                    for ev in data.get("event_ids").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                        if store::get_event(conn, ev).ok().flatten().is_some_and(|e| e.room_id == *room) {
                            if let Ok(w) = store::upsert_receipt(conn, room, uid, store::ReceiptType::Read, ev, ts).map(|_| crate::rooms::member_and_invited_ids(conn, room).unwrap_or_default()) {
                                wake.extend(w);
                            }
                        }
                    }
                }
            }
        }
        Some("m.device_list_update") => {
            let Some(user) = content.get("user_id").and_then(Value::as_str) else { return wake };
            if !from_origin(user, origin) {
                return wake;
            }
            if let Ok(Some(uid)) = store::user_id_of(conn, user) {
                if uid < 0 {
                    let _ = crate::keys::log_device_list_change(conn, uid, &chrono::Utc::now().to_rfc3339());
                    for room in store::rooms_for_user(conn, uid, Some(Membership::Join)).unwrap_or_default() {
                        wake.extend(store::room_members(conn, &room, Some(Membership::Join)).unwrap_or_default().into_iter().map(|m| m.user_id).filter(|u| *u > 0));
                    }
                }
            }
        }
        _ => {}
    }
    wake
}
