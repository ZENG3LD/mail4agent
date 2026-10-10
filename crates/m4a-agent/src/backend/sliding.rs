//! Client side of simplified sliding sync (MSC4186). The engine speaks `/sync` v3; this turns its
//! sync calls into sliding-sync calls and the answers back into v3 shape, so the engine does not
//! change. A server that does not offer it (or refuses it) gets plain `/sync` v3.
//!
//! The v3 `next_batch` the engine keeps is the sliding `pos`. Rooms left or banned are not
//! reported by sliding sync, so a leave seen elsewhere is the only way the engine learns of one.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use mail4agent_messenger::{HttpMethod, HttpResponseDescriptor, OutgoingRequest};
use serde_json::{json, Value};

use super::live::Live;
use super::matrix::SyncMode;
use crate::error::Result;

const PATH_SIMPLIFIED: &str = "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync";
const PATH_MSC4186: &str = "/_matrix/client/unstable/org.matrix.msc4186/sync";

const UNDECIDED: u8 = 0;
const ON: u8 = 1;
const OFF: u8 = 2;

pub struct Sliding {
    state: AtomicU8,
    forced_v3: AtomicU8,
    path: Mutex<&'static str>,
    pos: Mutex<Option<String>>,
    to_device_since: Mutex<Option<String>>,
}

impl Default for Sliding {
    fn default() -> Self {
        Self::new()
    }
}

impl Sliding {
    pub fn new() -> Self {
        Self { state: AtomicU8::new(UNDECIDED), forced_v3: AtomicU8::new(0), path: Mutex::new(PATH_SIMPLIFIED), pos: Mutex::new(None), to_device_since: Mutex::new(None) }
    }

    pub fn set_mode(&self, mode: SyncMode) {
        self.forced_v3.store((mode == SyncMode::V3) as u8, Ordering::Release);
    }

    pub fn active(&self) -> bool {
        self.state.load(Ordering::Acquire) == ON
    }

    /// Asks the server what it offers (`GET /versions`, `unstable_features`).
    pub fn decide(&self, live: &Live) {
        if self.forced_v3.load(Ordering::Acquire) == 1 {
            self.state.store(OFF, Ordering::Release);
            return;
        }
        let exec = live.exec();
        let offered = exec.get_json("/_matrix/client/versions").ok().filter(|(s, _)| *s == 200).map(|(_, v)| v);
        let feature = |k: &str| offered.as_ref().and_then(|v| v.get("unstable_features")).and_then(|f| f.get(k)).and_then(Value::as_bool).unwrap_or(false);
        if feature("org.matrix.simplified_msc3575") {
            *self.path.lock().unwrap_or_else(|e| e.into_inner()) = PATH_SIMPLIFIED;
            self.state.store(ON, Ordering::Release);
        } else if feature("org.matrix.msc4186") {
            *self.path.lock().unwrap_or_else(|e| e.into_inner()) = PATH_MSC4186;
            self.state.store(ON, Ordering::Release);
        } else {
            self.state.store(OFF, Ordering::Release);
        }
    }

    fn body(&self) -> Value {
        let since = self.to_device_since.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut to_device = json!({ "enabled": true });
        if let Some(s) = since {
            to_device["since"] = json!(s);
        }
        json!({
            "conn_id": "m4a",
            "lists": { "all": { "ranges": [[0, 99]], "timeline_limit": 20, "required_state": [["*", "*"]] } },
            "extensions": { "to_device": to_device, "e2ee": { "enabled": true }, "account_data": { "enabled": true } }
        })
    }

    /// Serves a v3 sync request by sliding sync. `Ok(None)`: not available, use v3.
    pub fn sync(&self, live: &Live, request: &OutgoingRequest) -> Result<Option<HttpResponseDescriptor>> {
        if self.state.load(Ordering::Acquire) != ON {
            return Ok(None);
        }
        let timeout = request.query.iter().find(|(n, _)| n == "timeout").map(|(_, v)| v.clone()).unwrap_or_else(|| "0".into());
        // A `since` the engine holds from another run means nothing here: the connection is new.
        let since = request.query.iter().find(|(n, _)| n == "since").map(|(_, v)| v.clone());
        let mut pos = self.pos.lock().unwrap_or_else(|e| e.into_inner()).clone().filter(|p| since.as_deref() == Some(p.as_str()));
        for attempt in 0..2 {
            let mut query = vec![("timeout".to_string(), timeout.clone())];
            if let Some(p) = &pos {
                query.push(("pos".to_string(), p.clone()));
            }
            let sliding_request = OutgoingRequest {
                id: request.id.clone(),
                method: HttpMethod::Post,
                path: self.path.lock().unwrap_or_else(|e| e.into_inner()).to_string(),
                query,
                body: Some(self.body()),
                kind: request.kind,
            };
            let r = live.execute(&sliding_request)?;
            let errcode = serde_json::from_slice::<Value>(&r.body).ok().and_then(|v| v.get("errcode").and_then(Value::as_str).map(str::to_string));
            match (r.status, errcode.as_deref()) {
                (200, _) => {
                    let v: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
                    let v3 = to_v3(&v);
                    *self.pos.lock().unwrap_or_else(|e| e.into_inner()) = v.get("pos").and_then(Value::as_str).map(str::to_string);
                    if let Some(n) = v.pointer("/extensions/to_device/next_batch").and_then(Value::as_str) {
                        *self.to_device_since.lock().unwrap_or_else(|e| e.into_inner()) = Some(n.to_string());
                    }
                    return Ok(Some(HttpResponseDescriptor { status: 200, body: serde_json::to_vec(&v3).unwrap_or_default() }));
                }
                (400, Some("M_UNKNOWN_POS")) if attempt == 0 => {
                    // The server lost the connection: start again.
                    *self.pos.lock().unwrap_or_else(|e| e.into_inner()) = None;
                    *self.to_device_since.lock().unwrap_or_else(|e| e.into_inner()) = None;
                    pos = None;
                }
                (404 | 405 | 501, _) | (_, Some("M_UNRECOGNIZED")) => {
                    // Not served after all: v3 from now on.
                    self.state.store(OFF, Ordering::Release);
                    return Ok(None);
                }
                _ => return Ok(Some(r)),
            }
        }
        Ok(None)
    }
}

/// A sliding-sync answer in the shape of a v3 `/sync` answer.
pub fn to_v3(v: &Value) -> Value {
    let mut join = serde_json::Map::new();
    let mut invite = serde_json::Map::new();
    if let Some(rooms) = v.get("rooms").and_then(Value::as_object) {
        for (id, room) in rooms {
            if let Some(stripped) = room.get("invite_state").and_then(Value::as_array) {
                invite.insert(id.clone(), json!({ "invite_state": { "events": stripped } }));
                continue;
            }
            let timeline = room.get("timeline").cloned().unwrap_or_else(|| json!([]));
            let mut entry = json!({
                "timeline": { "events": timeline, "limited": room.get("limited").and_then(Value::as_bool).unwrap_or(false) },
                "state": { "events": room.get("required_state").cloned().unwrap_or_else(|| json!([])) },
            });
            if let Some(p) = room.get("prev_batch") {
                entry["timeline"]["prev_batch"] = p.clone();
            }
            let n = room.get("notification_count").and_then(Value::as_u64);
            let h = room.get("highlight_count").and_then(Value::as_u64);
            if n.is_some() || h.is_some() {
                entry["unread_notifications"] = json!({ "notification_count": n.unwrap_or(0), "highlight_count": h.unwrap_or(0) });
            }
            join.insert(id.clone(), entry);
        }
    }
    let ext = v.get("extensions").cloned().unwrap_or(Value::Null);
    let mut out = json!({
        "next_batch": v.get("pos").and_then(Value::as_str).unwrap_or(""),
        "rooms": { "join": join, "invite": invite, "leave": {} },
        "to_device": { "events": ext.pointer("/to_device/events").cloned().unwrap_or_else(|| json!([])) },
        "account_data": { "events": ext.pointer("/account_data/global").cloned().unwrap_or_else(|| json!([])) },
    });
    if let Some(d) = ext.pointer("/e2ee/device_lists") {
        out["device_lists"] = d.clone();
    }
    if let Some(c) = ext.pointer("/e2ee/device_one_time_keys_count") {
        out["device_one_time_keys_count"] = c.clone();
    }
    if let Some(f) = ext.pointer("/e2ee/device_unused_fallback_key_types") {
        out["device_unused_fallback_key_types"] = f.clone();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sliding_answer_becomes_a_v3_answer() {
        let v = json!({
            "pos": "p7",
            "rooms": {
                "!a:s": { "required_state": [{"type":"m.room.create"}], "timeline": [{"type":"m.room.message","event_id":"$1"}], "limited": true, "prev_batch": "pb", "notification_count": 2 },
                "!i:s": { "invite_state": [{"type":"m.room.member","state_key":"@me:s"}] }
            },
            "extensions": {
                "to_device": { "next_batch": "t1", "events": [{"type":"m.room.encrypted"}] },
                "e2ee": { "device_lists": {"changed":["@x:s"]}, "device_one_time_keys_count": {"signed_curve25519": 5}, "device_unused_fallback_key_types": [] },
                "account_data": { "global": [{"type":"m.direct"}] }
            }
        });
        let o = to_v3(&v);
        assert_eq!(o["next_batch"], "p7");
        assert_eq!(o["rooms"]["join"]["!a:s"]["timeline"]["events"][0]["event_id"], "$1");
        assert_eq!(o["rooms"]["join"]["!a:s"]["timeline"]["limited"], true);
        assert_eq!(o["rooms"]["join"]["!a:s"]["state"]["events"][0]["type"], "m.room.create");
        assert_eq!(o["rooms"]["join"]["!a:s"]["unread_notifications"]["notification_count"], 2);
        assert!(o["rooms"]["join"].get("!i:s").is_none());
        assert_eq!(o["rooms"]["invite"]["!i:s"]["invite_state"]["events"][0]["state_key"], "@me:s");
        assert_eq!(o["to_device"]["events"][0]["type"], "m.room.encrypted");
        assert_eq!(o["device_lists"]["changed"][0], "@x:s");
        assert_eq!(o["device_one_time_keys_count"]["signed_curve25519"], 5);
        assert_eq!(o["account_data"]["events"][0]["type"], "m.direct");
        let e = to_v3(&json!({"pos":"p8"}));
        assert_eq!(e["next_batch"], "p8");
        assert!(e["rooms"]["join"].as_object().unwrap().is_empty());
    }
}
