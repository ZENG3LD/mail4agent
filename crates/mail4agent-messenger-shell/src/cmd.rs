//! M5: rich agent commands over the client's local socket (mail/Slack-like).
//! One JSON line `{"cmd":"rooms.list","as":"<nick>", ...}` in, one JSON line
//! out. No crypto in the request or the answer: the shell encrypts, decrypts
//! and tracks devices itself. A line without `cmd` is the legacy send request.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    mxid_localpart, CreateRoomKind, ItemContent, MessageKind, MessengerCommand, OpenedStore,
    OutgoingMessage, RoomId, UserId,
};

/// One command request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CmdRequest {
    /// Command name, e.g. `rooms.list`.
    pub cmd: String,
    /// Session nick that runs the command.
    #[serde(rename = "as")]
    pub as_nick: String,
    /// Command arguments (command specific).
    #[serde(default)]
    pub args: Value,
    /// The calling session's capability (see [`crate::SendRequest::cap`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<String>,
}

/// The answer to one [`CmdRequest`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CmdReply {
    /// Success flag.
    pub ok: bool,
    /// Why it failed. No secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Command result.
    #[serde(default)]
    pub data: Value,
}

impl CmdReply {
    /// A failed reply.
    pub fn failed(error: impl Into<String>) -> Self {
        Self { ok: false, error: Some(error.into()), data: Value::Null }
    }
    fn ok(data: Value) -> Self {
        Self { ok: true, error: None, data }
    }
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str).map(str::trim).filter(|v| !v.is_empty())
}

impl OpenedStore {
    /// Display title of a room: its name, or the other members for a DM/group.
    fn room_title(&self, room_id: &RoomId) -> String {
        let me = self.driver.core.user_id().clone();
        let Some(state) = self.driver.core.room_state(room_id) else { return String::new() };
        if let Some(name) = state.name.as_deref().filter(|n| !n.is_empty()) {
            return name.to_string();
        }
        let others: Vec<String> = state
            .members
            .iter()
            .filter(|(id, _)| **id != me)
            .map(|(id, m)| m.displayname.clone().unwrap_or_else(|| mxid_localpart(id.as_str()).to_string()))
            .collect();
        others.join(", ")
    }

    /// Resolves `room` (id, `#name`, name, or a nick for a DM) to a joined room id.
    fn resolve_room(&mut self, spec: &str, now_ms: i64) -> Result<RoomId, String> {
        if spec.starts_with('!') {
            return RoomId::parse(spec).map_err(|e| e.to_string());
        }
        let wanted = spec.trim_start_matches(['#', '@']).to_ascii_lowercase();
        let ids: Vec<RoomId> = self.driver.core.room_ids().cloned().collect();
        let by_name: Vec<RoomId> = ids
            .iter()
            .filter(|id| self.room_title(id).to_ascii_lowercase() == wanted)
            .cloned()
            .collect();
        if by_name.len() == 1 {
            return Ok(by_name[0].clone());
        }
        if by_name.len() > 1 {
            return Err(format!("{spec} matches several rooms; use the room id"));
        }
        if spec.starts_with('#') {
            return Err(format!("no room named {spec}"));
        }
        let id = self.ensure_dm(spec, now_ms).map_err(|e| format!("{spec}: {e}"))?;
        RoomId::parse(&id).map_err(|e| e.to_string())
    }

    fn settle_cmd(&mut self, now_ms: i64) {
        for i in 1..=6 {
            let _ = self.drive(now_ms + i * 1_000, false);
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    fn rows(&self, room_id: &RoomId, limit: usize) -> Vec<Value> {
        let Some(timeline) = self.driver.core.timeline(room_id) else { return Vec::new() };
        let mut out: Vec<Value> = timeline
            .items()
            .iter()
            .filter_map(|item| {
                let (kind, body) = match &item.content {
                    ItemContent::Text(t) => ("text", t.body.clone()),
                    ItemContent::Notice(t) => ("notice", t.body.clone()),
                    ItemContent::Emote(t) => ("emote", t.body.clone()),
                    ItemContent::Undecryptable { .. } => ("undecryptable", String::new()),
                    // Membership: body is "<user> <joined|left|invited|...>"; the subject is in "subject".
                    ItemContent::StateChange(mail4agent_messenger::room::timeline::StateChangeSummary::Member { user_id, membership, .. }) => {
                        let verb = match format!("{membership:?}").to_lowercase().as_str() {
                            "join" => "joined",
                            "leave" => if user_id.as_str() == item.sender.as_str() { "left" } else { "was removed" },
                            "invite" => "was invited",
                            "ban" => "was banned",
                            other => return Some(json!({ "event_id": item.event_id.as_ref().map(|e| e.as_str()), "from": mxid_localpart(item.sender.as_str()), "ts": item.origin_server_ts, "kind": "member", "subject": mxid_localpart(user_id), "body": format!("{} {other}", mxid_localpart(user_id)) })),
                        };
                        return Some(json!({ "event_id": item.event_id.as_ref().map(|e| e.as_str()), "from": mxid_localpart(item.sender.as_str()), "ts": item.origin_server_ts, "kind": "member", "subject": mxid_localpart(user_id), "body": format!("{} {verb}", mxid_localpart(user_id)) }));
                    }
                    _ => return None,
                };
                Some(json!({
                    "event_id": item.event_id.as_ref().map(|e| e.as_str()),
                    "from": mxid_localpart(item.sender.as_str()),
                    "from_id": item.sender.as_str(),
                    "ts": item.origin_server_ts,
                    "kind": kind,
                    "body": body,
                    "reply_to": item.relations.reply_to.as_ref().map(|e| e.as_str()),
                    "thread": item.relations.thread_root.as_ref().map(|e| e.as_str()),
                    "reactions": item.relations.reactions.iter().map(|(k, who)| {
                        // This account's own reaction event for `k`, so a client can take it back (redact).
                        let mine = item.event_id.as_ref().and_then(|t| {
                            timeline.relating_events_for(t).iter().find(|r| &r.sender == self.driver.core.user_id() && matches!(&r.relation, mail4agent_messenger::wire::events::RelatesTo::Annotation { key, .. } if key == k)).map(|r| r.event_id.as_str().to_string())
                        });
                        json!({ "key": k, "count": who.len(), "by": who.iter().map(|u| mxid_localpart(u.as_str())).collect::<Vec<_>>(), "mine": mine })
                    }).collect::<Vec<_>>(),
                    "state": crate::outcome_name(&item.send_state),
                }))
            })
            .collect();
        let skip = out.len().saturating_sub(limit);
        out.drain(..skip);
        out
    }

    fn send_into(&mut self, room: &RoomId, text: &str, reply_to: Option<&str>, now_ms: i64) -> CmdReply {
        let reply_to = match reply_to {
            Some(id) => match crate::EventId::parse(id) {
                Ok(id) => Some(id),
                Err(e) => return CmdReply::failed(format!("event id: {e}")),
            },
            None => None,
        };
        // Refuse here, not at the server: a send into a room this session is not in only earns a refusal
        // that would be stored as a failed row.
        let me = self.driver.core.user_id().as_str().to_string();
        if !self.member_joined(room.as_str(), &me) {
            return CmdReply::failed("this session has not joined that room (join it first)");
        }
        let before = self.texts().len();
        if let Err(e) = self.dispatch(
            MessengerCommand::SendMessage {
                room_id: room.clone(),
                message: OutgoingMessage { kind: MessageKind::Text, body: text.to_string(), reply_to, edit_of: None },
                txn_id: None,
            },
            now_ms,
        ) {
            return CmdReply::failed(format!("send: {e}"));
        }
        let mut t = now_ms;
        for _ in 0..30 {
            t += 1_000;
            let _ = self.drive(t, false);
            std::thread::sleep(std::time::Duration::from_millis(200));
            if let Some(row) = self.texts().into_iter().rev().find(|r| r.room_id == room.as_str() && r.body == text) {
                if row.outcome == "sent" {
                    return CmdReply::ok(json!({ "room": room.as_str(), "event_id": row.event_id }));
                }
                if row.outcome.starts_with("failed") {
                    return CmdReply::failed(format!("send {}", row.outcome));
                }
            }
        }
        let _ = before;
        CmdReply::failed("send not confirmed yet (queued)")
    }

    /// Runs one rich command for this session.
    pub fn run_command(&mut self, req: &CmdRequest, now_ms: i64) -> CmdReply {
        let a = &req.args;
        match req.cmd.as_str() {
            "rooms.list" => {
                let rooms: Vec<Value> = self
                    .rooms()
                    .into_iter()
                    .filter(|r| r.membership != "absent" && r.membership != "leave")
                    .map(|r| {
                        let id = RoomId::parse(&r.room_id).ok();
                        let title = id.as_ref().map(|i| self.room_title(i)).unwrap_or_default();
                        let last = id.as_ref().and_then(|i| self.rows(i, 1).into_iter().next());
                        json!({ "room": r.room_id, "title": title, "membership": r.membership,
                                "encrypted": r.encrypted, "last": last })
                    })
                    .collect();
                CmdReply::ok(json!({ "rooms": rooms }))
            }
            "rooms.read" => {
                let Some(spec) = arg_str(a, "room") else { return CmdReply::failed("room is required") };
                let limit = a.get("limit").and_then(Value::as_u64).unwrap_or(20).min(200) as usize;
                match self.resolve_room(spec, now_ms) {
                    Ok(id) => CmdReply::ok(json!({ "room": id.as_str(), "title": self.room_title(&id), "messages": self.rows(&id, limit) })),
                    Err(e) => CmdReply::failed(e),
                }
            }
            "rooms.send" | "rooms.reply" => {
                let (Some(spec), Some(text)) = (arg_str(a, "room"), arg_str(a, "text")) else {
                    return CmdReply::failed("room and text are required");
                };
                let reply_to = if req.cmd == "rooms.reply" {
                    match arg_str(a, "event") {
                        Some(e) => Some(e),
                        None => return CmdReply::failed("event is required for a reply"),
                    }
                } else {
                    None
                };
                match self.resolve_room(spec, now_ms) {
                    Ok(id) => self.send_into(&id, text, reply_to, now_ms),
                    Err(e) => CmdReply::failed(e),
                }
            }
            "rooms.join" | "rooms.leave" => {
                let Some(spec) = arg_str(a, "room") else { return CmdReply::failed("room is required") };
                let id = match self.resolve_room(spec, now_ms) {
                    Ok(id) => id,
                    Err(e) => return CmdReply::failed(e),
                };
                let command = if req.cmd == "rooms.join" {
                    MessengerCommand::JoinRoom { room_id: id.clone() }
                } else {
                    MessengerCommand::LeaveRoom { room_id: id.clone() }
                };
                match self.dispatch(command, now_ms) {
                    Ok(()) => {
                        self.settle_cmd(now_ms);
                        CmdReply::ok(json!({ "room": id.as_str() }))
                    }
                    Err(e) => CmdReply::failed(e.to_string()),
                }
            }
            "rooms.create" => {
                let Some(name) = arg_str(a, "name") else { return CmdReply::failed("name is required") };
                let invite: Vec<UserId> = a
                    .get("invite")
                    .and_then(Value::as_array)
                    .map(|v| v.iter().filter_map(Value::as_str).filter_map(|u| UserId::parse(u).ok()).collect())
                    .unwrap_or_default();
                let wanted = arg_str(a, "kind").unwrap_or("group");
                // `open` is an open room: the server's public plaintext shape (a channel) with the
                // write level lowered to 0 once the room exists, so everyone who joins can write.
                let open_for_all = wanted == "open";
                let kind = match wanted {
                    "channel" | "open" => CreateRoomKind::Channel { name: name.to_string(), topic: arg_str(a, "topic").map(str::to_string) },
                    "group" => CreateRoomKind::Group { name: name.to_string(), invite, members_can_invite: true },
                    other => return CmdReply::failed(format!("kind must be group, channel or open, not {other}")),
                };
                match self.dispatch(MessengerCommand::CreateRoom { kind }, now_ms) {
                    Ok(()) => {
                        let mut found = None;
                        for i in 1..=25 {
                            let _ = self.drive(now_ms + i * 1_000, false);
                            std::thread::sleep(std::time::Duration::from_millis(200));
                            found = self.rooms().into_iter().find(|r| {
                                r.membership == "join"
                                    && RoomId::parse(&r.room_id).map(|i| self.room_title(&i) == name).unwrap_or(false)
                            });
                            if found.is_some() {
                                break;
                            }
                        }
                        if open_for_all {
                            let Some(room) = found.as_ref().and_then(|r| RoomId::parse(&r.room_id).ok()) else {
                                return CmdReply::failed("the room was created but did not show up; its write level is still moderator-only");
                            };
                            if let Err(e) = self.dispatch(MessengerCommand::SetEventsDefault { room_id: room, level: 0 }, now_ms) {
                                return CmdReply::failed(format!("the room was created but its write level was not lowered: {e}"));
                            }
                            self.settle_cmd(now_ms);
                        }
                        CmdReply::ok(json!({ "room": found.map(|r| r.room_id) }))
                    }
                    Err(e) => CmdReply::failed(e.to_string()),
                }
            }
            "rooms.invite" => {
                let (Some(spec), Some(who)) = (arg_str(a, "room"), arg_str(a, "user")) else {
                    return CmdReply::failed("room and user are required");
                };
                let id = match self.resolve_room(spec, now_ms) {
                    Ok(id) => id,
                    Err(e) => return CmdReply::failed(e),
                };
                let user = if who.starts_with('@') && who.contains(':') {
                    who.to_string()
                } else {
                    match self.find_nick(who, now_ms) {
                        Ok(found) => found.user_id,
                        Err(e) => return CmdReply::failed(format!("{who}: {e}")),
                    }
                };
                let Ok(user_id) = UserId::parse(&user) else { return CmdReply::failed("bad user id") };
                match self.dispatch(MessengerCommand::Invite { room_id: id.clone(), user_id }, now_ms) {
                    Ok(()) => {
                        self.settle_cmd(now_ms);
                        CmdReply::ok(json!({ "room": id.as_str() }))
                    }
                    Err(e) => CmdReply::failed(e.to_string()),
                }
            }
            "rooms.react" => {
                let (Some(spec), Some(ev), Some(key)) = (arg_str(a, "room"), arg_str(a, "event"), arg_str(a, "key")) else {
                    return CmdReply::failed("room, event and key are required");
                };
                if key.is_empty() || key.len() > 64 {
                    return CmdReply::failed("bad key");
                }
                let id = match self.resolve_room(spec, now_ms) {
                    Ok(id) => id,
                    Err(e) => return CmdReply::failed(e),
                };
                let Ok(target) = crate::EventId::parse(ev) else { return CmdReply::failed("bad event id") };
                match self.dispatch(MessengerCommand::React { room_id: id.clone(), target, key: key.to_string() }, now_ms) {
                    Ok(()) => {
                        self.settle_cmd(now_ms);
                        CmdReply::ok(json!({ "room": id.as_str() }))
                    }
                    Err(e) => CmdReply::failed(e.to_string()),
                }
            }
            "rooms.members" => {
                let Some(spec) = arg_str(a, "room") else { return CmdReply::failed("room is required") };
                let id = match self.resolve_room(spec, now_ms) {
                    Ok(id) => id,
                    Err(e) => return CmdReply::failed(e),
                };
                let Some(state) = self.driver.core.room_state(&id) else { return CmdReply::failed("unknown room") };
                let members: Vec<Value> = state.members.iter().map(|(u, m)| json!({ "user": u.as_str(), "membership": format!("{:?}", m.membership).to_lowercase(), "level": state.power_levels.users.get(u).copied().unwrap_or(state.power_levels.users_default) })).collect();
                CmdReply::ok(json!({ "room": id.as_str(), "members": members }))
            }
            "rooms.redact" => {
                let (Some(spec), Some(ev)) = (arg_str(a, "room"), arg_str(a, "event")) else {
                    return CmdReply::failed("room and event are required");
                };
                let id = match self.resolve_room(spec, now_ms) {
                    Ok(id) => id,
                    Err(e) => return CmdReply::failed(e),
                };
                let Ok(target) = crate::EventId::parse(ev) else { return CmdReply::failed("bad event id") };
                match self.dispatch(MessengerCommand::Redact { room_id: id.clone(), target, reason: None }, now_ms) {
                    Ok(()) => {
                        self.settle_cmd(now_ms);
                        CmdReply::ok(json!({ "room": id.as_str() }))
                    }
                    Err(e) => CmdReply::failed(e.to_string()),
                }
            }
            "rooms.power" => {
                let (Some(spec), Some(who)) = (arg_str(a, "room"), arg_str(a, "user")) else {
                    return CmdReply::failed("room and user are required");
                };
                let level = a.get("level").and_then(Value::as_i64).unwrap_or(100);
                let id = match self.resolve_room(spec, now_ms) {
                    Ok(id) => id,
                    Err(e) => return CmdReply::failed(e),
                };
                let user = if who.starts_with('@') && who.contains(':') {
                    who.to_string()
                } else {
                    match self.find_nick(who, now_ms) {
                        Ok(found) => found.user_id,
                        Err(e) => return CmdReply::failed(format!("{who}: {e}")),
                    }
                };
                let Ok(user_id) = UserId::parse(&user) else { return CmdReply::failed("bad user id") };
                match self.dispatch(MessengerCommand::SetPowerLevel { room_id: id.clone(), user_id, level }, now_ms) {
                    Ok(()) => {
                        self.settle_cmd(now_ms);
                        CmdReply::ok(json!({ "room": id.as_str(), "level": level }))
                    }
                    Err(e) => CmdReply::failed(e.to_string()),
                }
            }
            "mentions" => {
                let limit = a.get("limit").and_then(Value::as_u64).unwrap_or(20).min(200) as usize;
                let me = self.nick().unwrap_or("").to_ascii_lowercase();
                let my_id = self.driver.core.user_id().as_str().to_string();
                let ids: Vec<RoomId> = self.driver.core.room_ids().cloned().collect();
                let mut hits = Vec::new();
                for id in ids {
                    for mut row in self.rows(&id, 200) {
                        let body = row["body"].as_str().unwrap_or("").to_ascii_lowercase();
                        let from_me = row["from_id"].as_str() == Some(my_id.as_str());
                        if !from_me && !me.is_empty() && body.contains(&format!("@{me}")) {
                            row["room"] = json!(id.as_str());
                            hits.push(row);
                        }
                    }
                }
                hits.sort_by_key(|r| r["ts"].as_i64().unwrap_or(0));
                let skip = hits.len().saturating_sub(limit);
                hits.drain(..skip);
                CmdReply::ok(json!({ "mentions": hits }))
            }
            "threads.read" => {
                let (Some(spec), Some(root)) = (arg_str(a, "room"), arg_str(a, "event")) else {
                    return CmdReply::failed("room and event are required");
                };
                match self.resolve_room(spec, now_ms) {
                    Ok(id) => {
                        let rows: Vec<Value> = self
                            .rows(&id, 500)
                            .into_iter()
                            .filter(|r| r["event_id"].as_str() == Some(root) || r["thread"].as_str() == Some(root) || r["reply_to"].as_str() == Some(root))
                            .collect();
                        CmdReply::ok(json!({ "room": id.as_str(), "messages": rows }))
                    }
                    Err(e) => CmdReply::failed(e),
                }
            }
            other => CmdReply::failed(format!("unknown command {other}")),
        }
    }
}
