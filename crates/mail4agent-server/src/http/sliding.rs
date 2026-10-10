//! Simplified sliding sync (MSC4186): `POST .../org.matrix.simplified_msc3575/sync`.
//!
//! Built on the regular sync: `pos` is a sync token, the room lists are sorted by recent activity
//! (`sort`: by_recency, by_activity or by_name; changes between responses come as SYNC / INSERT /
//! DELETE / INVALIDATE operations), the rooms inside a list's ranges are sent in full once and then by delta, and
//! the to-device, e2ee, account-data, receipts and typing extensions are filled from the same
//! response. Per connection (user, device, `conn_id`) the server remembers which rooms it has sent
//! in memory; after a restart those rooms are simply sent in full again.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use rusqlite::Connection;
use serde_json::{json, Value};

use super::{resolve_caller, with_conn_pub, with_read_pub, Homeserver};
use crate::error::MatrixError;
use crate::live::WaitOutcome;
use crate::store::{self, Membership};

type ConnKey = (i64, String, String);

/// What the server remembers of one connection: the rooms it has sent in full, and per list the
/// room ids it last reported for each range (to say what changed as list operations).
#[derive(Clone, Default)]
struct ConnState {
    sent: HashSet<String>,
    lists: HashMap<String, Vec<(Range, Vec<String>)>>,
}

type Range = (usize, usize);

fn conns() -> &'static Mutex<HashMap<ConnKey, ConnState>> {
    static C: OnceLock<Mutex<HashMap<ConnKey, ConnState>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// How a list is ordered: the first known entry of its `sort` array.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Sort {
    /// Newest message first (state changes do not move a room). The default.
    Recency,
    /// Newest event of any kind first (a rename or a join moves the room too).
    Activity,
    /// Alphabetical by room name.
    Name,
}

fn sort_of(l: &Value) -> Sort {
    l.get("sort")
        .and_then(Value::as_array)
        .and_then(|a| {
            a.iter().find_map(|s| match s.as_str()? {
                "by_recency" => Some(Sort::Recency),
                "by_activity" => Some(Sort::Activity),
                "by_name" => Some(Sort::Name),
                _ => None,
            })
        })
        .unwrap_or(Sort::Recency)
}

/// The list operations that turn what the client holds for one range into the current rooms.
/// `prev` is what was reported before (None: a fresh connection or list); `ranges` are the
/// ranges asked now. A range never seen is SYNCed; an unchanged one says nothing; a room that
/// moved (or one that came in while another fell out) is a DELETE plus an INSERT; anything else
/// is SYNCed again; ranges the client stopped asking for are INVALIDATEd.
fn list_ops(prev: Option<&[(Range, Vec<String>)]>, ranges: &[Range], matching: &[String]) -> (Vec<Value>, Vec<(Range, Vec<String>)>) {
    let mut ops = Vec::new();
    let mut now = Vec::new();
    for &(a, b) in ranges {
        let ids: Vec<String> = matching.iter().skip(a).take(b.saturating_sub(a) + 1).cloned().collect();
        match prev.and_then(|p| p.iter().find(|(r, _)| *r == (a, b))) {
            None => ops.push(json!({ "op": "SYNC", "range": [a, b], "room_ids": ids })),
            Some((_, old)) if *old == ids => {}
            Some((_, old)) => match single_move(old, &ids) {
                Some((j, k)) => {
                    ops.push(json!({ "op": "DELETE", "index": a + j }));
                    ops.push(json!({ "op": "INSERT", "index": a + k, "room_id": ids[k] }));
                }
                None => ops.push(json!({ "op": "SYNC", "range": [a, b], "room_ids": ids })),
            },
        }
        now.push(((a, b), ids));
    }
    for (r, _) in prev.into_iter().flatten() {
        if !ranges.contains(r) {
            ops.insert(0, json!({ "op": "INVALIDATE", "range": [r.0, r.1] }));
        }
    }
    (ops, now)
}

/// `Some((j, k))` when deleting index `j` of `old` and inserting at index `k` of `new` makes them equal.
fn single_move(old: &[String], new: &[String]) -> Option<(usize, usize)> {
    if old.len() != new.len() || old.len() > 150 || old.is_empty() {
        return None;
    }
    (0..old.len()).find(|&i| old[i] != new[i])?;
    // Prefer a pure move (the same room at both ends); a room that bumped to the top is the
    // usual case, so look from the back.
    for pure in [true, false] {
        for j in (0..old.len()).rev() {
            let mut p = old.to_vec();
            let gone = p.remove(j);
            for k in 0..new.len() {
                let mut n = new.to_vec();
                let put = n.remove(k);
                if p == n && (!pure || gone == put) {
                    return Some((j, k));
                }
            }
        }
    }
    None
}

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new()
        .route("/client/unstable/org.matrix.simplified_msc3575/sync", post(sliding_sync))
        .route("/client/unstable/org.matrix.msc4186/sync", post(sliding_sync))
        .route("/client/v5/sync", post(sliding_sync))
}

#[derive(serde::Deserialize, Default)]
struct Q {
    pos: Option<String>,
    timeout: Option<u64>,
}

/// What a list or subscription asks for per room.
#[derive(Clone, Default)]
struct RoomAsk {
    required_state: Vec<(String, String)>,
    timeline_limit: i64,
}

fn ask_of(v: &Value) -> RoomAsk {
    let required_state = v
        .get("required_state")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|p| Some((p.get(0)?.as_str()?.to_string(), p.get(1)?.as_str()?.to_string()))).collect())
        .unwrap_or_default();
    RoomAsk { required_state, timeline_limit: v.get("timeline_limit").and_then(Value::as_i64).unwrap_or(10).clamp(0, 50) }
}

fn state_wanted(ev: &store::MatrixEvent, ask: &RoomAsk, me: &str, senders: &HashSet<String>) -> bool {
    let key = ev.state_key.as_deref().unwrap_or("");
    ask.required_state.iter().any(|(t, k)| {
        (t == "*" || *t == ev.event_type)
            && (k == "*" || k == key || (k == "$ME" && key == me) || (k == "$LAZY" && (key == me || senders.contains(key))))
    })
}

fn filter_passes(conn: &Connection, uid: i64, room: &store::Room, member: Membership, f: &Value) -> bool {
    if let Some(dm) = f.get("is_dm").and_then(Value::as_bool) {
        if dm != (room.kind == store::RoomKind::Dm) {
            return false;
        }
    }
    if let Some(enc) = f.get("is_encrypted").and_then(Value::as_bool) {
        if enc != room.is_encrypted {
            return false;
        }
    }
    if let Some(inv) = f.get("is_invite").and_then(Value::as_bool) {
        if inv != (member == Membership::Invite) {
            return false;
        }
    }
    let rtype = crate::spaces::room_type(conn, &room.id).ok().flatten();
    if let Some(ts) = f.get("room_types").and_then(Value::as_array) {
        if !ts.iter().any(|t| t.as_str() == rtype.as_deref()) && !(rtype.is_none() && ts.iter().any(Value::is_null)) {
            return false;
        }
    }
    if let Some(ts) = f.get("not_room_types").and_then(Value::as_array) {
        if ts.iter().any(|t| t.as_str() == rtype.as_deref() && rtype.is_some()) {
            return false;
        }
    }
    let _ = uid;
    true
}

fn last_event(conn: &Connection, room_id: &str) -> Option<store::MatrixEvent> {
    let public = crate::public_channels::is_public_room(conn, room_id).unwrap_or(false);
    let v = if public { crate::public_channels::events_before(conn, room_id, i64::MAX, 1) } else { store::events_in_room_before(conn, room_id, i64::MAX, 1) };
    v.ok().and_then(|mut v| v.pop())
}

fn recent(conn: &Connection, room_id: &str, upto: i64, limit: i64) -> Vec<store::MatrixEvent> {
    if limit == 0 {
        return vec![];
    }
    let public = crate::public_channels::is_public_room(conn, room_id).unwrap_or(false);
    let v = if public { crate::public_channels::events_before(conn, room_id, upto, limit) } else { store::events_in_room_before(conn, room_id, upto, limit) };
    let mut v = v.unwrap_or_default();
    v.reverse();
    v
}

struct Ctx<'a> {
    conn: &'a Connection,
    uid: i64,
    mxid: &'a str,
    dev: &'a str,
}

fn room_json(cx: &Ctx, room: &store::Room, member: Membership, ask: &RoomAsk, initial: bool, since: i64, upto: i64, block: Option<&Value>) -> Result<Value, MatrixError> {
    let conn = cx.conn;
    let mut out = json!({ "initial": initial, "is_dm": room.kind == store::RoomKind::Dm });
    if member == Membership::Invite {
        let me = store::current_state_event(conn, &room.id, "m.room.member", cx.mxid)?;
        let mut ev = vec![];
        if let Some(me) = &me {
            ev = store::stripped_invite_state(conn, &room.id, me.sender_user_id)?;
            ev.push(store::stripped_state_json(conn, me)?);
        }
        out["invite_state"] = json!(ev);
        out["bump_stamp"] = json!(me.map(|m| m.stream_id).unwrap_or(0));
        return Ok(out);
    }
    let all_state = store::current_state_all(conn, &room.id)?;
    if let Some(n) = all_state.iter().find(|e| e.event_type == "m.room.name") {
        if let Some(name) = serde_json::from_str::<Value>(&n.content).ok().and_then(|c| c.get("name").and_then(Value::as_str).map(str::to_string)) {
            if !name.is_empty() {
                out["name"] = json!(name);
            }
        }
    }
    let timeline: Vec<store::MatrixEvent> = if initial {
        recent(conn, &room.id, upto.saturating_add(1), ask.timeline_limit)
    } else {
        let sent = block.and_then(|b| b.pointer("/timeline/events")).and_then(Value::as_array).cloned().unwrap_or_default();
        out["timeline"] = json!(sent);
        vec![]
    };
    let senders: HashSet<String> = timeline.iter().filter_map(|e| store::mxid_of(conn, e.sender_user_id).ok().flatten()).collect();
    if initial {
        let mut tl = Vec::new();
        for e in &timeline {
            tl.push(crate::sync::format_event(conn, cx.uid, cx.dev, e)?);
        }
        out["timeline"] = json!(tl);
        out["prev_batch"] = json!(format!("t{}", timeline.first().map(|e| e.stream_id).unwrap_or(0)));
        out["limited"] = json!(timeline.len() as i64 >= ask.timeline_limit && ask.timeline_limit > 0);
    }
    let mut rs = Vec::new();
    for e in all_state.iter().filter(|e| (initial || e.stream_id > since) && state_wanted(e, ask, cx.mxid, &senders)) {
        rs.push(crate::sync::format_event(conn, cx.uid, cx.dev, e)?);
    }
    out["required_state"] = json!(rs);
    let joined = store::room_members(conn, &room.id, Some(Membership::Join))?;
    out["joined_count"] = json!(joined.len());
    out["invited_count"] = json!(store::room_members(conn, &room.id, Some(Membership::Invite))?.len());
    if out.get("name").is_none() {
        let mut heroes = Vec::new();
        for m in joined.iter().filter(|m| m.user_id != cx.uid).take(5) {
            if let Some(mx) = store::mxid_of(conn, m.user_id)? {
                heroes.push(json!({ "user_id": mx, "displayname": crate::nick::effective_label(conn, m.user_id)? }));
            }
        }
        out["heroes"] = json!(heroes);
    }
    out["bump_stamp"] = json!(last_event(conn, &room.id).map(|e| e.stream_id).unwrap_or(0));
    let unread = block.and_then(|b| b.get("unread_notifications")).cloned().unwrap_or_else(|| json!({}));
    out["notification_count"] = unread.get("notification_count").cloned().unwrap_or(json!(0));
    out["highlight_count"] = unread.get("highlight_count").cloned().unwrap_or(json!(0));
    Ok(out)
}

struct Row {
    recency: i64,
    activity: i64,
    room: store::Room,
    member: Membership,
}

fn name_key(conn: &Connection, room_id: &str) -> String {
    store::current_state_event(conn, room_id, "m.room.name", "")
        .ok()
        .flatten()
        .and_then(|e| serde_json::from_str::<Value>(&e.content).ok())
        .and_then(|c| c.get("name").and_then(Value::as_str).map(str::to_lowercase))
        .unwrap_or_default()
}

fn build(cx: &Ctx, typing: &crate::typing::TypingRegistry, pos: Option<crate::sync_token::SyncToken>, req: &Value, st: &ConnState) -> Result<(Value, ConnState, bool), MatrixError> {
    let conn = cx.conn;
    let since = pos.map(|p| p.stream_id).unwrap_or(0);
    let upto = store::max_stream_id(conn)?;
    let fresh = pos.is_none();
    // Every room the user is in or invited to, with the two stamps lists sort by.
    let mut rows: Vec<Row> = Vec::new();
    for m in [Membership::Join, Membership::Invite] {
        for id in store::rooms_for_user(conn, cx.uid, Some(m))? {
            if let Some(r) = store::get_room(conn, &id)? {
                let (recency, activity) = if m == Membership::Invite {
                    let s = store::current_state_event(conn, &id, "m.room.member", cx.mxid)?.map(|e| e.stream_id).unwrap_or(0);
                    (s, s)
                } else {
                    let public = crate::public_channels::is_public_room(conn, &id).unwrap_or(false);
                    let evs = if public { crate::public_channels::events_before(conn, &id, i64::MAX, 20) } else { store::events_in_room_before(conn, &id, i64::MAX, 20) }.unwrap_or_default();
                    let activity = evs.first().map(|e| e.stream_id).unwrap_or(0);
                    let recency = evs.iter().find(|e| e.state_key.is_none()).map(|e| e.stream_id).unwrap_or(activity);
                    (recency, activity)
                };
                rows.push(Row { recency, activity, room: r, member: m });
            }
        }
    }
    // What each list shows, in its own order, and what that means for the rooms to send.
    let mut wanted: Vec<(String, RoomAsk)> = Vec::new();
    let mut lists_out = serde_json::Map::new();
    let mut lists_state: HashMap<String, Vec<(Range, Vec<String>)>> = HashMap::new();
    let mut any_ops = false;
    let mut names: HashMap<String, String> = HashMap::new();
    if let Some(lists) = req.get("lists").and_then(Value::as_object) {
        for (name, l) in lists {
            let ask = ask_of(l);
            let filt = l.get("filters").cloned().unwrap_or(json!({}));
            let mut matching: Vec<&Row> = rows.iter().filter(|r| filter_passes(conn, cx.uid, &r.room, r.member, &filt)).collect();
            match sort_of(l) {
                Sort::Recency => matching.sort_by(|a, b| b.recency.cmp(&a.recency).then_with(|| a.room.id.cmp(&b.room.id))),
                Sort::Activity => matching.sort_by(|a, b| b.activity.cmp(&a.activity).then_with(|| a.room.id.cmp(&b.room.id))),
                Sort::Name => {
                    for r in &matching {
                        names.entry(r.room.id.clone()).or_insert_with(|| name_key(conn, &r.room.id));
                    }
                    // Named rooms alphabetically, unnamed ones after them by recency.
                    matching.sort_by(|a, b| {
                        let (na, nb) = (&names[&a.room.id], &names[&b.room.id]);
                        na.is_empty().cmp(&nb.is_empty()).then_with(|| na.cmp(nb)).then_with(|| b.recency.cmp(&a.recency)).then_with(|| a.room.id.cmp(&b.room.id))
                    });
                }
            }
            let ids: Vec<String> = matching.iter().map(|r| r.room.id.clone()).collect();
            let ranges: Vec<Range> = l
                .get("ranges")
                .and_then(Value::as_array)
                .map(|a| a.iter().map(|rg| (rg.get(0).and_then(Value::as_u64).unwrap_or(0) as usize, rg.get(1).and_then(Value::as_u64).unwrap_or(0) as usize)).filter(|(a, b)| a <= b).take(8).collect())
                .unwrap_or_default();
            let (ops, kept) = list_ops(if fresh { None } else { st.lists.get(name).map(Vec::as_slice) }, &ranges, &ids);
            any_ops |= !ops.is_empty();
            let mut entry = json!({ "count": ids.len() });
            if !ops.is_empty() {
                entry["ops"] = json!(ops);
            }
            lists_out.insert(name.clone(), entry);
            lists_state.insert(name.clone(), kept);
            for (a, b) in ranges {
                for id in ids.iter().skip(a).take(b - a + 1) {
                    if !wanted.iter().any(|(w, _)| w == id) {
                        wanted.push((id.clone(), ask.clone()));
                    }
                }
            }
        }
    }
    if let Some(subs) = req.get("room_subscriptions").and_then(Value::as_object) {
        for (id, s) in subs {
            if rows.iter().any(|r| r.room.id == *id) && !wanted.iter().any(|(w, _)| w == id) {
                wanted.push((id.clone(), ask_of(s)));
            }
        }
    }
    // Only the rooms in view are built: a first response costs the size of the asked ranges.
    let filter = crate::sync::SyncFilter { only_rooms: Some(wanted.iter().map(|(id, _)| id.clone()).collect()), ..Default::default() };
    let sync = crate::sync::build_sync_response(conn, typing, cx.uid, cx.mxid, cx.dev, pos, &filter, false, Instant::now())?;
    let mut rooms_out = serde_json::Map::new();
    let mut now_sent = HashSet::new();
    let mut receipts = serde_json::Map::new();
    let mut typing_out = serde_json::Map::new();
    let mut room_account = serde_json::Map::new();
    for (id, ask) in &wanted {
        let Some(row) = rows.iter().find(|r| r.room.id == *id) else { continue };
        let (room, member) = (&row.room, row.member);
        now_sent.insert(id.clone());
        let block = sync.pointer(&format!("/rooms/join/{}", json_ptr(id)));
        let initial = !st.sent.contains(id) || fresh;
        if initial || block.is_some() {
            let mut j = room_json(cx, room, member, ask, initial, since, upto, block)?;
            j["bump_stamp"] = json!(row.recency);
            rooms_out.insert(id.clone(), j);
        }
        if let Some(b) = block {
            for ev in b.pointer("/ephemeral/events").and_then(Value::as_array).into_iter().flatten() {
                match ev.get("type").and_then(Value::as_str) {
                    Some("m.receipt") => {
                        receipts.insert(id.clone(), ev.clone());
                    }
                    Some("m.typing") => {
                        typing_out.insert(id.clone(), ev.clone());
                    }
                    _ => {}
                }
            }
            if let Some(a) = b.pointer("/account_data/events").and_then(Value::as_array).filter(|a| !a.is_empty()) {
                room_account.insert(id.clone(), json!(a));
            }
        }
    }
    let mut ext = serde_json::Map::new();
    let on = |name: &str| req.pointer(&format!("/extensions/{name}/enabled")).and_then(Value::as_bool).unwrap_or(false);
    if on("to_device") {
        ext.insert("to_device".into(), json!({ "next_batch": sync["next_batch"], "events": sync["to_device"]["events"] }));
    }
    if on("e2ee") {
        ext.insert(
            "e2ee".into(),
            json!({ "device_lists": sync["device_lists"], "device_one_time_keys_count": sync["device_one_time_keys_count"], "device_unused_fallback_key_types": sync["device_unused_fallback_key_types"] }),
        );
    }
    if on("account_data") {
        ext.insert("account_data".into(), json!({ "global": sync["account_data"]["events"], "rooms": room_account }));
    }
    if on("receipts") {
        ext.insert("receipts".into(), json!({ "rooms": receipts }));
    }
    if on("typing") {
        ext.insert("typing".into(), json!({ "rooms": typing_out }));
    }
    let quiet = rooms_out.is_empty()
        && !any_ops
        && sync["to_device"]["events"].as_array().is_none_or(|a| a.is_empty())
        && sync["account_data"]["events"].as_array().is_none_or(|a| a.is_empty())
        && sync["device_lists"]["changed"].as_array().is_none_or(|a| a.is_empty())
        && receipts.is_empty()
        && typing_out.is_empty();
    let resp = json!({ "pos": sync["next_batch"], "lists": lists_out, "rooms": rooms_out, "extensions": ext });
    Ok((resp, ConnState { sent: now_sent, lists: lists_state }, quiet))
}

fn json_ptr(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

async fn sliding_sync(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Query(q): Query<Q>, body: Option<Json<Value>>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let req = body.map(|b| b.0).unwrap_or_else(|| json!({}));
    let (uid, mxid, dev) = (caller.user_id, caller.mxid, caller.device_id);
    let conn_id = req.get("conn_id").and_then(Value::as_str).unwrap_or("").to_string();
    let key: ConnKey = (uid, dev.clone(), conn_id);
    let pos = q.pos.as_deref().map(crate::sync_token::parse).transpose()?;
    let timeout = Duration::from_millis(q.timeout.unwrap_or(0).min(crate::sync::SYNC_MAX_TIMEOUT_MS));
    let deadline = Instant::now() + timeout;
    let mut sent: ConnState = match pos {
        Some(_) => conns().lock().map(|c| c.get(&key).cloned().unwrap_or_default()).unwrap_or_default(),
        None => ConnState::default(),
    };
    loop {
        let registration = state.live.register(&format!("user:{uid}"));
        let pos_now = {
            let dev = dev.clone();
            with_conn_pub(&state, move |c| {
                // A position from another store means a fresh start; a held one is the retention ack.
                let p = match pos {
                    Some(t) if t.stream_id > store::max_stream_id(c)? => None,
                    o => o,
                };
                if let Some(t) = p {
                    let now_ms = chrono::Utc::now().timestamp_millis();
                    let _ = crate::retention::record_device_ack(c, uid, &dev, t.stream_id, now_ms);
                }
                Ok(p)
            })
            .await?
        };
        if pos_now.is_none() {
            sent = ConnState::default();
        }
        let (st, req2, sent2, mxid2, dev2) = (Arc::clone(&state), req.clone(), sent.clone(), mxid.clone(), dev.clone());
        let (resp, now_sent, quiet) = with_read_pub(&state, move |c| {
            let cx = Ctx { conn: c, uid, mxid: &mxid2, dev: &dev2 };
            build(&cx, &st.typing, pos_now, &req2, &sent2)
        })
        .await?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !quiet || pos_now.is_none() || remaining.is_zero() || registration.wait(remaining).await == WaitOutcome::TimedOut {
            if let Ok(mut c) = conns().lock() {
                if c.len() > 20_000 {
                    c.clear();
                }
                c.insert(key, now_sent);
            }
            return Ok(Json(resp));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn list_operations_describe_what_changed() {
        let (ops, kept) = list_ops(None, &[(0, 2)], &v(&["a", "b", "c", "d"]));
        assert_eq!(ops, vec![json!({"op":"SYNC","range":[0,2],"room_ids":["a","b","c"]})]);
        // Nothing changed: no operation.
        assert!(list_ops(Some(&kept), &[(0, 2)], &v(&["a", "b", "c", "d"])).0.is_empty());
        // A room moved to the top.
        let (ops, _) = list_ops(Some(&kept), &[(0, 2)], &v(&["c", "a", "b", "d"]));
        assert_eq!(ops, vec![json!({"op":"DELETE","index":2}), json!({"op":"INSERT","index":0,"room_id":"c"})]);
        // A new room at the top pushes the last one out of the range.
        let (ops, _) = list_ops(Some(&kept), &[(0, 2)], &v(&["x", "a", "b", "c"]));
        assert_eq!(ops, vec![json!({"op":"DELETE","index":2}), json!({"op":"INSERT","index":0,"room_id":"x"})]);
        // A moved room inside a range that does not start at 0 reports absolute indexes.
        let (_, k2) = list_ops(None, &[(1, 3)], &v(&["a", "b", "c", "d"]));
        let (ops, _) = list_ops(Some(&k2), &[(1, 3)], &v(&["a", "c", "d", "b"]));
        assert_eq!(ops, vec![json!({"op":"DELETE","index":1}), json!({"op":"INSERT","index":3,"room_id":"b"})]);
        // A shuffle is a SYNC; a dropped range is INVALIDATEd while the new one is SYNCed.
        let (ops, _) = list_ops(Some(&kept), &[(0, 2)], &v(&["c", "b", "a", "d"]));
        assert_eq!(ops[0]["op"], "SYNC");
        let (ops, _) = list_ops(Some(&kept), &[(3, 5)], &v(&["a", "b", "c", "d"]));
        assert_eq!((ops[0]["op"].as_str(), ops[0]["range"].clone(), ops[1]["op"].as_str()), (Some("INVALIDATE"), json!([0, 2]), Some("SYNC")));
    }

    #[test]
    fn sort_modes_are_read_from_the_first_known_entry() {
        assert_eq!(sort_of(&json!({})), Sort::Recency);
        assert_eq!(sort_of(&json!({"sort":["by_name"]})), Sort::Name);
        assert_eq!(sort_of(&json!({"sort":["by_notification_level","by_activity"]})), Sort::Activity);
    }
}
