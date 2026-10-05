//! `/sync` snapshot. Returns JSON. Does not wait, poll, or wake.

use std::time::Instant;

use rusqlite::Connection;

use crate::error::MatrixError;
use crate::events::client_event_json;
use crate::store::{Membership, ReceiptType, Room};
use crate::sync_token;

/// `timeout` (ms) is clamped to this ceiling regardless of what the client
/// asks for (plan §4 `/sync` row).
pub const SYNC_MAX_TIMEOUT_MS: u64 = 30_000;

/// `filter.room.timeline.limit` default and ceiling (P10 brief — overrides
/// plan §3.2's own "default 20" wherever they differ).
pub const SYNC_TIMELINE_DEFAULT_LIMIT: i64 = 10;

pub const SYNC_TIMELINE_MAX_LIMIT: i64 = 50;

/// `to_device.events` cap per response (P10 brief).
pub const SYNC_TO_DEVICE_CAP: i64 = 100;

/// `m.heroes` cap (plan §3.4).
pub const SYNC_HERO_LIMIT: i64 = 5;


// ============================================================================
// Filter — `room.timeline.limit/types/not_types`, `room.state.
// lazy_load_members`, `room.include_leave`, `account_data.types/not_types`.
// `presence`/`event_fields` are accepted (serde ignores unrecognized JSON
// keys by default — no `deny_unknown_fields`) and never interpreted.
// ============================================================================

#[derive(serde::Deserialize, Default, Clone)]
pub struct RoomTimelineFilter {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub types: Option<Vec<String>>,
    #[serde(default)]
    pub not_types: Option<Vec<String>>,
}


#[derive(serde::Deserialize, Default, Clone)]
pub struct RoomStateFilter {
    #[serde(default)]
    pub lazy_load_members: Option<bool>,
}


#[derive(serde::Deserialize, Default, Clone)]
pub struct RoomFilter {
    #[serde(default)]
    pub timeline: RoomTimelineFilter,
    #[serde(default)]
    pub state: RoomStateFilter,
    #[serde(default)]
    pub include_leave: bool,
}


#[derive(serde::Deserialize, Default, Clone)]
pub struct AccountDataFilter {
    #[serde(default)]
    pub types: Option<Vec<String>>,
    #[serde(default)]
    pub not_types: Option<Vec<String>>,
}


#[derive(serde::Deserialize, Default, Clone)]
pub struct SyncFilter {
    #[serde(default)]
    pub room: RoomFilter,
    #[serde(default)]
    pub account_data: AccountDataFilter,
}


/// `types`/`not_types` gate shared by the timeline and account-data filter
/// sections — own copy per this codebase's one-copy-per-route-module
/// convention (mirrors `routes::matrix::messaging::event_passes_filter`).
pub fn passes_type_filter(value: &str, types: &Option<Vec<String>>, not_types: &Option<Vec<String>>) -> bool {
    if let Some(types) = types {
        if !types.iter().any(|t| t == value) {
            return false;
        }
    }
    if let Some(not_types) = not_types {
        if not_types.iter().any(|t| t == value) {
            return false;
        }
    }
    true
}


impl SyncFilter {
    fn timeline_limit(&self) -> i64 {
        self.room.timeline.limit.unwrap_or(SYNC_TIMELINE_DEFAULT_LIMIT).clamp(1, SYNC_TIMELINE_MAX_LIMIT)
    }

    /// Default `true` — every client this server ships sets it, and it is
    /// the single biggest `/sync` payload-size win for anything but a tiny
    /// room (plan §3.3).
    pub fn lazy_load_members(&self) -> bool {
        self.room.state.lazy_load_members.unwrap_or(true)
    }

    fn include_leave(&self) -> bool {
        self.room.include_leave
    }

    fn timeline_event_passes(&self, event_type: &str) -> bool {
        passes_type_filter(event_type, &self.room.timeline.types, &self.room.timeline.not_types)
    }

    fn account_data_passes(&self, data_type: &str) -> bool {
        passes_type_filter(data_type, &self.account_data.types, &self.account_data.not_types)
    }
}


/// Resolve the `filter` query param: a stored `filter_id` (looked up via
/// [`crate::store::get_filter`], scoped to `user_id` — the same isolation
/// `routes::matrix::account::get_filter` enforces) or inline JSON (a leading
/// `{`). Absent/empty is [`SyncFilter::default`].
pub fn parse_filter_param(conn: &Connection, user_id: i64, raw: Option<&str>) -> Result<SyncFilter, MatrixError> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(SyncFilter::default());
    };
    let definition = if raw.starts_with('{') {
        raw.to_string()
    } else {
        let filter_id: i64 = raw.parse().map_err(|_| MatrixError::invalid_param("filter must be a filter id or inline JSON"))?;
        crate::store::get_filter(conn, user_id, filter_id)?.ok_or_else(|| MatrixError::not_found("no such filter"))?
    };
    serde_json::from_str(&definition).map_err(|_| MatrixError::invalid_param("malformed filter"))
}


// ============================================================================
// Response emptiness — what makes a long-poll keep waiting
// ============================================================================

fn events_array_is_empty(value: &serde_json::Value, key: &str) -> bool {
    value.get(key).and_then(|v| v.get("events")).and_then(|v| v.as_array()).map(|a| a.is_empty()).unwrap_or(true)
}


/// "No rooms/account-data/to-device/device-lists changes, no typing/receipt
/// change" (P10 brief) — `device_one_time_keys_count`/
/// `device_unused_fallback_key_types` are deliberately NOT part of this
/// check: they are static per-device facts always present, never a "new
/// since last time" signal.
pub fn sync_response_is_empty(value: &serde_json::Value) -> bool {
    let rooms_empty = value
        .get("rooms")
        .map(|rooms| {
            ["join", "invite", "leave"]
                .iter()
                .all(|kind| rooms.get(kind).and_then(|v| v.as_object()).map(|o| o.is_empty()).unwrap_or(true))
        })
        .unwrap_or(true);
    let device_lists_empty = value
        .get("device_lists")
        .map(|dl| {
            ["changed", "left"]
                .iter()
                .all(|k| dl.get(k).and_then(|v| v.as_array()).map(|a| a.is_empty()).unwrap_or(true))
        })
        .unwrap_or(true);
    rooms_empty && events_array_is_empty(value, "account_data") && events_array_is_empty(value, "to_device") && device_lists_empty
}


// ============================================================================
// Event formatting helpers
// ============================================================================

pub fn format_event(conn: &Connection, caller_user_id: i64, caller_device_id: &str, event: &crate::store::MatrixEvent) -> Result<serde_json::Value, MatrixError> {
    let own_txn_id = crate::store::txn_id_for_event(conn, caller_user_id, caller_device_id, &event.event_id)?;
    client_event_json(conn, event, own_txn_id.as_deref())
}


pub fn format_pagination_token(stream_id: i64) -> String {
    format!("t{stream_id}")
}


/// One coalesced `m.receipt` ephemeral event (plan §3.6): every `m.read`
/// receipt (visible to the whole room by definition) plus ONLY the caller's
/// own `m.read.private` receipt — Matrix's own privacy rule that a private
/// receipt must never reach another user's `/sync`. `None` when `receipts`
/// contained only OTHER users' private receipts — after the privacy filter
/// there is nothing left worth an (otherwise empty-content) event at all,
/// and an empty-but-present `m.receipt` event would wrongly count as "this
/// room changed" for the emptiness check that gates a room's inclusion.
pub fn build_receipt_event(conn: &Connection, caller_user_id: i64, receipts: &[crate::store::ReceiptRow]) -> Result<Option<serde_json::Value>, MatrixError> {
    let mut by_event: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    for receipt in receipts {
        if receipt.receipt_type == ReceiptType::ReadPrivate && receipt.user_id != caller_user_id {
            continue;
        }
        let Some(user_mxid) = crate::store::mxid_of(conn, receipt.user_id)? else { continue };

        let event_entry = by_event.entry(receipt.event_id.clone()).or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        let event_map = event_entry.as_object_mut().ok_or_else(MatrixError::internal)?;
        let type_entry = event_map
            .entry(receipt.receipt_type.as_str().to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        let type_map = type_entry.as_object_mut().ok_or_else(MatrixError::internal)?;
        type_map.insert(user_mxid, serde_json::json!({ "ts": receipt.ts }));
    }
    if by_event.is_empty() {
        return Ok(None);
    }
    Ok(Some(serde_json::json!({ "type": "m.receipt", "content": serde_json::Value::Object(by_event) })))
}


// ============================================================================
// Per-room block builders
// ============================================================================

/// One `rooms.join.{roomId}` block, or `None` when this is an incremental
/// sync AND nothing changed for this room at all (a room is only listed
/// when something happened — see the module doc's emptiness rule).
#[allow(clippy::too_many_arguments)]
pub fn build_join_room_block(
    conn: &Connection,
    typing: &crate::typing::TypingRegistry,
    room: &Room,
    caller_user_id: i64,
    caller_mxid: &str,
    caller_device_id: &str,
    since_stream: i64,
    upto: i64,
    is_initial_or_full: bool,
    typing_gen_since: u64,
    filter: &SyncFilter,
    now: Instant,
) -> Result<Option<serde_json::Value>, MatrixError> {
    let member_event = crate::store::current_state_event(conn, &room.id, "m.room.member", caller_mxid)?;
    let joined_stream = member_event.as_ref().map(|e| e.stream_id).unwrap_or(0);
    let newly_joined = !is_initial_or_full && joined_stream > since_stream;
    let full_view = is_initial_or_full || newly_joined;
    let effective_since = if full_view { 0 } else { since_stream };

    let limit = filter.timeline_limit();
    let (mut timeline_events, limited) = if full_view {
        let mut page = crate::store::events_in_room_before(conn, &room.id, upto.saturating_add(1), limit + 1)?;
        let limited = page.len() as i64 > limit;
        if limited {
            page.pop(); // drop the oldest of the N+1 (page is newest-first)
        }
        page.reverse(); // ascending
        (page, limited)
    } else {
        let mut page = crate::store::events_in_room_after(conn, &room.id, since_stream, limit + 1)?;
        let limited = page.len() as i64 > limit;
        if limited {
            let drop_count = page.len() - limit as usize;
            page.drain(0..drop_count); // keep only the newest `limit`
        }
        (page, limited)
    };
    // Computed from the RAW (pre-type-filter) page — `limited` signals a gap
    // in raw stream continuity, independent of what a content filter thins
    // out (matches `routes::matrix::messaging::paginate_messages`'s own
    // precedent).
    let prev_batch = timeline_events.first().map(|e| format_pagination_token(e.stream_id - 1));
    timeline_events.retain(|e| filter.timeline_event_passes(&e.event_type));

    // STATE
    let mut state_events: Vec<crate::store::MatrixEvent> = Vec::new();
    if filter.lazy_load_members() {
        // Clause (a): member events of every DISTINCT sender in the
        // returned (capped) timeline window.
        let mut senders: Vec<i64> = timeline_events.iter().map(|e| e.sender_user_id).collect();
        senders.sort_unstable();
        senders.dedup();
        for sender in senders {
            if let Some(mxid) = crate::store::mxid_of(conn, sender)? {
                if let Some(ev) = crate::store::current_state_event(conn, &room.id, "m.room.member", &mxid)? {
                    state_events.push(ev);
                }
            }
        }
        // Clause (b): the matrix-spec#942 gap rule — only when there is
        // actually a gap the timeline did not cover (incremental + limited;
        // a full/initial view has no prior client state to keep consistent
        // with, so nothing to backfill).
        if !full_view && limited {
            for ev in crate::store::member_state_changed_in_window(conn, &room.id, since_stream, upto)? {
                if !state_events.iter().any(|existing| existing.event_id == ev.event_id) {
                    state_events.push(ev);
                }
            }
        }
    } else {
        state_events.extend(crate::store::state_events_of_type_at(conn, &room.id, "m.room.member", upto)?);
    }
    // Every OTHER state type: the delta since `effective_since` (never
    // gated on `limited` — see the module doc), MINUS anything already
    // present in the returned `timeline` (manager review, 2026-09-24):
    // `state` is the state at the START of the timeline window, not a
    // second copy of state changes the client is ALREADY receiving as
    // timeline entries. On a non-limited incremental sync this makes
    // non-member `state` collapse to empty (every state change in the
    // window is, by definition, already IN that unlimited timeline); on a
    // limited one, only the gap's changes — the ones the truncated
    // timeline did NOT cover — survive the exclusion below.
    state_events.extend(crate::store::non_member_state_changed_in_window(conn, &room.id, effective_since, upto)?);
    let timeline_event_ids: std::collections::HashSet<&str> = timeline_events.iter().map(|e| e.event_id.as_str()).collect();
    state_events.retain(|e| !timeline_event_ids.contains(e.event_id.as_str()));

    // EPHEMERAL: typing + receipts
    let mut ephemeral_events = Vec::new();
    let room_typing_serial = typing.typing_serial(&room.id, now);
    if full_view || room_typing_serial > typing_gen_since {
        let user_ids: Vec<String> =
            typing.typing_users(&room.id, now).into_iter().filter_map(|uid| crate::store::mxid_of(conn, uid).ok().flatten()).collect();
        ephemeral_events.push(serde_json::json!({ "type": "m.typing", "content": { "user_ids": user_ids } }));
    }
    let receipts = crate::store::receipts_changed_in_room(conn, &room.id, effective_since, upto)?;
    if !receipts.is_empty() {
        if let Some(receipt_event) = build_receipt_event(conn, caller_user_id, &receipts)? {
            ephemeral_events.push(receipt_event);
        }
    }

    // ACCOUNT DATA
    let mut account_data_events = Vec::new();
    for row in crate::store::account_data_since(conn, caller_user_id, &room.id, effective_since)? {
        if !filter.account_data_passes(&row.data_type) {
            continue;
        }
        let content: serde_json::Value = serde_json::from_str(&row.content).unwrap_or_else(|_| serde_json::json!({}));
        account_data_events.push(serde_json::json!({ "type": row.data_type, "content": content }));
    }

    let is_empty_incremental =
        !full_view && timeline_events.is_empty() && state_events.is_empty() && ephemeral_events.is_empty() && account_data_events.is_empty();
    if is_empty_incremental {
        return Ok(None);
    }

    let mut timeline_json = Vec::with_capacity(timeline_events.len());
    for event in &timeline_events {
        timeline_json.push(format_event(conn, caller_user_id, caller_device_id, event)?);
    }
    let mut state_json = Vec::with_capacity(state_events.len());
    for event in &state_events {
        state_json.push(format_event(conn, caller_user_id, caller_device_id, event)?);
    }

    // `summary` is always attached whenever the room block itself is sent
    // (never gated on detecting a change against a prior sync — this
    // server does not persist a "last reported summary" to compare
    // against; re-sending unchanged, cheap, idempotent metadata is spec-
    // permitted and harmless, unlike re-sending the whole timeline would
    // be).
    let heroes: Vec<String> = crate::store::room_heroes(conn, &room.id, caller_user_id, SYNC_HERO_LIMIT)?
        .into_iter()
        .filter_map(|uid| crate::store::mxid_of(conn, uid).ok().flatten())
        .collect();
    let joined_count = crate::store::room_members(conn, &room.id, Some(Membership::Join))?.len();
    let invited_count = crate::store::room_members(conn, &room.id, Some(Membership::Invite))?.len();
    let notification_count = crate::store::notification_count(conn, room, caller_user_id)?;

    let mut timeline = serde_json::json!({ "events": timeline_json, "limited": limited });
    if let Some(prev_batch) = prev_batch {
        timeline["prev_batch"] = serde_json::Value::String(prev_batch);
    }

    Ok(Some(serde_json::json!({
        "summary": {
            "m.heroes": heroes,
            "m.joined_member_count": joined_count,
            "m.invited_member_count": invited_count,
        },
        "state": { "events": state_json },
        "timeline": timeline,
        "ephemeral": { "events": ephemeral_events },
        "account_data": { "events": account_data_events },
        // `highlight_count` is always 0 — no push-rule/keyword-highlight
        // engine in this server (plan §3.5).
        "unread_notifications": { "notification_count": notification_count, "highlight_count": 0 },
    })))
}


/// One `rooms.invite.{roomId}` block, or `None` when the invite is not new
/// (an incremental sync whose invite predates `since_stream`).
pub fn build_invite_room_block(conn: &Connection, room_id: &str, caller_mxid: &str, is_initial: bool, since_stream: i64) -> Result<Option<serde_json::Value>, MatrixError> {
    let Some(member_event) = crate::store::current_state_event(conn, room_id, "m.room.member", caller_mxid)? else {
        return Ok(None);
    };
    if !(is_initial || member_event.stream_id > since_stream) {
        return Ok(None);
    }
    let mut events = crate::store::stripped_invite_state(conn, room_id, member_event.sender_user_id)?;
    events.push(crate::store::stripped_state_json(conn, &member_event)?);
    Ok(Some(serde_json::json!({ "invite_state": { "events": events } })))
}


/// One `rooms.leave.{roomId}` block: timeline up to and including the
/// leave/kick/ban event itself (naturally bounded — nothing after that
/// point is ever queried), `state` minimal (v1 simplification: the client
/// was previously joined, so it already has the room's bootstrap state from
/// before it left — nothing new is reconstructed here).
pub fn build_leave_room_block(
    conn: &Connection,
    room: &Room,
    caller_user_id: i64,
    caller_device_id: &str,
    member_event: &crate::store::MatrixEvent,
    limit: i64,
) -> Result<serde_json::Value, MatrixError> {
    let mut page = crate::store::events_in_room_before(conn, &room.id, member_event.stream_id.saturating_add(1), limit + 1)?;
    let limited = page.len() as i64 > limit;
    if limited {
        page.pop();
    }
    page.reverse();

    let mut events_json = Vec::with_capacity(page.len());
    for event in &page {
        events_json.push(format_event(conn, caller_user_id, caller_device_id, event)?);
    }

    Ok(serde_json::json!({
        "timeline": { "events": events_json, "limited": limited },
        "state": { "events": [] },
    }))
}


// ============================================================================
// The whole-response builder — one consistent cut (see the module doc)
// ============================================================================

#[allow(clippy::too_many_arguments)]
pub fn build_sync_response(
    conn: &Connection,
    typing: &crate::typing::TypingRegistry,
    caller_user_id: i64,
    caller_mxid: &str,
    caller_device_id: &str,
    since: Option<sync_token::SyncToken>,
    filter: &SyncFilter,
    full_state: bool,
    now: Instant,
) -> Result<serde_json::Value, MatrixError> {
    let upto = crate::store::max_stream_id(conn)?;
    let since_stream = since.map(|t| t.stream_id).unwrap_or(0);
    let typing_gen_since = since.map(|t| t.typing_gen).unwrap_or(0);
    // Snapshotted BEFORE any per-room typing read (mirrors `live.rs`'s own
    // "register before read" discipline): any typing change racing in
    // AFTER this point still stamps a room serial strictly greater than
    // what we are about to hand back as `next_batch`, so the client's NEXT
    // poll (using that value as its own `typing_gen_since`) is guaranteed
    // to observe it. Capturing this AFTER building rooms would risk the
    // reverse: a change landing after a room's own (already-negative) check
    // but before this snapshot would be stamped INTO next_batch without
    // ever having been reported — silently lost until a later change
    // happens to exceed it.
    let typing_gen_now = typing.current_typing_gen();
    let is_initial = since.is_none() || full_state;

    // Delete-after-ack: the client asking for `since_stream` is itself the
    // proof it already durably received everything up to that point
    // (plan §3.7). A no-op for an initial sync (`since_stream == 0`).
    crate::keys::delete_to_device_up_to(conn, caller_user_id, caller_device_id, since_stream)?;

    let timeline_limit = filter.timeline_limit();

    let joined_room_ids = crate::store::rooms_for_user(conn, caller_user_id, Some(Membership::Join))?;
    // Changed-room prefilter (manager review, 2026-09-24): on an initial/
    // `full_state` sync every joined room is built regardless (there is no
    // `since` boundary to prefilter against). On an incremental sync,
    // building EVERY joined room's block just to discover most did not
    // change costs a room block builder's own dozen-odd queries per room —
    // with a few hundred rooms that is thousands of queries per wake, all
    // held under the single `messenger.db` mutex, blocking every other
    // user. `rooms_changed_in_window` answers "did anything happen here at
    // all" in three cheap, indexed queries total (not per room), and the
    // in-memory typing check costs nothing; only rooms in the resulting set
    // ever reach [`build_join_room_block`].
    let rooms_to_build: Vec<String> = if is_initial {
        joined_room_ids.clone()
    } else {
        let mut changed = crate::store::rooms_changed_in_window(conn, &joined_room_ids, caller_user_id, since_stream, upto)?;
        for room_id in &joined_room_ids {
            if typing.typing_serial(room_id, now) > typing_gen_since {
                changed.insert(room_id.clone());
            }
        }
        joined_room_ids.iter().filter(|room_id| changed.contains(*room_id)).cloned().collect()
    };

    let mut rooms_join = serde_json::Map::new();
    for room_id in rooms_to_build {
        let Some(room) = crate::store::get_room(conn, &room_id)? else { continue };
        if let Some(block) = build_join_room_block(
            conn,
            typing,
            &room,
            caller_user_id,
            caller_mxid,
            caller_device_id,
            since_stream,
            upto,
            is_initial,
            typing_gen_since,
            filter,
            now,
        )? {
            rooms_join.insert(room_id, block);
        }
    }

    let mut rooms_invite = serde_json::Map::new();
    for room_id in crate::store::rooms_for_user(conn, caller_user_id, Some(Membership::Invite))? {
        if let Some(block) = build_invite_room_block(conn, &room_id, caller_mxid, is_initial, since_stream)? {
            rooms_invite.insert(room_id, block);
        }
    }

    // Left rooms: an initial sync omits them entirely (there is no boundary
    // to test "left inside the window" against), and even on an incremental
    // sync only when the filter opts in (`room.include_leave`, default
    // false — P10 brief).
    let mut rooms_leave = serde_json::Map::new();
    if since.is_some() && filter.include_leave() {
        for membership in [Membership::Leave, Membership::Ban] {
            for room_id in crate::store::rooms_for_user(conn, caller_user_id, Some(membership))? {
                let Some(room) = crate::store::get_room(conn, &room_id)? else { continue };
                let Some(member_event) = crate::store::current_state_event(conn, &room_id, "m.room.member", caller_mxid)? else { continue };
                if member_event.stream_id > since_stream {
                    let block = build_leave_room_block(conn, &room, caller_user_id, caller_device_id, &member_event, timeline_limit)?;
                    rooms_leave.insert(room_id, block);
                }
            }
        }
    }

    let account_data_since_global = if is_initial { 0 } else { since_stream };
    let mut global_account_data = Vec::new();
    for row in crate::store::account_data_since(conn, caller_user_id, crate::store::GLOBAL_ACCOUNT_DATA_ROOM, account_data_since_global)? {
        if !filter.account_data_passes(&row.data_type) {
            continue;
        }
        let content: serde_json::Value = serde_json::from_str(&row.content).unwrap_or_else(|_| serde_json::json!({}));
        global_account_data.push(serde_json::json!({ "type": row.data_type, "content": content }));
    }

    // Cap to-device delivery at `SYNC_TO_DEVICE_CAP`. If capped, lower ONLY
    // `next_batch`'s own stream position to the last DELIVERED message's
    // `stream_id` (P10 brief's "deliver in order and let the next sync
    // continue" option) — every other field in THIS response still reflects
    // the full `upto` snapshot; anything past the lowered watermark that
    // would otherwise have been reported now is simply reported again on
    // the next call, which is safe (event ids are stable, receipts/account
    // data are last-write-wins).
    let mut to_device_raw = crate::keys::to_device_for(conn, caller_user_id, caller_device_id, since_stream, SYNC_TO_DEVICE_CAP + 1)?;
    let to_device_capped = to_device_raw.len() as i64 > SYNC_TO_DEVICE_CAP;
    if to_device_capped {
        to_device_raw.truncate(SYNC_TO_DEVICE_CAP as usize);
    }
    let effective_upto = if to_device_capped { to_device_raw.last().map(|m| m.stream_id).unwrap_or(upto) } else { upto };
    let mut to_device_events = Vec::with_capacity(to_device_raw.len());
    for message in &to_device_raw {
        let Some(sender_mxid) = crate::store::mxid_of(conn, message.sender_user_id)? else { continue };
        let content: serde_json::Value = serde_json::from_str(&message.content).unwrap_or_else(|_| serde_json::json!({}));
        to_device_events.push(serde_json::json!({ "sender": sender_mxid, "type": message.event_type, "content": content }));
    }

    // Device lists: omitted entirely on an initial/`full_state` sync (a
    // fresh client queries `/keys/query` for every room member outright —
    // an incremental DELTA has no meaning against no prior state).
    //
    // Incrementally, `changed` also carries users who newly share an
    // encrypted room with the caller (a join/invite since `since`), and `left`
    // users who no longer share any room with it — see
    // [`super::keys::device_list_delta`], which `/keys/changes` shares.
    let (device_lists_changed, device_lists_left) = if is_initial {
        (Vec::<String>::new(), Vec::<String>::new())
    } else {
        let delta = crate::key_ops::device_list_delta(conn, caller_user_id, since_stream, upto)?;
        (delta.changed, delta.left)
    };

    let otk_counts = crate::keys::count_one_time_keys(conn, caller_user_id, caller_device_id)?;
    let unused_fallback = crate::keys::unused_fallback_key_types(conn, caller_user_id, caller_device_id)?;

    let next_batch = sync_token::format(effective_upto, typing_gen_now);

    Ok(serde_json::json!({
        "next_batch": next_batch,
        "account_data": { "events": global_account_data },
        "to_device": { "events": to_device_events },
        "device_lists": { "changed": device_lists_changed, "left": device_lists_left },
        "device_one_time_keys_count": otk_counts,
        "device_unused_fallback_key_types": unused_fallback,
        // No presence pushed at all in this server (plan §4/research §1.6).
        "presence": { "events": [] },
        "rooms": {
            "join": serde_json::Value::Object(rooms_join),
            "invite": serde_json::Value::Object(rooms_invite),
            "leave": serde_json::Value::Object(rooms_leave),
        },
    }))
}
#[derive(serde::Deserialize, Default)]
pub struct SyncQuery {
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub full_state: Option<bool>,
}
