//! Timeline send, redact, and history paging over an open connection.
//! Entitlements are the builder's. A private room does not consult a paid flag.

use std::collections::HashSet;

use rusqlite::Connection;

use crate::error::MatrixError;
use crate::events::client_event_json;
use crate::store::{Membership, PowerAction, Room, TxnDedupEntry};

// ============================================================================
// Rate limits (plan §3.8) — own copies per this codebase's
// one-copy-per-route-module convention (mirrors `dm_db::DM_MESSAGE_DAILY_LIMIT`
// via `routes::dm::create_message`'s own daily check).
// ============================================================================

/// Per-sender messages-per-day cap in private rooms, mirroring
/// [`dm_db`](crate::dm_db)'s own `DM_MESSAGE_DAILY_LIMIT` value.
pub const MATRIX_SEND_DAILY_LIMIT: i64 = 300;

/// Short-window burst cap: at most this many sends/redacts per device.
pub const BURST_LIMIT_COUNT: i64 = 20;

/// ...within this many seconds.
pub const BURST_LIMIT_WINDOW_SECS: i64 = 10;


pub const ONE_DAY_MS: u64 = 24 * 60 * 60 * 1000;


pub fn check_rate_limits(conn: &Connection, user_id: i64, device_id: &str, now: &str) -> Result<(), MatrixError> {
    let now_dt = chrono::DateTime::parse_from_rfc3339(now).map_err(|_| MatrixError::internal())?;

    let since_ms = (now_dt - chrono::Duration::hours(24)).timestamp_millis();
    let daily = crate::store::private_room_messages_sent_since(conn, user_id, since_ms)?;
    if daily >= MATRIX_SEND_DAILY_LIMIT {
        return Err(MatrixError::limit_exceeded(ONE_DAY_MS));
    }

    let burst_since = (now_dt - chrono::Duration::seconds(BURST_LIMIT_WINDOW_SECS)).to_rfc3339();
    let burst = crate::store::txn_dedup_count_since(conn, user_id, device_id, &burst_since)?;
    if burst >= BURST_LIMIT_COUNT {
        return Err(MatrixError::limit_exceeded(BURST_LIMIT_WINDOW_SECS as u64 * 1000));
    }
    Ok(())
}


// ============================================================================
// Pagination tokens and limits — shared by `/messages` and `/relations`
// ============================================================================

pub const MESSAGES_DEFAULT_LIMIT: i64 = 10;

pub const MESSAGES_MAX_LIMIT: i64 = 100;


/// A parsed pagination position — see the module doc.
///
/// A `t{stream_id}` token (or a bare integer) sits ON event `stream_id`:
/// a backward page starts strictly before it, a forward page strictly after
/// it. A sync token `s{stream_id}_{typing_gen}` (a `/sync` `next_batch` or
/// `prev_batch`) sits AFTER event `stream_id` — that event was already
/// delivered — so a backward page from it must still include that event. The
/// typing half of a sync token is irrelevant to history and is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamToken {
    pub stream_id: i64,
    pub after_event: bool,
}


impl StreamToken {
    /// The exclusive upper bound of a page that walks backward from this
    /// position: events with `stream_id < bound`.
    pub fn backward_bound(self) -> i64 {
        if self.after_event {
            self.stream_id.saturating_add(1)
        } else {
            self.stream_id
        }
    }

    /// The exclusive lower bound of a page that walks forward from this
    /// position: events with `stream_id > bound`.
    pub fn forward_bound(self) -> i64 {
        self.stream_id
    }

    /// The `to=` boundary of a page walking `dir`: the far end a page must
    /// not cross. It is the position's bound as seen from the opposite walk
    /// direction, since `to` is approached rather than left.
    pub fn to_bound(self, dir: Direction) -> i64 {
        match dir {
            Direction::Backward => self.forward_bound(),
            Direction::Forward => self.backward_bound(),
        }
    }
}


/// `"t{stream_id}"`, a bare `"0"`, or a sync token `"s{stream_id}_{typing_gen}"`
/// — see the module doc. Anything else, and any negative stream id, is
/// refused with `M_INVALID_PARAM`.
pub fn parse_stream_token(raw: &str) -> Result<StreamToken, MatrixError> {
    let malformed = || MatrixError::invalid_param("malformed pagination token");
    let token = if raw.starts_with('s') {
        let sync = crate::sync_token::parse(raw).map_err(|_| malformed())?;
        StreamToken { stream_id: sync.stream_id, after_event: true }
    } else {
        let digits = raw.strip_prefix('t').unwrap_or(raw);
        StreamToken { stream_id: digits.parse::<i64>().map_err(|_| malformed())?, after_event: false }
    };
    if token.stream_id < 0 {
        return Err(malformed());
    }
    Ok(token)
}


/// The page start `GET /messages` walks from: the explicit `from` token when
/// present, else the far end of the timeline for `dir` — the newest event
/// going backward, the very beginning going forward (Matrix makes `from`
/// optional and defines exactly this).
pub fn resolve_messages_start(conn: &Connection, from: Option<StreamToken>, dir: Direction) -> rusqlite::Result<i64> {
    Ok(match (from, dir) {
        (Some(token), Direction::Backward) => token.backward_bound(),
        (Some(token), Direction::Forward) => token.forward_bound(),
        (None, Direction::Backward) => crate::store::max_stream_id(conn)?.saturating_add(1),
        (None, Direction::Forward) => 0,
    })
}


pub fn format_stream_token(stream_id: i64) -> String {
    format!("t{stream_id}")
}


pub fn clamp_limit(requested: Option<i64>) -> i64 {
    requested.unwrap_or(MESSAGES_DEFAULT_LIMIT).clamp(1, MESSAGES_MAX_LIMIT)
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Backward,
    Forward,
}


impl Direction {
    pub fn from_query(raw: Option<&str>) -> Result<Self, MatrixError> {
        match raw.unwrap_or("b") {
            "b" => Ok(Direction::Backward),
            "f" => Ok(Direction::Forward),
            _ => Err(MatrixError::invalid_param("dir must be 'b' or 'f'")),
        }
    }
}


#[derive(serde::Deserialize, Default, Clone)]
pub struct EventFilter {
    #[serde(default)]
    pub types: Option<Vec<String>>,
    #[serde(default)]
    pub not_types: Option<Vec<String>>,
    #[serde(default)]
    pub lazy_load_members: bool,
}


pub fn event_passes_filter(event_type: &str, filter: &EventFilter) -> bool {
    if let Some(types) = &filter.types {
        if !types.iter().any(|t| t == event_type) {
            return false;
        }
    }
    if let Some(not_types) = &filter.not_types {
        if not_types.iter().any(|t| t == event_type) {
            return false;
        }
    }
    true
}


pub fn parse_filter(raw: Option<&str>) -> Result<EventFilter, MatrixError> {
    match raw {
        Some(raw) => serde_json::from_str(raw).map_err(|_| MatrixError::invalid_param("malformed filter")),
        None => Ok(EventFilter::default()),
    }
}


// ============================================================================
// DB-only gate/read helpers — own copies of `routes::matrix::rooms`'s small
// checks (per this codebase's one-copy-per-route-module convention); only
// `member_and_invited_ids` (the wake fan-out set) is reused verbatim — see
// the module doc.
// ============================================================================

pub fn power_levels_of(conn: &Connection, room_id: &str) -> Result<serde_json::Value, MatrixError> {
    match crate::store::current_state_event(conn, room_id, "m.room.power_levels", "")? {
        Some(event) => Ok(serde_json::from_str(&event.content)?),
        None => Ok(serde_json::json!({})),
    }
}


pub fn require_member(membership: Option<Membership>) -> Result<(), MatrixError> {
    match membership {
        Some(Membership::Join) => Ok(()),
        _ => Err(MatrixError::forbidden("not a member of this room")),
    }
}


pub fn require_power(power_levels: &serde_json::Value, mxid: &str, action: PowerAction) -> Result<(), MatrixError> {
    if crate::store::can(power_levels, action, mxid) {
        Ok(())
    } else {
        Err(MatrixError::forbidden("insufficient power level for this action"))
    }
}


// ============================================================================
// Pure decision functions — no DB, no `MatrixCaller`, unit-tested directly
// ============================================================================

/// Every state-event type `PUT /state/{eventType}/{stateKey}` owns, refused
/// outright on `/send` (P6 binding rule) — includes our own
/// `org.example.legacy_dm_key` alongside the standard `m.room.*` state
/// types.
pub const REFUSED_SEND_STATE_TYPES: [&str;
 10] = [
    "m.room.create",
    "m.room.member",
    "m.room.power_levels",
    "m.room.join_rules",
    "m.room.history_visibility",
    "m.room.name",
    "m.room.topic",
    "m.room.avatar",
    "m.room.encryption",
    "m.room.pinned_events",
];
pub const LEGACY_DM_KEY_STATE_TYPE: &str = "org.example.legacy_dm_key";


/// `PUT /send/{eventType}/{txnId}`'s type-refusal rule (P6 binding rule):
/// state-event types and `org.example.legacy_dm_key` go through
/// `/state`; `org.example.legacy_dm` is migration-only; `m.room.redaction`
/// goes through `/redact`; and, in an encrypted room, only `m.room.encrypted`
/// and `m.reaction` (server-visible metadata, coordinator ruling) are
/// accepted at all.
pub fn check_send_event_type_allowed(event_type: &str, room_is_encrypted: bool) -> Result<(), MatrixError> {
    if REFUSED_SEND_STATE_TYPES.contains(&event_type) || event_type == LEGACY_DM_KEY_STATE_TYPE {
        return Err(MatrixError::bad_json(format!("{event_type} is a state event; send it via PUT /state/{{eventType}}/{{stateKey}}")));
    }
    if event_type == "org.example.legacy_dm" {
        return Err(MatrixError::forbidden("org.example.legacy_dm is migration-only and cannot be sent by a client"));
    }
    if event_type == "m.room.redaction" {
        return Err(MatrixError::bad_json("use PUT /rooms/{roomId}/redact/{eventId}/{txnId} to redact an event"));
    }
    if room_is_encrypted && event_type != "m.room.encrypted" && event_type != "m.reaction" {
        return Err(MatrixError::forbidden("only m.room.encrypted and m.reaction may be sent in an encrypted room"));
    }
    Ok(())
}


/// An `m.replace` must come from the target event's ORIGINAL sender (P6
/// binding rule) — a no-op for content with no `m.relates_to`, or a
/// `rel_type` other than `m.replace`.
pub fn check_replace_target_sender(conn: &Connection, content: &serde_json::Value, sender_user_id: i64) -> Result<(), MatrixError> {
    let Some(relates_to) = content.get("m.relates_to") else { return Ok(()) };
    if relates_to.get("rel_type").and_then(|v| v.as_str()) != Some("m.replace") {
        return Ok(());
    }
    let Some(target_id) = relates_to.get("event_id").and_then(|v| v.as_str()) else { return Ok(()) };
    let target = crate::store::get_event(conn, target_id)?.ok_or_else(|| MatrixError::not_found("relation target not found"))?;
    if target.sender_user_id != sender_user_id {
        return Err(MatrixError::invalid_param("m.replace must be sent by the target event's original sender"));
    }
    Ok(())
}


// ============================================================================
// DB-only action cores — `&mut Connection`, no `MatrixCaller`, unit-tested
// directly against an in-memory `matrix_store` fixture
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct SendOutcome {
    pub event: crate::store::MatrixEvent,
    pub is_new: bool,
    pub wake_ids: HashSet<i64>,
}


/// `PUT /send/{eventType}/{txnId}`'s whole DB-side decision + write (plan §4
/// `send` row): txn-dedup peek first (a repeat short-circuits everything
/// else and returns the ORIGINAL event, per the idempotency rule); then
/// Member, the type-refusal rule, PowerCheck(`events[type]` else
/// `events_default`), the
/// send-rate limits, and the `m.replace`-sender rule; then the dedup-checked
/// insert itself.
#[allow(clippy::too_many_arguments)]
pub fn apply_send(
    conn: &mut Connection,
    room: &Room,
    caller_user_id: i64,
    caller_mxid: &str,
    device_id: &str,
    txn_id: &str,
    event_id: &str,
    event_type: &str,
    content_str: &str,
    now: &str,
    origin_ts: i64,
) -> Result<SendOutcome, MatrixError> {
    if let TxnDedupEntry::Seen(existing_event_id) = crate::store::txn_dedup_lookup(conn, caller_user_id, device_id, txn_id)? {
        let existing_event_id = existing_event_id.ok_or_else(MatrixError::internal)?;
        let event = crate::store::get_event(conn, &existing_event_id)?.ok_or_else(MatrixError::internal)?;
        return Ok(SendOutcome { event, is_new: false, wake_ids: HashSet::new() });
    }

    let caller_membership = crate::store::room_member(conn, &room.id, caller_user_id)?.map(|m| m.membership);
    require_member(caller_membership)?;
    check_send_event_type_allowed(event_type, room.is_encrypted)?;

    let power_levels = power_levels_of(conn, &room.id)?;
    if crate::store::user_level(&power_levels, caller_mxid) < crate::store::event_level(&power_levels, event_type, false) {
        return Err(MatrixError::forbidden("insufficient power level to send this event"));
    }

    check_rate_limits(conn, caller_user_id, device_id, now)?;

    let content: serde_json::Value = serde_json::from_str(content_str)?;
    check_replace_target_sender(conn, &content, caller_user_id)?;

    match crate::store::insert_timeline_event_deduped(conn, device_id, txn_id, event_id, &room.id, caller_user_id, event_type, content_str, origin_ts, now)? {
        crate::store::DedupedWrite::New(event) => {
            let wake_ids = crate::rooms::member_and_invited_ids(conn, &room.id)?;
            Ok(SendOutcome { event, is_new: true, wake_ids })
        }
        // Cannot happen — the peek above already established `NotSeen`
        // under the same connection, and this module's single-writer
        // discipline means nothing else can have raced it — but handled
        // defensively rather than panicking.
        crate::store::DedupedWrite::Existing(event) => Ok(SendOutcome { event, is_new: false, wake_ids: HashSet::new() }),
    }
}


#[derive(Debug, Clone, PartialEq)]
pub struct RedactOutcome {
    pub event: crate::store::MatrixEvent,
    pub is_new: bool,
    pub wake_ids: HashSet<i64>,
}


/// `PUT /redact/{eventId}/{txnId}`'s whole DB-side decision + write (plan §4
/// `redact` row): txn-dedup peek first; then Member; then own-event OR
/// PowerCheck(redact) — redact does NOT require the sender's level to
/// exceed the target's own level (spec rule, unlike kick/ban/unban); then
/// the dedup-checked redaction itself (which enforces the v11
/// unredactable-event-type rule and maps to 403 via
/// `MatrixStoreError::UnredactableEvent`).
#[allow(clippy::too_many_arguments)]
pub fn apply_redact(
    conn: &mut Connection,
    room_id: &str,
    caller_user_id: i64,
    caller_mxid: &str,
    device_id: &str,
    txn_id: &str,
    target_event_id: &str,
    redaction_event_id: &str,
    reason: Option<&str>,
    now: &str,
    origin_ts: i64,
) -> Result<RedactOutcome, MatrixError> {
    if let TxnDedupEntry::Seen(existing_event_id) = crate::store::txn_dedup_lookup(conn, caller_user_id, device_id, txn_id)? {
        let existing_event_id = existing_event_id.ok_or_else(MatrixError::internal)?;
        let event = crate::store::get_event(conn, &existing_event_id)?.ok_or_else(MatrixError::internal)?;
        return Ok(RedactOutcome { event, is_new: false, wake_ids: HashSet::new() });
    }

    let caller_membership = crate::store::room_member(conn, room_id, caller_user_id)?.map(|m| m.membership);
    require_member(caller_membership)?;

    let target = crate::store::get_event(conn, target_event_id)?.ok_or_else(|| MatrixError::not_found("no such event"))?;
    if target.room_id != room_id {
        return Err(MatrixError::not_found("no such event"));
    }
    if target.sender_user_id != caller_user_id {
        let power_levels = power_levels_of(conn, room_id)?;
        require_power(&power_levels, caller_mxid, PowerAction::Redact)?;
    }

    match crate::store::redact_event_deduped(conn, device_id, txn_id, room_id, target_event_id, redaction_event_id, caller_user_id, reason, origin_ts, now)? {
        crate::store::DedupedWrite::New(event) => {
            let wake_ids = crate::rooms::member_and_invited_ids(conn, room_id)?;
            Ok(RedactOutcome { event, is_new: true, wake_ids })
        }
        crate::store::DedupedWrite::Existing(event) => Ok(RedactOutcome { event, is_new: false, wake_ids: HashSet::new() }),
    }
}


/// One page of `/messages`' timeline window — [`get_messages`]'s own DB-only
/// core, unit-tested directly.
pub struct MessagesPage {
    pub chunk: Vec<crate::store::MatrixEvent>,
    pub start: String,
    /// `None` when there is nothing further this caller could ever see
    /// beyond this page (the physical edge of the room, the caller's own
    /// [`crate::store::HistoryWindow`], or an explicit `to=` boundary) —
    /// NEVER `None` merely because a `types`/`not_types` filter thinned this
    /// particular page (more matching events could still exist further on).
    pub end: Option<String>,
}


#[allow(clippy::too_many_arguments)]
pub fn paginate_messages(
    conn: &Connection,
    room_id: &str,
    window: crate::store::HistoryWindow,
    from_stream: i64,
    to_stream: Option<i64>,
    dir: Direction,
    limit: i64,
    filter: &EventFilter,
) -> rusqlite::Result<MessagesPage> {
    let raw_page = match dir {
        Direction::Backward => crate::store::events_in_room_before(conn, room_id, from_stream, limit)?,
        Direction::Forward => crate::store::events_in_room_after(conn, room_id, from_stream, limit)?,
    };
    let raw_len = raw_page.len();

    let hard_truncated = |e: &crate::store::MatrixEvent| -> bool {
        if !window.contains(e.stream_id) {
            return true;
        }
        match (to_stream, dir) {
            (Some(to), Direction::Backward) => e.stream_id <= to,
            (Some(to), Direction::Forward) => e.stream_id >= to,
            (None, _) => false,
        }
    };
    let any_hard_truncated = raw_page.iter().any(hard_truncated);
    let chunk: Vec<crate::store::MatrixEvent> =
        raw_page.iter().filter(|e| !hard_truncated(e) && event_passes_filter(&e.event_type, filter)).cloned().collect();

    let end = if raw_len < limit as usize || any_hard_truncated {
        None
    } else {
        raw_page.last().map(|e| format_stream_token(e.stream_id))
    };

    Ok(MessagesPage { chunk, start: format_stream_token(from_stream), end })
}


pub fn lazy_load_member_state(conn: &Connection, room_id: &str, chunk: &[crate::store::MatrixEvent]) -> Result<Vec<serde_json::Value>, MatrixError> {
    let mut senders: Vec<i64> = chunk.iter().map(|e| e.sender_user_id).collect();
    senders.sort_unstable();
    senders.dedup();

    let mut out = Vec::new();
    for sender in senders {
        let Some(mxid) = crate::store::mxid_of(conn, sender)? else { continue };
        if let Some(event) = crate::store::current_state_event(conn, room_id, "m.room.member", &mxid)? {
            out.push(client_event_json(conn, &event, None)?);
        }
    }
    Ok(out)
}


// ============================================================================
// PUT /_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}
// ============================================================================

#[derive(serde::Deserialize, Default)]
pub struct RedactBody {
    #[serde(default)]
    pub reason: Option<String>,
}


// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/messages
// ============================================================================

#[derive(serde::Deserialize)]
pub struct MessagesQuery {
    /// Optional (Matrix v1.3+): absent means "from the newest event" for
    /// `dir=b` and "from the beginning" for `dir=f`.
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub dir: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub filter: Option<String>,
}


// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/relations/{eventId}[/{relType}[/{eventType}]]
// ============================================================================

#[derive(serde::Deserialize, Default)]
pub struct RelationsQuery {
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}
