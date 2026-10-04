//! Typing, receipts, and read markers.
//! [`crate::typing::TypingRegistry`] is in memory. This module does not wake.

use std::collections::HashSet;
use std::time::Instant;

use rusqlite::Connection;

use crate::error::MatrixError;
use crate::store::{Membership, ReceiptType, Room};

/// Applied when a `PUT .../typing/{userId}` body omits `timeout` and
/// `typing: true` — matches
/// [`crate::typing::TypingRegistry::set_typing`]'s own clamp
/// ceiling (its private `TYPING_MAX_TIMEOUT_MS`), so an omitted timeout
/// behaves the same as the largest timeout a client could ask for.
pub const DEFAULT_TYPING_TIMEOUT_MS: u64 = 30_000;


// ============================================================================
// DB-only gate helper — own copy per this codebase's convention (mirrors
// `routes::matrix::rooms::require_member`/`routes::matrix::messaging::
// require_member` byte-for-byte).
// ============================================================================

pub fn require_member(membership: Option<Membership>) -> Result<(), MatrixError> {
    match membership {
        Some(Membership::Join) => Ok(()),
        _ => Err(MatrixError::forbidden("not a member of this room")),
    }
}
pub fn check_typing_target(target_mxid: &str, caller_mxid: &str) -> Result<(), MatrixError> {
    if target_mxid == caller_mxid {
        Ok(())
    } else {
        Err(MatrixError::forbidden("userId must be the caller's own mxid"))
    }
}
pub fn apply_typing(
    conn: &Connection,
    typing_registry: &crate::typing::TypingRegistry,
    room_id: &str,
    caller_user_id: i64,
    typing: bool,
    timeout_ms: u64,
    now: Instant,
) -> Result<Option<HashSet<i64>>, MatrixError> {
    crate::store::get_room(conn, room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
    let membership = crate::store::room_member(conn, room_id, caller_user_id)?.map(|m| m.membership);
    require_member(membership)?;

    let changed = typing_registry.set_typing(room_id, caller_user_id, typing, timeout_ms, now);
    if !changed {
        return Ok(None);
    }
    Ok(Some(crate::rooms::member_and_invited_ids(conn, room_id)?))
}


/// `POST /receipt/{receiptType}/{eventId}`'s whole DB-side decision (plan §4
/// `receipt` row, and the `m.read`/`m.read.private` branches of `POST
/// /read_markers`): Member, then the target event must be visible to the
/// caller ([`crate::store::visible_upper_bound`] — for a `join`ed member
/// (the only membership this gate accepts) this is always
/// [`crate::store::HistoryWindow::All`] unless a `world_readable` room's
/// event simply does not exist in THIS room at all, which the room-id filter
/// below already catches), then [`crate::store::upsert_receipt`]'s own
/// monotonic upsert. Returns `None` (no wake) when the upsert did not
/// actually move the receipt forward — a backwards or repeat receipt is a
/// silent no-op, detected here by comparing the receipt's `stream_id`
/// before and after the upsert, never by re-deriving the monotonic
/// comparison a second time.
pub fn apply_receipt(
    conn: &mut Connection,
    room: &Room,
    caller_user_id: i64,
    receipt_type: ReceiptType,
    event_id: &str,
    now_ms: i64,
) -> Result<Option<HashSet<i64>>, MatrixError> {
    let caller_membership = crate::store::room_member(conn, &room.id, caller_user_id)?.map(|m| m.membership);
    require_member(caller_membership)?;

    let window = crate::store::visible_upper_bound(conn, room, caller_user_id)?;
    let target = crate::store::get_event(conn, event_id)?
        .filter(|e| e.room_id == room.id)
        .ok_or_else(|| MatrixError::not_found("no such event"))?;
    if !window.contains(target.stream_id) {
        return Err(MatrixError::forbidden("event is outside your visible history"));
    }

    let before = crate::store::get_receipt(conn, &room.id, caller_user_id, receipt_type)?;
    let new_stream_id = crate::store::upsert_receipt(conn, &room.id, caller_user_id, receipt_type, event_id, now_ms)?;
    if before.as_ref().map(|r| r.stream_id) == Some(new_stream_id) {
        return Ok(None);
    }

    let wake_ids = match receipt_type {
        // Visible to every joined+invited member by definition — filing a
        // read receipt is itself proof the caller could read the event.
        ReceiptType::Read => crate::rooms::member_and_invited_ids(conn, &room.id)?,
        // Matrix's own privacy guarantee: a private receipt must never
        // reach another user's `/sync` — only the caller's own devices.
        ReceiptType::ReadPrivate => HashSet::from([caller_user_id]),
    };
    Ok(Some(wake_ids))
}


/// `POST /read_markers`'s whole DB-side decision (plan §4 `read_markers`
/// row): Member, then `m.fully_read` (stored verbatim as per-room account
/// data for the caller, waking only their own devices) and/or `m.read`/
/// `m.read.private` (each delegated to [`apply_receipt`], which applies its
/// own wake rule per type). Every field is independently optional — a call
/// naming only one of the three touches only that one.
pub fn apply_read_markers(
    conn: &mut Connection,
    room: &Room,
    caller_user_id: i64,
    fully_read_event_id: Option<&str>,
    read_event_id: Option<&str>,
    read_private_event_id: Option<&str>,
    now_ms: i64,
) -> Result<HashSet<i64>, MatrixError> {
    let caller_membership = crate::store::room_member(conn, &room.id, caller_user_id)?.map(|m| m.membership);
    require_member(caller_membership)?;

    let mut wake_ids = HashSet::new();

    if let Some(event_id) = fully_read_event_id {
        crate::store::upsert_account_data(
            conn,
            caller_user_id,
            &room.id,
            "m.fully_read",
            &serde_json::json!({ "event_id": event_id }).to_string(),
        )?;
        wake_ids.insert(caller_user_id);
    }
    if let Some(event_id) = read_event_id {
        if let Some(ids) = apply_receipt(conn, room, caller_user_id, ReceiptType::Read, event_id, now_ms)? {
            wake_ids.extend(ids);
        }
    }
    if let Some(event_id) = read_private_event_id {
        if let Some(ids) = apply_receipt(conn, room, caller_user_id, ReceiptType::ReadPrivate, event_id, now_ms)? {
            wake_ids.extend(ids);
        }
    }

    Ok(wake_ids)
}


// ============================================================================
// PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}
// ============================================================================

#[derive(serde::Deserialize)]
pub struct TypingBody {
    pub typing: bool,
    #[serde(default)]
    pub timeout: Option<u64>,
}


// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/read_markers
// ============================================================================

#[derive(serde::Deserialize, Default)]
pub struct ReadMarkersBody {
    #[serde(rename = "m.fully_read", default)]
    pub fully_read: Option<String>,
    #[serde(rename = "m.read", default)]
    pub read: Option<String>,
    #[serde(rename = "m.read.private", default)]
    pub read_private: Option<String>,
}
pub fn expired_typing_wake_ids(conn: &Connection, typing_registry: &crate::typing::TypingRegistry, now: Instant) -> (usize, HashSet<i64>) {
    let expired_rooms = typing_registry.rooms_with_expired_typing(now);
    let room_count = expired_rooms.len();
    let mut ids = HashSet::new();
    for room_id in expired_rooms {
        match crate::rooms::member_and_invited_ids(conn, &room_id) {
            Ok(members) => ids.extend(members),
            Err(e) => tracing::error!("expired_typing_wake_ids: failed to list members of {}: {}", room_id, e),
        }
    }
    (room_count, ids)
}
#[cfg(test)]
mod tests { 
    use super::*;
    use std::time::Duration;

    pub const T0: &str = "2026-09-24T00:00:00+00:00";
    pub const ROOM: &str = "!testroom:example.org";

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        crate::store::create_matrix_schema(&conn).expect("matrix schema");
        conn
    }

    /// A room with two joined members: user 1 ("alice") and user 2 ("bob").
    fn make_room_with_two_members(conn: &mut Connection) -> (String, String) {
        crate::store::create_room(
            conn,
            ROOM,
            crate::store::RoomKind::Group,
            1,
            T0,
            false,
            crate::store::JoinRule::Invite,
            crate::store::HistoryVisibility::Shared,
            None,
            None,
        )
        .expect("create room");
        let alice = crate::store::ensure_matrix_user(conn, 1, "alice00000000000000000000000001", T0).expect("alice");
        let bob = crate::store::ensure_matrix_user(conn, 2, "bob000000000000000000000000002", T0).expect("bob");
        crate::store::apply_state_event(conn, &crate::store::StateEventWrite { event_id: "$m1", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 900, now: T0 }).expect("alice joins");
        crate::store::apply_state_event(conn, &crate::store::StateEventWrite { event_id: "$m2", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &bob, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 }).expect("bob joins");
        (alice, bob)
    }

    // ---- typing_for_another_user_is_forbidden ----

    #[test]
    fn typing_for_another_user_is_forbidden() {
        let err = check_typing_target("@bob:example.org", "@alice:example.org").unwrap_err();
        assert_eq!(err.errcode, "M_FORBIDDEN");
        assert!(check_typing_target("@alice:example.org", "@alice:example.org").is_ok());
    }

    // ---- throttled_typing_does_not_wake ----

    #[test]
    fn throttled_typing_does_not_wake() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let typing = crate::typing::TypingRegistry::new();
        let t0 = Instant::now();

        let first = apply_typing(&conn, &typing, ROOM, 1, true, 5_000, t0).expect("first typing accepted");
        assert!(first.is_some(), "the first typing:true must wake the room");

        let second = apply_typing(&conn, &typing, ROOM, 1, true, 5_000, t0 + Duration::from_millis(500)).expect("throttled repeat");
        assert!(second.is_none(), "a throttled repeat must not wake anyone");
    }

    #[test]
    fn typing_by_a_non_member_is_forbidden() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let typing = crate::typing::TypingRegistry::new();

        let err = apply_typing(&conn, &typing, ROOM, 999, true, 5_000, Instant::now()).unwrap_err();
        assert_eq!(err.errcode, "M_FORBIDDEN");
    }

    // ---- private_receipt_wakes_only_own_devices ----

    #[test]
    fn private_receipt_wakes_only_own_devices() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let event = crate::store::insert_timeline_event(&mut conn, "$msg", ROOM, 2, "m.room.message", "{}", 1000).expect("message");

        let room = crate::store::get_room(&conn, ROOM).expect("get room").expect("room exists");
        let wake_ids = apply_receipt(&mut conn, &room, 1, ReceiptType::ReadPrivate, &event.event_id, 1500)
            .expect("apply private receipt")
            .expect("a new receipt must report a change");
        assert_eq!(wake_ids, HashSet::from([1]), "m.read.private must wake ONLY the caller's own devices, never other room members");
    }

    #[test]
    fn read_receipt_wakes_every_joined_member() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let event = crate::store::insert_timeline_event(&mut conn, "$msg", ROOM, 2, "m.room.message", "{}", 1000).expect("message");

        let room = crate::store::get_room(&conn, ROOM).expect("get room").expect("room exists");
        let wake_ids = apply_receipt(&mut conn, &room, 1, ReceiptType::Read, &event.event_id, 1500)
            .expect("apply read receipt")
            .expect("a new receipt must report a change");
        assert_eq!(wake_ids, HashSet::from([1, 2]), "m.read must wake every joined member, including the caller's own other devices");
    }

    // ---- backwards_receipt_is_a_noop ----

    #[test]
    fn backwards_receipt_is_a_noop() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let e1 = crate::store::insert_timeline_event(&mut conn, "$e1", ROOM, 2, "m.room.message", "{}", 1000).expect("e1");
        let e2 = crate::store::insert_timeline_event(&mut conn, "$e2", ROOM, 2, "m.room.message", "{}", 2000).expect("e2");
        let room = crate::store::get_room(&conn, ROOM).expect("get room").expect("room exists");

        let forward = apply_receipt(&mut conn, &room, 1, ReceiptType::Read, &e2.event_id, 2500).expect("advance to e2");
        assert!(forward.is_some());

        let backward = apply_receipt(&mut conn, &room, 1, ReceiptType::Read, &e1.event_id, 3000).expect("attempted backward move");
        assert!(backward.is_none(), "a backwards receipt must be a silent no-op, never a wake");

        let stored = crate::store::get_receipt(&conn, ROOM, 1, ReceiptType::Read).expect("get receipt").expect("receipt exists");
        assert_eq!(stored.event_id, e2.event_id, "the receipt must still point at e2, not have moved backward to e1");
    }

    // ---- fully_read_is_stored_as_room_account_data ----

    #[test]
    fn fully_read_is_stored_as_room_account_data() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let event = crate::store::insert_timeline_event(&mut conn, "$msg", ROOM, 2, "m.room.message", "{}", 1000).expect("message");
        let room = crate::store::get_room(&conn, ROOM).expect("get room").expect("room exists");

        let wake_ids = apply_read_markers(&mut conn, &room, 1, Some(&event.event_id), None, None, 1500).expect("apply read markers");
        assert_eq!(wake_ids, HashSet::from([1]), "m.fully_read must wake only the caller's own devices");

        let stored = crate::store::get_account_data(&conn, 1, ROOM, "m.fully_read").expect("get account data").expect("row exists");
        let content: serde_json::Value = serde_json::from_str(&stored.content).expect("json content");
        assert_eq!(content, serde_json::json!({ "event_id": event.event_id }));
    }

    #[test]
    fn read_markers_can_combine_fully_read_with_a_receipt() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let event = crate::store::insert_timeline_event(&mut conn, "$msg", ROOM, 2, "m.room.message", "{}", 1000).expect("message");
        let room = crate::store::get_room(&conn, ROOM).expect("get room").expect("room exists");

        let wake_ids =
            apply_read_markers(&mut conn, &room, 1, Some(&event.event_id), Some(&event.event_id), None, 1500).expect("apply read markers");
        assert_eq!(wake_ids, HashSet::from([1, 2]), "the embedded m.read receipt must wake every joined member on top of the caller's own devices");
        assert!(crate::store::get_account_data(&conn, 1, ROOM, "m.fully_read").expect("get account data").is_some());
        assert!(crate::store::get_receipt(&conn, ROOM, 1, ReceiptType::Read).expect("get receipt").is_some());
    }

    // ---- receipt_on_invisible_event_is_refused ----

    #[test]
    fn receipt_on_invisible_event_is_refused() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);

        pub const OTHER_ROOM: &str = "!otherroom:example.org";
        crate::store::create_room(
            &conn,
            OTHER_ROOM,
            crate::store::RoomKind::Group,
            1,
            T0,
            false,
            crate::store::JoinRule::Invite,
            crate::store::HistoryVisibility::Shared,
            None,
            None,
        )
        .expect("create other room");
        let foreign_event = crate::store::insert_timeline_event(&mut conn, "$foreign", OTHER_ROOM, 1, "m.room.message", "{}", 1000).expect("foreign event");

        let room = crate::store::get_room(&conn, ROOM).expect("get room").expect("room exists");
        let err = apply_receipt(&mut conn, &room, 1, ReceiptType::Read, &foreign_event.event_id, 1500).unwrap_err();
        assert_eq!(err.errcode, "M_NOT_FOUND");
    }

    #[test]
    fn receipt_on_a_nonexistent_event_is_refused() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let room = crate::store::get_room(&conn, ROOM).expect("get room").expect("room exists");

        let err = apply_receipt(&mut conn, &room, 1, ReceiptType::Read, "$never-existed", 1500).unwrap_err();
        assert_eq!(err.errcode, "M_NOT_FOUND");
    }

    // ---- expired_typing_wake_ids (wake_rooms_with_expired_typing's DB-only half) ----

    #[test]
    pub fn expired_typing_wake_ids_covers_the_expired_rooms_joined_members() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let typing = crate::typing::TypingRegistry::new();
        let t0 = Instant::now();
        assert!(typing.set_typing(ROOM, 1, true, 100, t0));

        let (room_count, ids) = expired_typing_wake_ids(&conn, &typing, t0 + Duration::from_millis(500));
        assert_eq!(room_count, 1, "exactly one room had its typing state expire");
        assert_eq!(ids, HashSet::from([1, 2]), "every joined member of the expired room must be woken");

        // A second sweep with nothing newly expired reports nothing.
        let (room_count_again, ids_again) = expired_typing_wake_ids(&conn, &typing, t0 + Duration::from_millis(600));
        assert_eq!(room_count_again, 0, "a room with no NEWLY expired typing flag must not be reported again");
        assert!(ids_again.is_empty(), "a room with no NEWLY expired typing flag must not be reported again");
    }

    #[test]
    pub fn expired_typing_wake_ids_is_empty_when_nothing_is_typing() {
        let conn = test_conn();
        let typing = crate::typing::TypingRegistry::new();
        let (room_count, ids) = expired_typing_wake_ids(&conn, &typing, Instant::now());
        assert_eq!(room_count, 0);
        assert!(ids.is_empty());
    }

}
