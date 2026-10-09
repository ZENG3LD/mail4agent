//! Public plaintext store (channels; a forum could join later).
//!
//! BOUNDARY. This module owns the tables `pub_events` and `pub_txn`. Nothing
//! here writes `events`, `relations`, `receipts` or `txn_dedup` (the closed
//! store), and nothing in [`crate::retention`] ever reads or deletes these
//! tables. Bodies stay: a public channel is plaintext by design (MLC
//! decision), so posts are kept until a moderator redacts them.
//!
//! What stays in the closed store for a channel room: the room row, its
//! membership and its *state* events (create, member, join rules, name,
//! power levels). Only timeline events (`m.room.message`, `m.reaction`,
//! `m.room.redaction`, ...) of a plaintext channel live here. DMs, groups and
//! already-encrypted rooms never touch this module.
//!
//! The store shares the global stream counter with the closed store so
//! `/sync` and `/messages` can merge both by stream id; that counter is the
//! only shared state. Reactions/edits keep `m.relates_to` inside the content
//! (clients fold them); there is no server-side `relations` aggregation here.
//!
//! Whether this store runs in the same process as the closed one is open
//! (owner decision): the boundary is the table set plus this module's API.

use rusqlite::{params, Connection, OptionalExtension};

use crate::store::MatrixEvent;

/// DDL for the public store. Called from `init_messenger_db`.
pub fn create_public_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS pub_events (
            stream_id        INTEGER PRIMARY KEY,
            event_id         TEXT NOT NULL UNIQUE,
            room_id          TEXT NOT NULL,
            sender_user_id   INTEGER NOT NULL,
            event_type       TEXT NOT NULL,
            content          TEXT NOT NULL,
            origin_server_ts INTEGER NOT NULL,
            txn_id           TEXT,
            redacts          TEXT,
            redacted_by      TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_pub_events_room_stream ON pub_events(room_id, stream_id);
        CREATE TABLE IF NOT EXISTS pub_txn (
            user_id    INTEGER NOT NULL,
            device_id  TEXT NOT NULL,
            txn_id     TEXT NOT NULL,
            event_id   TEXT NOT NULL,
            PRIMARY KEY (user_id, device_id, txn_id)
        );
        "#,
    )
}

/// SQL predicate (on `rooms`) selecting plaintext public channels. The one
/// definition of "public store room", also used by retention to stay away.
pub const PUBLIC_ROOM_PREDICATE: &str = "kind = 'channel' AND is_encrypted = 0";

/// Whether `room_id` is a plaintext public channel (its timeline lives here).
pub fn is_public_room(conn: &Connection, room_id: &str) -> rusqlite::Result<bool> {
    let found: Option<i64> = conn
        .query_row(&format!("SELECT 1 FROM rooms WHERE id = ?1 AND {PUBLIC_ROOM_PREDICATE}"), params![room_id], |r| r.get(0))
        .optional()?;
    Ok(found.is_some())
}

const COLS: &str = "stream_id, event_id, room_id, sender_user_id, event_type, content, origin_server_ts, txn_id, redacts, redacted_by";

fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MatrixEvent> {
    Ok(MatrixEvent {
        stream_id: row.get(0)?,
        event_id: row.get(1)?,
        room_id: row.get(2)?,
        sender_user_id: row.get(3)?,
        event_type: row.get(4)?,
        state_key: None,
        content: row.get(5)?,
        origin_server_ts: row.get(6)?,
        txn_id: row.get(7)?,
        redacts: row.get(8)?,
        redacted_by: row.get(9)?,
    })
}

/// One public event by id.
pub fn get_event(conn: &Connection, event_id: &str) -> rusqlite::Result<Option<MatrixEvent>> {
    conn.query_row(&format!("SELECT {COLS} FROM pub_events WHERE event_id = ?1"), params![event_id], from_row).optional()
}

/// Events strictly after `since_stream`, oldest first.
pub fn events_after(conn: &Connection, room_id: &str, since_stream: i64, limit: i64) -> rusqlite::Result<Vec<MatrixEvent>> {
    let mut stmt = conn.prepare(&format!("SELECT {COLS} FROM pub_events WHERE room_id = ?1 AND stream_id > ?2 ORDER BY stream_id ASC LIMIT ?3"))?;
    let rows = stmt.query_map(params![room_id, since_stream, limit], from_row)?;
    rows.collect()
}

/// Events strictly before `before_stream`, newest first.
pub fn events_before(conn: &Connection, room_id: &str, before_stream: i64, limit: i64) -> rusqlite::Result<Vec<MatrixEvent>> {
    let mut stmt = conn.prepare(&format!("SELECT {COLS} FROM pub_events WHERE room_id = ?1 AND stream_id < ?2 ORDER BY stream_id DESC LIMIT ?3"))?;
    let rows = stmt.query_map(params![room_id, before_stream, limit], from_row)?;
    rows.collect()
}

/// The public event a `(user, device, txn)` already produced, if any.
pub fn seen_txn(conn: &Connection, user_id: i64, device_id: &str, txn_id: &str) -> rusqlite::Result<Option<MatrixEvent>> {
    let id: Option<String> = conn
        .query_row("SELECT event_id FROM pub_txn WHERE user_id = ?1 AND device_id = ?2 AND txn_id = ?3", params![user_id, device_id, txn_id], |r| r.get(0))
        .optional()?;
    match id {
        Some(id) => get_event(conn, &id),
        None => Ok(None),
    }
}

/// Result of a deduped public write.
pub enum PublicWrite {
    /// New event.
    New(MatrixEvent),
    /// Same `(user, device, txn)` seen before.
    Existing(MatrixEvent),
}

/// Insert one timeline event (deduped per user/device/txn) into the public store.
#[allow(clippy::too_many_arguments)]
pub fn insert_event_deduped(
    conn: &mut Connection,
    device_id: &str,
    txn_id: &str,
    event_id: &str,
    room_id: &str,
    sender_user_id: i64,
    event_type: &str,
    content: &str,
    origin_server_ts: i64,
) -> rusqlite::Result<PublicWrite> {
    let tx = conn.transaction()?;
    let seen: Option<String> = tx
        .query_row("SELECT event_id FROM pub_txn WHERE user_id = ?1 AND device_id = ?2 AND txn_id = ?3", params![sender_user_id, device_id, txn_id], |r| r.get(0))
        .optional()?;
    if let Some(existing) = seen {
        let event = get_event(&tx, &existing)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        tx.commit()?;
        return Ok(PublicWrite::Existing(event));
    }
    let stream_id = crate::store::next_stream_id(&tx)?;
    tx.execute(
        "INSERT INTO pub_events (stream_id, event_id, room_id, sender_user_id, event_type, content, origin_server_ts, txn_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![stream_id, event_id, room_id, sender_user_id, event_type, content, origin_server_ts, txn_id],
    )?;
    tx.execute("INSERT INTO pub_txn (user_id, device_id, txn_id, event_id) VALUES (?1,?2,?3,?4)", params![sender_user_id, device_id, txn_id, event_id])?;
    tx.commit()?;
    Ok(PublicWrite::New(MatrixEvent {
        stream_id,
        event_id: event_id.to_string(),
        room_id: room_id.to_string(),
        sender_user_id,
        event_type: event_type.to_string(),
        state_key: None,
        content: content.to_string(),
        origin_server_ts,
        txn_id: Some(txn_id.to_string()),
        redacts: None,
        redacted_by: None,
    }))
}

/// Redact a public event: strip its content, record the redaction event.
#[allow(clippy::too_many_arguments)]
pub fn redact_deduped(
    conn: &mut Connection,
    device_id: &str,
    txn_id: &str,
    room_id: &str,
    target_event_id: &str,
    redaction_event_id: &str,
    sender_user_id: i64,
    reason: Option<&str>,
    origin_server_ts: i64,
) -> rusqlite::Result<PublicWrite> {
    let mut content = serde_json::json!({ "redacts": target_event_id });
    if let Some(r) = reason {
        content["reason"] = serde_json::Value::String(r.to_string());
    }
    let content = content.to_string();
    let written = insert_event_deduped(conn, device_id, txn_id, redaction_event_id, room_id, sender_user_id, "m.room.redaction", &content, origin_server_ts)?;
    if let PublicWrite::New(mut event) = written {
        conn.execute("UPDATE pub_events SET redacts = ?1 WHERE event_id = ?2", params![target_event_id, redaction_event_id])?;
        conn.execute("UPDATE pub_events SET content = '{}', redacted_by = ?1 WHERE event_id = ?2", params![redaction_event_id, target_event_id])?;
        event.redacts = Some(target_event_id.to_string());
        return Ok(PublicWrite::New(event));
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::store::create_matrix_schema(&conn).unwrap();
        crate::keys::create_matrix_keys_schema(&conn).unwrap();
        crate::retention::create_retention_schema(&conn).unwrap();
        create_public_schema(&conn).unwrap();
        conn.execute("INSERT INTO rooms (id, kind, creator_user_id, created_at, is_encrypted) VALUES ('!c:x','channel',1,'t',0)", []).unwrap();
        conn.execute("INSERT INTO rooms (id, kind, creator_user_id, created_at, is_encrypted) VALUES ('!g:x','group',1,'t',1)", []).unwrap();
        conn
    }

    #[test]
    fn only_plaintext_channels_are_public_rooms() {
        let conn = db();
        assert!(is_public_room(&conn, "!c:x").unwrap());
        assert!(!is_public_room(&conn, "!g:x").unwrap());
    }

    #[test]
    fn public_writes_never_touch_the_closed_tables_and_dedup() {
        let mut conn = db();
        let a = insert_event_deduped(&mut conn, "D", "t1", "$a", "!c:x", 1, "m.room.message", r#"{"body":"hi"}"#, 10).unwrap();
        assert!(matches!(a, PublicWrite::New(_)));
        let again = insert_event_deduped(&mut conn, "D", "t1", "$zzz", "!c:x", 1, "m.room.message", "{}", 11).unwrap();
        assert!(matches!(again, PublicWrite::Existing(ref e) if e.event_id == "$a"));
        for table in ["events", "relations", "receipts", "txn_dedup"] {
            let n: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)).unwrap();
            assert_eq!(n, 0, "{table} must stay untouched by the public store");
        }
        assert_eq!(events_after(&conn, "!c:x", 0, 10).unwrap().len(), 1);
    }

    #[test]
    fn retention_never_deletes_public_posts() {
        let mut conn = db();
        for i in 0..5 {
            insert_event_deduped(&mut conn, "D", &format!("t{i}"), &format!("$e{i}"), "!c:x", 1, "m.room.message", r#"{"body":"x"}"#, 1).unwrap();
        }
        let policy = crate::retention::RetentionPolicy { ttl_ms: 1, ack_grace_ms: 0, keep_last: 0, stale_device_ms: 1 };
        crate::retention::purge_delivered_events(&mut conn, 10_000_000, &policy).unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM pub_events", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 5);
    }

    #[test]
    fn redaction_strips_content() {
        let mut conn = db();
        insert_event_deduped(&mut conn, "D", "t1", "$a", "!c:x", 1, "m.room.message", r#"{"body":"hi"}"#, 10).unwrap();
        redact_deduped(&mut conn, "D", "t2", "!c:x", "$a", "$r", 1, Some("spam"), 11).unwrap();
        let ev = get_event(&conn, "$a").unwrap().unwrap();
        assert_eq!(ev.content, "{}");
        assert_eq!(ev.redacted_by.as_deref(), Some("$r"));
    }
}
