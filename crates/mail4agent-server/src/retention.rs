//! Delivery-window retention (design: docs/mail4agent/messenger-model.md,
//! "Server is a router"). The server is not an archive: a message event is
//! only needed until every live device of every joined member has fetched it.
//!
//! * [`record_device_ack`] — a `/sync?since=s<N>` proves the device holds
//!   every event up to stream id `N` (additive table `device_acks`).
//! * [`retention_report`] — how many message events a purge would drop.
//! * [`purge_delivered_events`] — drops them. NOT scheduled anywhere: the
//!   owner decides when to switch it on (it changes what `/rooms/{id}/messages`
//!   can return, see the design doc).
//!
//! Only non-state events of CLOSED rooms are ever touched: plaintext public
//! channels live in `pub_events` ([`crate::public_channels`]) and are excluded
//! here by construction and by predicate.
//! Only non-state events are ever touched. State, keys, membership and
//! to-device queues are untouched here.

use rusqlite::{params, Connection};

/// Most events one purge pass removes (keeps the DB lock short).
pub const PURGE_BATCH: usize = 1000;

/// `device_acks` DDL. Called from `init_messenger_db`.
pub fn create_retention_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS device_acks (
            user_id    INTEGER NOT NULL,
            device_id  TEXT NOT NULL,
            stream_id  INTEGER NOT NULL,
            updated_ms INTEGER NOT NULL,
            PRIMARY KEY (user_id, device_id)
        );
        "#,
    )
}

/// Records that `device_id` has received everything up to `stream_id`.
/// Monotonic: an older token never moves the ack back.
pub fn record_device_ack(conn: &Connection, user_id: i64, device_id: &str, stream_id: i64, now_ms: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO device_acks (user_id, device_id, stream_id, updated_ms) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(user_id, device_id) DO UPDATE SET
           stream_id = MAX(stream_id, excluded.stream_id), updated_ms = excluded.updated_ms",
        params![user_id, device_id, stream_id, now_ms],
    )?;
    Ok(())
}

/// Retention knobs.
#[derive(Debug, Clone, Copy)]
pub struct RetentionPolicy {
    /// Hard TTL: any message event older than this goes, acked or not.
    pub ttl_ms: i64,
    /// Grace after full ack before deletion (lets slow readers/retries land).
    pub ack_grace_ms: i64,
    /// Always keep this many newest message events per room.
    pub keep_last: i64,
    /// A device that has not acked within this window no longer holds
    /// deletion back (it falls under the hard TTL).
    pub stale_device_ms: i64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self { ttl_ms: 14 * 86_400_000, ack_grace_ms: 300_000, keep_last: 0, stale_device_ms: 30 * 86_400_000 }
    }
}

/// What a purge would do right now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetentionReport {
    /// Message events stored.
    pub message_events: i64,
    /// Of those, deletable under the policy.
    pub eligible: i64,
}

fn eligible_ids(conn: &Connection, now_ms: i64, policy: &RetentionPolicy) -> rusqlite::Result<Vec<String>> {
    let mut out = Vec::new();
    let rooms: Vec<String> = conn
        .prepare("SELECT DISTINCT room_id FROM events WHERE state_key IS NULL AND room_id NOT IN (SELECT id FROM rooms WHERE kind = 'channel' AND is_encrypted = 0)")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    for room in rooms {
        // Lowest stream id acked by every live device of every joined member;
        // None when some live device never acked (blocks ack-based deletion).
        let mut stmt = conn.prepare(
            "SELECT d.user_id, d.device_id, a.stream_id, a.updated_ms
               FROM room_members m JOIN devices d ON d.user_id = m.user_id
               LEFT JOIN device_acks a ON a.user_id = d.user_id AND a.device_id = d.device_id
              WHERE m.room_id = ?1 AND m.membership = 'join'",
        )?;
        let mut min_ack: Option<i64> = Some(i64::MAX);
        let rows = stmt.query_map(params![room], |r| {
            Ok((r.get::<_, Option<i64>>(2)?, r.get::<_, Option<i64>>(3)?))
        })?;
        for row in rows {
            let (ack, updated) = row?;
            match (ack, updated) {
                (Some(ack), Some(updated)) if now_ms - updated <= policy.stale_device_ms => {
                    min_ack = min_ack.map(|m| m.min(ack));
                }
                (Some(_), Some(_)) => {} // stale device: ignored
                _ => min_ack = None,      // never acked: hold back
            }
        }
        let ack_bound = min_ack.filter(|m| *m != i64::MAX).unwrap_or(-1);
        let mut ev = conn.prepare(
            "SELECT event_id FROM events WHERE room_id = ?1 AND state_key IS NULL
               AND stream_id NOT IN (SELECT stream_id FROM events WHERE room_id = ?1 AND state_key IS NULL
                                     ORDER BY stream_id DESC LIMIT ?2)
               AND ((stream_id <= ?3 AND origin_server_ts <= ?4) OR origin_server_ts <= ?5)",
        )?;
        let ids = ev.query_map(
            params![room, policy.keep_last, ack_bound, now_ms - policy.ack_grace_ms, now_ms - policy.ttl_ms],
            |r| r.get::<_, String>(0),
        )?;
        for id in ids {
            out.push(id?);
        }
    }
    Ok(out)
}

/// Counts message events and how many a purge would delete.
pub fn retention_report(conn: &Connection, now_ms: i64, policy: &RetentionPolicy) -> rusqlite::Result<RetentionReport> {
    let message_events = conn.query_row("SELECT COUNT(*) FROM events WHERE state_key IS NULL", [], |r| r.get(0))?;
    Ok(RetentionReport { message_events, eligible: eligible_ids(conn, now_ms, policy)?.len() as i64 })
}

/// Deletes eligible message events (and rows pointing at them). Returns how
/// many events were removed.
pub fn purge_delivered_events(conn: &mut Connection, now_ms: i64, policy: &RetentionPolicy) -> rusqlite::Result<usize> {
    let mut ids = eligible_ids(conn, now_ms, policy)?;
    ids.truncate(PURGE_BATCH);
    let tx = conn.transaction()?;
    let mut removed = 0;
    for id in &ids {
        tx.execute("DELETE FROM relations WHERE event_id = ?1 OR target_id = ?1", params![id])?;
        tx.execute("DELETE FROM receipts WHERE event_id = ?1", params![id])?;
        tx.execute("DELETE FROM txn_dedup WHERE event_id = ?1", params![id])?;
        // Legacy table may be absent (dropped when empty).
        let _ = tx.execute("DELETE FROM legacy_dm_message_map WHERE event_id = ?1", params![id]);
        tx.execute("UPDATE events SET redacts = NULL WHERE redacts = ?1", params![id])?;
        tx.execute("UPDATE events SET redacted_by = NULL WHERE redacted_by = ?1", params![id])?;
        removed += tx.execute("DELETE FROM events WHERE event_id = ?1 AND state_key IS NULL", params![id])?;
    }
    // Idempotency records only matter inside the ring window.
    let cutoff = chrono::DateTime::from_timestamp_millis(now_ms - policy.ttl_ms)
        .map(|d| d.to_rfc3339())
        .unwrap_or_default();
    if !cutoff.is_empty() {
        tx.execute("DELETE FROM txn_dedup WHERE created_at < ?1", params![cutoff])?;
    }
    // Media blobs are ciphertext attachments: same pump rule, same TTL.
    tx.execute("DELETE FROM media WHERE created_ms < ?1", params![now_ms - policy.ttl_ms])?;
    tx.commit()?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        crate::store::create_matrix_schema(&conn).unwrap();
        crate::keys::create_matrix_keys_schema(&conn).unwrap();
        create_retention_schema(&conn).unwrap();
        conn.execute("INSERT INTO rooms (id, kind, creator_user_id, created_at) VALUES ('!r:x', 'group', 1, 't')", []).unwrap();
        conn
    }

    fn add_event(conn: &Connection, stream: i64, ts: i64) {
        conn.execute(
            "INSERT INTO events (stream_id, event_id, room_id, sender_user_id, event_type, state_key, content, origin_server_ts)
             VALUES (?1, ?2, '!r:x', 1, 'm.room.encrypted', NULL, '{}', ?3)",
            params![stream, format!("$e{stream}"), ts],
        )
        .unwrap();
    }

    #[test]
    fn ack_is_monotonic() {
        let conn = db();
        record_device_ack(&conn, 1, "D", 10, 1).unwrap();
        record_device_ack(&conn, 1, "D", 5, 2).unwrap();
        let s: i64 = conn.query_row("SELECT stream_id FROM device_acks", [], |r| r.get(0)).unwrap();
        assert_eq!(s, 10);
    }

    #[test]
    fn ttl_purges_unacked_but_keeps_last_n() {
        let mut conn = db();
        for i in 1..=30 {
            add_event(&conn, i, 1_000);
        }
        let policy = RetentionPolicy { ttl_ms: 5_000, ack_grace_ms: 0, keep_last: 20, stale_device_ms: 1 };
        let now = 100_000;
        assert_eq!(retention_report(&conn, now, &policy).unwrap(), RetentionReport { message_events: 30, eligible: 10 });
        assert_eq!(purge_delivered_events(&mut conn, now, &policy).unwrap(), 10);
        let left: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 20);
    }

    #[test]
    fn deleted_only_after_every_live_device_acked() {
        let mut conn = db();
        for u in [1, 2] {
            conn.execute("INSERT INTO room_members (room_id, user_id, membership, updated_at) VALUES ('!r:x', ?1, 'join', 't')", params![u]).unwrap();
            conn.execute("INSERT INTO devices (user_id, device_id, credential_kind, credential_ref, created_at, last_seen_at) VALUES (?1, 'D', 'Bearer', ?2, 't', 't')", params![u, format!("c{u}")]).unwrap();
        }
        for i in 1..=3 {
            add_event(&conn, i, 1_000);
        }
        conn.execute("INSERT INTO txn_dedup (user_id, device_id, txn_id, event_id, created_at) VALUES (1, 'D', 't1', '$e1', 't')", []).unwrap();
        let policy = RetentionPolicy { ttl_ms: 10_000_000, ack_grace_ms: 0, keep_last: 0, stale_device_ms: 10_000_000 };
        let now = 100_000;
        assert_eq!(purge_delivered_events(&mut conn, now, &policy).unwrap(), 0, "nobody acked");
        record_device_ack(&conn, 1, "D", 3, now).unwrap();
        assert_eq!(purge_delivered_events(&mut conn, now, &policy).unwrap(), 0, "one device still behind");
        record_device_ack(&conn, 2, "D", 2, now).unwrap();
        assert_eq!(purge_delivered_events(&mut conn, now, &policy).unwrap(), 2, "events 1,2 acked by all");
        let left: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 1);
    }

    #[test]
    fn young_events_survive_without_acks() {
        let conn = db();
        for i in 1..=30 {
            add_event(&conn, i, 99_000);
        }
        let policy = RetentionPolicy { ttl_ms: 50_000, ack_grace_ms: 0, keep_last: 5, stale_device_ms: 1 };
        assert_eq!(retention_report(&conn, 100_000, &policy).unwrap().eligible, 0);
    }
}
