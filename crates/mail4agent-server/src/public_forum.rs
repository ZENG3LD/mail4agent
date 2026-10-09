//! Public forum store (plaintext, server-side state). Seam only: storage and a
//! small API, no HTTP routes yet.
//!
//! Same boundary rule as [`crate::public_channels`]: tables `pf_boards`,
//! `pf_threads`, `pf_replies` belong to this module; the closed store
//! (`events`, `relations`, `receipts`, `txn_dedup`, keys) never reads or
//! writes them and [`crate::retention`] never deletes them. A forum board is
//! not a room and a thread is not an event. The chart's own forum (social.db,
//! forum v1) is a different product and is not copied here; this is the
//! neutral open store both MLC and m4a can land on.
//!
//! Role gates are a named seam: [`BoardGate`] has only `Open` today;
//! `check_post_allowed` is the single place a role/paywall check will go.

use rusqlite::{params, Connection, OptionalExtension};

/// DDL. Called from `create_matrix_schema` beside the other stores.
pub fn create_forum_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS pf_boards (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            slug       TEXT NOT NULL UNIQUE,
            title      TEXT NOT NULL,
            gate       TEXT NOT NULL DEFAULT 'open',
            created_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pf_threads (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            board_id       INTEGER NOT NULL REFERENCES pf_boards(id),
            author_user_id INTEGER NOT NULL,
            title          TEXT NOT NULL,
            body           TEXT NOT NULL,
            created_ms     INTEGER NOT NULL,
            locked         INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_pf_threads_board ON pf_threads(board_id, id);
        CREATE TABLE IF NOT EXISTS pf_replies (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            thread_id      INTEGER NOT NULL REFERENCES pf_threads(id),
            author_user_id INTEGER NOT NULL,
            body           TEXT NOT NULL,
            created_ms     INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_pf_replies_thread ON pf_replies(thread_id, id);
        "#,
    )
}

/// Who may post on a board. Only `Open` exists; role/paywall gates plug in here later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoardGate {
    /// Any signed-in user.
    Open,
}

/// The one place a role gate will be enforced.
pub fn check_post_allowed(_gate: BoardGate, _user_id: i64) -> Result<(), &'static str> {
    Ok(())
}

/// A thread row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thread {
    /// Thread id.
    pub id: i64,
    /// Board id.
    pub board_id: i64,
    /// Author.
    pub author_user_id: i64,
    /// Title.
    pub title: String,
    /// Opening post body (plaintext).
    pub body: String,
    /// Creation time, ms.
    pub created_ms: i64,
    /// Locked threads take no replies.
    pub locked: bool,
}

/// Creates a board (idempotent per slug) and returns its id.
pub fn create_board(conn: &Connection, slug: &str, title: &str, now_ms: i64) -> rusqlite::Result<i64> {
    conn.execute("INSERT OR IGNORE INTO pf_boards (slug, title, created_ms) VALUES (?1, ?2, ?3)", params![slug, title, now_ms])?;
    conn.query_row("SELECT id FROM pf_boards WHERE slug = ?1", params![slug], |r| r.get(0))
}

/// Opens a thread on a board.
pub fn create_thread(conn: &Connection, board_id: i64, user_id: i64, title: &str, body: &str, now_ms: i64) -> rusqlite::Result<i64> {
    check_post_allowed(BoardGate::Open, user_id).map_err(|_| rusqlite::Error::InvalidQuery)?;
    conn.execute(
        "INSERT INTO pf_threads (board_id, author_user_id, title, body, created_ms) VALUES (?1,?2,?3,?4,?5)",
        params![board_id, user_id, title, body, now_ms],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Replies to a thread. `Ok(None)` when the thread is locked or absent.
pub fn reply(conn: &Connection, thread_id: i64, user_id: i64, body: &str, now_ms: i64) -> rusqlite::Result<Option<i64>> {
    let locked: Option<i64> = conn.query_row("SELECT locked FROM pf_threads WHERE id = ?1", params![thread_id], |r| r.get(0)).optional()?;
    if locked != Some(0) {
        return Ok(None);
    }
    check_post_allowed(BoardGate::Open, user_id).map_err(|_| rusqlite::Error::InvalidQuery)?;
    conn.execute("INSERT INTO pf_replies (thread_id, author_user_id, body, created_ms) VALUES (?1,?2,?3,?4)", params![thread_id, user_id, body, now_ms])?;
    Ok(Some(conn.last_insert_rowid()))
}

/// Newest threads first.
pub fn list_threads(conn: &Connection, board_id: i64, limit: i64) -> rusqlite::Result<Vec<Thread>> {
    let mut stmt = conn.prepare("SELECT id, board_id, author_user_id, title, body, created_ms, locked FROM pf_threads WHERE board_id = ?1 ORDER BY id DESC LIMIT ?2")?;
    let rows = stmt.query_map(params![board_id, limit], |r| {
        Ok(Thread { id: r.get(0)?, board_id: r.get(1)?, author_user_id: r.get(2)?, title: r.get(3)?, body: r.get(4)?, created_ms: r.get(5)?, locked: r.get::<_, i64>(6)? != 0 })
    })?;
    rows.collect()
}

/// Replies in posting order: `(id, author, body, created_ms)`.
pub fn list_replies(conn: &Connection, thread_id: i64) -> rusqlite::Result<Vec<(i64, i64, String, i64)>> {
    let mut stmt = conn.prepare("SELECT id, author_user_id, body, created_ms FROM pf_replies WHERE thread_id = ?1 ORDER BY id")?;
    let rows = stmt.query_map(params![thread_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
    rows.collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::store::create_matrix_schema(&conn).unwrap();
        crate::keys::create_matrix_keys_schema(&conn).unwrap();
        crate::retention::create_retention_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn board_thread_reply_roundtrip_and_lock() {
        let conn = db();
        let board = create_board(&conn, "general", "General", 1).unwrap();
        assert_eq!(create_board(&conn, "general", "x", 2).unwrap(), board);
        let t = create_thread(&conn, board, 7, "hello", "first post", 3).unwrap();
        assert!(reply(&conn, t, 8, "re", 4).unwrap().is_some());
        assert_eq!(list_replies(&conn, t).unwrap().len(), 1);
        assert_eq!(list_threads(&conn, board, 10).unwrap()[0].body, "first post");
        conn.execute("UPDATE pf_threads SET locked = 1 WHERE id = ?1", params![t]).unwrap();
        assert!(reply(&conn, t, 8, "late", 5).unwrap().is_none());
    }

    #[test]
    fn closed_store_and_retention_never_touch_the_forum() {
        let mut conn = db();
        let board = create_board(&conn, "b", "B", 1).unwrap();
        create_thread(&conn, board, 1, "t", "body", 1).unwrap();
        let policy = crate::retention::RetentionPolicy { ttl_ms: 1, ack_grace_ms: 0, keep_last: 0, stale_device_ms: 1 };
        crate::retention::purge_delivered_events(&mut conn, 10_000_000, &policy).unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM pf_threads", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
        for table in ["events", "relations", "receipts", "txn_dedup"] {
            let c: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)).unwrap();
            assert_eq!(c, 0, "{table}");
        }
    }
}
