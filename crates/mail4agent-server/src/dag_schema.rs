//! Tables of the room DAG layer (see `f3.rs`): events with their edges, forward extremities and
//! state groups. Created together with the rest of the messenger schema, always (they are empty
//! unless the `f3-hash-ids` feature has made a room a DAG room), idempotently, inside the single
//! writer's boot step, so a database can switch the feature on or off without a migration.
//!
//! * `dag_rooms`: rooms that are DAG rooms. Every other room is legacy and never appears here.
//! * `dag_events`: one row per event the room knows (accepted, soft-failed, or imported as an
//!   outlier). `pdu` is the signed wire JSON, or its skeleton once the content was erased.
//! * `dag_edges` / `dag_auth`: `prev_events` and `auth_events` of each event.
//! * `dag_extremities`: the room's forward extremities.
//! * `dag_state_groups` + `dag_state_group_entries`: full state snapshots; `dag_event_state` maps
//!   an event to the snapshot of the room state after it. A message shares its parent's group.

use rusqlite::Connection;

pub fn create_dag_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS dag_rooms (
            room_id      TEXT PRIMARY KEY,
            room_version TEXT NOT NULL DEFAULT '11'
        );
        CREATE TABLE IF NOT EXISTS dag_events (
            event_id         TEXT PRIMARY KEY,
            room_id          TEXT NOT NULL,
            depth            INTEGER NOT NULL,
            event_type       TEXT NOT NULL,
            sender           TEXT NOT NULL,
            state_key        TEXT,
            origin_server_ts INTEGER NOT NULL,
            pdu              TEXT NOT NULL,
            outlier          INTEGER NOT NULL DEFAULT 0,
            soft_failed      INTEGER NOT NULL DEFAULT 0,
            skeleton         INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS dag_events_room ON dag_events (room_id, depth);
        CREATE TABLE IF NOT EXISTS dag_edges (
            event_id      TEXT NOT NULL,
            prev_event_id TEXT NOT NULL,
            PRIMARY KEY (event_id, prev_event_id)
        );
        CREATE TABLE IF NOT EXISTS dag_auth (
            event_id      TEXT NOT NULL,
            auth_event_id TEXT NOT NULL,
            PRIMARY KEY (event_id, auth_event_id)
        );
        CREATE TABLE IF NOT EXISTS dag_extremities (
            room_id  TEXT NOT NULL,
            event_id TEXT NOT NULL,
            PRIMARY KEY (room_id, event_id)
        );
        CREATE TABLE IF NOT EXISTS dag_state_groups (
            group_id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id  TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS dag_state_group_entries (
            group_id   INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            state_key  TEXT NOT NULL,
            event_id   TEXT NOT NULL,
            PRIMARY KEY (group_id, event_type, state_key)
        );
        CREATE TABLE IF NOT EXISTS dag_event_state (
            event_id TEXT PRIMARY KEY,
            group_id INTEGER NOT NULL
        );
        "#,
    )
}
