//! The mailbox's schema, as versioned [`stk_db::Migration`]s.
//!
//! One migration per line of this file's history: a shipped migration's
//! `sql` is never edited after it has run anywhere, because
//! [`stk_db::MigrationRunner`] records completion by version number alone
//! -- changing a version's SQL after the fact would leave already-migrated
//! databases silently out of sync with a fresh one. A schema change is
//! always a new, higher-numbered [`stk_db::Migration`] appended to
//! [`migrations`], never an edit to an existing entry.

use stk_db::Migration;

/// `v1`: the mailbox's whole schema -- participants, rooms, room
/// membership, messages, acks, and the idempotency ledger. Six tables,
/// because this crate is new and none of them have shipped independently
/// yet; a later schema change appends `v2`, `v3`, ... here rather than
/// touching this string.
///
/// Column and index choices, table by table:
///
/// - `participants.secret_digest` is a `BLOB` of the raw 32-byte SHA-256
///   digest, not lower-hex text: it is only ever compared byte-for-byte
///   (see `mail4agent_core::MailboxEngine::authenticate`) and never
///   displayed or logged, so a text encoding would only cost bytes on
///   disk and cycles on every authentication for no benefit.
///   `idx_participants_secret_digest` is the index that lookup runs
///   against, `UNIQUE` because two participants sharing a digest would
///   mean two participants sharing a secret.
/// - `room_members` is queried both ways -- "members of a room" (its
///   primary key's leading column, `room_id`) and "rooms containing a
///   participant" (`idx_room_members_participant`, the reverse). It
///   carries a foreign key on `room_id` only: rooms are never deleted by
///   this store (there is no such `MailStore` method), so that constraint
///   is free to enforce and catches a real bug -- a membership row naming
///   a room that was never created. It deliberately carries **no**
///   foreign key on `participant_id`: `MailStore::deregister_participant`
///   leaves a departed participant's membership rows in place on purpose
///   (they are inert, never a leak -- see `mail4agent_core::store`'s
///   module doc comment), and a hard foreign key here would turn that
///   into a delete failure the first time a deregistered participant had
///   ever joined a room.
/// - `messages` splits its columns the same way the mailbox this crate
///   replaces did, and for the same reason: `to_kind` /
///   `to_participant` / `to_room` / `created_at_unix_ms` are exactly what
///   `direct_messages_since` / `room_messages_since` filter and order on,
///   so they are real columns with matching partial indexes
///   (`idx_messages_direct_recipient`, `idx_messages_room_recipient` --
///   partial so a room-addressed row is never scanned while looking for
///   direct mail, and vice versa). `subject`, `body`, `reply_to`,
///   `correlation` and `refs` are never filtered or ordered on anywhere in
///   `MailStore` -- every caller reads them back verbatim -- so they live
///   together in one JSON `payload` column rather than five more columns
///   that would need a migration each time this crate's callers wanted a
///   new field on a message.
/// - `acks` is keyed by `(message_id, reader)` directly as its primary
///   key: a room-addressed message has one ack per reader, never one
///   total, and that primary key is also the exact shape `get_ack` and
///   `record_ack`'s idempotent upsert (see `store.rs`) key against.
/// - `idempotency` is keyed by `(sender, idempotency_key)` as its primary
///   key -- not a secondary `UNIQUE` index over a surrogate id -- so
///   `insert_message`'s check-and-insert is enforced by that constraint
///   directly: a repeat send racing the same key fails the `INSERT`
///   itself rather than a read-then-write pair a second caller could
///   interleave with.
const SCHEMA_V1_SQL: &str = "
CREATE TABLE participants (
    id            TEXT PRIMARY KEY,
    label         TEXT,
    secret_digest BLOB NOT NULL,
    may_send      INTEGER NOT NULL,
    may_read      INTEGER NOT NULL,
    operator      INTEGER NOT NULL
);

CREATE UNIQUE INDEX idx_participants_secret_digest ON participants(secret_digest);

CREATE TABLE rooms (
    id                 TEXT PRIMARY KEY,
    created_at_unix_ms INTEGER NOT NULL
);

CREATE TABLE room_members (
    room_id        TEXT NOT NULL REFERENCES rooms(id),
    participant_id TEXT NOT NULL,
    PRIMARY KEY (room_id, participant_id)
);

CREATE INDEX idx_room_members_participant ON room_members(participant_id);

CREATE TABLE messages (
    message_id         TEXT PRIMARY KEY,
    from_participant   TEXT NOT NULL,
    to_kind            TEXT NOT NULL CHECK (to_kind IN ('direct', 'room')),
    to_participant     TEXT,
    to_room            TEXT,
    created_at_unix_ms INTEGER NOT NULL,
    payload            TEXT NOT NULL
);

CREATE INDEX idx_messages_direct_recipient
    ON messages(to_participant, created_at_unix_ms)
    WHERE to_kind = 'direct';

CREATE INDEX idx_messages_room_recipient
    ON messages(to_room, created_at_unix_ms)
    WHERE to_kind = 'room';

CREATE TABLE acks (
    message_id       TEXT NOT NULL,
    reader           TEXT NOT NULL,
    acked_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (message_id, reader)
);

CREATE TABLE idempotency (
    sender          TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    message_id      TEXT NOT NULL,
    PRIMARY KEY (sender, idempotency_key)
);
";

/// This crate's own migrations, in the order [`stk_db::MigrationRunner`]
/// must apply them. A daemon runs these once against the [`stk_db::Db`] it
/// hands to [`crate::SqliteMailStore::new`]; [`crate::SqliteMailStore::open_in_memory`]
/// runs them itself for tests and small tools.
pub fn migrations() -> Vec<Migration> {
    vec![Migration::new(1, "mail4agent_v1_schema", SCHEMA_V1_SQL)]
}
