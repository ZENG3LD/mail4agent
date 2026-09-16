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

/// `v2`: sessions, plus room for a session on both sides of a message's
/// envelope. **Never edits `SCHEMA_V1_SQL` above** -- a live database
/// (the mailbox on 18301) is at v1 right now with real participants,
/// rooms and messages in it, and every one of those rows must still read
/// back exactly as before once this migration has run.
///
/// - `sessions` is new. Keyed on `session_id` alone, not on `(account,
///   session_id)`, because `MailStore::get_session` looks a session up
///   by its id with no account in hand yet -- that lookup is exactly how
///   `MailboxEngine::ensure_session` and `::resolve_identity` *learn*
///   which account owns a session, so the primary key has to support it
///   without the account as an input. `idx_sessions_account` is the
///   reverse index `sessions_of` runs against, playing the same role
///   `idx_room_members_participant` already plays for `rooms_containing`.
///   `card` carries the session's whole `SessionCard` -- its
///   `attested`/`corroborated`/`declared` groups together -- as one JSON
///   blob, the same choice `messages.payload` already made for this
///   crate's free-form fields: nothing inside a `SessionCard` is filtered
///   or ordered on by any `MailStore` method, so it earns no columns of
///   its own. `account` and `last_seen_unix_ms` do get real columns
///   because `sessions_of` filters on the former and `ensure_session`
///   refreshes the latter on every call.
///
/// - `messages` gains a session shape on **both** sides of the envelope.
///   `to_kind`'s `CHECK` widens from `('direct', 'room')` to `('direct',
///   'session', 'room')`, with a new `to_session` column alongside the
///   existing `to_participant`/`to_room` -- a session recipient gets its
///   own column rather than sharing `to_participant` with a direct
///   account address, so a query can never confuse the two kinds even if
///   it forgot to check `to_kind` first. `from_participant` was `NOT
///   NULL` and singular in v1 because nothing but an account could ever
///   send a message then; it now gains a sibling `from_kind` (defaulted
///   to `'direct'`, matching what every v1 row actually means) and a
///   nullable `from_session`, mirroring the `to` side exactly.
///
///   SQLite has no `ALTER TABLE ... DROP CONSTRAINT` (or any way to
///   widen one in place), so loosening `to_kind`'s `CHECK` means
///   rebuilding the table: create the v2 shape under a temporary name,
///   copy every v1 row across (`from_kind` literally `'direct'`,
///   `to_session` literally `NULL` -- the only values a v1 row could
///   ever have meant), drop the v1 table, rename the new one into place,
///   and recreate every index the old table carried (both survive
///   unchanged: `idx_messages_direct_recipient`,
///   `idx_messages_room_recipient`) plus the new
///   `idx_messages_session_recipient`, indexed the same way the rest of
///   this table is -- `messages_to_since` and `room_messages_since` are
///   both still exactly "messages for this address, no older than this
///   time".
///
/// - `acks` and `idempotency` need **no schema change at all**. Their
///   `reader`/`sender` columns were always plain `TEXT`, and a v1 row's
///   value there was already exactly an account's [`mail4agent_api::Address::Direct`]
///   `Display` form (`"claude"`) -- the same string
///   `mail4agent_store_stk::store::address_text` still writes for a
///   direct address today. A session's `Display` form (`"claude/s-7f3a..."`)
///   is simply a longer string in the same column; the two can never
///   collide because neither a participant id's nor a session id's
///   charset permits `/` (see `Address`'s own `Display`/`FromStr` doc
///   comment in `mail4agent-api`). This is the one place the
///   address-as-a-key change turned out to cost nothing: only the
///   `messages` table's structured, per-kind columns needed rebuilding.
const SCHEMA_V2_SQL: &str = "
CREATE TABLE sessions (
    session_id        TEXT PRIMARY KEY,
    account           TEXT NOT NULL,
    card              TEXT NOT NULL,
    last_seen_unix_ms INTEGER NOT NULL
);

CREATE INDEX idx_sessions_account ON sessions(account);

CREATE TABLE messages_v2 (
    message_id         TEXT PRIMARY KEY,
    from_participant   TEXT NOT NULL,
    from_kind          TEXT NOT NULL DEFAULT 'direct' CHECK (from_kind IN ('direct', 'session')),
    from_session       TEXT,
    to_kind            TEXT NOT NULL CHECK (to_kind IN ('direct', 'session', 'room')),
    to_participant     TEXT,
    to_session         TEXT,
    to_room            TEXT,
    created_at_unix_ms INTEGER NOT NULL,
    payload            TEXT NOT NULL
);

INSERT INTO messages_v2 (
    message_id, from_participant, from_kind, from_session,
    to_kind, to_participant, to_session, to_room, created_at_unix_ms, payload
)
SELECT message_id, from_participant, 'direct', NULL,
       to_kind, to_participant, NULL, to_room, created_at_unix_ms, payload
FROM messages;

DROP TABLE messages;

ALTER TABLE messages_v2 RENAME TO messages;

CREATE INDEX idx_messages_direct_recipient
    ON messages(to_participant, created_at_unix_ms)
    WHERE to_kind = 'direct';

CREATE INDEX idx_messages_session_recipient
    ON messages(to_participant, to_session, created_at_unix_ms)
    WHERE to_kind = 'session';

CREATE INDEX idx_messages_room_recipient
    ON messages(to_room, created_at_unix_ms)
    WHERE to_kind = 'room';
";

/// This crate's own migrations, in the order [`stk_db::MigrationRunner`]
/// must apply them. A daemon runs these once against the [`stk_db::Db`] it
/// hands to [`crate::SqliteMailStore::new`]; [`crate::SqliteMailStore::open_in_memory`]
/// runs them itself for tests and small tools.
pub fn migrations() -> Vec<Migration> {
    vec![
        Migration::new(1, "mail4agent_v1_schema", SCHEMA_V1_SQL),
        Migration::new(2, "mail4agent_v2_sessions_and_session_addressing", SCHEMA_V2_SQL),
    ]
}
