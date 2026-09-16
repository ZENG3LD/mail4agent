//! [`SqliteMailStore`] -- the [`MailStore`] implementation this crate
//! exists to provide. See the crate's module doc comment for the
//! blocking-vs-async discipline every method here follows.

use mail4agent_api::{Ack, Address, Message, MessageId, MessageRef, ParticipantId, RoomId};
use mail4agent_core::{
    InsertMessageOutcome, MailStore, ParticipantRecord, ParticipantSummary, RoomRecord, RoomSummary, SecretDigest,
    StoreError,
};
use serde::{Deserialize, Serialize};
use stk_db::rusqlite::{self, OptionalExtension};
use stk_db::{Db, DbConfig, MigrationRunner};

use crate::migrations::migrations;

/// A [`MailStore`] backed by SQLite through stk's [`Db`]. Every mutating
/// method below is exactly one transaction, matching the contract
/// `mail4agent_core::store`'s module doc comment sets for a persistent
/// implementation.
pub struct SqliteMailStore {
    db: Db,
}

impl SqliteMailStore {
    /// Wraps an already-open [`Db`]. The caller is responsible for having
    /// run [`crate::migrations`] against it first -- typically through the
    /// same `ServerBuilder` wiring that opened `db` -- so this constructor
    /// stays infallible and a daemon can hand in the very `Db` its own
    /// builder produced.
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Opens a fresh in-memory [`Db`] and runs this crate's own migrations
    /// against it. Convenience for tests and small tools; a real daemon
    /// wants a file-backed `Db` it built (and migrated) itself and should
    /// use [`Self::new`] instead.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let db = Db::open(&DbConfig::in_memory())
            .map_err(|err| StoreError::new(format!("open in-memory db: {err}")))?;
        db.run_migrations_blocking(MigrationRunner::new(migrations()))
            .map_err(|err| StoreError::new(format!("run migrations: {err}")))?;
        Ok(Self { db })
    }

    /// The underlying [`Db`] handle. Clones share the same connection (see
    /// [`Db`]'s own doc comment) -- useful when a daemon wants this store
    /// and some other stk-backed subsystem sharing one sqlite file.
    pub fn db(&self) -> Db {
        self.db.clone()
    }
}

impl MailStore for SqliteMailStore {
    fn register_participant(&mut self, id: ParticipantId, record: ParticipantRecord) -> Result<(), StoreError> {
        self.db
            .write_blocking(|conn| {
                conn.execute(
                    "INSERT INTO participants (id, label, secret_digest, may_send, may_read, operator)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        id.as_str(),
                        record.label,
                        record.secret_digest.as_slice(),
                        record.may_send,
                        record.may_read,
                        record.operator,
                    ],
                )?;
                Ok(())
            })
            .map_err(|err| StoreError::new(format!("register_participant({id}): {err}")))
    }

    fn deregister_participant(&mut self, id: &ParticipantId) -> Result<(), StoreError> {
        self.db
            .write_blocking(|conn| {
                conn.execute("DELETE FROM participants WHERE id = ?1", rusqlite::params![id.as_str()])?;
                Ok(())
            })
            .map_err(|err| StoreError::new(format!("deregister_participant({id}): {err}")))
    }

    fn set_participant_secret_digest(&mut self, id: &ParticipantId, digest: SecretDigest) -> Result<(), StoreError> {
        self.db
            .write_blocking(|conn| {
                conn.execute(
                    "UPDATE participants SET secret_digest = ?1 WHERE id = ?2",
                    rusqlite::params![digest.as_slice(), id.as_str()],
                )?;
                Ok(())
            })
            .map_err(|err| StoreError::new(format!("set_participant_secret_digest({id}): {err}")))
    }

    fn get_participant(&self, id: &ParticipantId) -> Result<Option<ParticipantRecord>, StoreError> {
        self.db
            .read_blocking(|conn| {
                conn.query_row(
                    "SELECT label, secret_digest, may_send, may_read, operator FROM participants WHERE id = ?1",
                    rusqlite::params![id.as_str()],
                    |row| {
                        Ok(ParticipantRecord {
                            label: row.get(0)?,
                            secret_digest: digest_from_row(row, 1)?,
                            may_send: row.get(2)?,
                            may_read: row.get(3)?,
                            operator: row.get(4)?,
                        })
                    },
                )
                .optional()
            })
            .map_err(|err| StoreError::new(format!("get_participant({id}): {err}")))
    }

    fn find_participant_by_digest(
        &self,
        digest: &SecretDigest,
    ) -> Result<Option<(ParticipantId, ParticipantRecord)>, StoreError> {
        let found = self
            .db
            .read_blocking(|conn| {
                conn.query_row(
                    "SELECT id, label, may_send, may_read, operator FROM participants WHERE secret_digest = ?1",
                    rusqlite::params![digest.as_slice()],
                    |row| {
                        let id: String = row.get(0)?;
                        let label: Option<String> = row.get(1)?;
                        let may_send: bool = row.get(2)?;
                        let may_read: bool = row.get(3)?;
                        let operator: bool = row.get(4)?;
                        Ok((id, label, may_send, may_read, operator))
                    },
                )
                .optional()
            })
            .map_err(|err| StoreError::new(format!("find_participant_by_digest: {err}")))?;

        let Some((id, label, may_send, may_read, operator)) = found else {
            return Ok(None);
        };
        let participant_id = ParticipantId::new(id).map_err(|err| {
            StoreError::new(format!("find_participant_by_digest: stored participant id failed validation: {err}"))
        })?;
        Ok(Some((
            participant_id,
            ParticipantRecord { label, secret_digest: *digest, may_send, may_read, operator },
        )))
    }

    fn create_room(&mut self, id: RoomId, created_at_unix_ms: u64) -> Result<(), StoreError> {
        let created_at = i64::try_from(created_at_unix_ms)
            .map_err(|_| StoreError::new(format!("create_room({id}): created_at_unix_ms overflows i64")))?;
        self.db
            .write_blocking(|conn| {
                conn.execute(
                    "INSERT INTO rooms (id, created_at_unix_ms) VALUES (?1, ?2)",
                    rusqlite::params![id.as_str(), created_at],
                )?;
                Ok(())
            })
            .map_err(|err| StoreError::new(format!("create_room({id}): {err}")))
    }

    fn add_room_member(&mut self, room: &RoomId, participant: ParticipantId) -> Result<(), StoreError> {
        self.db
            .write_blocking(|conn| {
                conn.execute(
                    "INSERT INTO room_members (room_id, participant_id) VALUES (?1, ?2)
                     ON CONFLICT (room_id, participant_id) DO NOTHING",
                    rusqlite::params![room.as_str(), participant.as_str()],
                )?;
                Ok(())
            })
            .map_err(|err| StoreError::new(format!("add_room_member({room}, {participant}): {err}")))
    }

    fn remove_room_member(&mut self, room: &RoomId, participant: &ParticipantId) -> Result<(), StoreError> {
        self.db
            .write_blocking(|conn| {
                conn.execute(
                    "DELETE FROM room_members WHERE room_id = ?1 AND participant_id = ?2",
                    rusqlite::params![room.as_str(), participant.as_str()],
                )?;
                Ok(())
            })
            .map_err(|err| StoreError::new(format!("remove_room_member({room}, {participant}): {err}")))
    }

    fn get_room(&self, id: &RoomId) -> Result<Option<RoomRecord>, StoreError> {
        let created_at = self
            .db
            .read_blocking(|conn| {
                conn.query_row(
                    "SELECT created_at_unix_ms FROM rooms WHERE id = ?1",
                    rusqlite::params![id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
            })
            .map_err(|err| StoreError::new(format!("get_room({id}): {err}")))?;

        let Some(created_at) = created_at else {
            return Ok(None);
        };
        let created_at_unix_ms = u64::try_from(created_at)
            .map_err(|_| StoreError::new(format!("get_room({id}): stored created_at_unix_ms is negative")))?;

        let member_ids: Vec<String> = self
            .db
            .read_blocking(|conn| {
                let mut statement = conn.prepare("SELECT participant_id FROM room_members WHERE room_id = ?1")?;
                let rows = statement.query_map(rusqlite::params![id.as_str()], |row| row.get(0))?;
                rows.collect()
            })
            .map_err(|err| StoreError::new(format!("get_room({id}): {err}")))?;

        let mut members = std::collections::BTreeSet::new();
        for member_id in member_ids {
            let participant_id = ParticipantId::new(member_id).map_err(|err| {
                StoreError::new(format!("get_room({id}): stored member id failed validation: {err}"))
            })?;
            members.insert(participant_id);
        }
        Ok(Some(RoomRecord { created_at_unix_ms, members }))
    }

    fn insert_message(
        &mut self,
        message: Message,
        idempotency: Option<(ParticipantId, String)>,
    ) -> Result<InsertMessageOutcome, StoreError> {
        let (to_kind, to_participant, to_room) = address_columns(&message.to);
        let payload = MessagePayloadWrite {
            subject: &message.subject,
            body: &message.body,
            reply_to: message.reply_to.as_ref().map(MessageId::as_str),
            correlation: message.correlation.as_deref(),
            refs: &message.refs,
        };
        let payload_json = serde_json::to_string(&payload)
            .map_err(|err| StoreError::new(format!("insert_message({}): serialize payload: {err}", message.message_id)))?;
        let created_at_unix_ms = i64::try_from(message.created_at_unix_ms).map_err(|_| {
            StoreError::new(format!("insert_message({}): created_at_unix_ms overflows i64", message.message_id))
        })?;

        let raw_outcome = self
            .db
            .write_blocking(|conn| -> rusqlite::Result<RawInsertOutcome> {
                let tx = conn.transaction()?;
                tx.execute(
                    "INSERT INTO messages
                        (message_id, from_participant, to_kind, to_participant, to_room, created_at_unix_ms, payload)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        message.message_id.as_str(),
                        message.from.as_str(),
                        to_kind,
                        to_participant,
                        to_room,
                        created_at_unix_ms,
                        payload_json,
                    ],
                )?;

                let outcome = match &idempotency {
                    Some((sender, key)) => match tx.execute(
                        "INSERT INTO idempotency (sender, idempotency_key, message_id) VALUES (?1, ?2, ?3)",
                        rusqlite::params![sender.as_str(), key, message.message_id.as_str()],
                    ) {
                        Ok(_) => RawInsertOutcome::Inserted,
                        Err(rusqlite::Error::SqliteFailure(sql_err, _))
                            if sql_err.code == rusqlite::ErrorCode::ConstraintViolation =>
                        {
                            let existing: String = tx.query_row(
                                "SELECT message_id FROM idempotency WHERE sender = ?1 AND idempotency_key = ?2",
                                rusqlite::params![sender.as_str(), key],
                                |row| row.get(0),
                            )?;
                            RawInsertOutcome::Deduplicated(existing)
                        }
                        Err(other) => return Err(other),
                    },
                    None => RawInsertOutcome::Inserted,
                };

                // On `Inserted`, commit both statements above. On
                // `Deduplicated`, `tx` is simply dropped here without a
                // commit, rolling back the message row this transaction
                // just wrote -- the idempotency ledger's UNIQUE constraint
                // already proved another send owns this (sender, key)
                // pair, so nothing new should persist.
                if matches!(outcome, RawInsertOutcome::Inserted) {
                    tx.commit()?;
                }
                Ok(outcome)
            })
            .map_err(|err| StoreError::new(format!("insert_message({}): {err}", message.message_id)))?;

        match raw_outcome {
            RawInsertOutcome::Inserted => Ok(InsertMessageOutcome::Inserted),
            RawInsertOutcome::Deduplicated(existing) => {
                let message_id = MessageId::new(existing).map_err(|err| {
                    StoreError::new(format!(
                        "insert_message({}): stored idempotency row names an invalid message id: {err}",
                        message.message_id
                    ))
                })?;
                Ok(InsertMessageOutcome::Deduplicated { message_id })
            }
        }
    }

    fn get_message(&self, id: &MessageId) -> Result<Option<Message>, StoreError> {
        let row = self
            .db
            .read_blocking(|conn| {
                conn.query_row(
                    "SELECT message_id, from_participant, to_kind, to_participant, to_room, created_at_unix_ms, payload
                       FROM messages WHERE message_id = ?1",
                    rusqlite::params![id.as_str()],
                    row_to_stored_message,
                )
                .optional()
            })
            .map_err(|err| StoreError::new(format!("get_message({id}): {err}")))?;
        row.map(assemble_message).transpose()
    }

    fn direct_messages_since(&self, participant: &ParticipantId, since_unix_ms: u64) -> Result<Vec<Message>, StoreError> {
        let since = i64::try_from(since_unix_ms).map_err(|_| {
            StoreError::new(format!("direct_messages_since({participant}): since_unix_ms overflows i64"))
        })?;
        let rows = self
            .db
            .read_blocking(|conn| {
                let mut statement = conn.prepare(
                    "SELECT message_id, from_participant, to_kind, to_participant, to_room, created_at_unix_ms, payload
                       FROM messages
                      WHERE to_kind = 'direct' AND to_participant = ?1 AND created_at_unix_ms >= ?2
                   ORDER BY created_at_unix_ms ASC",
                )?;
                let rows = statement.query_map(rusqlite::params![participant.as_str(), since], row_to_stored_message)?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(|err| StoreError::new(format!("direct_messages_since({participant}): {err}")))?;
        rows.into_iter().map(assemble_message).collect()
    }

    fn room_messages_since(&self, room: &RoomId, since_unix_ms: u64) -> Result<Vec<Message>, StoreError> {
        let since = i64::try_from(since_unix_ms)
            .map_err(|_| StoreError::new(format!("room_messages_since({room}): since_unix_ms overflows i64")))?;
        let rows = self
            .db
            .read_blocking(|conn| {
                let mut statement = conn.prepare(
                    "SELECT message_id, from_participant, to_kind, to_participant, to_room, created_at_unix_ms, payload
                       FROM messages
                      WHERE to_kind = 'room' AND to_room = ?1 AND created_at_unix_ms >= ?2
                   ORDER BY created_at_unix_ms ASC",
                )?;
                let rows = statement.query_map(rusqlite::params![room.as_str(), since], row_to_stored_message)?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(|err| StoreError::new(format!("room_messages_since({room}): {err}")))?;
        rows.into_iter().map(assemble_message).collect()
    }

    fn rooms_containing(&self, participant: &ParticipantId) -> Result<Vec<RoomId>, StoreError> {
        let room_ids: Vec<String> = self
            .db
            .read_blocking(|conn| {
                let mut statement = conn.prepare("SELECT room_id FROM room_members WHERE participant_id = ?1")?;
                let rows = statement.query_map(rusqlite::params![participant.as_str()], |row| row.get(0))?;
                rows.collect()
            })
            .map_err(|err| StoreError::new(format!("rooms_containing({participant}): {err}")))?;

        room_ids
            .into_iter()
            .map(|id| {
                RoomId::new(id).map_err(|err| {
                    StoreError::new(format!("rooms_containing({participant}): stored room id failed validation: {err}"))
                })
            })
            .collect()
    }

    fn record_ack(&mut self, ack: Ack) -> Result<Ack, StoreError> {
        let acked_at = i64::try_from(ack.acked_at_unix_ms)
            .map_err(|_| StoreError::new(format!("record_ack({}, {}): acked_at_unix_ms overflows i64", ack.message_id, ack.reader)))?;

        // `DO UPDATE SET reader = excluded.reader` is a genuine no-op --
        // `reader` is part of the conflict key, so it never changes -- but
        // it is what makes SQLite treat this as an upsert rather than a
        // skipped insert, which is what lets `RETURNING` hand back
        // whichever row is now on file (the one this call just wrote, or
        // an earlier ack for the same (message_id, reader) pair) in the
        // same round trip, atomically: two concurrent acks of the same
        // message by the same reader read back the very same
        // `acked_at_unix_ms`, never two different ones.
        let stored_acked_at: i64 = self
            .db
            .write_blocking(|conn| {
                conn.query_row(
                    "INSERT INTO acks (message_id, reader, acked_at_unix_ms) VALUES (?1, ?2, ?3)
                     ON CONFLICT (message_id, reader) DO UPDATE SET reader = excluded.reader
                     RETURNING acked_at_unix_ms",
                    rusqlite::params![ack.message_id.as_str(), ack.reader.as_str(), acked_at],
                    |row| row.get(0),
                )
            })
            .map_err(|err| StoreError::new(format!("record_ack({}, {}): {err}", ack.message_id, ack.reader)))?;

        let acked_at_unix_ms = u64::try_from(stored_acked_at).map_err(|_| {
            StoreError::new(format!("record_ack({}, {}): stored acked_at_unix_ms is negative", ack.message_id, ack.reader))
        })?;
        Ok(Ack { message_id: ack.message_id, reader: ack.reader, acked_at_unix_ms })
    }

    fn get_ack(&self, message_id: &MessageId, reader: &ParticipantId) -> Result<Option<Ack>, StoreError> {
        let row = self
            .db
            .read_blocking(|conn| {
                conn.query_row(
                    "SELECT acked_at_unix_ms FROM acks WHERE message_id = ?1 AND reader = ?2",
                    rusqlite::params![message_id.as_str(), reader.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
            })
            .map_err(|err| StoreError::new(format!("get_ack({message_id}, {reader}): {err}")))?;

        let Some(acked_at) = row else {
            return Ok(None);
        };
        let acked_at_unix_ms = u64::try_from(acked_at)
            .map_err(|_| StoreError::new(format!("get_ack({message_id}, {reader}): stored acked_at_unix_ms is negative")))?;
        Ok(Some(Ack { message_id: message_id.clone(), reader: reader.clone(), acked_at_unix_ms }))
    }

    fn list_participants(&self) -> Result<Vec<ParticipantSummary>, StoreError> {
        let rows: Vec<(String, Option<String>)> = self
            .db
            .read_blocking(|conn| {
                let mut statement = conn.prepare("SELECT id, label FROM participants ORDER BY id")?;
                let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(|err| StoreError::new(format!("list_participants: {err}")))?;

        rows.into_iter()
            .map(|(id, label)| {
                let id = ParticipantId::new(id).map_err(|err| {
                    StoreError::new(format!("list_participants: stored participant id failed validation: {err}"))
                })?;
                Ok(ParticipantSummary { id, label })
            })
            .collect()
    }

    fn list_rooms(&self) -> Result<Vec<RoomSummary>, StoreError> {
        // One transaction-free read over two statements against the same
        // connection, not two separate `read_blocking` calls: this keeps
        // the room list and the membership rows a single consistent
        // snapshot rather than two reads a concurrent write could land
        // between.
        let (room_ids, member_rows): (Vec<String>, Vec<(String, String)>) = self
            .db
            .read_blocking(|conn| {
                let mut room_statement = conn.prepare("SELECT id FROM rooms ORDER BY id")?;
                let room_ids =
                    room_statement.query_map([], |row| row.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;

                let mut member_statement = conn.prepare("SELECT room_id, participant_id FROM room_members")?;
                let member_rows = member_statement
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<rusqlite::Result<Vec<(String, String)>>>()?;

                Ok((room_ids, member_rows))
            })
            .map_err(|err| StoreError::new(format!("list_rooms: {err}")))?;

        let mut members_by_room: std::collections::HashMap<String, std::collections::BTreeSet<ParticipantId>> =
            std::collections::HashMap::new();
        for (room_id, participant_id) in member_rows {
            let participant_id = ParticipantId::new(participant_id).map_err(|err| {
                StoreError::new(format!("list_rooms: stored member id failed validation: {err}"))
            })?;
            members_by_room.entry(room_id).or_default().insert(participant_id);
        }

        room_ids
            .into_iter()
            .map(|id_str| {
                let members = members_by_room.remove(&id_str).unwrap_or_default();
                let id = RoomId::new(id_str)
                    .map_err(|err| StoreError::new(format!("list_rooms: stored room id failed validation: {err}")))?;
                Ok(RoomSummary { id, members })
            })
            .collect()
    }
}

/// What [`MailStore::insert_message`]'s own transaction decided, before
/// its message id has been re-validated into a [`MessageId`]. Kept
/// separate from [`InsertMessageOutcome`] because the closure passed to
/// `write_blocking` returns a plain [`rusqlite::Result`] and has no way to
/// surface a [`StoreError`] from a failed [`MessageId::new`] -- that
/// validation happens once, after the transaction has already committed
/// or rolled back.
enum RawInsertOutcome {
    Inserted,
    Deduplicated(String),
}

/// A message row exactly as its seven columns hold it, before
/// [`assemble_message`] re-validates each id and parses `payload` back
/// into the rest of a [`Message`].
struct StoredMessageRow {
    message_id: String,
    from_participant: String,
    to_kind: String,
    to_participant: Option<String>,
    to_room: Option<String>,
    created_at_unix_ms: i64,
    payload: String,
}

fn row_to_stored_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMessageRow> {
    Ok(StoredMessageRow {
        message_id: row.get(0)?,
        from_participant: row.get(1)?,
        to_kind: row.get(2)?,
        to_participant: row.get(3)?,
        to_room: row.get(4)?,
        created_at_unix_ms: row.get(5)?,
        payload: row.get(6)?,
    })
}

/// The JSON shape of `messages.payload`, written by borrowing straight out
/// of a [`Message`] the caller already owns -- see [`MessagePayloadRead`]
/// for the owned counterpart a row is parsed back into.
#[derive(Serialize)]
struct MessagePayloadWrite<'a> {
    subject: &'a str,
    body: &'a str,
    reply_to: Option<&'a str>,
    correlation: Option<&'a str>,
    refs: &'a [MessageRef],
}

/// The owned counterpart of [`MessagePayloadWrite`], for parsing
/// `messages.payload` back out of a row. `refs` defaults on decode so a
/// payload written before some future field addition still deserializes.
#[derive(Deserialize)]
struct MessagePayloadRead {
    subject: String,
    body: String,
    reply_to: Option<String>,
    correlation: Option<String>,
    #[serde(default)]
    refs: Vec<MessageRef>,
}

/// Reassembles a [`Message`] from a [`StoredMessageRow`], re-validating
/// every id this store itself wrote (defence in depth against a row
/// hand-edited outside this crate, not against anything a normal call
/// path can produce).
fn assemble_message(row: StoredMessageRow) -> Result<Message, StoreError> {
    let message_id = MessageId::new(row.message_id)
        .map_err(|err| StoreError::new(format!("stored message id failed validation: {err}")))?;
    let from = ParticipantId::new(row.from_participant)
        .map_err(|err| StoreError::new(format!("stored sender id failed validation: {err}")))?;
    let to = address_from_columns(&row.to_kind, row.to_participant, row.to_room)?;
    let created_at_unix_ms = u64::try_from(row.created_at_unix_ms)
        .map_err(|_| StoreError::new("stored created_at_unix_ms is negative".to_string()))?;
    let payload: MessagePayloadRead = serde_json::from_str(&row.payload)
        .map_err(|err| StoreError::new(format!("stored message payload failed to parse: {err}")))?;
    let reply_to = payload
        .reply_to
        .map(MessageId::new)
        .transpose()
        .map_err(|err| StoreError::new(format!("stored reply_to failed validation: {err}")))?;

    Ok(Message {
        message_id,
        from,
        to,
        subject: payload.subject,
        body: payload.body,
        reply_to,
        correlation: payload.correlation,
        refs: payload.refs,
        created_at_unix_ms,
    })
}

/// Splits an [`Address`] into `(to_kind, to_participant, to_room)` the way
/// `messages` stores it.
fn address_columns(address: &Address) -> (&'static str, Option<&str>, Option<&str>) {
    match address {
        Address::Direct { participant } => ("direct", Some(participant.as_str()), None),
        Address::Room { room } => ("room", None, Some(room.as_str())),
    }
}

/// The inverse of [`address_columns`].
fn address_from_columns(kind: &str, to_participant: Option<String>, to_room: Option<String>) -> Result<Address, StoreError> {
    match kind {
        "direct" => {
            let participant = to_participant
                .ok_or_else(|| StoreError::new("stored message has to_kind = direct but to_participant is NULL".to_string()))?;
            let participant = ParticipantId::new(participant)
                .map_err(|err| StoreError::new(format!("stored direct recipient id failed validation: {err}")))?;
            Ok(Address::Direct { participant })
        }
        "room" => {
            let room = to_room
                .ok_or_else(|| StoreError::new("stored message has to_kind = room but to_room is NULL".to_string()))?;
            let room = RoomId::new(room)
                .map_err(|err| StoreError::new(format!("stored room recipient id failed validation: {err}")))?;
            Ok(Address::Room { room })
        }
        other => Err(StoreError::new(format!("stored message has unknown to_kind {other:?}"))),
    }
}

/// A tiny local error so [`digest_from_row`] can report a length mismatch
/// through rusqlite's own `FromSqlConversionFailure` rather than panicking
/// on the `TryFrom` it uses to size the digest down to `[u8; 32]`.
#[derive(Debug)]
struct DigestLengthError(usize);

impl std::fmt::Display for DigestLengthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "secret_digest column must be exactly 32 bytes, got {}", self.0)
    }
}

impl std::error::Error for DigestLengthError {}

fn digest_from_row(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<SecretDigest> {
    let bytes: Vec<u8> = row.get(idx)?;
    let len = bytes.len();
    <[u8; 32]>::try_from(bytes)
        .map_err(|_| rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Blob, Box::new(DigestLengthError(len))))
}
