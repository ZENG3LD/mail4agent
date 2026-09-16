//! The mailbox's own storage boundary: the [`MailStore`] trait plus
//! [`InMemoryStore`], the implementation this crate's tests run against.
//!
//! **This crate does not write SQLite.** Persistence is a separate task; what
//! belongs here is the shape of the boundary, chosen so a SQLite
//! implementation can satisfy it with one transaction per mutating method --
//! each mutating method below corresponds to exactly one engine-level
//! mutation (register a participant, send a message, record an ack, ...),
//! never a fragment of one, so nothing needs two round trips to stay
//! consistent.
//!
//! Every method returns `Result<_, StoreError>`: a store is a real
//! dependency (disk, a lock, a connection) that can fail independently of
//! anything a caller did wrong, and a fallible implementation cannot satisfy
//! an infallible trait without panicking -- unacceptable in a service whose
//! job is to stay reachable. [`crate::MailboxEngine`] maps a [`StoreError`]
//! into [`mail4agent_api::MailError::StoreUnavailable`], naming only the
//! failing operation; the [`StoreError`] itself is logged via
//! `tracing::error!` and never crosses the wire (see the engine's
//! `store_unavailable` helper).

use std::collections::{BTreeSet, HashMap};

use mail4agent_api::{Ack, Address, Message, MessageId, ParticipantId, RoomId};
use thiserror::Error;

/// The SHA-256 digest of a participant's secret. The engine stores only
/// this, never the secret itself -- see `MailboxEngine::authenticate`'s doc
/// comment for why an exact-digest index is safe to look up directly rather
/// than scanned.
pub type SecretDigest = [u8; 32];

/// An error from a [`MailStore`] implementation itself -- I/O, a lock, a
/// corrupt row -- as distinct from a domain refusal
/// ([`mail4agent_api::MailError`]). Carries a message meant for
/// `tracing::error!`, never for a caller: see the module doc comment.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct StoreError(pub String);

impl StoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// A registered participant, as the mailbox's own registry holds it.
///
/// `label` is display metadata only. `secret_digest` is the SHA-256 digest
/// of the participant's bearer secret -- the plaintext is generated once, on
/// registration or rotation, handed back to the caller, and never stored.
/// `may_send` and `may_read` gate [`crate::MailboxEngine::send`] and the
/// read-side operations respectively; `operator` additionally lets a
/// participant read any *named* address one at a time (see
/// `crate::MailboxEngine::inbox_of`), never the whole mailbox in one call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParticipantRecord {
    pub label: Option<String>,
    pub secret_digest: SecretDigest,
    pub may_send: bool,
    pub may_read: bool,
    pub operator: bool,
}

/// A room the mailbox tracks membership for. Membership is explicit and
/// mailbox-owned -- never recomputed from a foreign graph (see
/// `mail4agent/CLAUDE.md` and
/// `mailbox-service-extraction-and-signed-session-identity-2026-09-16.md`
/// §5b: this is what makes a room's readability immune to something
/// unrelated growing too large elsewhere).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomRecord {
    pub created_at_unix_ms: u64,
    pub members: BTreeSet<ParticipantId>,
}

/// A directory-listable summary of a registered participant: enough to
/// list it, and no more. Deliberately excludes [`ParticipantRecord`]'s
/// `secret_digest`, `may_send`, `may_read` and `operator` -- a directory
/// answers "who exists", never "what may they do" or anything that would
/// help forge one, and a type that structurally has no `secret_digest`
/// field cannot leak one even by accident, regardless of what
/// [`MailStore::list_participants`]'s implementation does internally. See
/// `mail4agent_api::DirectoryEntry`, the wire type this is assembled into.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParticipantSummary {
    pub id: ParticipantId,
    pub label: Option<String>,
}

/// A directory-listable summary of a room: its id and current membership,
/// as raw fact -- not yet filtered through any one caller's point of view.
/// `crate::MailboxEngine::directory` is what turns "who is a member" into
/// "is the caller a member".
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomSummary {
    pub id: RoomId,
    pub members: BTreeSet<ParticipantId>,
}

/// What [`MailStore::insert_message`] did. Distinguishes a genuinely new
/// message from a retry recognised by its idempotency key, so the engine can
/// return the *original* [`mail4agent_api::SendResponse`] without needing a
/// second read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InsertMessageOutcome {
    /// The message was new and is now stored.
    Inserted,
    /// A prior send from the same participant already used this idempotency
    /// key; nothing was created, and this is the id of that prior message.
    Deduplicated { message_id: MessageId },
}

/// The mailbox's persistence boundary. One mutating method per engine-level
/// mutation (see the module doc comment on why); reads are split finely
/// enough that each maps onto a single indexed SQL query rather than a
/// linear scan.
pub trait MailStore {
    /// Registers a new participant. The caller (the engine) has already
    /// confirmed no participant is registered under this id.
    fn register_participant(&mut self, id: ParticipantId, record: ParticipantRecord) -> Result<(), StoreError>;

    /// Removes a participant's registration entirely, including its place
    /// in the secret-digest index. Room memberships naming this id are left
    /// as-is: the id can never authenticate again without a fresh
    /// registration, so a stale membership entry is inert, not a leak.
    fn deregister_participant(&mut self, id: &ParticipantId) -> Result<(), StoreError>;

    /// Replaces a participant's stored secret digest -- the shared
    /// mechanism behind both revoking and rotating a secret (see
    /// `crate::MailboxEngine::rotate_participant_secret`).
    fn set_participant_secret_digest(&mut self, id: &ParticipantId, digest: SecretDigest) -> Result<(), StoreError>;

    fn get_participant(&self, id: &ParticipantId) -> Result<Option<ParticipantRecord>, StoreError>;

    /// Looks a participant up by the exact digest of a presented secret.
    /// See `crate::MailboxEngine::authenticate` for why this is an index
    /// lookup, not a scan.
    fn find_participant_by_digest(
        &self,
        digest: &SecretDigest,
    ) -> Result<Option<(ParticipantId, ParticipantRecord)>, StoreError>;

    /// Creates a room with no members. The caller has already confirmed no
    /// room is registered under this id.
    fn create_room(&mut self, id: RoomId, created_at_unix_ms: u64) -> Result<(), StoreError>;

    /// Idempotent: adding an existing member is a no-op.
    fn add_room_member(&mut self, room: &RoomId, participant: ParticipantId) -> Result<(), StoreError>;

    /// Idempotent: removing a non-member is a no-op.
    fn remove_room_member(&mut self, room: &RoomId, participant: &ParticipantId) -> Result<(), StoreError>;

    fn get_room(&self, id: &RoomId) -> Result<Option<RoomRecord>, StoreError>;

    /// Stores `message` unless `idempotency` names a (sender, key) pair
    /// already recorded against an earlier message, in which case nothing
    /// is created and that earlier message's id is returned. One call, one
    /// transaction: a SQLite implementation satisfies this with an insert
    /// under a `UNIQUE (sender, key)` constraint (or an equivalent
    /// check-and-insert within one transaction), never a separate
    /// read-then-write pair that could race under concurrent callers.
    fn insert_message(
        &mut self,
        message: Message,
        idempotency: Option<(ParticipantId, String)>,
    ) -> Result<InsertMessageOutcome, StoreError>;

    fn get_message(&self, id: &MessageId) -> Result<Option<Message>, StoreError>;

    /// Messages addressed directly to `participant`, no older than
    /// `since_unix_ms`.
    fn direct_messages_since(&self, participant: &ParticipantId, since_unix_ms: u64) -> Result<Vec<Message>, StoreError>;

    /// Messages addressed to `room`, no older than `since_unix_ms`. Not
    /// gated on membership -- the caller (the engine) decides who may see
    /// the result.
    fn room_messages_since(&self, room: &RoomId, since_unix_ms: u64) -> Result<Vec<Message>, StoreError>;

    /// Every room `participant` currently belongs to.
    fn rooms_containing(&self, participant: &ParticipantId) -> Result<Vec<RoomId>, StoreError>;

    /// Records an acknowledgement, or returns the one already on file for
    /// this `(message_id, reader)` pair unchanged. One call, one
    /// transaction, so two concurrent acks of the same message by the same
    /// reader cannot both "win" with different timestamps.
    fn record_ack(&mut self, ack: Ack) -> Result<Ack, StoreError>;

    fn get_ack(&self, message_id: &MessageId, reader: &ParticipantId) -> Result<Option<Ack>, StoreError>;

    /// Every registered participant, for the mailbox's own directory
    /// (`crate::MailboxEngine::directory`). Returns the full set, always
    /// -- this mailbox is a small, local directory, not a paginated
    /// social graph. **Never returns a secret digest or a permission
    /// bit**: see [`ParticipantSummary`]'s own doc comment for why the
    /// return type itself rules that out.
    fn list_participants(&self) -> Result<Vec<ParticipantSummary>, StoreError>;

    /// Every room the mailbox tracks, with its current membership, for
    /// the same directory. Also the full set, always, for the same reason.
    fn list_rooms(&self) -> Result<Vec<RoomSummary>, StoreError>;
}

/// An in-memory [`MailStore`], used by this crate's own tests. Not meant for
/// production use: nothing here survives a process restart, and every
/// method always succeeds -- there is no disk, lock or connection here to
/// fail.
#[derive(Default)]
pub struct InMemoryStore {
    participants: HashMap<ParticipantId, ParticipantRecord>,
    digest_index: HashMap<SecretDigest, ParticipantId>,
    rooms: HashMap<RoomId, RoomRecord>,
    messages: HashMap<MessageId, Message>,
    idempotency: HashMap<(ParticipantId, String), MessageId>,
    acks: HashMap<(MessageId, ParticipantId), Ack>,
}

impl MailStore for InMemoryStore {
    fn register_participant(&mut self, id: ParticipantId, record: ParticipantRecord) -> Result<(), StoreError> {
        self.digest_index.insert(record.secret_digest, id.clone());
        self.participants.insert(id, record);
        Ok(())
    }

    fn deregister_participant(&mut self, id: &ParticipantId) -> Result<(), StoreError> {
        if let Some(record) = self.participants.remove(id) {
            self.digest_index.remove(&record.secret_digest);
        }
        Ok(())
    }

    fn set_participant_secret_digest(&mut self, id: &ParticipantId, digest: SecretDigest) -> Result<(), StoreError> {
        if let Some(record) = self.participants.get_mut(id) {
            self.digest_index.remove(&record.secret_digest);
            record.secret_digest = digest;
            self.digest_index.insert(digest, id.clone());
        }
        Ok(())
    }

    fn get_participant(&self, id: &ParticipantId) -> Result<Option<ParticipantRecord>, StoreError> {
        Ok(self.participants.get(id).cloned())
    }

    fn find_participant_by_digest(
        &self,
        digest: &SecretDigest,
    ) -> Result<Option<(ParticipantId, ParticipantRecord)>, StoreError> {
        let Some(id) = self.digest_index.get(digest) else {
            return Ok(None);
        };
        Ok(self.participants.get(id).map(|record| (id.clone(), record.clone())))
    }

    fn create_room(&mut self, id: RoomId, created_at_unix_ms: u64) -> Result<(), StoreError> {
        self.rooms.insert(id, RoomRecord { created_at_unix_ms, members: BTreeSet::new() });
        Ok(())
    }

    fn add_room_member(&mut self, room: &RoomId, participant: ParticipantId) -> Result<(), StoreError> {
        if let Some(record) = self.rooms.get_mut(room) {
            record.members.insert(participant);
        }
        Ok(())
    }

    fn remove_room_member(&mut self, room: &RoomId, participant: &ParticipantId) -> Result<(), StoreError> {
        if let Some(record) = self.rooms.get_mut(room) {
            record.members.remove(participant);
        }
        Ok(())
    }

    fn get_room(&self, id: &RoomId) -> Result<Option<RoomRecord>, StoreError> {
        Ok(self.rooms.get(id).cloned())
    }

    fn insert_message(
        &mut self,
        message: Message,
        idempotency: Option<(ParticipantId, String)>,
    ) -> Result<InsertMessageOutcome, StoreError> {
        if let Some(key) = &idempotency {
            if let Some(existing) = self.idempotency.get(key) {
                return Ok(InsertMessageOutcome::Deduplicated { message_id: existing.clone() });
            }
        }
        let message_id = message.message_id.clone();
        self.messages.insert(message_id.clone(), message);
        if let Some(key) = idempotency {
            self.idempotency.insert(key, message_id);
        }
        Ok(InsertMessageOutcome::Inserted)
    }

    fn get_message(&self, id: &MessageId) -> Result<Option<Message>, StoreError> {
        Ok(self.messages.get(id).cloned())
    }

    fn direct_messages_since(&self, participant: &ParticipantId, since_unix_ms: u64) -> Result<Vec<Message>, StoreError> {
        Ok(self
            .messages
            .values()
            .filter(|message| {
                message.created_at_unix_ms >= since_unix_ms
                    && matches!(&message.to, Address::Direct { participant: p } if p == participant)
            })
            .cloned()
            .collect())
    }

    fn room_messages_since(&self, room: &RoomId, since_unix_ms: u64) -> Result<Vec<Message>, StoreError> {
        Ok(self
            .messages
            .values()
            .filter(|message| {
                message.created_at_unix_ms >= since_unix_ms
                    && matches!(&message.to, Address::Room { room: r } if r == room)
            })
            .cloned()
            .collect())
    }

    fn rooms_containing(&self, participant: &ParticipantId) -> Result<Vec<RoomId>, StoreError> {
        Ok(self
            .rooms
            .iter()
            .filter(|(_, record)| record.members.contains(participant))
            .map(|(id, _)| id.clone())
            .collect())
    }

    fn record_ack(&mut self, ack: Ack) -> Result<Ack, StoreError> {
        Ok(self.acks.entry((ack.message_id.clone(), ack.reader.clone())).or_insert(ack).clone())
    }

    fn get_ack(&self, message_id: &MessageId, reader: &ParticipantId) -> Result<Option<Ack>, StoreError> {
        Ok(self.acks.get(&(message_id.clone(), reader.clone())).cloned())
    }

    fn list_participants(&self) -> Result<Vec<ParticipantSummary>, StoreError> {
        Ok(self
            .participants
            .iter()
            .map(|(id, record)| ParticipantSummary { id: id.clone(), label: record.label.clone() })
            .collect())
    }

    fn list_rooms(&self) -> Result<Vec<RoomSummary>, StoreError> {
        Ok(self
            .rooms
            .iter()
            .map(|(id, record)| RoomSummary { id: id.clone(), members: record.members.clone() })
            .collect())
    }
}
