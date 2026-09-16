//! [`MailboxService`] -- the async facade over the synchronous
//! [`MailboxEngine`]. See `mail4agent/CLAUDE.md`, "The engine is
//! synchronous; the daemon is not": every method here is `async` and does
//! its real work inside [`tokio::task::spawn_blocking`], taking the
//! engine's own lock there. A handler has no other way to reach the
//! engine, so it cannot forget the rule -- if a handler needs a new
//! operation, the method belongs here, never a `spawn_blocking` inline in
//! `routes/`.
//!
//! Two handles share one underlying [`stk::Db`]: `engine` (mutating and
//! authenticating calls, serialised through a [`tokio::sync::Mutex`]) and
//! `reader` (plain [`MailStore`] reads -- `get_participant`,
//! `rooms_containing` -- that [`MailboxEngine`]'s own public surface does
//! not expose: the operator bit the auth layer needs, and the room
//! memberships `/mail/whoami` needs). Both are already-public trait
//! methods on a committed crate ([`mail4agent_core::MailStore`],
//! implemented by [`SqliteMailStore`]); this facade reads them directly
//! through a second store handle over the same connection rather than
//! growing `mail4agent-core`'s own API for two reads.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mail4agent_api::{
    Ack, Directory, InboxPage, MailError, Message, MessageId, ParticipantId, RoomId, SendRequest,
    SendResponse, UnreadCount,
};
use mail4agent_core::{MailStore, MailboxEngine, ParticipantPermissions, StoreError};
use mail4agent_store_stk::SqliteMailStore;
use tokio::sync::Mutex as AsyncMutex;

/// A caller resolved from its bearer secret: everything a handler needs to
/// know about who it is talking to, from one call to
/// [`MailboxService::authenticate`]. Carries only what a handler actually
/// reads (`id`, `label`, `operator`) -- `may_send`/`may_read` are enforced
/// by the engine itself on every call that cares, so this facade does not
/// duplicate that check by also surfacing the raw flags here.
#[derive(Clone, Debug)]
pub struct AuthenticatedParticipant {
    pub id: ParticipantId,
    pub label: Option<String>,
    pub operator: bool,
}

pub struct MailboxService {
    engine: Arc<AsyncMutex<MailboxEngine<SqliteMailStore>>>,
    reader: Arc<SqliteMailStore>,
}

impl MailboxService {
    /// `engine_store` and `reader_store` must be two [`SqliteMailStore`]
    /// handles opened over the SAME underlying [`stk::Db`] (clones of one
    /// connection -- see [`SqliteMailStore::db`]), so a read through
    /// `reader` always observes what `engine` has already committed.
    pub fn new(engine_store: SqliteMailStore, reader_store: SqliteMailStore) -> Self {
        Self {
            engine: Arc::new(AsyncMutex::new(MailboxEngine::new(engine_store))),
            reader: Arc::new(reader_store),
        }
    }

    /// Authenticates `token` against the participant registry. This is the
    /// one place a bearer becomes a [`ParticipantId`] on this facade --
    /// `MailboxAuth` (the `stk::AuthLayer` impl) calls it to grant tiers,
    /// and every handler calls it again to learn *who* it is talking to.
    /// The participant id is never carried in the granted tiers (a
    /// `TokenTier::Scope` is a capability marker, not a place to smuggle a
    /// subject), so re-asking this same question, one more indexed digest
    /// read, is the only way a handler learns it -- deliberate, not an
    /// oversight (`mail4agent/CLAUDE.md`'s "a sender is never a field the
    /// caller fills in", applied at the HTTP boundary too).
    pub async fn authenticate(&self, token: &str) -> Result<AuthenticatedParticipant, MailError> {
        let engine = self.engine.clone();
        let reader = self.reader.clone();
        let token = token.to_string();
        run_blocking("authenticate", move || {
            let id = {
                let guard = engine.blocking_lock();
                guard.authenticate(&token)?
            };
            let record = reader
                .get_participant(&id)
                .map_err(|err| store_unavailable("get_participant", err))?
                .ok_or_else(|| MailError::UnknownParticipant { participant: id.clone() })?;
            Ok(AuthenticatedParticipant { id, label: record.label, operator: record.operator })
        })
        .await
    }

    pub async fn send(&self, sender: ParticipantId, request: SendRequest) -> Result<SendResponse, MailError> {
        let engine = self.engine.clone();
        let now = now_unix_ms();
        run_blocking("send", move || {
            let mut guard = engine.blocking_lock();
            guard.send(&sender, request, now)
        })
        .await
    }

    pub async fn inbox(
        &self,
        reader_id: ParticipantId,
        since_unix_ms: u64,
        limit: u16,
    ) -> Result<InboxPage, MailError> {
        let engine = self.engine.clone();
        run_blocking("inbox", move || {
            let guard = engine.blocking_lock();
            guard.inbox(&reader_id, since_unix_ms, limit)
        })
        .await
    }

    pub async fn ack(&self, reader_id: ParticipantId, message_id: MessageId) -> Result<Ack, MailError> {
        let engine = self.engine.clone();
        let now = now_unix_ms();
        run_blocking("ack", move || {
            let mut guard = engine.blocking_lock();
            guard.ack(&reader_id, &message_id, now)
        })
        .await
    }

    pub async fn message_get(&self, reader_id: ParticipantId, message_id: MessageId) -> Result<Message, MailError> {
        let engine = self.engine.clone();
        run_blocking("message_get", move || {
            let guard = engine.blocking_lock();
            guard.message_get(&reader_id, &message_id)
        })
        .await
    }

    pub async fn unread_count_of(
        &self,
        caller: ParticipantId,
        target: ParticipantId,
    ) -> Result<UnreadCount, MailError> {
        let engine = self.engine.clone();
        run_blocking("unread_count_of", move || {
            let guard = engine.blocking_lock();
            guard.unread_count_of(&caller, &target)
        })
        .await
    }

    /// The mailbox's own directory: every registered participant and every
    /// room, from `caller`'s point of view (see
    /// [`mail4agent_core::MailboxEngine::directory`]).
    pub async fn directory(&self, caller: ParticipantId) -> Result<Directory, MailError> {
        let engine = self.engine.clone();
        run_blocking("directory", move || {
            let guard = engine.blocking_lock();
            guard.directory(&caller)
        })
        .await
    }

    /// Room memberships for `participant` -- the accessor `/mail/whoami`
    /// needs that [`MailboxEngine`]'s own public surface does not expose.
    /// Reads through [`MailStore::rooms_containing`] directly on `reader`.
    pub async fn rooms_of(&self, participant: ParticipantId) -> Result<Vec<RoomId>, MailError> {
        let reader = self.reader.clone();
        run_blocking("rooms_containing", move || {
            reader
                .rooms_containing(&participant)
                .map_err(|err| store_unavailable("rooms_containing", err))
        })
        .await
    }

    /// Whether `id` is already registered. Used only by the bootstrap
    /// check (see `bootstrap.rs`) to decide whether a first operator
    /// participant still needs minting.
    pub async fn participant_exists(&self, id: ParticipantId) -> Result<bool, MailError> {
        let reader = self.reader.clone();
        run_blocking("get_participant", move || {
            reader
                .get_participant(&id)
                .map(|found| found.is_some())
                .map_err(|err| store_unavailable("get_participant", err))
        })
        .await
    }

    pub async fn register_participant(
        &self,
        id: ParticipantId,
        label: Option<String>,
        permissions: ParticipantPermissions,
    ) -> Result<String, MailError> {
        let engine = self.engine.clone();
        run_blocking("register_participant", move || {
            let mut guard = engine.blocking_lock();
            guard.register_participant(id, label, permissions)
        })
        .await
    }

    pub async fn rotate_participant_secret(&self, id: ParticipantId) -> Result<String, MailError> {
        let engine = self.engine.clone();
        run_blocking("rotate_participant_secret", move || {
            let mut guard = engine.blocking_lock();
            guard.rotate_participant_secret(&id)
        })
        .await
    }

    pub async fn deregister_participant(&self, id: ParticipantId) -> Result<(), MailError> {
        let engine = self.engine.clone();
        run_blocking("deregister_participant", move || {
            let mut guard = engine.blocking_lock();
            guard.deregister_participant(&id)
        })
        .await
    }

    pub async fn create_room(&self, id: RoomId) -> Result<(), MailError> {
        let engine = self.engine.clone();
        let now = now_unix_ms();
        run_blocking("create_room", move || {
            let mut guard = engine.blocking_lock();
            guard.create_room(id, now)
        })
        .await
    }

    pub async fn add_room_member(&self, room: RoomId, participant: ParticipantId) -> Result<(), MailError> {
        let engine = self.engine.clone();
        run_blocking("add_room_member", move || {
            let mut guard = engine.blocking_lock();
            guard.add_room_member(&room, participant)
        })
        .await
    }

    pub async fn remove_room_member(&self, room: RoomId, participant: ParticipantId) -> Result<(), MailError> {
        let engine = self.engine.clone();
        run_blocking("remove_room_member", move || {
            let mut guard = engine.blocking_lock();
            guard.remove_room_member(&room, &participant)
        })
        .await
    }
}

/// Runs `f` on a blocking thread and maps a task panic into
/// [`MailError::StoreUnavailable`] -- the same refusal shape a store
/// failure inside `f` already uses, so a caller cannot tell "the blocking
/// task panicked" from "the store returned an error" apart, which is
/// correct: neither is a domain refusal the caller can act on, and the
/// engine's own `store_unavailable` already confines the real detail to
/// the log.
async fn run_blocking<F, T>(operation: &'static str, f: F) -> Result<T, MailError>
where
    F: FnOnce() -> Result<T, MailError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        Err(join_err) => {
            tracing::error!(operation, error = %join_err, "mailbox blocking task panicked");
            Err(MailError::StoreUnavailable { operation: operation.to_string() })
        }
    }
}

/// Mirrors `mail4agent_core::engine`'s own `store_unavailable`: logs the
/// real [`StoreError`] for the operator and returns only the operation
/// name to the caller -- the failure detail never crosses into a
/// caller-visible refusal (`mail4agent/CLAUDE.md`, "Discipline").
fn store_unavailable(operation: &'static str, err: StoreError) -> MailError {
    tracing::error!(operation, error = %err, "mail store operation failed");
    MailError::StoreUnavailable { operation: operation.to_string() }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
