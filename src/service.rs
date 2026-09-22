//! [`MailboxService`] -- the async facade over the synchronous
//! [`MailboxEngine`]. See `mail4agent/CLAUDE.md`, "The engine is
//! synchronous; the daemon is not": every method here is `async` and does
//! its real work inside [`tokio::task::spawn_blocking`], taking the
//! engine's own lock there. A handler has no other way to reach the
//! engine, so it cannot forget the rule -- if a handler needs a new
//! operation, the method belongs here, never a `spawn_blocking` inline in
//! `routes/`.
//!
//! Two handles share one underlying [`mail4agent_store_sqlite::Db`]: `engine` (mutating and
//! authenticating calls, serialised through a [`tokio::sync::Mutex`]) and
//! `reader` (plain [`MailStore`] reads -- `get_participant`,
//! `rooms_containing`, `get_session` -- that [`MailboxEngine`]'s own public
//! surface does not expose: the operator bit the auth layer needs, the room
//! memberships `/mail/whoami` needs, and the session card `/mail/whoami`
//! and `/mail/status` need back). Both are already-public trait methods on
//! a committed crate ([`mail4agent_core::MailStore`], implemented by
//! [`SqliteMailStore`]); this facade reads them directly through a second
//! store handle over the same connection rather than growing
//! `mail4agent-core`'s own API for these reads.
//!
//! This is also where the two async-only features documented in the crate
//! contract's task brief live, precisely because they need tokio and the
//! engine must not:
//!
//! - **A waiting `inbox`** ([`Self::inbox`]/[`Self::inbox_wait`]): a read
//!   that finds nothing parks on a per-account [`tokio::sync::Notify`]
//!   ([`DeliveryNotifier`]) instead of returning empty at once, woken the
//!   moment [`Self::send`] delivers something that account could read.
//!   `mail4agent-core` gains no notion of waiting at all -- the wait is
//!   pure facade state, checked, released and re-checked around the
//!   engine's own synchronous, already-existing `inbox` call.
//! - **A delivery listener** ([`Self::set_listener`]/[`Self::spawn_listener_delivery`]):
//!   fired in the background after [`Self::send`]'s own write has already
//!   committed, never inside it, and never allowed to fail the send that
//!   triggered it.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mail4agent_api::{
    Ack, Address, DeliveryNotification, Directory, InboxPage, MailError, Message, MessageId, ParticipantId, RoomId,
    SendRequest, SendResponse, SessionCard, SessionId, UnreadCount,
};
use mail4agent_core::{MailStore, MailboxEngine, ParticipantPermissions, StoreError};
use mail4agent_store_sqlite::SqliteMailStore;
use tokio::sync::{Mutex as AsyncMutex, Notify};

/// A caller resolved from its bearer secret: everything a handler needs to
/// know about the **account**, from one call to
/// [`MailboxService::authenticate`]. Carries only what a handler actually
/// reads (`id`, `label`, `operator`) -- `may_send`/`may_read` are enforced
/// by the engine itself on every call that cares, so this facade does not
/// duplicate that check by also surfacing the raw flags here.
///
/// This is the account, never the session -- see `crate::identity` for how
/// a `/mail/*` or `/mcp` handler turns this into the caller's own
/// [`Address`] before it ever touches the mail surface.
#[derive(Clone, Debug)]
pub struct AuthenticatedParticipant {
    pub id: ParticipantId,
    pub label: Option<String>,
    pub operator: bool,
}

pub struct MailboxService {
    engine: Arc<AsyncMutex<MailboxEngine<SqliteMailStore>>>,
    reader: Arc<SqliteMailStore>,
    /// Wakes a waiting [`Self::inbox`] call the moment mail arrives for its
    /// account -- see this module's own doc comment.
    delivery: Arc<DeliveryNotifier>,
    /// Fires a registered delivery listener's URL. A short-timeout,
    /// no-retry client built once and cloned per notification (a
    /// [`reqwest::Client`] clone shares its connection pool -- this is not
    /// a fresh client per call).
    listener_http: reqwest::Client,
}

impl MailboxService {
    /// `engine_store` and `reader_store` must be two [`SqliteMailStore`]
    /// handles opened over the SAME underlying [`mail4agent_store_sqlite::Db`] (clones of one
    /// connection -- see [`SqliteMailStore::db`]), so a read through
    /// `reader` always observes what `engine` has already committed.
    pub fn new(engine_store: SqliteMailStore, reader_store: SqliteMailStore) -> Self {
        Self {
            engine: Arc::new(AsyncMutex::new(MailboxEngine::new(engine_store))),
            reader: Arc::new(reader_store),
            delivery: Arc::new(DeliveryNotifier::new()),
            listener_http: listener_http_client(),
        }
    }

    /// Authenticates `token` against the participant registry. This is the
    /// one place a bearer becomes a [`ParticipantId`] (an **account**) on
    /// this facade -- `crate::auth::require_tier` calls it to grant tiers,
    /// and every handler calls it again to learn *which
    /// account* it is talking to, before resolving *which session* of that
    /// account (`crate::identity::resolve_session`). The participant id is
    /// never carried in the granted tiers (a `TokenTier::Scope` is a
    /// capability marker, not a place to smuggle a subject), so re-asking
    /// this same question, one more indexed digest read, is the only way a
    /// handler learns it -- deliberate, not an oversight
    /// (`mail4agent/CLAUDE.md`'s "a sender is never a field the caller
    /// fills in", applied at the HTTP boundary too).
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

    /// Registers a session, or refreshes an already-registered one --
    /// see [`mail4agent_core::MailboxEngine::ensure_session`]. The only way
    /// a session enters the mailbox at all; called from
    /// `crate::identity::resolve_session` on every `/mail/*` and `/mcp`
    /// request, never directly from a route handler.
    pub async fn ensure_session(
        &self,
        account: ParticipantId,
        session_id: SessionId,
        card: SessionCard,
        now_unix_ms: u64,
    ) -> Result<SessionId, MailError> {
        let engine = self.engine.clone();
        run_blocking("ensure_session", move || {
            let mut guard = engine.blocking_lock();
            guard.ensure_session(account, session_id, card, now_unix_ms)
        })
        .await
    }

    /// Sets a session's declared group -- what it is working on, its role,
    /// which session spawned it. The only writer of that group (see
    /// [`mail4agent_core::MailboxEngine::set_declared`]); reached through
    /// `POST /mail/status` / `m4a_mail_status`.
    pub async fn set_declared(
        &self,
        session: SessionId,
        working_on: Option<String>,
        role: Option<String>,
        parent: Option<SessionId>,
    ) -> Result<(), MailError> {
        let engine = self.engine.clone();
        run_blocking("set_declared", move || {
            let mut guard = engine.blocking_lock();
            guard.set_declared(&session, working_on, role, parent)
        })
        .await
    }

    /// The stored card for `session`, or `None` if it has never reached
    /// [`Self::ensure_session`]. Reads through [`MailStore::get_session`]
    /// directly on `reader` -- `/mail/whoami` and `/mail/status` are the
    /// two callers.
    pub async fn session_card(&self, session: SessionId) -> Result<Option<SessionCard>, MailError> {
        let reader = self.reader.clone();
        run_blocking("get_session", move || {
            reader
                .get_session(&session)
                .map(|found| found.map(|record| record.card))
                .map_err(|err| store_unavailable("get_session", err))
        })
        .await
    }

    /// Sends a message, then -- **after** that write has committed, never
    /// inside it -- wakes any waiting [`Self::inbox`] call for every
    /// account this message just became readable to, and fires each such
    /// account's registered delivery listener in the background (see
    /// [`Self::spawn_listener_delivery`]). Neither of those two follow-ups
    /// can turn a successful send into a failure: [`Self::accounts_for`]
    /// degrades to an empty list rather than erroring if a room's own
    /// membership cannot be read, and a listener's own failure is logged
    /// and dropped, never propagated (see that method's own doc comment).
    pub async fn send(&self, sender: Address, request: SendRequest) -> Result<SendResponse, MailError> {
        let engine = self.engine.clone();
        let now = now_unix_ms();
        let to = request.to.clone();
        let from = sender.clone();
        let response = run_blocking("send", move || {
            let mut guard = engine.blocking_lock();
            guard.send(&sender, request, now)
        })
        .await?;

        let accounts = self.accounts_for(&to).await;
        self.delivery.notify_accounts(&accounts);
        for account in accounts {
            self.spawn_listener_delivery(account, to.clone(), from.clone(), response.message_id.clone());
        }

        Ok(response)
    }

    /// Reads a page of `reader_address`'s own inbox. `wait` is `None` for
    /// today's behaviour (answer at once, empty or not); `Some(duration)`
    /// long-polls up to that bound when the page would otherwise be empty
    /// -- see [`Self::inbox_wait`]. The daemon (`routes::mail::inbox_impl`)
    /// is what clamps a caller's requested wait to
    /// [`mail4agent_api::INBOX_WAIT_SECS_MAX`] before it ever reaches here;
    /// this method takes whatever [`Duration`] it is given.
    pub async fn inbox(
        &self,
        reader_address: Address,
        since_unix_ms: u64,
        limit: u16,
        wait: Option<Duration>,
    ) -> Result<InboxPage, MailError> {
        match wait {
            Some(wait) => self.inbox_wait(reader_address, since_unix_ms, limit, wait).await,
            None => self.inbox_once(reader_address, since_unix_ms, limit).await,
        }
    }

    /// Today's behaviour exactly: one engine call, answer immediately
    /// whatever it returns. The building block both [`Self::inbox`]'s
    /// no-wait path and [`Self::inbox_wait`]'s own loop call.
    async fn inbox_once(&self, reader_address: Address, since_unix_ms: u64, limit: u16) -> Result<InboxPage, MailError> {
        let engine = self.engine.clone();
        run_blocking("inbox", move || {
            let guard = engine.blocking_lock();
            guard.inbox(&reader_address, since_unix_ms, limit)
        })
        .await
    }

    /// Long-polls an empty inbox: check, release, wait, re-check -- never
    /// holding the engine's lock while parked, which would stop every other
    /// caller for up to a minute and turn this convenience into an outage.
    /// [`Self::inbox_once`] already acquires and releases the lock only for
    /// the duration of its own blocking read; nothing here holds anything
    /// across the `.await` below.
    ///
    /// A caller with a genuine error (an unknown session, a room address,
    /// ...) gets that error immediately, on the first check -- waiting is
    /// only for "nothing to read yet", never for "the request itself is
    /// bad". Expiry answers an **empty page**, not an error: waiting and
    /// finding nothing is not a refusal.
    async fn inbox_wait(
        &self,
        reader_address: Address,
        since_unix_ms: u64,
        limit: u16,
        wait: Duration,
    ) -> Result<InboxPage, MailError> {
        // `reader_address.account()` is `None` only for a room address,
        // which `MailboxEngine::inbox`'s own identity resolution already
        // refuses before this loop ever sees an `Ok` page below -- so by
        // the time an empty-but-`Ok` page reaches the `None` arm, that
        // arm is unreachable in practice. Kept as a real `Option` match
        // (an immediate return, never a busy loop) rather than an
        // `expect()`, so a future widening of what `inbox` accepts fails
        // safe instead of panicking.
        let notify = reader_address.account().map(|account| self.delivery.notify_for(account));
        let deadline = Instant::now() + wait;

        loop {
            // Subscribe BEFORE checking the store: `tokio::sync::Notify`
            // guarantees a `notify_waiters()` call is observed by any
            // `Notified` future that already existed at the time of that
            // call, even if that future has not been polled yet -- so a
            // `send` landing between this line and the `.await` below is
            // never missed. This is the exact "check, release, wait,
            // re-check" shape the crate contract's task brief requires.
            let notified = notify.as_ref().map(|n| n.notified());
            let page = self.inbox_once(reader_address.clone(), since_unix_ms, limit).await?;
            if !page.messages.is_empty() {
                return Ok(page);
            }
            let Some(notified) = notified else {
                return Ok(page);
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(page);
            }
            // Whether this returns because of a notification or because
            // the timeout elapsed first makes no difference here -- either
            // way the loop re-checks the store next, and the deadline
            // check above is what actually decides when to stop.
            let _ = tokio::time::timeout(remaining, notified).await;
        }
    }

    /// The set of accounts a message addressed to `to` becomes readable to:
    /// the one account a [`Address::Direct`]/[`Address::Session`] names, or
    /// every current member of an [`Address::Room`]. Shared by
    /// [`Self::send`]'s two follow-ups (waking a waiting `inbox`, firing a
    /// registered listener) -- both ultimately ask the same question, "who
    /// just gained something to read".
    async fn accounts_for(&self, to: &Address) -> Vec<ParticipantId> {
        match to {
            Address::Direct { participant } | Address::Session { participant, .. } => vec![participant.clone()],
            Address::Room { room } => self.room_members(room).await,
        }
    }

    /// `room`'s current membership, or an empty list if the read itself
    /// fails -- this is used only to decide who to wake or notify, never to
    /// decide whether a message was delivered (the engine's own `send` has
    /// already done that), so degrading to "notify no one" on a read
    /// failure costs a wake-up or a doorbell, never correctness.
    async fn room_members(&self, room: &RoomId) -> Vec<ParticipantId> {
        let reader = self.reader.clone();
        let room = room.clone();
        run_blocking("get_room", move || {
            reader.get_room(&room).map_err(|err| store_unavailable("get_room", err))
        })
        .await
        .ok()
        .flatten()
        .map(|record| record.members.into_iter().collect())
        .unwrap_or_default()
    }

    /// Registers (`Some`) or removes (`None`, via [`Self::remove_listener`])
    /// the URL the mailbox notifies for `account` -- see
    /// [`mail4agent_core::MailboxEngine::set_listener`], which performs the
    /// actual structural (bounded, loopback-only) validation.
    pub async fn set_listener(&self, account: ParticipantId, url: String) -> Result<(), MailError> {
        let engine = self.engine.clone();
        run_blocking("set_listener", move || {
            let mut guard = engine.blocking_lock();
            guard.set_listener(&account, url)
        })
        .await
    }

    pub async fn remove_listener(&self, account: ParticipantId) -> Result<(), MailError> {
        let engine = self.engine.clone();
        run_blocking("remove_listener", move || {
            let mut guard = engine.blocking_lock();
            guard.remove_listener(&account)
        })
        .await
    }

    /// Fires `account`'s registered delivery listener, if it has one,
    /// entirely in the background: spawned as its own task so it never adds
    /// its own latency (let alone its own failure) to the [`Self::send`]
    /// call that triggered it. A listener that is down, refuses the
    /// request, or times out is logged and otherwise ignored -- this is the
    /// same rule the harness's own run-finish summary mail already applies
    /// to a foreign endpoint it does not control. No retry: see
    /// [`listener_http_client`]'s own doc comment on why that is
    /// deliberate, not an oversight.
    fn spawn_listener_delivery(&self, account: ParticipantId, to: Address, from: Address, message_id: MessageId) {
        let reader = self.reader.clone();
        let http = self.listener_http.clone();
        tokio::spawn(async move {
            let lookup = account.clone();
            let listener_url = match tokio::task::spawn_blocking(move || reader.get_participant(&lookup)).await {
                Ok(Ok(Some(record))) => record.listener_url,
                Ok(Ok(None)) => None,
                Ok(Err(err)) => {
                    tracing::warn!(%account, error = %err, "delivery listener lookup failed; skipping notification");
                    None
                }
                Err(join_err) => {
                    tracing::warn!(%account, error = %join_err, "delivery listener lookup task panicked; skipping notification");
                    None
                }
            };
            let Some(url) = listener_url else { return };

            let notification = DeliveryNotification { account, to, message_id, from };
            match http.post(&url).json(&notification).send().await {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => {
                    tracing::warn!(%url, status = %response.status(), "delivery listener responded with a non-success status");
                }
                Err(err) => {
                    tracing::warn!(%url, error = %err, "delivery listener notification failed");
                }
            }
        });
    }

    pub async fn ack(&self, reader_address: Address, message_id: MessageId) -> Result<Ack, MailError> {
        let engine = self.engine.clone();
        let now = now_unix_ms();
        run_blocking("ack", move || {
            let mut guard = engine.blocking_lock();
            guard.ack(&reader_address, &message_id, now)
        })
        .await
    }

    pub async fn message_get(&self, reader_address: Address, message_id: MessageId) -> Result<Message, MailError> {
        let engine = self.engine.clone();
        run_blocking("message_get", move || {
            let guard = engine.blocking_lock();
            guard.message_get(&reader_address, &message_id)
        })
        .await
    }

    pub async fn unread_count_of(&self, caller: Address, target: Address) -> Result<UnreadCount, MailError> {
        let engine = self.engine.clone();
        run_blocking("unread_count_of", move || {
            let guard = engine.blocking_lock();
            guard.unread_count_of(&caller, &target)
        })
        .await
    }

    /// The mailbox's own directory: every registered account (with its
    /// live sessions nested under it) and every room, from `caller`'s point
    /// of view (see [`mail4agent_core::MailboxEngine::directory`]).
    /// `mail4agent_attest::is_alive` is the liveness check the engine asks
    /// for -- `mail4agent-core` learns nothing about processes itself, and
    /// this facade is exactly the boundary where that fact gets supplied.
    pub async fn directory(&self, caller: Address) -> Result<Directory, MailError> {
        let engine = self.engine.clone();
        run_blocking("directory", move || {
            let guard = engine.blocking_lock();
            guard.directory(&caller, &mail4agent_attest::is_alive)
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

/// Wakes a long-polling [`MailboxService::inbox`] call the moment mail
/// arrives for its account. One [`tokio::sync::Notify`] per account,
/// created lazily the first time anything waits for that account and
/// reused after that -- `mail4agent-core` itself carries no notion of
/// waiting at all (see this module's own doc comment); this is purely a
/// wake-up signal layered outside it, never a second source of truth for
/// what mail exists. A spurious wake (mail landing for a sibling session of
/// the same account, or a send that deduplicated and created nothing)
/// merely costs the waiting caller one extra store read before it goes
/// back to waiting -- see [`MailboxService::inbox_wait`].
struct DeliveryNotifier {
    per_account: std::sync::Mutex<HashMap<ParticipantId, Arc<Notify>>>,
}

impl DeliveryNotifier {
    fn new() -> Self {
        Self { per_account: std::sync::Mutex::new(HashMap::new()) }
    }

    /// Returns the shared [`Notify`] for `account`, creating it on first
    /// use. The lock here is held only long enough to get-or-insert the
    /// entry -- **never across an `.await`** -- which is exactly the
    /// discipline that keeps a waiting reader from ever blocking a
    /// concurrent caller: holding this lock for up to a minute would turn
    /// this convenience into an outage.
    fn notify_for(&self, account: &ParticipantId) -> Arc<Notify> {
        let mut guard = match self.per_account.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.entry(account.clone()).or_insert_with(|| Arc::new(Notify::new())).clone()
    }

    /// Wakes every currently-waiting caller for each of `accounts` that has
    /// ever been waited on. An account nobody has ever called a waiting
    /// `inbox` for has no entry at all -- this never creates one, so
    /// sending mail to an account that has never long-polled costs nothing
    /// here beyond one map lookup.
    fn notify_accounts(&self, accounts: &[ParticipantId]) {
        let guard = match self.per_account.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        for account in accounts {
            if let Some(notify) = guard.get(account) {
                notify.notify_waiters();
            }
        }
    }
}

/// Short connect and request timeouts, no retries. This is a best-effort
/// doorbell, not a delivery guarantee: retry and backoff are deliberately
/// not implemented in this version -- adding them later only tightens the
/// guarantee this client offers, it does not change the notification's
/// wire shape or require anything already registered to change.
const LISTENER_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const LISTENER_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Builds the shared client [`MailboxService::spawn_listener_delivery`]
/// fires every notification through. Falls back to an unbounded default
/// client (logged, never a panic) on the practically-unreachable case that
/// building one with these two timeouts itself fails.
fn listener_http_client() -> reqwest::Client {
    match reqwest::Client::builder().connect_timeout(LISTENER_CONNECT_TIMEOUT).timeout(LISTENER_REQUEST_TIMEOUT).build()
    {
        Ok(client) => client,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to build the delivery-listener HTTP client with its configured timeouts; \
                 falling back to an unbounded default client"
            );
            reqwest::Client::new()
        }
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

/// The current wall clock, in milliseconds since the Unix epoch. `pub(crate)`
/// so `crate::identity::resolve_session` -- which needs "now" for
/// `MailboxService::ensure_session` the same way every mutating method
/// here does -- reads it from this one place rather than duplicating
/// `SystemTime::now()` handling.
pub(crate) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_service() -> MailboxService {
        let engine_store = SqliteMailStore::open_in_memory().expect("in-memory store opens and migrates");
        let reader_store = SqliteMailStore::new(engine_store.db());
        MailboxService::new(engine_store, reader_store)
    }

    async fn register(service: &MailboxService, name: &str) -> ParticipantId {
        let id = ParticipantId::new(name).expect("valid participant id");
        let permissions = ParticipantPermissions { may_send: true, may_read: true, operator: false };
        service.register_participant(id.clone(), None, permissions).await.expect("register test participant");
        id
    }

    fn direct(id: &ParticipantId) -> Address {
        Address::Direct { participant: id.clone() }
    }

    fn send_request(to: Address, subject: &str, body: &str) -> SendRequest {
        SendRequest {
            to,
            subject: subject.to_string(),
            body: body.to_string(),
            reply_to: None,
            correlation: None,
            refs: Vec::new(),
            idempotency_key: None,
        }
    }

    // ------------------------------------------------------------------
    // Feature 1 -- the waiting inbox
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn waiting_inbox_returns_promptly_when_mail_arrives_while_waiting() {
        let service = Arc::new(test_service().await);
        let alice = register(&service, "alice").await;
        let alice_address = direct(&alice);

        let waiter = {
            let service = service.clone();
            let alice_address = alice_address.clone();
            tokio::spawn(async move { service.inbox(alice_address, 0, 50, Some(Duration::from_secs(10))).await })
        };
        // Give the spawned waiter a moment to actually reach its own
        // `notified.await` before the message lands -- not required for
        // correctness (see `MailboxService::inbox_wait`'s own doc comment
        // on why the ordering is race-safe either way), but this is what
        // makes the test exercise the "arrives while waiting" path rather
        // than "was already there on the first check".
        tokio::time::sleep(Duration::from_millis(100)).await;

        service.send(alice_address.clone(), send_request(alice_address.clone(), "hi", "hi")).await.expect("send succeeds");

        let started = Instant::now();
        let page = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("the waiter must return well before its own 10s cap once notified")
            .expect("waiter task did not panic")
            .expect("inbox call succeeds");
        assert_eq!(page.messages.len(), 1);
        assert!(started.elapsed() < Duration::from_secs(5), "must be woken, not merely time out");
    }

    #[tokio::test]
    async fn waiting_inbox_answers_an_empty_page_on_expiry_not_an_error() {
        let service = test_service().await;
        let alice = register(&service, "alice").await;

        let page = service
            .inbox(direct(&alice), 0, 50, Some(Duration::from_millis(150)))
            .await
            .expect("a wait that expires with nothing to read is Ok, not Err");
        assert!(page.messages.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_waiting_read_does_not_block_a_concurrent_send_or_another_callers_read() {
        let service = Arc::new(test_service().await);
        let alice = register(&service, "alice").await;
        let bob = register(&service, "bob").await;
        let alice_address = direct(&alice);
        let bob_address = direct(&bob);

        // Alice waits on an empty inbox for up to 10s -- if a waiting read
        // held the engine's own lock for that whole window (rather than
        // releasing it while parked), everything below would stall for it.
        let waiter = {
            let service = service.clone();
            let alice_address = alice_address.clone();
            tokio::spawn(async move { service.inbox(alice_address, 0, 50, Some(Duration::from_secs(10))).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;

        let started = Instant::now();
        service.send(bob_address.clone(), send_request(bob_address.clone(), "hi", "hi")).await.expect("bob's send succeeds");
        let bob_page = service.inbox(bob_address.clone(), 0, 50, None).await.expect("bob's own read succeeds");
        assert_eq!(bob_page.messages.len(), 1);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "a concurrent send and read must not be stalled by alice's still-open wait (took {:?})",
            started.elapsed()
        );

        // Wake alice's own wait so nothing is left dangling past this test.
        service.send(alice_address.clone(), send_request(alice_address.clone(), "hi", "hi")).await.expect("alice's send succeeds");
        let alice_page = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("alice's waiter must return promptly once notified")
            .expect("waiter task did not panic")
            .expect("alice's waiting inbox call succeeds");
        assert_eq!(alice_page.messages.len(), 1);
    }

    // ------------------------------------------------------------------
    // Feature 2 -- the delivery listener
    // ------------------------------------------------------------------

    /// A real local HTTP server (not a mock trait) bound to an ephemeral
    /// loopback port, so `MailboxService::spawn_listener_delivery`'s actual
    /// HTTP path is exercised end to end. Returns the URL to register plus
    /// a channel that yields each notification body it receives.
    async fn start_test_listener() -> (String, tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let app = axum::Router::new().route(
            "/notify",
            axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(body);
                    axum::http::StatusCode::OK
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().expect("bound listener has a local address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://127.0.0.1:{}/notify", addr.port()), rx)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_registered_listener_receives_ids_but_never_subject_or_body() {
        let service = test_service().await;
        let alice = register(&service, "alice").await;

        let (listener_url, mut received) = start_test_listener().await;
        service.set_listener(alice.clone(), listener_url).await.expect("set_listener succeeds");

        let response = service
            .send(direct(&alice), send_request(direct(&alice), "SECRET SUBJECT", "SECRET BODY"))
            .await
            .expect("send succeeds");

        let body = tokio::time::timeout(Duration::from_secs(2), received.recv())
            .await
            .expect("the listener must be notified within the bound")
            .expect("the notification channel was not closed");

        assert_eq!(body["account"], serde_json::json!("alice"));
        assert_eq!(body["message_id"], serde_json::json!(response.message_id.as_str()));
        assert!(body.get("subject").is_none(), "notification must never carry a subject field: {body}");
        assert!(body.get("body").is_none(), "notification must never carry a body field: {body}");
        let raw = body.to_string();
        assert!(!raw.contains("SECRET"), "notification leaked message content: {raw}");
    }

    #[tokio::test]
    async fn a_failing_listener_does_not_fail_the_send() {
        let service = test_service().await;
        let alice = register(&service, "alice").await;

        // A loopback port bound and then immediately released -- nobody is
        // listening on it by the time the send fires, the shape a down
        // listener actually takes.
        let dead_port = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind an ephemeral loopback port");
            listener.local_addr().expect("bound listener has a local address").port()
        };
        let dead_listener_url = format!("http://127.0.0.1:{dead_port}/nobody-home");
        service.set_listener(alice.clone(), dead_listener_url).await.expect("set_listener succeeds");

        service
            .send(direct(&alice), send_request(direct(&alice), "hi", "hi"))
            .await
            .expect("send succeeds even though the registered listener is unreachable");
    }

    #[tokio::test]
    async fn a_non_loopback_listener_url_is_refused_by_name() {
        let service = test_service().await;
        let alice = register(&service, "alice").await;

        let err = service
            .set_listener(alice, "http://example.com/hook".to_string())
            .await
            .expect_err("a non-loopback url must be refused");
        assert!(matches!(err, MailError::Malformed { field, .. } if field == "url"));
    }
}
