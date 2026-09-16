//! The mailbox engine: authentication, the participant/room registry, and
//! the four mail operations (send, inbox, ack, message lookup) laid over a
//! [`crate::MailStore`].

use mail4agent_api::{
    Ack, Address, InboxPage, MailError, Message, MessageId, Participant, ParticipantId, RoomId,
    SendRequest, SendResponse, UnreadCount, MESSAGE_ID_HEX_LEN, MESSAGE_ID_PREFIX,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::store::{InsertMessageOutcome, MailStore, ParticipantRecord, SecretDigest, StoreError};

/// Length, in lower-hex characters, of a freshly generated participant
/// secret: 32 random bytes (256 bits of entropy) rendered as hex. See
/// `MailboxEngine::authenticate` for why that much entropy is exactly what
/// makes an exact-digest lookup safe.
pub const SECRET_HEX_LEN: usize = 64;

/// What a newly registered (or re-permissioned) participant may do.
/// Distinct from [`ParticipantRecord`]: this is the caller-facing shape a
/// registration call takes, without the label or the secret digest, which
/// the engine derives itself.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ParticipantPermissions {
    pub may_send: bool,
    pub may_read: bool,
    pub operator: bool,
}

/// The mailbox engine. Generic over its [`MailStore`] so the same logic
/// runs against [`crate::InMemoryStore`] in tests and, later, a persistent
/// store -- neither of which this crate needs to know about here.
pub struct MailboxEngine<S> {
    store: S,
}

impl<S: MailStore> MailboxEngine<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Authenticates a presented secret and derives the caller's identity
    /// from the match -- **never** from anything the caller states. This is
    /// the one place a [`ParticipantId`] is allowed to enter the engine from
    /// outside; every other method takes an already-authenticated id as an
    /// argument (see `mail4agent/CLAUDE.md`'s "a sender is never a field the
    /// caller fills in").
    ///
    /// Participants are indexed by the SHA-256 digest of their secret and
    /// looked up by that exact digest, not scanned. That lookup is safe to
    /// do by direct index rather than in constant time because the secret
    /// is 32 random bytes: 256 bits of entropy an attacker cannot already
    /// be close to guessing, so nothing the lookup structure's timing could
    /// reveal (which bucket, how many probes) narrows the search in any
    /// useful way. The digest found is then confirmed against the presented
    /// one with a constant-time compare (`subtle`) before being trusted --
    /// redundant with an exact map lookup by construction, but it costs
    /// nothing and removes any dependency on the map's own equality/hashing
    /// behaviour for the actual authentication decision.
    pub fn authenticate(&self, presented_secret: &str) -> Result<ParticipantId, MailError> {
        let digest = sha256_digest(presented_secret.as_bytes());
        let found = self
            .store
            .find_participant_by_digest(&digest)
            .map_err(|err| store_unavailable("find_participant_by_digest", err))?;
        let Some((id, record)) = found else {
            return Err(MailError::PermissionDenied { need: "mail:authenticate".to_string() });
        };
        if bool::from(record.secret_digest.ct_eq(&digest)) {
            Ok(id)
        } else {
            Err(MailError::PermissionDenied { need: "mail:authenticate".to_string() })
        }
    }

    /// Registers a new participant and returns its secret. The secret is
    /// generated here, handed back **once**, and never stored -- only its
    /// digest is kept, in [`ParticipantRecord::secret_digest`].
    pub fn register_participant(
        &mut self,
        id: ParticipantId,
        label: Option<String>,
        permissions: ParticipantPermissions,
    ) -> Result<String, MailError> {
        Participant { id: id.clone(), label: label.clone() }.validate()?;
        let existing = self.store.get_participant(&id).map_err(|err| store_unavailable("get_participant", err))?;
        if existing.is_some() {
            return Err(MailError::Malformed {
                field: "participant".to_string(),
                reason: format!("participant \"{id}\" is already registered"),
            });
        }
        let secret = generate_secret();
        let record = ParticipantRecord {
            label,
            secret_digest: sha256_digest(secret.as_bytes()),
            may_send: permissions.may_send,
            may_read: permissions.may_read,
            operator: permissions.operator,
        };
        self.store.register_participant(id, record).map_err(|err| store_unavailable("register_participant", err))?;
        Ok(secret)
    }

    /// Removes a participant's registration. Its secret stops authenticating
    /// immediately; stale entries in a room's member set naming this id are
    /// inert (see [`MailStore::deregister_participant`]'s doc comment).
    pub fn deregister_participant(&mut self, id: &ParticipantId) -> Result<(), MailError> {
        self.require_participant(id)?;
        self.store.deregister_participant(id).map_err(|err| store_unavailable("deregister_participant", err))
    }

    /// Issues a fresh secret for an existing participant, invalidating the
    /// old one. Shares its mechanism with [`Self::revoke_participant_secret`]
    /// -- revoking is rotating and discarding the new secret rather than
    /// returning it.
    pub fn rotate_participant_secret(&mut self, id: &ParticipantId) -> Result<String, MailError> {
        self.require_participant(id)?;
        let secret = generate_secret();
        self.store
            .set_participant_secret_digest(id, sha256_digest(secret.as_bytes()))
            .map_err(|err| store_unavailable("set_participant_secret_digest", err))?;
        Ok(secret)
    }

    /// Invalidates a participant's current secret without issuing a new
    /// one usable by anyone: it is replaced by the digest of a fresh secret
    /// that is generated and immediately discarded, so no plaintext maps to
    /// it. The participant must call [`Self::rotate_participant_secret`] (or
    /// be re-registered) to authenticate again.
    pub fn revoke_participant_secret(&mut self, id: &ParticipantId) -> Result<(), MailError> {
        self.rotate_participant_secret(id).map(|_secret| ())
    }

    /// Creates a room with no members. `now_unix_ms` is threaded through by
    /// the caller (not read from a clock here) so the engine stays a pure
    /// function of its inputs -- the same discipline [`Self::send`] and
    /// [`Self::ack`] follow.
    pub fn create_room(&mut self, id: RoomId, now_unix_ms: u64) -> Result<(), MailError> {
        let existing = self.store.get_room(&id).map_err(|err| store_unavailable("get_room", err))?;
        if existing.is_some() {
            return Err(MailError::Malformed {
                field: "room".to_string(),
                reason: format!("room \"{id}\" already exists"),
            });
        }
        self.store.create_room(id, now_unix_ms).map_err(|err| store_unavailable("create_room", err))
    }

    /// Adds `participant` to `room`. Idempotent: adding an existing member
    /// is not an error.
    pub fn add_room_member(&mut self, room: &RoomId, participant: ParticipantId) -> Result<(), MailError> {
        let room_record = self.store.get_room(room).map_err(|err| store_unavailable("get_room", err))?;
        if room_record.is_none() {
            return Err(MailError::UnknownRoom { room: room.clone() });
        }
        let participant_record =
            self.store.get_participant(&participant).map_err(|err| store_unavailable("get_participant", err))?;
        if participant_record.is_none() {
            return Err(MailError::UnknownParticipant { participant });
        }
        self.store.add_room_member(room, participant).map_err(|err| store_unavailable("add_room_member", err))
    }

    /// Removes `participant` from `room`. Idempotent: removing a
    /// non-member is not an error. Readability of a room is present-tense
    /// (see [`Self::is_readable`]): once removed, the participant's next
    /// [`Self::inbox`] call shows none of that room's mail at all, past or
    /// future -- there is no partial history left behind for a former
    /// member.
    pub fn remove_room_member(&mut self, room: &RoomId, participant: &ParticipantId) -> Result<(), MailError> {
        let room_record = self.store.get_room(room).map_err(|err| store_unavailable("get_room", err))?;
        if room_record.is_none() {
            return Err(MailError::UnknownRoom { room: room.clone() });
        }
        self.store.remove_room_member(room, participant).map_err(|err| store_unavailable("remove_room_member", err))
    }

    /// Sends a message. `sender` must already be the id [`Self::authenticate`]
    /// returned for the presented credential -- **never** a field read out
    /// of `request`; [`SendRequest`] has no `from`, and must never grow one
    /// (`mail4agent/CLAUDE.md`).
    ///
    /// **Sending to a room never requires membership; reading one does.**
    /// This mirrors the mailbox being ported: anyone could write to a task
    /// forum, but only those who could see the task could read it (see
    /// `mailbox-service-extraction-and-signed-session-identity-2026-09-16.md`
    /// §5b). It is a deliberate parity choice, not an oversight, and it is
    /// worth revisiting once this crate has its own callers: a mailbox that
    /// lets any registered participant write into a room it cannot itself
    /// read is a wider write surface than most groupware would choose.
    ///
    /// A message's id is derived from its content and, when present, from
    /// [`SendRequest::idempotency_key`] (see [`derive_message_id`]); a
    /// repeat send carrying the same key from the same sender returns the
    /// original [`SendResponse`] and creates nothing, checked and recorded
    /// atomically by [`MailStore::insert_message`]. Without a key, a repeat
    /// send is a second message -- correct, because sending the same text
    /// twice on purpose should produce two messages.
    pub fn send(&mut self, sender: &ParticipantId, request: SendRequest, now_unix_ms: u64) -> Result<SendResponse, MailError> {
        request.validate()?;
        let sender_record = self.require_participant(sender)?;
        if !sender_record.may_send {
            return Err(MailError::PermissionDenied { need: "mail:send".to_string() });
        }
        match &request.to {
            Address::Direct { participant } => {
                let exists =
                    self.store.get_participant(participant).map_err(|err| store_unavailable("get_participant", err))?;
                if exists.is_none() {
                    return Err(MailError::UnknownParticipant { participant: participant.clone() });
                }
            }
            Address::Room { room } => {
                let exists = self.store.get_room(room).map_err(|err| store_unavailable("get_room", err))?;
                if exists.is_none() {
                    return Err(MailError::UnknownRoom { room: room.clone() });
                }
            }
        }

        let idempotency = request.idempotency_key.clone().map(|key| (sender.clone(), key));
        let message_id = derive_message_id(sender, &request, now_unix_ms);
        let message = Message {
            message_id: message_id.clone(),
            from: sender.clone(),
            to: request.to,
            subject: request.subject,
            body: request.body,
            reply_to: request.reply_to,
            correlation: request.correlation,
            refs: request.refs,
            created_at_unix_ms: now_unix_ms,
        };
        message.validate()?;

        let outcome =
            self.store.insert_message(message, idempotency).map_err(|err| store_unavailable("insert_message", err))?;
        let message_id = match outcome {
            InsertMessageOutcome::Inserted => message_id,
            InsertMessageOutcome::Deduplicated { message_id } => message_id,
        };
        Ok(SendResponse { message_id, from: sender.clone() })
    }

    /// Returns a page of `reader`'s **own** inbox: messages addressed
    /// directly to `reader`, plus messages to any room `reader` is
    /// *currently* a member of (membership is evaluated now, not at send
    /// time), no older than `since_unix_ms`, ordered by `created_at_unix_ms`
    /// then `message_id`, truncated to `limit`. `unread` counts every
    /// currently-readable message with no ack on file for `reader`,
    /// independent of `since` and `limit`.
    ///
    /// **This never widens for an operator.** "An operator may read any
    /// address" means any address it *names*, one at a time -- see
    /// [`Self::inbox_of`], the door through which an operator reaches
    /// someone else's inbox. An operator calling this method sees only its
    /// own mail, exactly like anyone else.
    pub fn inbox(&self, reader: &ParticipantId, since_unix_ms: u64, limit: u16) -> Result<InboxPage, MailError> {
        let record = self.require_participant(reader)?;
        self.require_read_permission(&record)?;
        self.build_inbox(reader, since_unix_ms, limit)
    }

    /// Returns `target`'s inbox by exactly [`Self::inbox`]'s own rule --
    /// never widened, regardless of who is asking. Requires
    /// `caller.operator` or `caller == target`; refuses
    /// `PermissionDenied { need: "mail:operator" }` otherwise.
    ///
    /// This is the operator door onto a *named* address, one at a time --
    /// not a firehose over the whole mailbox. When `caller == target` this
    /// is exactly [`Self::inbox`] under another name (and still requires
    /// `target`'s own `may_read`); when an operator names someone else,
    /// the target's own `may_read` is not consulted, because the
    /// authorization has already been established by the operator bit.
    pub fn inbox_of(
        &self,
        caller: &ParticipantId,
        target: &ParticipantId,
        since_unix_ms: u64,
        limit: u16,
    ) -> Result<InboxPage, MailError> {
        let caller_record = self.require_participant(caller)?;
        if caller != target && !caller_record.operator {
            return Err(MailError::PermissionDenied { need: "mail:operator".to_string() });
        }
        if caller == target {
            self.require_read_permission(&caller_record)?;
        } else {
            self.require_participant(target)?;
        }
        self.build_inbox(target, since_unix_ms, limit)
    }

    /// Records `reader`'s acknowledgement of `message_id`. Refuses
    /// `NotAddressedToYou` unless `reader` may read the message (see
    /// [`Self::is_readable`], which keeps its operator override: a named
    /// single message is a different thing from a bulk inbox listing).
    /// Idempotent on `(message_id, reader)`: a second ack of the same
    /// message by the same reader returns the first ack unchanged rather
    /// than overwriting its timestamp.
    ///
    /// `now_unix_ms` is threaded through by the caller for the same reason
    /// [`Self::send`] takes it: the engine reads no clock of its own.
    pub fn ack(&mut self, reader: &ParticipantId, message_id: &MessageId, now_unix_ms: u64) -> Result<Ack, MailError> {
        let record = self.require_participant(reader)?;
        self.require_read_permission(&record)?;
        let message = self
            .store
            .get_message(message_id)
            .map_err(|err| store_unavailable("get_message", err))?
            .ok_or_else(|| MailError::UnknownMessage { message_id: message_id.clone() })?;
        if !self.is_readable(&message, reader, &record)? {
            return Err(MailError::NotAddressedToYou { message_id: message_id.clone() });
        }
        let ack = Ack { message_id: message_id.clone(), reader: reader.clone(), acked_at_unix_ms: now_unix_ms };
        ack.validate()?;
        self.store.record_ack(ack).map_err(|err| store_unavailable("record_ack", err))
    }

    /// Fetches one message by id. Refuses `UnknownMessage` if no such
    /// message exists, `NotAddressedToYou` if it exists but `reader` may
    /// not read it (see [`Self::is_readable`], which keeps its operator
    /// override for the same reason [`Self::ack`] does).
    pub fn message_get(&self, reader: &ParticipantId, message_id: &MessageId) -> Result<Message, MailError> {
        let record = self.require_participant(reader)?;
        self.require_read_permission(&record)?;
        let message = self
            .store
            .get_message(message_id)
            .map_err(|err| store_unavailable("get_message", err))?
            .ok_or_else(|| MailError::UnknownMessage { message_id: message_id.clone() })?;
        if !self.is_readable(&message, reader, &record)? {
            return Err(MailError::NotAddressedToYou { message_id: message_id.clone() });
        }
        Ok(message)
    }

    /// Returns how many currently-readable messages `target` has not yet
    /// acked -- the same figure [`InboxPage::unread`] carries for the same
    /// participant. Requires `caller.operator` or `caller == target`, the
    /// same authorization [`Self::inbox_of`] uses, enforced here rather
    /// than left to a wire layer that could forget it.
    pub fn unread_count_of(&self, caller: &ParticipantId, target: &ParticipantId) -> Result<UnreadCount, MailError> {
        let caller_record = self.require_participant(caller)?;
        if caller != target && !caller_record.operator {
            return Err(MailError::PermissionDenied { need: "mail:operator".to_string() });
        }
        if caller == target {
            self.require_read_permission(&caller_record)?;
        } else {
            self.require_participant(target)?;
        }
        let unread = self.count_unread(target)?;
        Ok(UnreadCount { participant: target.clone(), unread })
    }

    fn require_participant(&self, id: &ParticipantId) -> Result<ParticipantRecord, MailError> {
        self.store
            .get_participant(id)
            .map_err(|err| store_unavailable("get_participant", err))?
            .ok_or_else(|| MailError::UnknownParticipant { participant: id.clone() })
    }

    fn require_read_permission(&self, record: &ParticipantRecord) -> Result<(), MailError> {
        if record.may_read || record.operator {
            Ok(())
        } else {
            Err(MailError::PermissionDenied { need: "mail:read".to_string() })
        }
    }

    /// Whether `reader` may read `message`: always true for an operator
    /// (`record.operator`, "an operator may read any *named* address");
    /// otherwise true only if `message` is addressed directly to `reader`,
    /// or to a room `reader` is currently a member of. Used only by
    /// [`Self::ack`] and [`Self::message_get`], which each already name one
    /// specific message -- unlike [`Self::inbox`]/[`Self::inbox_of`], which
    /// never let an operator bit widen a bulk listing.
    fn is_readable(&self, message: &Message, reader: &ParticipantId, record: &ParticipantRecord) -> Result<bool, MailError> {
        if record.operator {
            return Ok(true);
        }
        match &message.to {
            Address::Direct { participant } => Ok(participant == reader),
            Address::Room { room } => {
                let room_record = self.store.get_room(room).map_err(|err| store_unavailable("get_room", err))?;
                Ok(room_record.is_some_and(|room_record| room_record.members.contains(reader)))
            }
        }
    }

    /// `participant`'s own readable messages, no older than `since_unix_ms`:
    /// direct mail plus mail to rooms currently joined. Never widened by an
    /// operator bit -- that authorization question is answered by
    /// [`Self::inbox_of`]'s caller/target check before this runs, not by
    /// this function reading more than `participant`'s own mail.
    fn own_messages(&self, participant: &ParticipantId, since_unix_ms: u64) -> Result<Vec<Message>, MailError> {
        let mut messages = self
            .store
            .direct_messages_since(participant, since_unix_ms)
            .map_err(|err| store_unavailable("direct_messages_since", err))?;
        let rooms =
            self.store.rooms_containing(participant).map_err(|err| store_unavailable("rooms_containing", err))?;
        for room in rooms {
            let room_messages = self
                .store
                .room_messages_since(&room, since_unix_ms)
                .map_err(|err| store_unavailable("room_messages_since", err))?;
            messages.extend(room_messages);
        }
        Ok(messages)
    }

    fn build_inbox(&self, participant: &ParticipantId, since_unix_ms: u64, limit: u16) -> Result<InboxPage, MailError> {
        let mut messages = self.own_messages(participant, since_unix_ms)?;
        messages.sort_by(|a, b| a.created_at_unix_ms.cmp(&b.created_at_unix_ms).then_with(|| a.message_id.cmp(&b.message_id)));
        messages.truncate(usize::from(limit));
        let unread = self.count_unread(participant)?;
        Ok(InboxPage { messages, unread })
    }

    fn count_unread(&self, participant: &ParticipantId) -> Result<u32, MailError> {
        let messages = self.own_messages(participant, 0)?;
        let mut unread = 0u32;
        for message in messages {
            let ack = self
                .store
                .get_ack(&message.message_id, participant)
                .map_err(|err| store_unavailable("get_ack", err))?;
            if ack.is_none() {
                unread += 1;
            }
        }
        Ok(unread)
    }
}

/// Maps a [`StoreError`] into [`MailError::StoreUnavailable`], naming only
/// `operation`. The [`StoreError`] itself -- the actual filesystem message,
/// lock state, or corruption detail -- is logged here via `tracing::error!`
/// for the operator and goes no further: nothing about *why* the store
/// failed crosses into a caller-visible refusal.
fn store_unavailable(operation: &'static str, err: StoreError) -> MailError {
    tracing::error!(operation, error = %err, "mail store operation failed");
    MailError::StoreUnavailable { operation: operation.to_string() }
}

fn generate_secret() -> String {
    let mut bytes = [0u8; SECRET_HEX_LEN / 2];
    getrandom::getrandom(&mut bytes).expect("OS random source unavailable: cannot mint a participant secret without it");
    hex::encode(bytes)
}

fn sha256_digest(data: &[u8]) -> SecretDigest {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hasher.finalize());
    digest
}

/// Derives a [`MessageId`] from a send's content and, when present, its
/// idempotency key -- the "derivation" half of "derivation plus an explicit
/// idempotency key" that replaces the operation ledger the ported mailbox
/// shared with task mutations
/// (`mailbox-service-extraction-and-signed-session-identity-2026-09-16.md`).
///
/// When [`SendRequest::idempotency_key`] is `Some`, the hash input is fully
/// determined by `(sender, request, now_unix_ms, key)`. When it is `None`,
/// this mixes in 16 fresh random bytes: without them, two deliberately
/// identical sends (no key -- by design a second message, see
/// [`SendRequest::idempotency_key`]) would derive the same id and collide.
/// This is the one place derivation is not pure content-hashing, and it is
/// harmless to correctness either way: whether a send is stored is decided
/// by [`MailStore::insert_message`]'s own idempotency check, never by
/// whether two derived ids happen to match.
fn derive_message_id(sender: &ParticipantId, request: &SendRequest, now_unix_ms: u64) -> MessageId {
    let mut hasher = Sha256::new();
    hasher.update(sender.as_str().as_bytes());
    hasher.update([0u8]);
    match &request.to {
        Address::Direct { participant } => {
            hasher.update(b"direct:");
            hasher.update(participant.as_str().as_bytes());
        }
        Address::Room { room } => {
            hasher.update(b"room:");
            hasher.update(room.as_str().as_bytes());
        }
    }
    hasher.update([0u8]);
    hasher.update(request.subject.as_bytes());
    hasher.update([0u8]);
    hasher.update(request.body.as_bytes());
    hasher.update([0u8]);
    if let Some(reply_to) = &request.reply_to {
        hasher.update(reply_to.as_str().as_bytes());
    }
    hasher.update([0u8]);
    if let Some(correlation) = &request.correlation {
        hasher.update(correlation.as_bytes());
    }
    hasher.update([0u8]);
    for reference in &request.refs {
        hasher.update(reference.kind.as_bytes());
        hasher.update([0u8]);
        hasher.update(reference.locator.as_bytes());
        hasher.update([0u8]);
        if let Some(digest) = &reference.digest {
            hasher.update(digest.as_bytes());
        }
        hasher.update([0u8]);
    }
    hasher.update(now_unix_ms.to_le_bytes());
    hasher.update([0u8]);
    match &request.idempotency_key {
        Some(key) => hasher.update(key.as_bytes()),
        None => {
            let mut nonce = [0u8; 16];
            getrandom::getrandom(&mut nonce).expect("OS random source unavailable: cannot mint a message id without it");
            hasher.update(nonce);
        }
    }
    let digest = hasher.finalize();
    let hex_digest = hex::encode(digest);
    let body = &hex_digest[..MESSAGE_ID_HEX_LEN];
    MessageId::new(format!("{MESSAGE_ID_PREFIX}{body}")).expect("derived message id always matches MessageId's own shape")
}
