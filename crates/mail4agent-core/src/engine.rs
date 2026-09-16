//! The mailbox engine: authentication, the participant/room/session
//! registry, and the mail operations (send, inbox, ack, message lookup)
//! laid over a [`crate::MailStore`].

use mail4agent_api::{
    Ack, Address, Directory, DirectoryEntry, InboxPage, MailError, Message, MessageId, Participant,
    ParticipantId, RoomEntry, RoomId, SendRequest, SendResponse, SessionCard, SessionEntry, SessionId,
    UnreadCount, MESSAGE_ID_HEX_LEN, MESSAGE_ID_PREFIX,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::store::{InsertMessageOutcome, MailStore, ParticipantRecord, SecretDigest, SessionRecord, StoreError};

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

/// A liveness check the engine is *given*, never one it performs itself:
/// `mail4agent-core` learns nothing about processes or Windows (see
/// `mail4agent-attest`, which lives outside this crate entirely and is
/// exactly the shape this closure expects -- `mail4agent_attest::is_alive`
/// coerces to it directly). Takes `(pid, started_at_unix_ms)`, the same pair
/// [`mail4agent_api::SessionAttested`] carries, and answers whether that
/// process is still the one that started at that time.
pub type LivenessCheck<'a> = &'a dyn Fn(u32, u64) -> bool;

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
    /// outside; every other method takes an already-authenticated identity
    /// as an argument (see `mail4agent/CLAUDE.md`'s "a sender is never a
    /// field the caller fills in").
    ///
    /// Authenticates the **account** only. Which session, if any, is
    /// calling is a separate fact the caller establishes by kernel
    /// attestation (`mail4agent-attest`, outside this crate) and hands to
    /// [`Self::ensure_session`] -- this method has no notion of a session at
    /// all.
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
    /// is not an error. Membership is always an *account*'s: every session
    /// of `participant` inherits it (see [`Self::resolve_identity`]).
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

    /// Registers a session, or refreshes an already-registered one --
    /// idempotent, and the only way a session enters the mailbox at all.
    /// This replaces enrolment as a separate step
    /// (`mailbox-service-extraction-and-signed-session-identity-2026-09-16.md`
    /// §5e): the first call for a given `session_id` creates it under
    /// `account`; every later call for the same id refreshes `last_seen` and
    /// `card`'s `attested`/`corroborated` groups.
    ///
    /// **Never touches `card.declared`.** [`Self::set_declared`] is the only
    /// way that group is ever written -- so this preserves whatever is
    /// already on file (empty, the first time) regardless of what the
    /// caller passed in `card.declared`. A caller that wants to declare
    /// something calls [`Self::set_declared`] itself; passing it here would
    /// let attestation traffic silently overwrite what a session said about
    /// itself.
    ///
    /// Refuses [`MailError::SessionAccountMismatch`] if `session_id` is
    /// already on file under a *different* account: a session's account
    /// cannot change out from under it, only be created once.
    pub fn ensure_session(
        &mut self,
        account: ParticipantId,
        session_id: SessionId,
        card: SessionCard,
        now_unix_ms: u64,
    ) -> Result<SessionId, MailError> {
        card.validate()?;
        session_id.validate()?;
        self.require_participant(&account)?;

        let existing = self.store.get_session(&session_id).map_err(|err| store_unavailable("get_session", err))?;
        let declared = match &existing {
            Some(record) if record.account == account => record.card.declared.clone(),
            Some(record) => {
                return Err(MailError::SessionAccountMismatch {
                    session: session_id,
                    expected: record.account.clone(),
                    presented: account,
                });
            }
            None => Default::default(),
        };
        let merged = SessionCard { attested: card.attested, corroborated: card.corroborated, declared };
        merged.validate()?;

        let record = SessionRecord { account, card: merged, last_seen_unix_ms: now_unix_ms };
        self.store.upsert_session(session_id.clone(), record).map_err(|err| store_unavailable("upsert_session", err))?;
        Ok(session_id)
    }

    /// Sets `session`'s declared group -- what it is working on, its role,
    /// which session spawned it. The **only** way that group is ever
    /// written; [`Self::ensure_session`] never touches it (see that
    /// method's own doc comment). Refuses [`MailError::UnknownSession`] if
    /// `session` has never been through [`Self::ensure_session`].
    pub fn set_declared(
        &mut self,
        session: &SessionId,
        working_on: Option<String>,
        role: Option<String>,
        parent: Option<SessionId>,
    ) -> Result<(), MailError> {
        session.validate()?;
        let mut record = self
            .store
            .get_session(session)
            .map_err(|err| store_unavailable("get_session", err))?
            .ok_or_else(|| MailError::UnknownSession { session: session.clone() })?;
        let declared = mail4agent_api::SessionDeclared { working_on, role, parent };
        declared.validate()?;
        record.card.declared = declared;
        self.store.upsert_session(session.clone(), record).map_err(|err| store_unavailable("upsert_session", err))
    }

    /// Sends a message. `sender` must already be the address
    /// [`Self::authenticate`] (plus, for a session, [`Self::ensure_session`])
    /// established -- **never** a field read out of `request`; [`SendRequest`]
    /// has no `from`, and must never grow one (`mail4agent/CLAUDE.md`).
    /// `sender` is the session's own address when a session sends, the
    /// account's when an account does -- see [`Address`].
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
    /// repeat send carrying the same key from the same sender address
    /// returns the original [`SendResponse`] and creates nothing, checked
    /// and recorded atomically by [`MailStore::insert_message`]. Without a
    /// key, a repeat send is a second message -- correct, because sending
    /// the same text twice on purpose should produce two messages.
    pub fn send(&mut self, sender: &Address, request: SendRequest, now_unix_ms: u64) -> Result<SendResponse, MailError> {
        request.validate()?;
        let (_, sender_record) = self.resolve_identity(sender)?;
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
            Address::Session { participant, session } => {
                let session_record =
                    self.store.get_session(session).map_err(|err| store_unavailable("get_session", err))?;
                match session_record {
                    Some(record) if &record.account == participant => {}
                    Some(record) => {
                        return Err(MailError::SessionAccountMismatch {
                            session: session.clone(),
                            expected: record.account,
                            presented: participant.clone(),
                        });
                    }
                    None => return Err(MailError::UnknownSession { session: session.clone() }),
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
    /// directly to `reader` (its own session address if `reader` is a
    /// session, plus its account's direct mail -- see
    /// [`Self::own_messages`]), plus messages to any room its account is
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
    pub fn inbox(&self, reader: &Address, since_unix_ms: u64, limit: u16) -> Result<InboxPage, MailError> {
        let (account, record) = self.resolve_identity(reader)?;
        self.require_read_permission(&record)?;
        self.build_inbox(reader, &account, since_unix_ms, limit)
    }

    /// Returns `target`'s inbox by exactly [`Self::inbox`]'s own rule --
    /// never widened, regardless of who is asking. Requires
    /// `caller.operator` or `caller == target`; refuses
    /// `PermissionDenied { need: "mail:operator" }` otherwise.
    ///
    /// This is the operator door onto a *named* address, one at a time --
    /// not a firehose over the whole mailbox. `target` may name an account
    /// or one specific session of it. When `caller == target` this is
    /// exactly [`Self::inbox`] under another name (and still requires
    /// `target`'s own `may_read`); when an operator names someone else,
    /// the target's own `may_read` is not consulted, because the
    /// authorization has already been established by the operator bit.
    pub fn inbox_of(
        &self,
        caller: &Address,
        target: &Address,
        since_unix_ms: u64,
        limit: u16,
    ) -> Result<InboxPage, MailError> {
        let (_, caller_record) = self.resolve_identity(caller)?;
        if caller != target && !caller_record.operator {
            return Err(MailError::PermissionDenied { need: "mail:operator".to_string() });
        }
        let (target_account, target_record) = self.resolve_identity(target)?;
        if caller == target {
            self.require_read_permission(&target_record)?;
        }
        self.build_inbox(target, &target_account, since_unix_ms, limit)
    }

    /// Records `reader`'s acknowledgement of `message_id`. Refuses
    /// `NotAddressedToYou` unless `reader` may read the message (see
    /// [`Self::is_readable`], which keeps its operator override: a named
    /// single message is a different thing from a bulk inbox listing).
    /// Idempotent on `(message_id, reader)`: a second ack of the same
    /// message by the same reader address returns the first ack unchanged
    /// rather than overwriting its timestamp.
    ///
    /// `now_unix_ms` is threaded through by the caller for the same reason
    /// [`Self::send`] takes it: the engine reads no clock of its own.
    pub fn ack(&mut self, reader: &Address, message_id: &MessageId, now_unix_ms: u64) -> Result<Ack, MailError> {
        let (account, record) = self.resolve_identity(reader)?;
        self.require_read_permission(&record)?;
        let message = self
            .store
            .get_message(message_id)
            .map_err(|err| store_unavailable("get_message", err))?
            .ok_or_else(|| MailError::UnknownMessage { message_id: message_id.clone() })?;
        if !self.is_readable(&message, reader, &account, &record)? {
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
    pub fn message_get(&self, reader: &Address, message_id: &MessageId) -> Result<Message, MailError> {
        let (account, record) = self.resolve_identity(reader)?;
        self.require_read_permission(&record)?;
        let message = self
            .store
            .get_message(message_id)
            .map_err(|err| store_unavailable("get_message", err))?
            .ok_or_else(|| MailError::UnknownMessage { message_id: message_id.clone() })?;
        if !self.is_readable(&message, reader, &account, &record)? {
            return Err(MailError::NotAddressedToYou { message_id: message_id.clone() });
        }
        Ok(message)
    }

    /// Returns how many currently-readable messages `target` has not yet
    /// acked -- the same figure [`InboxPage::unread`] carries for the same
    /// address. Requires `caller.operator` or `caller == target`, the same
    /// authorization [`Self::inbox_of`] uses, enforced here rather than left
    /// to a wire layer that could forget it.
    pub fn unread_count_of(&self, caller: &Address, target: &Address) -> Result<UnreadCount, MailError> {
        let (_, caller_record) = self.resolve_identity(caller)?;
        if caller != target && !caller_record.operator {
            return Err(MailError::PermissionDenied { need: "mail:operator".to_string() });
        }
        let (target_account, target_record) = self.resolve_identity(target)?;
        if caller == target {
            self.require_read_permission(&target_record)?;
        }
        let unread = self.count_unread(target, &target_account)?;
        Ok(UnreadCount { target: target.clone(), unread })
    }

    /// Returns the mailbox's own directory: every registered account (id
    /// and label; never a secret digest or a permission bit -- see
    /// [`crate::ParticipantSummary`]), each with its own live sessions
    /// nested under it, and every room the mailbox tracks, each marked with
    /// whether `caller`'s account currently belongs to it.
    ///
    /// `is_alive` is *given*, never performed here: this crate learns
    /// nothing about processes (see [`LivenessCheck`]). It is called once
    /// per listed session, with that session's own `(pid,
    /// started_at_unix_ms)`, to fill [`SessionEntry::live`].
    ///
    /// Gated on `caller.may_read`, the same capability [`Self::inbox`] and
    /// [`Self::message_get`] require: seeing who else exists is a read of
    /// the mailbox, not a distinct capability. **A participant is visible
    /// to every other participant that may read at all, with no exception
    /// for a listed participant's own permission bits** -- knowing someone
    /// exists is not the capability that matters (reading their mail is,
    /// and that is unaffected by this), so gating the directory's
    /// completeness on each *target's* `may_read`/`may_send` would only
    /// make it an unreliable directory for no privacy this mailbox
    /// actually provides.
    pub fn directory(&self, caller: &Address, is_alive: LivenessCheck<'_>) -> Result<Directory, MailError> {
        let (account, record) = self.resolve_identity(caller)?;
        self.require_read_permission(&record)?;

        let participants = self.store.list_participants().map_err(|err| store_unavailable("list_participants", err))?;
        let mut entries = Vec::with_capacity(participants.len());
        for summary in participants {
            let sessions = self
                .store
                .sessions_of(&summary.id)
                .map_err(|err| store_unavailable("sessions_of", err))?
                .into_iter()
                .map(|(id, record)| SessionEntry {
                    live: is_alive(record.card.attested.pid, record.card.attested.started_at_unix_ms),
                    last_seen_unix_ms: record.last_seen_unix_ms,
                    card: record.card,
                    id,
                })
                .collect();
            entries.push(DirectoryEntry { id: summary.id, label: summary.label, sessions });
        }

        let rooms = self
            .store
            .list_rooms()
            .map_err(|err| store_unavailable("list_rooms", err))?
            .into_iter()
            .map(|summary| RoomEntry { member: summary.members.contains(&account), id: summary.id })
            .collect();

        Ok(Directory { participants: entries, rooms })
    }

    fn require_participant(&self, id: &ParticipantId) -> Result<ParticipantRecord, MailError> {
        self.store
            .get_participant(id)
            .map_err(|err| store_unavailable("get_participant", err))?
            .ok_or_else(|| MailError::UnknownParticipant { participant: id.clone() })
    }

    /// Resolves any [`Address`] that can identify a caller (a
    /// [`Address::Direct`] account or a [`Address::Session`] one -- never a
    /// [`Address::Room`], which names somewhere mail goes, not someone) to
    /// the account it acts as and that account's registry record. A session
    /// borrows its account's permission bits wholesale: it carries none of
    /// its own (see [`SessionRecord`]).
    ///
    /// Refuses [`MailError::UnknownSession`] if `address` names a session
    /// that has never reached [`Self::ensure_session`], and
    /// [`MailError::SessionAccountMismatch`] if it names a session that has,
    /// but under a different account than the one given alongside it.
    fn resolve_identity(&self, address: &Address) -> Result<(ParticipantId, ParticipantRecord), MailError> {
        address.validate()?;
        match address {
            Address::Direct { participant } => {
                let record = self.require_participant(participant)?;
                Ok((participant.clone(), record))
            }
            Address::Session { participant, session } => {
                let session_record = self
                    .store
                    .get_session(session)
                    .map_err(|err| store_unavailable("get_session", err))?
                    .ok_or_else(|| MailError::UnknownSession { session: session.clone() })?;
                if &session_record.account != participant {
                    return Err(MailError::SessionAccountMismatch {
                        session: session.clone(),
                        expected: session_record.account,
                        presented: participant.clone(),
                    });
                }
                let record = self.require_participant(participant)?;
                Ok((participant.clone(), record))
            }
            Address::Room { room } => Err(MailError::Malformed {
                field: "address".to_string(),
                reason: format!("a room (\"{room}\") cannot act as a participant identity"),
            }),
        }
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
    /// otherwise depends on `message.to`. Mail to an account
    /// ([`Address::Direct`]) is readable by that account or by any of its
    /// sessions -- a session inherits its account's mail, per
    /// `mailbox-service-extraction-and-signed-session-identity-2026-09-16.md`
    /// §5e. Mail to one specific session ([`Address::Session`]) is readable
    /// only by that exact session, never by its account or a sibling
    /// session. Mail to a room is readable by any current member of it,
    /// account-wide. Used only by [`Self::ack`] and [`Self::message_get`],
    /// which each already name one specific message -- unlike
    /// [`Self::inbox`]/[`Self::inbox_of`], which never let an operator bit
    /// widen a bulk listing.
    fn is_readable(
        &self,
        message: &Message,
        reader: &Address,
        account: &ParticipantId,
        record: &ParticipantRecord,
    ) -> Result<bool, MailError> {
        if record.operator {
            return Ok(true);
        }
        match &message.to {
            Address::Direct { participant } => Ok(participant == account),
            Address::Session { .. } => Ok(reader == &message.to),
            Address::Room { room } => {
                let room_record = self.store.get_room(room).map_err(|err| store_unavailable("get_room", err))?;
                Ok(room_record.is_some_and(|room_record| room_record.members.contains(account)))
            }
        }
    }

    /// `identity`'s own readable messages, no older than `since_unix_ms`:
    /// mail addressed to `identity` exactly, plus -- when `identity` is a
    /// session -- its account's direct mail too, plus mail to rooms
    /// `account` currently belongs to. Never widened by an operator bit --
    /// that authorization question is answered by [`Self::inbox_of`]'s
    /// caller/target check before this runs, not by this function reading
    /// more than `identity`'s own mail.
    fn own_messages(&self, identity: &Address, account: &ParticipantId, since_unix_ms: u64) -> Result<Vec<Message>, MailError> {
        let mut messages = self
            .store
            .messages_to_since(identity, since_unix_ms)
            .map_err(|err| store_unavailable("messages_to_since", err))?;
        if matches!(identity, Address::Session { .. }) {
            let account_address = Address::Direct { participant: account.clone() };
            let account_messages = self
                .store
                .messages_to_since(&account_address, since_unix_ms)
                .map_err(|err| store_unavailable("messages_to_since", err))?;
            messages.extend(account_messages);
        }
        let rooms = self.store.rooms_containing(account).map_err(|err| store_unavailable("rooms_containing", err))?;
        for room in rooms {
            let room_messages = self
                .store
                .room_messages_since(&room, since_unix_ms)
                .map_err(|err| store_unavailable("room_messages_since", err))?;
            messages.extend(room_messages);
        }
        Ok(messages)
    }

    fn build_inbox(
        &self,
        identity: &Address,
        account: &ParticipantId,
        since_unix_ms: u64,
        limit: u16,
    ) -> Result<InboxPage, MailError> {
        let mut messages = self.own_messages(identity, account, since_unix_ms)?;
        messages.sort_by(|a, b| a.created_at_unix_ms.cmp(&b.created_at_unix_ms).then_with(|| a.message_id.cmp(&b.message_id)));
        messages.truncate(usize::from(limit));
        let unread = self.count_unread(identity, account)?;
        Ok(InboxPage { messages, unread })
    }

    /// Counts what `identity` has not yet acknowledged.
    ///
    /// `identity`'s **own** messages never count. They reach its inbox --
    /// a room is a shared log and its author belongs in it -- but an author
    /// has by definition read what it wrote, and counting it would invite
    /// exactly the loop this mailbox exists to avoid: an agent polls, sees
    /// something unread, and answers itself. This is address-exact: a
    /// message a *sibling* session sent still counts as unread for
    /// `identity`, the same way Matrix tracks read state per device rather
    /// than per account.
    fn count_unread(&self, identity: &Address, account: &ParticipantId) -> Result<u32, MailError> {
        let messages = self.own_messages(identity, account, 0)?;
        let mut unread = 0u32;
        for message in messages {
            if &message.from == identity {
                continue;
            }
            let ack = self
                .store
                .get_ack(&message.message_id, identity)
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
/// determined by `(sender, request, now_unix_ms, key)`. `sender` is mixed in
/// through its `Display` form, which is injective across [`Address`]'s three
/// shapes (`claude`, `claude/s-...`, `#room-1` never collide -- see
/// [`Address`]'s own `Display`/`FromStr` doc comment), so two different
/// sending addresses never derive the same id by coincidence. When the key
/// is `None`, this mixes in 16 fresh random bytes: without them, two
/// deliberately identical sends (no key -- by design a second message, see
/// [`SendRequest::idempotency_key`]) would derive the same id and collide.
/// This is the one place derivation is not pure content-hashing, and it is
/// harmless to correctness either way: whether a send is stored is decided
/// by [`MailStore::insert_message`]'s own idempotency check, never by
/// whether two derived ids happen to match.
fn derive_message_id(sender: &Address, request: &SendRequest, now_unix_ms: u64) -> MessageId {
    let mut hasher = Sha256::new();
    hasher.update(sender.to_string().as_bytes());
    hasher.update([0u8]);
    match &request.to {
        Address::Direct { participant } => {
            hasher.update(b"direct:");
            hasher.update(participant.as_str().as_bytes());
        }
        Address::Session { participant, session } => {
            hasher.update(b"session:");
            hasher.update(participant.as_str().as_bytes());
            hasher.update([0u8]);
            hasher.update(session.as_str().as_bytes());
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
