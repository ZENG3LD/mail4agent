//! [`MessengerCore`] — the single-writer kernel tying every earlier piece
//! together (plan §3's `lib.rs`/`sync_engine.rs`, work pieces M13a+M13b):
//! the `/sync` loop, to-device/device-list/room ingestion, Megolm decrypt,
//! the receive-side [`MessengerCommand`] variants (M13a), and the per-room
//! ordered send pipeline plus every room-membership/tag/typing command
//! (M13b, this module's own "M13b send pipeline" section below).
//!
//! # Kernel API shape
//!
//! [`MessengerCore::open`] rebuilds a core from whatever a shell already
//! has durably stored (sealed records) plus fresh, caller-supplied config.
//! From there, a shell drives one tick at a time:
//!
//! 1. [`MessengerCore::releasable_requests`] — everything safe to send
//!    right now (the flush-before-send barrier already applied).
//! 2. Execute each, feed the result back via [`MessengerCore::on_response`]
//!    or [`MessengerCore::on_transport_error`].
//! 3. [`MessengerCore::take_flush_batch`]/[`MessengerCore::ack_flush`] —
//!    persist whatever mutated, ack once durable.
//! 4. [`MessengerCore::events`] — drain whatever became visible, to diff
//!    against the adapter's own last-rendered snapshot.
//!
//! No function here calls a clock or an RNG itself (crate doc, `ids`/
//! `outgoing_queue`'s own module docs): every entry point that needs time
//! takes `now_ms` explicitly, and retry jitter comes from the
//! [`crate::outgoing_queue::Jitter`] supplied to [`MessengerCore::open`].
//!
//! # Counters that must never repeat across a restart
//!
//! [`crate::ids::RequestId`]/[`crate::ids::TxnId`] are minted from one
//! monotonic seed per device session (`ids`'s own module doc) — this
//! module is that seed's one owner, persisted as [`Counters`]. A bump is
//! written through [`crate::store::StateStore::save_counters`] in the same
//! synchronous call that mints the id ([`MessengerCore::next_request_id`]),
//! which is what lets the ordinary flush-before-send barrier
//! (`crate::persist`'s module doc) cover it for free: the very next
//! [`crate::outgoing_queue::OutgoingQueue::enqueue`] call this id feeds
//! into calls [`crate::persist::FlushEpoch::seal_for_request`] itself,
//! which folds the counter's own not-yet-batched dirty write into the same
//! batch the new request's `required_seq` waits on. A reused id after a
//! crash would be silently deduplicated by the server into the OLD
//! event/request — the exact "resend a `/keys/claim`, waste one OTK" cost
//! [`crate::outgoing_queue`]'s own module doc accepts is very different
//! from resending a `TxnId` a room member already has under a different
//! plaintext, which is why this restore rule is load-bearing, not
//! defensive polish.
//!
//! [`MessengerCore::open`] restores each sequence to
//! `max(persisted, 1 + highest seed still embedded in a pending request)`
//! — see [`restore_counter`]'s own doc for why the `pending` half of that
//! max matters at all given the write-before-mint discipline above (belt
//! and suspenders, not the primary guarantee). Only [`crate::ids::RequestId`]
//! has a structural "still pending" source to scan
//! ([`crate::store::StateStore::pending_requests`] — every pending request
//! carries its own id); [`crate::ids::TxnId`] does not (a `TxnId` is baked
//! into a request's `path`/`body`, never a distinct field), so its restore
//! relies solely on the persisted value. [`MessengerCore::next_txn_id`] is
//! the send pipeline's own counterpart to
//! [`MessengerCore::next_request_id`] — symmetric restore, symmetric
//! write-before-mint discipline.
//!
//! # Sync ingestion order
//!
//! One `/sync` request is ever outstanding at a time
//! ([`crate::outgoing_queue::Lane::Sync`]'s own cap), 30s long-poll,
//! `since` = the persisted [`crate::store::StateStore::sync_token`] (initial
//! sync when `None`). On a successful response, in order: (1) to-device
//! events — Olm-decrypt, route `m.room_key` into
//! [`crate::crypto::group_sessions::GroupSessionManager`], drop a
//! replayed/otherwise-unrecoverable decrypt silently, keep an
//! [`crate::crypto::olm_sessions::OlmDecryptError::UnknownSenderDevice`] in
//! a small bounded retry list re-tried after the next `/keys/query`.
//! [`crate::crypto::olm_sessions::OlmSessionManager::decrypt_to_device`]
//! checks the sender's device BEFORE it creates or advances any session, so
//! a refused event has consumed nothing (no one-time key, no ratchet step) and
//! the retry decrypts it from scratch -- the room key inside the very first
//! message from a peer whose device this account has not queried yet (the
//! usual case: the to-device share arrives before any `/keys/query` for
//! them) is not lost.
//! `m.room_key.withheld`/`m.room_key_request`/`m.forwarded_room_key` are a
//! no-op hook for `crypto::withheld` (M8); (2) `device_lists.changed`/
//! `left` → [`crate::crypto::device_tracker::DeviceTracker`]; (3) OTK
//! counts / unused fallback types →
//! [`crate::crypto::account::OlmAccountState::on_sync_counts`], may enqueue
//! `/keys/upload`; (4) any outdated tracked user → one `/keys/query`; (5)
//! rooms join/invite/leave (a member seen joining an encrypted room is marked
//! outdated and queried right after, step 5b) — state → [`crate::room::state::RoomState`],
//! timeline → [`crate::room::timeline::Timeline::apply_timeline_batch`],
//! Megolm events decrypted via
//! [`crate::crypto::group_sessions::GroupSessionManager::decrypt_event`] →
//! [`crate::room::timeline::Timeline::set_decrypted`] or
//! `Undecryptable{reason}`; ephemeral typing/receipts; room account data;
//! summary + unread; (6) global account data (`m.direct`) → later read by
//! [`MessengerCore::room_kind`]; (7) the new sync token is persisted LAST,
//! after everything it covers. When a room key newly arrives (step 1),
//! every `Undecryptable` item across every loaded timeline whose session id
//! now matches is retried automatically, in addition to the caller's own
//! [`MessengerCommand::RetryDecryption`].

use crate::crypto::account::OlmAccountState;
use crate::crypto::device_tracker::{DeviceTracker, StoredDevice};
use crate::crypto::group_sessions::{GroupSessionManager, RoomEventPlaintext};
use crate::crypto::olm_sessions::{OlmDecryptError, OlmSessionManager};
use crate::error::MessengerError;
use crate::ids::{DeviceId, EventId, RequestId, RoomId, TxnId, UserId};
use crate::outgoing_queue::{Jitter, Lane, OutgoingQueue, PendingRequest, ResponseOutcome};
use crate::persist::{FlushBatch, SealedRecord};
use crate::room::state::RoomState;
use crate::room::timeline::{
    interpret_content, ForwardRefusal, ItemContent, SendState, Timeline, KEY_FORWARDED, KEY_FORWARDED_FROM,
};
use crate::room::RoomKind;
use crate::store::sealed::SealedRecordCodec;
use crate::store::{CryptoStore, RecordCodec, StateStore, Store};
use crate::wire::events::{
    DirectContent, InReplyTo, MegolmEncryptedContent, Membership, RawEvent, ReceiptContent, RelatesTo,
    RoomEncryptedContent, RoomKeyContent, StrippedStateEvent, TagContent, TagInfo, TextLikeMessageContent,
    ToDeviceEvent, TypingContent, Unsigned,
};
use crate::wire::sync::{parse_sync_response, InvitedRoom, JoinedRoom, LeftRoom};
use crate::wire::{percent_decode_segment, HttpResponseDescriptor, OutgoingRequest, OutgoingRequestKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use zeroize::Zeroizing;

/// `/sync`'s own long-poll timeout (research doc §1.4's convention).
const SYNC_TIMEOUT_MS: u64 = 30_000;
/// `GET /rooms/{roomId}/messages`'s page size for
/// [`MessengerCommand::LoadOlder`].
const LOAD_OLDER_PAGE_SIZE: u32 = 50;
/// How long a `typing: true` indicator asks the server to hold before
/// auto-clearing it (client-server API's own `timeout` field).
const TYPING_TIMEOUT_MS: u64 = 30_000;
/// How many to-device events with an as-yet-[`OlmDecryptError::UnknownSenderDevice`]
/// sender this core holds for a retry after the next `/keys/query`, oldest
/// evicted first — same bounded-FIFO doctrine as
/// [`crate::room::timeline`]'s own pending-relation queue.
const UNKNOWN_SENDER_RETRY_CAPACITY: usize = 256;
/// How often [`MessengerCommand::SetTyping`] actually sends a `typing:
/// true` PUT while the caller keeps re-asserting it — a `false` (stop) is
/// never debounced (M13b's own send-pipeline doc).
const TYPING_DEBOUNCE_MS: i64 = 4_000;
/// [`GroupSessionManager::chunk_recipients_for_send_to_device`]'s own cap
/// already bounds one `sendToDevice` request's device count; this is the
/// wire event type every such request carries when it is sharing a Megolm
/// room key -- the OUTER to-device type is always `m.room.encrypted` (the
/// body is already Olm ciphertext; the inner, only-visible-after-decrypt
/// type is `m.room_key`), matching every other Olm-wrapped to-device send
/// this crate builds (`crypto::olm_sessions`'s own module doc).
const ROOM_KEY_SHARE_EVENT_TYPE: &str = "m.room.encrypted";

/// This device's own [`crate::ids::RequestId`]/[`crate::ids::TxnId`]
/// minting sequences — see this module's own doc, "Counters that must
/// never repeat across a restart".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    /// The next, never-yet-handed-out [`crate::ids::RequestId`] seed.
    pub next_request_id: u64,
    /// The next, never-yet-handed-out [`crate::ids::TxnId`] seed. Not
    /// minted from anywhere in this piece yet (see this module's own doc)
    /// — restored and persisted symmetrically with `next_request_id` so
    /// M13b's send pipeline needs no new persistence of its own.
    pub next_txn_id: u64,
}

/// Computes the value a counter must resume from after a restart: never
/// below what was durably persisted, and never low enough to reissue an id
/// a still-pending request already carries. `max_used_seed` is the highest
/// seed [`MessengerCore::open`] found embedded in a request
/// [`crate::store::StateStore::pending_requests`] is still tracking (`None`
/// when nothing is pending, or when this counter has no such structural
/// source to scan at all — see this module's own doc for
/// [`crate::ids::TxnId`]'s case). This is a defensive second check, not the
/// primary guarantee: under the write-before-mint discipline
/// [`MessengerCore::next_request_id`] follows, the persisted value alone
/// should already dominate every pending id.
fn restore_counter(persisted_next: u64, max_used_seed: Option<u64>) -> u64 {
    match max_used_seed {
        Some(seed) => persisted_next.max(seed.saturating_add(1)),
        None => persisted_next,
    }
}

/// Static identity a shell supplies once at [`MessengerCore::open`] time —
/// never re-derived, never changed for the lifetime of a device session
/// (plan §4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreConfig {
    /// This account's own user id.
    pub user_id: UserId,
    /// This device's own, server-assigned device id.
    pub device_id: DeviceId,
    /// The homeserver's own server name — not consumed by this crate's own
    /// logic yet (every id this core builds, including
    /// [`MessengerCommand::CreateRoom`]'s, is either read whole off the wire
    /// or supplied by a caller who already has one; `CreateRoomKind` has no
    /// alias field), kept on [`CoreConfig`] because a shell already has to
    /// know it to reach the homeserver at all, and a still-later piece
    /// (minting a room alias's local part into a full alias) will need it.
    pub server_name: String,
}

/// Secret material a shell supplies once at [`MessengerCore::open`] time,
/// alongside [`CoreConfig`]'s static identity fields. The session private
/// key is not here: it is the Olm account
/// [`crate::crypto::account::OlmAccountState::load_or_create`] generates
/// (`mail4agent_vodozemac::olm::Account::new`) and pickles into the store.
/// These two fields are optional 32-byte keys the caller already holds.
/// `Default` leaves both absent. Nothing in this crate reads `backup_key`
/// yet.
#[derive(Default)]
pub struct CoreSecrets {
    /// This device's record-sealing key. `None` when this core is opened
    /// with a non-sealing codec (every test in this crate uses
    /// [`crate::store::InsecurePlainCodecForTests`] instead).
    /// [`MessengerCore::open_sealed`] is the only consumer: it requires
    /// this field to build its own [`SealedRecordCodec`] and fails loudly
    /// if it is absent rather than silently falling back to an unsealed
    /// store.
    pub store_seal_key: Option<Zeroizing<[u8; 32]>>,
    /// This account's server-side key-backup key, supplied by the caller.
    /// Carried for a later Megolm session backup/restore; nothing in this
    /// crate reads it yet.
    pub backup_key: Option<Zeroizing<[u8; 32]>>,
}

/// Which `m.room.message` shape [`OutgoingMessage`] renders as (M13b send
/// pipeline).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    /// `msgtype: "m.text"`.
    Text,
    /// `msgtype: "m.notice"`.
    Notice,
    /// `msgtype: "m.emote"`.
    Emote,
}

impl MessageKind {
    fn msgtype(self) -> &'static str {
        match self {
            MessageKind::Text => "m.text",
            MessageKind::Notice => "m.notice",
            MessageKind::Emote => "m.emote",
        }
    }
}

/// One message a caller wants sent via [`MessengerCommand::SendMessage`] —
/// M13b's binding content shape: text/notice/emote, an optional reply
/// pointer, and an optional edit target (which must name one of the
/// caller's own already-sent events — [`MessengerCore::dispatch`] rejects
/// an edit of someone else's event rather than silently sending a
/// replacement the room's other members will refuse to accept, per
/// `m.replace`'s own "must come from the original sender" rule,
/// `crate::room::relations`'s own module doc). `reply_to` and `edit_of`
/// are mutually exclusive at the wire level — if both are set, `edit_of`
/// wins (an edit's own `m.relates_to` is `m.replace`, not a reply).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutgoingMessage {
    /// Which `msgtype` this renders as.
    pub kind: MessageKind,
    /// The message's own plain-text body (the edited/new body, if this is
    /// an edit).
    pub body: String,
    /// A rich-reply pointer (`m.in_reply_to`), if any.
    pub reply_to: Option<EventId>,
    /// The event this message replaces, if this is an edit — must be one
    /// of the caller's own already-sent events (this module's own doc).
    pub edit_of: Option<EventId>,
}

/// Which shape [`MessengerCommand::CreateRoom`] builds, mapped onto the
/// server's own `POST /createRoom` field set (`visibility`/`is_direct`/
/// `invite`/`name`/`topic` — the server derives `kind` itself from
/// `visibility`+`is_direct`, per the server plan's §5; a client never
/// sends a `preset`/`kind` field directly).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreateRoomKind {
    /// A 1:1 conversation: `is_direct: true`, exactly one invitee. Also
    /// merges the new room into this account's own `m.direct` account data
    /// once the room is created (this module's own doc).
    Dm {
        /// The other party.
        peer: UserId,
    },
    /// A private multi-person room.
    Group {
        /// The room's display name.
        name: String,
        /// Users to invite at creation time.
        invite: Vec<UserId>,
        /// `true` gives every member the `invite` power level (`0`);
        /// `false` restricts inviting to a moderator/owner (`50`) — the
        /// server plan's §5 `group` column.
        members_can_invite: bool,
    },
    /// A public, announcement-style room (never encrypted — server plan
    /// §5: "never — server refuses to set it on a public room").
    Channel {
        /// The room's display name.
        name: String,
        /// The room's topic, if any.
        topic: Option<String>,
    },
}

/// One command a shell/adapter dispatches into the core — both the M13a
/// receive-side variants (`MarkRead`, `SetTyping`, `RetryDecryption`,
/// `LoadOlder`) and the M13b send/room-membership ones. Only `PartialEq`
/// (not `Eq`): [`MessengerCommand::SetTag`]'s `order: Option<f64>` cannot
/// implement `Eq`.
#[derive(Clone, Debug, PartialEq)]
pub enum MessengerCommand {
    /// Sends one message into a room's per-room ordered send pipeline
    /// (this module's own doc) — encrypts first if the room is encrypted,
    /// sharing the room key to any not-yet-shared device before the
    /// message itself is sent. A [`crate::room::timeline::TimelineItem`]
    /// local echo appears immediately, in [`crate::room::timeline::SendState::Sending`].
    SendMessage {
        /// The room to send into.
        room_id: RoomId,
        /// The message content.
        message: OutgoingMessage,
        /// A caller-supplied transaction id (deterministic tests); `None`
        /// mints a fresh one from this device's own counter.
        txn_id: Option<TxnId>,
    },
    /// Forwards one event of `from_room` into `to_room`, through the same
    /// per-room send pipeline as [`MessengerCommand::SendMessage`] (so it is
    /// Megolm-encrypted when `to_room` is encrypted).
    ///
    /// The forward rules live HERE, in the engine. The content is read from
    /// the source timeline item's DECRYPTED content -- for an edited item the
    /// latest edit's `m.new_content` -- with `m.relates_to`, `m.mentions`
    /// and `m.new_content` removed and any earlier forward marker replaced
    /// by this hop's own:
    ///
    /// - source room encrypted: `"forwarded": true` and
    ///   nothing else -- no original sender, no room id, no room name;
    /// - source room unencrypted (a public channel):
    ///   `"forwarded_from": {"room_id", "room_name"}` --
    ///   no sender.
    ///
    /// The event type `m.room.message` is kept. An unrecognized `msgtype`
    /// passes through as the raw content object plus the marker.
    ///
    /// Refused with [`MessengerError::IntentRefused`], naming the event,
    /// when the source item is missing, redacted, still sealed
    /// (undecryptable or not decrypted yet), or not an `m.room.message`;
    /// and when `to_room` is unknown to this core (its encryption state
    /// cannot be known, and a plaintext send into it could leak an
    /// encrypted room's content).
    Forward {
        /// The room the event is taken from.
        from_room: RoomId,
        /// The event being forwarded.
        event_id: EventId,
        /// The room it is sent into.
        to_room: RoomId,
        /// A caller-supplied transaction id; `None` mints a fresh one.
        txn_id: Option<TxnId>,
    },
    /// Sends a plaintext `m.reaction` — never Megolm-encrypted, even in an
    /// encrypted room (allowed there as metadata, per the server's own
    /// rule this crate mirrors).
    React {
        /// The room the reaction is sent in.
        room_id: RoomId,
        /// The event being reacted to.
        target: EventId,
        /// The reaction's own key (typically an emoji).
        key: String,
    },
    /// Redacts an event (`PUT /rooms/{roomId}/redact/{eventId}/{txnId}`).
    Redact {
        /// The room the target event lives in.
        room_id: RoomId,
        /// The event being redacted.
        target: EventId,
        /// Why, if given.
        reason: Option<String>,
    },
    /// Re-queues a [`crate::room::timeline::SendState::Failed`] send at the
    /// back of its room's own send queue, WITHOUT re-encrypting it if it
    /// had already been encrypted (the exact same ciphertext, the exact
    /// same `txn_id` — this module's own doc). A no-op if `txn_id` names
    /// no currently-failed send in `room_id`.
    RetrySend {
        /// The room the failed send belongs to.
        room_id: RoomId,
        /// The failed send's own transaction id.
        txn_id: TxnId,
    },
    /// Creates a room (`POST /createRoom`).
    CreateRoom {
        /// Which shape to create.
        kind: CreateRoomKind,
    },
    /// Joins a room this account has been invited to (or a public
    /// channel).
    JoinRoom {
        /// The room to join.
        room_id: RoomId,
    },
    /// Leaves a room.
    LeaveRoom {
        /// The room to leave.
        room_id: RoomId,
    },
    /// Invites a user to a room.
    Invite {
        /// The room to invite into.
        room_id: RoomId,
        /// The user being invited.
        user_id: UserId,
    },
    /// Removes a member from a room (`POST /rooms/{roomId}/kick`) — the
    /// next encrypted send in this room rotates its Megolm session
    /// automatically, excluding them (`crypto::group_sessions`'s own
    /// rotation-trigger doc).
    Kick {
        /// The room to remove them from.
        room_id: RoomId,
        /// The member being removed.
        user_id: UserId,
        /// Why, if given.
        reason: Option<String>,
    },
    /// Adds (or updates) an `m.tag` room-account-data tag.
    SetTag {
        /// The room being tagged.
        room_id: RoomId,
        /// The tag's own name.
        tag: String,
        /// The tag's sort order among sibling tags, if any.
        order: Option<f64>,
    },
    /// Removes a tag from a room.
    RemoveTag {
        /// The room the tag is removed from.
        room_id: RoomId,
        /// The tag's own name.
        tag: String,
    },
    /// Sets this room's read-up-to marker to `event_id` (`POST
    /// /rooms/{roomId}/read_markers`).
    MarkRead {
        /// The room being marked read.
        room_id: RoomId,
        /// The last event the user has seen.
        event_id: EventId,
    },
    /// Starts or stops this device's own typing indicator in a room (`PUT
    /// /rooms/{roomId}/typing/{userId}`).
    SetTyping {
        /// The room to set the indicator in.
        room_id: RoomId,
        /// `true` to start, `false` to clear.
        typing: bool,
    },
    /// Re-attempts decrypting one currently-undecryptable timeline item
    /// (e.g. after the user manually re-verifies a device) — the same
    /// retry this core already runs automatically the moment a matching
    /// room key arrives (this module's own doc).
    RetryDecryption {
        /// The room the item lives in.
        room_id: RoomId,
        /// The item's event id.
        event_id: EventId,
    },
    /// Fetches one older page of a room's timeline (`GET
    /// /rooms/{roomId}/messages?dir=b`), prepending it once the response
    /// arrives. A no-op if this room has no further history to page into
    /// (no gap, no back-pagination token).
    LoadOlder {
        /// The room to page further back into.
        room_id: RoomId,
    },
    /// Sets one piece of this account's own global account data (`PUT
    /// /user/{userId}/account_data/{type}`) -- optimistically applied to
    /// [`MessengerCore::global_account_data`] in the same call (this
    /// module's own doc: the account-data endpoint replaces the whole
    /// value, so there is nothing to merge).
    SetAccountData {
        /// The account-data type being set.
        event_type: String,
        /// The full new value.
        content: serde_json::Value,
    },
    /// Sets one piece of `room_id`'s own room-scoped account data (`PUT
    /// /user/{userId}/rooms/{roomId}/account_data/{type}`) -- optimistically
    /// applied to [`MessengerCore::room_account_data`] in the same call.
    /// [`MessengerCommand::SetTag`]/`RemoveTag` are the `"m.tag"`-specific
    /// counterpart to this general command and behave the same way. Every
    /// account-data write travels on [`crate::outgoing_queue::Lane::
    /// AccountData`]: strictly FIFO, one in flight, so two writes to the
    /// same key can neither race nor land out of order.
    SetRoomAccountData {
        /// The room the account data is scoped to.
        room_id: RoomId,
        /// The account-data type being set.
        event_type: String,
        /// The full new value.
        content: serde_json::Value,
    },
    /// Searches the public-room directory (`POST /publicRooms`). The
    /// latest result set is read back through
    /// [`MessengerCore::public_rooms_result`]; a response to a search
    /// superseded by a later one is dropped (this module's own doc).
    SearchPublicRooms {
        /// The search term.
        term: String,
    },
    /// Searches the user directory (`POST /user_directory/search`). The
    /// latest result set is read back through
    /// [`MessengerCore::user_search_result`]; same supersession rule as
    /// [`MessengerCommand::SearchPublicRooms`].
    SearchUsers {
        /// The search term.
        term: String,
    },
}

/// One user-visible change a shell/adapter should re-read from a snapshot
/// getter. See [`MessengerCore::events`] for delivery semantics and
/// [`MessengerCore::change_counter`] for the cheap "did anything change at
/// all" signal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessengerEvent {
    /// The room list itself changed shape this tick (a room appeared via
    /// join/invite/leave, or an already-known room's own state changed).
    RoomsChanged,
    /// `room_id`'s timeline gained or updated an item.
    TimelineChanged {
        /// The affected room.
        room_id: RoomId,
    },
    /// `room_id`'s typing-user set changed.
    TypingChanged {
        /// The affected room.
        room_id: RoomId,
    },
    /// `room_id`'s read-receipt set changed.
    ReceiptsChanged {
        /// The affected room.
        room_id: RoomId,
    },
    /// `room_id`'s server-reported unread count changed.
    UnreadChanged {
        /// The affected room.
        room_id: RoomId,
    },
    /// A previously-known device's Curve25519/Ed25519 keys changed — a
    /// security event a UI should surface, never silently apply (see
    /// [`crate::crypto::device_tracker`]'s own module doc for why the OLD
    /// keys are what this core keeps).
    DeviceKeyChanged {
        /// The device's owner.
        user_id: UserId,
        /// The device whose keys changed.
        device_id: DeviceId,
    },
    /// [`MessengerCore::public_rooms_result`] changed (a
    /// [`MessengerCommand::SearchPublicRooms`] response landed and was not
    /// superseded).
    PublicRoomsChanged,
    /// [`MessengerCore::user_search_result`] changed (a
    /// [`MessengerCommand::SearchUsers`] response landed and was not
    /// superseded).
    UserSearchChanged,
}

/// One Megolm room event this core could not decrypt yet, kept so a later
/// room-key arrival or an explicit [`MessengerCommand::RetryDecryption`]
/// can re-attempt it without re-fetching anything — see this module's own
/// "Sync ingestion order" doc.
#[derive(Clone)]
struct PendingDecryptItem {
    session_id: String,
    sender: UserId,
    origin_server_ts: i64,
    content: MegolmEncryptedContent,
}

/// `GET /rooms/{roomId}/messages`'s response shape, the parts this module
/// reads (research doc §1.5) — `chunk` arrives newest-first for a `dir=b`
/// page, reversed by [`MessengerCore::ingest_room_messages_response`]
/// before [`crate::room::timeline::Timeline::prepend_back_page`] (which
/// wants oldest-first, matching its own doc).
#[derive(Deserialize)]
struct RoomMessagesResponseBody {
    #[serde(default)]
    chunk: Vec<RawEvent>,
    #[serde(default)]
    end: Option<String>,
}

/// `PUT .../send/...`'s own response shape — the parts this module reads.
#[derive(Deserialize)]
struct SendResponseBody {
    event_id: EventId,
}

/// `POST /createRoom`'s own response shape — the parts this module reads.
#[derive(Deserialize)]
struct CreateRoomResponseBody {
    room_id: RoomId,
}

/// One row of a `POST /publicRooms` result -- read back through
/// [`MessengerCore::public_rooms_result`].
#[derive(Clone, Debug, PartialEq)]
pub struct PublicRoomsResultEntry {
    /// The room's own id.
    pub room_id: RoomId,
    /// The room's display name, if it set one.
    pub name: Option<String>,
    /// The room's topic, if it set one.
    pub topic: Option<String>,
    /// The room's own joined-member count.
    pub num_joined_members: u64,
}

/// `POST /publicRooms`'s own response shape — the parts this module reads.
#[derive(Deserialize)]
struct PublicRoomsResponseBody {
    #[serde(default)]
    chunk: Vec<PublicRoomsChunkEntry>,
}

#[derive(Deserialize)]
struct PublicRoomsChunkEntry {
    room_id: RoomId,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    topic: Option<String>,
    #[serde(default)]
    num_joined_members: u64,
}

/// One row of a `POST /user_directory/search` result -- read back through
/// [`MessengerCore::user_search_result`].
#[derive(Clone, Debug, PartialEq)]
pub struct UserDirectoryResultEntry {
    /// The user's own id.
    pub user_id: UserId,
    /// The user's display name, if they set one.
    pub display_name: Option<String>,
}

/// `POST /user_directory/search`'s own response shape — the parts this
/// module reads.
#[derive(Deserialize)]
struct UserDirectorySearchResponseBody {
    #[serde(default)]
    results: Vec<UserDirectorySearchResultEntry>,
}

#[derive(Deserialize)]
struct UserDirectorySearchResultEntry {
    user_id: UserId,
    #[serde(default)]
    display_name: Option<String>,
}

/// One room-scoped send's own content, before it is turned into wire bytes
/// (M13b send pipeline). A reaction/redaction never enters the key-sharing
/// half of the pipeline at all — only a room event ([`SendPayload::Message`],
/// [`SendPayload::Event`]) can be Megolm-encrypted.
#[derive(Clone)]
enum SendPayload {
    /// A composed message — goes through the key-query/claim/share phases
    /// when its room is encrypted.
    Message(OutgoingMessage),
    /// Any other room event whose wire type and plaintext content are
    /// already final (a forward) — walks the same phases as
    /// [`SendPayload::Message`].
    Event {
        /// The wire event type (`m.room.message`).
        event_type: String,
        /// The event's plaintext content.
        content: serde_json::Value,
    },
    /// A plaintext `m.reaction` — sent as-is, in any room.
    Reaction {
        /// The event being reacted to.
        target: EventId,
        /// The reaction's own key.
        key: String,
    },
    /// A redaction (`PUT .../redact/...`) — sent as-is, in any room.
    Redaction {
        /// The event being redacted.
        target: EventId,
        /// Why, if given.
        reason: Option<String>,
    },
}

/// A room event as it goes on the wire before any encryption — what
/// [`SendPayload::room_event`] derives from a [`SendPayload::Message`] or a
/// [`SendPayload::Event`].
struct RoomEventWire {
    event_type: String,
    content: serde_json::Value,
    /// The cleartext `m.relates_to` an encrypted envelope must copy
    /// ([`message_relates_to`]).
    relates_to: Option<RelatesTo>,
}

impl SendPayload {
    /// The room-event shape of this payload; `None` for a reaction or a
    /// redaction (never encrypted, never echoed into the timeline).
    fn room_event(&self) -> Option<RoomEventWire> {
        match self {
            SendPayload::Message(message) => Some(RoomEventWire {
                event_type: "m.room.message".to_string(),
                content: message_wire_content(message),
                relates_to: message_relates_to(message),
            }),
            SendPayload::Event { event_type, content } => {
                Some(RoomEventWire { event_type: event_type.clone(), content: content.clone(), relates_to: None })
            }
            SendPayload::Reaction { .. } | SendPayload::Redaction { .. } => None,
        }
    }

    fn is_room_event(&self) -> bool {
        matches!(self, SendPayload::Message(_) | SendPayload::Event { .. })
    }
}

/// The exact wire request a [`PendingSend`] will make once it reaches
/// [`SendPhase::AwaitingSend`] — computed once (either directly, for a
/// plaintext send, or after Megolm-encrypting a [`SendPayload::Message`])
/// and cached from then on, so a later [`MessengerCommand::RetrySend`]
/// never re-derives it (never re-encrypts — this module's own doc).
#[derive(Clone)]
enum WireSend {
    /// `PUT /rooms/{roomId}/send/{eventType}/{txnId}`.
    Event {
        /// The wire event type (`m.room.message`, `m.room.encrypted`, or
        /// `m.reaction`).
        event_type: String,
        /// The event's own content.
        content: serde_json::Value,
    },
    /// `PUT /rooms/{roomId}/redact/{eventId}/{txnId}`.
    Redact {
        /// The event being redacted.
        target: EventId,
        /// Why, if given.
        reason: Option<String>,
    },
}

/// Where one room-scoped send currently sits in its own pipeline (M13b's
/// module doc: key-query -> key-claim -> key-share -> the room event
/// itself, in that order, for an encrypted [`SendPayload::Message`];
/// straight to [`SendPhase::AwaitingSend`] for everything else).
#[derive(Clone)]
enum SendPhase {
    /// Waiting for an earlier send in the same room to finish first —
    /// [`MessengerCore::start_send_pipeline`] has not run for this send
    /// yet.
    Queued,
    /// Waiting on one `/keys/query` this pipeline itself minted, for a
    /// member whose device list is outdated or was never tracked at all —
    /// [`MessengerCore::send_request_owner`] is what routes the eventual
    /// response back to this send, so this phase itself carries no request
    /// id of its own.
    AwaitingKeysQuery,
    /// Waiting on one `/keys/claim`, for recipient devices this account
    /// has no Olm session with yet.
    AwaitingKeysClaim {
        /// Exactly the devices that request claimed a key for — needed to
        /// apply the response ([`OlmSessionManager::on_keys_claim_response`]
        /// takes the original request list, not just the response body).
        devices: Vec<StoredDevice>,
    },
    /// Waiting on every `sendToDevice` request sharing the room key with
    /// its not-yet-shared recipients — the room event itself is withheld
    /// until every one of these succeeds (this module's own doc: "WAIT for
    /// those requests to succeed before sending the room event").
    AwaitingKeyShare {
        /// Every still-outstanding share request's own id.
        pending: BTreeSet<RequestId>,
    },
    /// Waiting on the room event/redaction itself.
    AwaitingSend,
    /// Terminal: the send (or one of its pipeline steps) failed outright.
    /// Kept (rather than removed) so [`MessengerCommand::RetrySend`] can
    /// find it again, and so [`MessengerCore::send_failure_reason`] can
    /// surface why.
    Failed {
        /// The Matrix `errcode` the failing response carried.
        errcode: String,
    },
}

/// One room-scoped send this core is tracking end to end — from
/// [`MessengerCommand::SendMessage`]/`React`/`Redact` through to a
/// terminal [`SendPhase::AwaitingSend`] response. See this module's own
/// doc for the pipeline every [`SendPayload::Message`] in an encrypted
/// room walks through.
#[derive(Clone)]
struct PendingSend {
    /// The room this send belongs to — also this send's own place in
    /// [`MessengerCore::pending_sends`]'s per-room FIFO.
    room_id: RoomId,
    /// What is being sent.
    payload: SendPayload,
    /// Where this send currently sits in its own pipeline.
    phase: SendPhase,
    /// The exact wire request, once computed — see [`WireSend`]'s own doc.
    wire: Option<WireSend>,
}

/// One account-data slot: `(room, event type)`; `None` is this account's own
/// global account data.
type AccountDataKey = (Option<RoomId>, String);

/// Bookkeeping for one [`AccountDataKey`] that has account-data writes
/// queued or in flight (an entry exists only while `pending > 0`).
///
/// A write updates the cached value optimistically. Without this guard a
/// `/sync` that echoes an OLDER write of the same key would overwrite that
/// optimistic value, and the next edit would build on the stale copy and
/// silently drop a change. While writes are outstanding, `/sync` only
/// records what the server reports (`server_value`); the optimistic cache
/// stays authoritative. When the last write settles: a success keeps the
/// optimistic value (it is what the server now holds; the next sync
/// confirms it), a terminal failure restores `server_value`.
struct AccountDataGuard {
    /// Writes for this key queued or in flight.
    pending: u32,
    /// The last value the server is known to hold for the key: whatever
    /// the cache held when the first outstanding write was made, then
    /// whatever `/sync` reported since. `None`: nothing known (never seen).
    server_value: Option<serde_json::Value>,
}

/// The `(room, event type)` an account-data PUT `path` writes, or `None` if
/// `path` is not an account-data path.
fn account_data_key_from_path(path: &str) -> Option<AccountDataKey> {
    let segments: Vec<&str> = path.split('/').collect();
    let n = segments.len();
    if n < 4 || segments[n - 2] != "account_data" {
        return None;
    }
    let event_type = percent_decode_segment(segments[n - 1])?;
    if segments[n - 4] == "user" {
        return Some((None, event_type));
    }
    if n >= 6 && segments[n - 4] == "rooms" && segments[n - 6] == "user" {
        let room_id = RoomId::parse(percent_decode_segment(segments[n - 3])?).ok()?;
        return Some((Some(room_id), event_type));
    }
    None
}

/// The single-writer kernel — see this module's own doc.
pub struct MessengerCore<C: RecordCodec> {
    config: CoreConfig,
    store: Store<C>,
    account: OlmAccountState,
    outgoing: OutgoingQueue,
    counters: Counters,
    jitter: Box<dyn Jitter>,

    rooms: BTreeMap<RoomId, RoomState>,
    timelines: BTreeMap<RoomId, Timeline>,
    direct_account_data: Option<DirectContent>,
    global_account_data: BTreeMap<String, serde_json::Value>,
    room_account_data: BTreeMap<RoomId, BTreeMap<String, serde_json::Value>>,
    typing: BTreeMap<RoomId, Vec<UserId>>,
    receipts: BTreeMap<RoomId, ReceiptContent>,

    /// The latest [`MessengerCommand::SearchPublicRooms`] result set, read
    /// back through [`MessengerCore::public_rooms_result`].
    public_rooms_result: Vec<PublicRoomsResultEntry>,
    /// The [`RequestId`] of the most recently dispatched
    /// [`MessengerCommand::SearchPublicRooms`] -- a response naming any
    /// other id is a superseded search and is dropped (this module's own
    /// doc).
    latest_public_rooms_request: Option<RequestId>,
    /// The latest [`MessengerCommand::SearchUsers`] result set, read back
    /// through [`MessengerCore::user_search_result`].
    user_search_result: Vec<UserDirectoryResultEntry>,
    /// Same supersession tracking as `latest_public_rooms_request`, for
    /// [`MessengerCommand::SearchUsers`].
    latest_user_search_request: Option<RequestId>,

    /// Keys with account-data writes outstanding -- see
    /// [`AccountDataGuard`]. In-memory only: rebuilt at
    /// [`MessengerCore::open`] from the persisted request queue.
    account_data_guard: BTreeMap<AccountDataKey, AccountDataGuard>,
    /// Which key each outstanding account-data write belongs to.
    account_data_write_keys: BTreeMap<RequestId, AccountDataKey>,

    pending_decrypt: BTreeMap<RoomId, BTreeMap<EventId, PendingDecryptItem>>,
    unknown_sender_retry: VecDeque<ToDeviceEvent>,

    /// The last `now_ms` a [`MessengerCommand::SetTyping { typing: true,
    /// .. }`] actually sent a PUT at, per room — the debounce window
    /// [`TYPING_DEBOUNCE_MS`] is measured from (this module's own doc). No
    /// entry means either never sent, or explicitly stopped.
    typing_debounce: BTreeMap<RoomId, i64>,
    /// Every room-scoped send's own transaction id, in FIFO send order —
    /// only the front of each room's queue is active (this module's own
    /// "one message's pipeline completes before the next ... is
    /// encrypted" doc); [`MessengerCore::finish_active_send`] pops it and
    /// starts the next one.
    pending_sends: BTreeMap<RoomId, VecDeque<TxnId>>,
    /// Every [`PendingSend`] this core is tracking, keyed by its own
    /// `txn_id` — kept even after it leaves `pending_sends` (a terminal
    /// [`SendPhase::Failed`] stays here so [`MessengerCommand::RetrySend`]
    /// can find it again).
    send_state: BTreeMap<TxnId, PendingSend>,
    /// Which [`PendingSend`] a still-pending request (a key-query,
    /// key-claim, key-share, or the send/redact itself) this pipeline
    /// minted belongs to — same reasoning as `pending_kinds`.
    send_request_owner: BTreeMap<RequestId, TxnId>,
    /// Which [`CreateRoomKind`] a still-pending `POST /createRoom` request
    /// was building, so its response can merge `m.direct` for a
    /// [`CreateRoomKind::Dm`] (this module's own doc).
    pending_create_room: BTreeMap<RequestId, CreateRoomKind>,

    /// Every [`OutgoingRequestKind`] this core itself minted and is still
    /// waiting on, keyed by the [`RequestId`] it enqueued it under —
    /// [`crate::outgoing_queue::OutgoingQueue`] does not expose a way to
    /// look this back up given only an id, so this core tracks it
    /// alongside instead (see [`MessengerCore::enqueue_request`]).
    pending_kinds: BTreeMap<RequestId, OutgoingRequestKind>,
    /// Which room a still-pending `RoomMessages` request was paginating —
    /// same reasoning as `pending_kinds`.
    pending_room_messages: BTreeMap<RequestId, RoomId>,
    /// The currently outstanding `/sync` request's id, if any — this
    /// core's own single-flight tracking (this module's own doc).
    sync_request_id: Option<RequestId>,
    /// Whether a `/sync` request has completed successfully in THIS core's
    /// lifetime. Until then the next `/sync` is minted with `timeout=0` (an
    /// immediate catch-up answer, the matrix-js-sdk convention); only after
    /// it does the core long-poll.
    sync_caught_up: bool,
    /// [`FlushBatch`]es [`crate::outgoing_queue::OutgoingQueue::enqueue`]
    /// already drained from the store's own pending set (to seal a new
    /// request's [`crate::persist::RequiredSeq`]) but that a shell has not
    /// yet drained via [`MessengerCore::take_flush_batch`] — see
    /// [`MessengerCore::enqueue_request`]'s own doc for why this can't
    /// simply be re-derived from `store.take_flush_batch()` later.
    pending_flush_batches: VecDeque<FlushBatch>,

    events: Vec<MessengerEvent>,
    change_counter: u64,
    /// The last response this core could not ingest (a wire shape it does
    /// not decode, say), for [`MessengerCore::take_ingest_error`]. The
    /// response is otherwise dropped, so without this a shell would see
    /// nothing but a `/sync` loop that never advances.
    ingest_error: Option<String>,
}

impl<C: RecordCodec> MessengerCore<C> {
    /// Rebuilds a core from whatever a shell already read back from
    /// durable storage (`records`, possibly empty for a brand-new device),
    /// `config`, `secrets` (caller-supplied [`CoreSecrets`]: `store_seal_key`
    /// is consumed by [`MessengerCore::open_sealed`] before it reaches here,
    /// and `backup_key` is not read by this kernel), and a `jitter` source for
    /// [`crate::outgoing_queue::OutgoingQueue`]'s own retry backoff. `now_ms`
    /// is accepted for API symmetry with every other entry point (this
    /// crate's own "no clock inside" rule) but not read by anything in this
    /// piece's own restore logic yet — timeline content itself is never
    /// persisted (re-fetched off the next `/sync`/back-page instead, this
    /// module's own doc), so there is nothing time-sensitive to restore
    /// here before a later piece needs one.
    pub fn open(
        records: impl IntoIterator<Item = SealedRecord>,
        codec: C,
        config: CoreConfig,
        secrets: CoreSecrets,
        _now_ms: i64,
        jitter: Box<dyn Jitter>,
    ) -> Result<Self, MessengerError> {
        // The seal key lives in `codec` (`open_sealed` builds a
        // `SealedRecordCodec` from `store_seal_key`). `backup_key` stays on
        // `CoreSecrets` for the caller; this kernel does not read it.
        let _ = secrets;
        let mut store = Store::load(records, codec, config.device_id.clone())?;
        let mut outgoing = OutgoingQueue::load(&store)?;
        let account = OlmAccountState::load_or_create(&mut store)?;

        let mut rooms = BTreeMap::new();
        let mut timelines = BTreeMap::new();
        for room_id in store.room_ids()? {
            if let Some(bytes) = store.room_state(&room_id)? {
                let state: RoomState = serde_json::from_slice(bytes)
                    .map_err(|source| MessengerError::Crypto(format!("decode room state for {room_id}: {source}")))?;
                rooms.insert(room_id.clone(), state);
                timelines.insert(room_id, Timeline::new());
            }
        }

        let pending_requests = store.pending_requests()?;
        let max_pending_request_seed = pending_requests.iter().filter_map(|req| req.request.id.as_seed()).max();
        // A `/sync` restored from the store carries the timeout it was minted
        // with (a 30 s long-poll): replaying it would stall a resumed session
        // for that long before anything is known. It has no side effect to
        // lose, so drop it (its id already counted toward the seed above);
        // `ensure_sync_enqueued` mints a fresh catch-up sync from the
        // persisted token.
        outgoing.discard_kind(&mut store, OutgoingRequestKind::Sync)?;
        let persisted_counters = store.counters()?.unwrap_or_default();
        let counters = Counters {
            next_request_id: restore_counter(persisted_counters.next_request_id, max_pending_request_seed),
            next_txn_id: restore_counter(persisted_counters.next_txn_id, None),
        };
        if counters != persisted_counters {
            // Restoration actually advanced a value beyond what was on
            // disk (the defensive "pending" half of `restore_counter`
            // fired) -- persist the advanced value immediately so it, in
            // turn, can never be handed out a second time by a future
            // restart.
            store.save_counters(counters)?;
        }

        let mut core = Self {
            config,
            store,
            account,
            outgoing,
            counters,
            jitter,
            rooms,
            timelines,
            direct_account_data: None,
            global_account_data: BTreeMap::new(),
            room_account_data: BTreeMap::new(),
            typing: BTreeMap::new(),
            receipts: BTreeMap::new(),
            public_rooms_result: Vec::new(),
            latest_public_rooms_request: None,
            user_search_result: Vec::new(),
            latest_user_search_request: None,
            account_data_guard: BTreeMap::new(),
            account_data_write_keys: BTreeMap::new(),
            pending_decrypt: BTreeMap::new(),
            unknown_sender_retry: VecDeque::new(),
            typing_debounce: BTreeMap::new(),
            pending_sends: BTreeMap::new(),
            send_state: BTreeMap::new(),
            send_request_owner: BTreeMap::new(),
            pending_create_room: BTreeMap::new(),
            pending_kinds: BTreeMap::new(),
            pending_room_messages: BTreeMap::new(),
            sync_request_id: None,
            sync_caught_up: false,
            pending_flush_batches: VecDeque::new(),
            events: Vec::new(),
            change_counter: 0,
            ingest_error: None,
        };
        core.rebuild_account_data_guard(&pending_requests);
        Ok(core)
    }

    /// Rebuilds [`MessengerCore::account_data_guard`] (and the optimistic
    /// cache it protects) from account-data writes that were still pending
    /// when the core last stopped: each persisted request counts as one
    /// outstanding write for its key, and the newest request's body -- the
    /// value the server will hold once the queue drains -- is the cached
    /// value again. The server's own current value is unknown until
    /// `/sync` reports it.
    fn rebuild_account_data_guard(&mut self, pending_requests: &[PendingRequest]) {
        let mut writes: Vec<&PendingRequest> = pending_requests
            .iter()
            .filter(|record| matches!(record.request.kind, OutgoingRequestKind::AccountData | OutgoingRequestKind::RoomAccountData))
            .collect();
        writes.sort_by(|a, b| a.request.id.cmp(&b.request.id));
        for record in writes {
            let Some(key) = account_data_key_from_path(&record.request.path) else { continue };
            let Some(body) = record.request.body.clone() else { continue };
            let guard = self.account_data_guard.entry(key.clone()).or_insert(AccountDataGuard { pending: 0, server_value: None });
            guard.pending += 1;
            self.store_account_data_cache(&key, Some(body));
            self.account_data_write_keys.insert(record.request.id.clone(), key);
        }
    }

    /// Mints the next [`RequestId`], persisting the advanced [`Counters`]
    /// in the same call — see this module's own doc for why this ordering
    /// is what makes the flush-before-send barrier cover it for free.
    fn next_request_id(&mut self) -> Result<RequestId, MessengerError> {
        let seed = self.counters.next_request_id;
        self.counters.next_request_id = seed.saturating_add(1);
        self.store.save_counters(self.counters)?;
        Ok(RequestId::next(seed))
    }

    /// Mints the next [`TxnId`], persisting the advanced [`Counters`] in
    /// the same call — symmetric with [`MessengerCore::next_request_id`]
    /// (this module's own doc's "Counters that must never repeat across a
    /// restart" section).
    fn next_txn_id(&mut self) -> Result<TxnId, MessengerError> {
        let seed = self.counters.next_txn_id;
        self.counters.next_txn_id = seed.saturating_add(1);
        self.store.save_counters(self.counters)?;
        Ok(TxnId::new(seed))
    }

    /// Enqueues `request` on `lane`, remembering its kind so a later
    /// [`MessengerCore::on_response`] can route the response without
    /// [`crate::outgoing_queue::OutgoingQueue`] needing a by-id lookup of
    /// its own.
    ///
    /// [`crate::outgoing_queue::OutgoingQueue::enqueue`] already drains
    /// whatever was pending into a [`FlushBatch`] the instant it needs a
    /// [`crate::persist::RequiredSeq`] to seal the new request against
    /// (`crate::persist`'s own doc) — that batch is gone from the store's
    /// own pending set the moment it is produced, so if this method
    /// discarded it here, [`MessengerCore::take_flush_batch`] would never
    /// see it again and the request (and everything after it in the same
    /// lane) would stay unreleasable forever. [`MessengerCore::pending_flush_batches`]
    /// is where it waits instead, until a shell actually drains it.
    fn enqueue_request(&mut self, request: OutgoingRequest, lane: Lane) -> Result<(), MessengerError> {
        let id = request.id.clone();
        let kind = request.kind;
        if let Some(batch) = self.outgoing.enqueue(&mut self.store, request, lane)? {
            self.pending_flush_batches.push_back(batch);
        }
        self.pending_kinds.insert(id, kind);
        Ok(())
    }

    fn emit(&mut self, event: MessengerEvent) {
        self.change_counter = self.change_counter.wrapping_add(1);
        self.events.push(event);
    }

    fn drain_events(&mut self) -> Vec<MessengerEvent> {
        std::mem::take(&mut self.events)
    }

    // ---------------------------------------------------------------
    // M13b send pipeline
    // ---------------------------------------------------------------

    /// Starts (or queues) one room-scoped send — the shared entry point
    /// for [`MessengerCommand::SendMessage`]/`Forward`/`React`/
    /// `Redact`. Only a room event ([`SendPayload::Message`],
    /// [`SendPayload::Event`]) gets an immediate timeline local echo (this
    /// module's own doc): appended as [`SendState::LocalEcho`] then
    /// immediately moved to [`SendState::Sending`], matching the plan's
    /// own wording ("local echo in the timeline with `SendState::Sending`
    /// -> `MessengerEvent::TimelineChanged`") — both happen inside this one
    /// call, so a caller never observes the intermediate `LocalEcho` value.
    /// Sending a message also stops this device's own typing indicator in
    /// the room, unconditionally (module doc: "false on send").
    fn start_new_send(
        &mut self,
        room_id: RoomId,
        payload: SendPayload,
        caller_txn_id: Option<TxnId>,
        now_ms: i64,
    ) -> Result<(), MessengerError> {
        let txn_id = match caller_txn_id {
            Some(txn_id) => txn_id,
            None => self.next_txn_id()?,
        };

        if let Some(wire) = payload.room_event() {
            if self.typing_debounce.remove(&room_id).is_some() {
                if let Ok(request_id) = self.next_request_id() {
                    let request = OutgoingRequest::typing(request_id, &room_id, &self.config.user_id, false, None);
                    let _ = self.enqueue_request(request, Lane::Other);
                }
            }
            let content = match &payload {
                SendPayload::Message(message) => message_local_echo_content(message),
                _ => interpret_content(&wire.event_type, None, &wire.content),
            };
            let timeline = self.timelines.entry(room_id.clone()).or_default();
            timeline.push_local_echo(
                txn_id.clone(),
                self.config.user_id.clone(),
                now_ms,
                &wire.event_type,
                content,
                wire.content,
            );
            timeline.mark_send_state(&txn_id, SendState::Sending);
            self.emit(MessengerEvent::TimelineChanged { room_id: room_id.clone() });
        }

        self.send_state.insert(txn_id.clone(), PendingSend { room_id: room_id.clone(), payload, phase: SendPhase::Queued, wire: None });
        let queue = self.pending_sends.entry(room_id).or_default();
        let was_empty = queue.is_empty();
        queue.push_back(txn_id.clone());
        if was_empty {
            self.start_send_pipeline(&txn_id, now_ms)?;
        }
        Ok(())
    }

    /// Re-queues a [`SendPhase::Failed`] send at the back of its room's own
    /// FIFO, reusing its already-computed [`WireSend`] (never re-encrypting
    /// — [`MessengerCommand::RetrySend`]'s own doc). A no-op if `txn_id`
    /// names no currently-failed send in `room_id`.
    fn retry_send(&mut self, room_id: &RoomId, txn_id: &TxnId, now_ms: i64) -> Result<(), MessengerError> {
        let Some(pending) = self.send_state.get(txn_id) else { return Ok(()) };
        if pending.room_id != *room_id || !matches!(pending.phase, SendPhase::Failed { .. }) {
            return Ok(());
        }
        self.set_send_phase(txn_id, SendPhase::Queued);
        let queue = self.pending_sends.entry(room_id.clone()).or_default();
        let was_empty = queue.is_empty();
        queue.push_back(txn_id.clone());
        if was_empty {
            self.start_send_pipeline(txn_id, now_ms)?;
        }
        Ok(())
    }

    fn set_send_phase(&mut self, txn_id: &TxnId, phase: SendPhase) {
        if let Some(entry) = self.send_state.get_mut(txn_id) {
            entry.phase = phase;
        }
    }

    /// Advances `txn_id` (which must currently be the front of its room's
    /// own FIFO) to its next pipeline step. If [`PendingSend::wire`] is
    /// already computed (a retry, or any send re-entering this function
    /// after an earlier step completed), it goes straight to
    /// [`MessengerCore::begin_awaiting_send`] — never re-derived. Otherwise:
    /// a room event ([`SendPayload::Message`]/[`SendPayload::Event`]) in a
    /// currently-encrypted room enters the key pipeline; everything else
    /// builds its plaintext wire body directly.
    fn start_send_pipeline(&mut self, txn_id: &TxnId, now_ms: i64) -> Result<(), MessengerError> {
        let Some(pending) = self.send_state.get(txn_id) else { return Ok(()) };
        let room_id = pending.room_id.clone();

        if pending.wire.is_some() {
            return self.begin_awaiting_send(txn_id, &room_id);
        }

        let is_room_event = pending.payload.is_room_event();
        let encrypted_room = self.rooms.get(&room_id).is_some_and(|room| room.encryption.is_some());

        if is_room_event && encrypted_room {
            self.begin_key_pipeline(txn_id, &room_id, now_ms)
        } else {
            self.build_plaintext_wire_body(txn_id);
            self.begin_awaiting_send(txn_id, &room_id)
        }
    }

    /// Every user this account must consider a Megolm recipient for
    /// `room_id`: every currently join-or-invite member, plus this
    /// account's own user id (its OTHER devices also need the room key —
    /// `crypto::group_sessions`'s own module doc).
    fn encrypted_room_member_ids(&self, room_id: &RoomId) -> BTreeSet<UserId> {
        let mut ids: BTreeSet<UserId> = self
            .rooms
            .get(room_id)
            .map(|state| {
                state
                    .members
                    .iter()
                    .filter(|(_, member)| matches!(member.membership, Membership::Join | Membership::Invite))
                    .map(|(user_id, _)| user_id.clone())
                    .collect()
            })
            .unwrap_or_default();
        ids.insert(self.config.user_id.clone());
        ids
    }

    /// Marks any of `member_ids` this account has never tracked at all as
    /// newly tracked-and-outdated ([`DeviceTracker::on_device_lists`]),
    /// then returns every one of `member_ids` that is currently outdated
    /// (whether it already was, or just became so) — the send pipeline's
    /// own "any member's device list is outdated or unknown" check.
    fn mark_outdated_or_untracked(&mut self, member_ids: &BTreeSet<UserId>) -> Result<Vec<UserId>, MessengerError> {
        let tracked: BTreeMap<UserId, bool> = self.store.tracked_users()?.into_iter().collect();
        let mut outdated = Vec::new();
        let mut newly_tracked = Vec::new();
        for user_id in member_ids {
            match tracked.get(user_id) {
                Some(true) => outdated.push(user_id.clone()),
                Some(false) => {}
                None => newly_tracked.push(user_id.clone()),
            }
        }
        if !newly_tracked.is_empty() {
            DeviceTracker::on_device_lists(&mut self.store, &newly_tracked, &[])?;
            outdated.extend(newly_tracked);
        }
        Ok(outdated)
    }

    /// Every device this store currently has on file for any of
    /// `member_ids`.
    fn known_devices_for(&self, member_ids: &BTreeSet<UserId>) -> Result<Vec<StoredDevice>, MessengerError> {
        let mut all = Vec::new();
        for user_id in member_ids {
            all.extend(DeviceTracker::devices_for_user(&self.store, user_id)?);
        }
        Ok(all)
    }

    /// `known_devices`, filtered down to the devices this pipeline must
    /// actually reach: a current member's, not blocked, not this device's
    /// own.
    fn candidate_recipient_devices(&self, member_ids: &BTreeSet<UserId>, known_devices: &[StoredDevice]) -> Vec<StoredDevice> {
        known_devices
            .iter()
            .filter(|device| member_ids.contains(&device.user_id) && !device.blocked)
            .filter(|device| !(device.user_id == self.config.user_id && device.device_id == self.config.device_id))
            .cloned()
            .collect()
    }

    /// Step 1 of the encrypted-message pipeline (this module's own doc):
    /// if any recipient's device list is outdated or was never tracked at
    /// all, mint one `/keys/query` and wait for it; otherwise fall through
    /// to step 2.
    fn begin_key_pipeline(&mut self, txn_id: &TxnId, room_id: &RoomId, now_ms: i64) -> Result<(), MessengerError> {
        let members = self.encrypted_room_member_ids(room_id);
        let outdated = self.mark_outdated_or_untracked(&members)?;
        if !outdated.is_empty() {
            let request_id = self.next_request_id()?;
            if let Some(request) = DeviceTracker::keys_query_request(&self.store, request_id.clone())? {
                self.send_request_owner.insert(request_id.clone(), txn_id.clone());
                self.enqueue_request(request, Lane::Other)?;
                self.set_send_phase(txn_id, SendPhase::AwaitingKeysQuery);
                return Ok(());
            }
        }
        self.begin_keys_claim_or_share(txn_id, room_id, now_ms)
    }

    /// Step 2: if any recipient candidate has no established Olm session
    /// yet, mint one `/keys/claim` and wait for it; otherwise fall through
    /// to step 3.
    fn begin_keys_claim_or_share(&mut self, txn_id: &TxnId, room_id: &RoomId, now_ms: i64) -> Result<(), MessengerError> {
        let members = self.encrypted_room_member_ids(room_id);
        let known_devices = self.known_devices_for(&members)?;
        let candidates = self.candidate_recipient_devices(&members, &known_devices);
        let missing: Vec<StoredDevice> =
            OlmSessionManager::sessions_missing_for(&self.store, &candidates)?.into_iter().cloned().collect();
        if !missing.is_empty() {
            let request_id = self.next_request_id()?;
            let refs: Vec<&StoredDevice> = missing.iter().collect();
            if let Some(request) = OlmSessionManager::keys_claim_request(request_id.clone(), &refs) {
                self.send_request_owner.insert(request_id.clone(), txn_id.clone());
                self.enqueue_request(request, Lane::Other)?;
                self.set_send_phase(txn_id, SendPhase::AwaitingKeysClaim { devices: missing });
                return Ok(());
            }
        }
        self.begin_share_or_encrypt(txn_id, room_id, now_ms)
    }

    /// Step 3: ensures a current outbound Megolm session, fans out the
    /// room key (Olm to-device) to every not-yet-shared, currently-reachable
    /// device, and waits for every one of those `sendToDevice` calls to
    /// succeed before the room event itself is ever encrypted or sent
    /// (module doc: a share failure fails the whole message, not just the
    /// unreachable device). A device this account still has no Olm session
    /// with after step 2 (a refused/unanswered `/keys/claim`) is left out
    /// of the fan-out rather than failing the send outright — the same
    /// "can't reach everyone, degrade rather than block" doctrine this
    /// crate already applies to an unresolved UTD. If nothing needs
    /// sharing at all (already fully shared, or nobody reachable), falls
    /// straight through to encrypting and sending.
    fn begin_share_or_encrypt(&mut self, txn_id: &TxnId, room_id: &RoomId, now_ms: i64) -> Result<(), MessengerError> {
        let Some(encryption) = self.rooms.get(room_id).and_then(|room| room.encryption.clone()) else {
            self.build_plaintext_wire_body(txn_id);
            return self.begin_awaiting_send(txn_id, room_id);
        };
        let members = self.encrypted_room_member_ids(room_id);
        let known_devices = self.known_devices_for(&members)?;
        let update = GroupSessionManager::ensure_outbound_session(
            &mut self.store,
            room_id,
            &self.config.user_id,
            &self.config.device_id,
            &encryption,
            &members,
            &known_devices,
            now_ms,
        )?;
        let own_keys = self.account.identity_keys();
        GroupSessionManager::adopt_own_outbound_session(
            &mut self.store,
            room_id,
            &self.config.user_id,
            own_keys.curve25519,
            own_keys.ed25519,
            &update,
        )?;

        if let Some(room_key_content) = update.room_key_content.clone() {
            let missing_ids: BTreeSet<(UserId, DeviceId)> = OlmSessionManager::sessions_missing_for(&self.store, &update.new_recipients)?
                .into_iter()
                .map(|device| (device.user_id.clone(), device.device_id.clone()))
                .collect();
            let sessioned: Vec<StoredDevice> = update
                .new_recipients
                .into_iter()
                .filter(|device| !missing_ids.contains(&(device.user_id.clone(), device.device_id.clone())))
                .collect();

            let mut pending_ids = BTreeSet::new();
            for chunk in GroupSessionManager::chunk_recipients_for_send_to_device(&sessioned) {
                let body = GroupSessionManager::build_room_key_send_to_device_body(
                    &mut self.store,
                    &self.account,
                    &self.config.user_id,
                    &self.config.device_id,
                    chunk,
                    &room_key_content,
                )?;
                let request_id = self.next_request_id()?;
                let share_txn = self.next_txn_id()?;
                let request = OutgoingRequest::send_to_device(request_id.clone(), ROOM_KEY_SHARE_EVENT_TYPE, &share_txn, body);
                self.send_request_owner.insert(request_id.clone(), txn_id.clone());
                self.enqueue_request(request, Lane::ToDevice)?;
                pending_ids.insert(request_id);
            }
            if !pending_ids.is_empty() {
                self.set_send_phase(txn_id, SendPhase::AwaitingKeyShare { pending: pending_ids });
                return Ok(());
            }
        }

        self.finish_encrypt_and_send(txn_id, room_id)?;
        self.begin_awaiting_send(txn_id, room_id)
    }

    /// Step 4: Megolm-encrypts a room event under `room_id`'s (now current)
    /// outbound session — the inner type is the event's own (`m.room.message`,
    /// `m.sticker`), the outer is always `m.room.encrypted` — and caches the
    /// resulting [`WireSend::Event`]. A no-op for any other payload kind
    /// (never reached for one, since only a room event in an encrypted room
    /// enters the key pipeline at all).
    fn finish_encrypt_and_send(&mut self, txn_id: &TxnId, room_id: &RoomId) -> Result<(), MessengerError> {
        let Some(wire) = self.send_state.get(txn_id).and_then(|pending| pending.payload.room_event()) else {
            return Ok(());
        };
        let sender_curve = self.account.identity_keys().curve25519.to_base64();
        let encrypted = GroupSessionManager::encrypt_event(
            &mut self.store,
            room_id,
            &sender_curve,
            &self.config.device_id,
            &wire.event_type,
            wire.content,
            wire.relates_to,
        )?;
        let wire_content = serde_json::to_value(RoomEncryptedContent::Megolm(encrypted))?;
        if let Some(entry) = self.send_state.get_mut(txn_id) {
            entry.wire = Some(WireSend::Event { event_type: "m.room.encrypted".to_string(), content: wire_content });
        }
        Ok(())
    }

    /// Builds the plaintext [`WireSend`] for a room event
    /// ([`SendPayload::Message`]/[`SendPayload::Event`]) in an unencrypted
    /// room, a [`SendPayload::Reaction`] (any room), or a
    /// [`SendPayload::Redaction`] (any room) — the cases that never touch the
    /// key pipeline at all.
    fn build_plaintext_wire_body(&mut self, txn_id: &TxnId) {
        let Some(pending) = self.send_state.get(txn_id) else { return };
        let wire = match &pending.payload {
            SendPayload::Message(_) | SendPayload::Event { .. } => match pending.payload.room_event() {
                Some(room_event) => WireSend::Event { event_type: room_event.event_type, content: room_event.content },
                None => return,
            },
            SendPayload::Reaction { target, key } => WireSend::Event {
                event_type: "m.reaction".to_string(),
                content: serde_json::json!({
                    "m.relates_to": { "rel_type": "m.annotation", "event_id": target.as_str(), "key": key }
                }),
            },
            SendPayload::Redaction { target, reason } => WireSend::Redact { target: target.clone(), reason: reason.clone() },
        };
        if let Some(entry) = self.send_state.get_mut(txn_id) {
            entry.wire = Some(wire);
        }
    }

    /// Mints (or re-mints, for a retry) the actual `PUT .../send/...` or
    /// `PUT .../redact/...` request from [`PendingSend::wire`], on this
    /// room's own [`Lane::Room`] (preserves the room's own send order —
    /// this crate's `outgoing_queue`'s own doc).
    fn begin_awaiting_send(&mut self, txn_id: &TxnId, room_id: &RoomId) -> Result<(), MessengerError> {
        let Some(wire) = self.send_state.get(txn_id).and_then(|pending| pending.wire.clone()) else { return Ok(()) };
        let request_id = self.next_request_id()?;
        let request = match &wire {
            WireSend::Event { event_type, content } => {
                OutgoingRequest::room_send(request_id.clone(), room_id, event_type, txn_id, content.clone())
            }
            WireSend::Redact { target, reason } => {
                let body = match reason {
                    Some(reason) => serde_json::json!({ "reason": reason }),
                    None => serde_json::json!({}),
                };
                OutgoingRequest::room_redact(request_id.clone(), room_id, target, txn_id, body)
            }
        };
        self.send_request_owner.insert(request_id, txn_id.clone());
        self.enqueue_request(request, Lane::Room(room_id.clone()))?;
        self.set_send_phase(txn_id, SendPhase::AwaitingSend);
        Ok(())
    }

    /// Routes one successful response for a request this send pipeline
    /// itself minted onward to whatever step comes next. A no-op for any
    /// `kind` this pipeline never mints on its own behalf (defensive —
    /// every `send_request_owner` entry is inserted alongside a specific
    /// kind, this match is exhaustive over that set).
    fn advance_send_on_success(
        &mut self,
        txn_id: &TxnId,
        request_id: &RequestId,
        kind: Option<OutgoingRequestKind>,
        response: &HttpResponseDescriptor,
        now_ms: i64,
    ) {
        match kind {
            Some(OutgoingRequestKind::KeysQuery) => {
                let Some(room_id) = self.send_state.get(txn_id).map(|pending| pending.room_id.clone()) else { return };
                let _ = self.begin_keys_claim_or_share(txn_id, &room_id, now_ms);
            }
            Some(OutgoingRequestKind::KeysClaim) => {
                let Some(pending) = self.send_state.get(txn_id) else { return };
                let room_id = pending.room_id.clone();
                if let SendPhase::AwaitingKeysClaim { devices, .. } = &pending.phase {
                    let devices = devices.clone();
                    let refs: Vec<&StoredDevice> = devices.iter().collect();
                    let _ = OlmSessionManager::on_keys_claim_response(&mut self.store, &self.account, &refs, &response.body);
                }
                let _ = self.begin_share_or_encrypt(txn_id, &room_id, now_ms);
            }
            Some(OutgoingRequestKind::SendToDevice) => {
                let mut remaining = None;
                if let Some(entry) = self.send_state.get_mut(txn_id) {
                    if let SendPhase::AwaitingKeyShare { pending } = &mut entry.phase {
                        pending.remove(request_id);
                        remaining = Some(pending.len());
                    }
                }
                if remaining == Some(0) {
                    let Some(room_id) = self.send_state.get(txn_id).map(|pending| pending.room_id.clone()) else { return };
                    let _ = self.finish_encrypt_and_send(txn_id, &room_id);
                    let _ = self.begin_awaiting_send(txn_id, &room_id);
                }
            }
            Some(OutgoingRequestKind::RoomSend) | Some(OutgoingRequestKind::RoomRedact) => {
                self.complete_send_success(txn_id, response, now_ms);
            }
            _ => {}
        }
    }

    /// The room event/redaction itself succeeded: for a room event
    /// ([`SendPayload::Message`]/[`SendPayload::Event`]), attaches the
    /// server-confirmed event id to its echo (module doc: "200 -> store `event_id` on the echo
    /// (`SendState::Sent`)"); either way, removes this send's own
    /// bookkeeping and starts the room's next queued send, if any.
    fn complete_send_success(&mut self, txn_id: &TxnId, response: &HttpResponseDescriptor, now_ms: i64) {
        let Some(pending) = self.send_state.get(txn_id) else { return };
        let room_id = pending.room_id.clone();
        if pending.payload.is_room_event() {
            if let Ok(body) = serde_json::from_slice::<SendResponseBody>(&response.body) {
                if let Some(timeline) = self.timelines.get_mut(&room_id) {
                    timeline.set_echo_event_id(txn_id, body.event_id);
                }
                self.emit(MessengerEvent::TimelineChanged { room_id: room_id.clone() });
            }
        }
        self.send_state.remove(txn_id);
        self.finish_active_send(&room_id, txn_id, now_ms);
    }

    /// A step in `txn_id`'s own pipeline failed outright (a non-retryable
    /// 4xx anywhere along it): marks a room event's echo
    /// [`SendState::Failed`], moves this send to the terminal
    /// [`SendPhase::Failed`] (kept, not removed — [`MessengerCommand::RetrySend`]
    /// needs it), and starts the room's next queued send, if any.
    fn fail_send(&mut self, txn_id: &TxnId, errcode: String, now_ms: i64) {
        let Some(pending) = self.send_state.get(txn_id) else { return };
        let room_id = pending.room_id.clone();
        if pending.payload.is_room_event() {
            if let Some(timeline) = self.timelines.get_mut(&room_id) {
                timeline.mark_send_state(txn_id, SendState::Failed { reason: errcode.clone() });
            }
            self.emit(MessengerEvent::TimelineChanged { room_id: room_id.clone() });
        }
        self.set_send_phase(txn_id, SendPhase::Failed { errcode });
        self.finish_active_send(&room_id, txn_id, now_ms);
    }

    /// Pops `txn_id` off the front of `room_id`'s own send FIFO (if that is
    /// where it still is) and starts the next queued send's pipeline, if
    /// any — the "one message's pipeline completes before the next ... is
    /// encrypted" ordering rule, enforced structurally by never starting
    /// entry N+1 before entry N reaches a terminal state.
    fn finish_active_send(&mut self, room_id: &RoomId, txn_id: &TxnId, now_ms: i64) {
        if let Some(queue) = self.pending_sends.get_mut(room_id) {
            if queue.front() == Some(txn_id) {
                queue.pop_front();
            } else {
                queue.retain(|id| id != txn_id);
            }
        }
        let next = self.pending_sends.get(room_id).and_then(|queue| queue.front().cloned());
        if let Some(next_txn) = next {
            let _ = self.start_send_pipeline(&next_txn, now_ms);
        }
    }

    /// A shell calls this once per tick, executes each, and feeds the
    /// result back via [`MessengerCore::on_response`]/
    /// [`MessengerCore::on_transport_error`]. Also where the next `/sync`
    /// request is minted, if none is currently outstanding (this module's
    /// own doc).
    ///
    /// **One-shot per request: never discard a non-empty result.** Every
    /// [`OutgoingRequest`] this call returns is marked in flight by
    /// [`crate::outgoing_queue::OutgoingQueue::releasable`] as a side
    /// effect of being returned — it will not be offered again until a
    /// matching [`MessengerCore::on_response`]/
    /// [`MessengerCore::on_transport_error`] call clears that flag. A
    /// caller that calls this method purely to trigger the mint side
    /// effect (e.g. to force a freshly-dirtied `/sync` request's own flush
    /// epoch open before deciding whether to act) and then throws the
    /// return value away strands every request in that batch permanently
    /// in flight, since nothing else will ever release it. Call this
    /// exactly once per tick, and always drive every request it returns
    /// through to a response.
    pub fn releasable_requests(&mut self, now_ms: i64) -> Vec<OutgoingRequest> {
        self.ensure_sync_enqueued();
        self.outgoing.releasable(&self.store, now_ms)
    }

    fn ensure_sync_enqueued(&mut self) {
        if self.sync_request_id.is_some() {
            return;
        }
        let Ok(request_id) = self.next_request_id() else { return };
        let since = self.store.sync_token().ok().flatten().map(str::to_string);
        // The first `/sync` of a session must never long-poll. An initial
        // sync (no `since`) is answered at once by Synapse whatever `timeout`
        // says, but a server that treats a brand-new, still-empty account's
        // initial view as "nothing new" holds it for the full timeout -- and
        // this core publishes its device keys only once that first response
        // has landed. A resumed session (persisted `since`) has the same
        // need: the catch-up answer must not wait for news that may never
        // come. Live run, 2026-09-29: fresh accounts sat 30 s before their
        // keys went up.
        let timeout_ms = if since.is_some() && self.sync_caught_up { SYNC_TIMEOUT_MS } else { 0 };
        let request = OutgoingRequest::sync(request_id.clone(), since.as_deref(), Some(timeout_ms));
        if self.enqueue_request(request, Lane::Sync).is_ok() {
            self.sync_request_id = Some(request_id);
        }
    }

    /// Feeds one HTTP response back in, keyed by the id the original
    /// [`OutgoingRequest`] carried. Returns whatever became visible as a
    /// direct result of processing it (equivalent to calling
    /// [`MessengerCore::events`] immediately afterwards — there is exactly
    /// one underlying event queue behind both).
    pub fn on_response(&mut self, request_id: RequestId, resp: HttpResponseDescriptor, now_ms: i64) -> Vec<MessengerEvent> {
        let kind = self.pending_kinds.get(&request_id).copied();
        let room_messages_room = self.pending_room_messages.get(&request_id).cloned();
        let create_room_kind = self.pending_create_room.get(&request_id).cloned();
        let send_owner = self.send_request_owner.get(&request_id).cloned();

        let outcome = self.outgoing.on_response(&mut self.store, &request_id, resp, now_ms, self.jitter.as_mut());
        let (is_terminal, terminal_response, failed_errcode) = match outcome {
            Ok(Some(ResponseOutcome::Done(response))) => (true, Some(response), None),
            Ok(Some(ResponseOutcome::Failed { errcode, .. })) => (true, None, Some(errcode)),
            _ => (false, None, None),
        };

        if is_terminal {
            self.pending_kinds.remove(&request_id);
            if matches!(kind, Some(OutgoingRequestKind::Sync)) {
                self.sync_request_id = None;
                if terminal_response.is_some() {
                    self.sync_caught_up = true;
                }
            }
            if room_messages_room.is_some() {
                self.pending_room_messages.remove(&request_id);
            }
            self.pending_create_room.remove(&request_id);
            self.send_request_owner.remove(&request_id);
            if let Some(key) = self.account_data_write_keys.remove(&request_id) {
                self.settle_account_data_write(&key, terminal_response.is_some());
            }
        }

        if let Some(response) = &terminal_response {
            // A parse/logic failure against an otherwise-successful HTTP
            // response is dropped, not applied: the one invariant that
            // matters -- never advancing past a partially-applied `/sync` --
            // holds structurally, since `ingest_sync` only persists the new
            // sync token as its very last step. The failure is kept for
            // [`MessengerCore::take_ingest_error`] so a shell can show it.
            if let Err(error) = self.handle_terminal_success(&request_id, kind, room_messages_room, create_room_kind, response) {
                self.ingest_error = Some(match kind {
                    Some(kind) => format!("{kind:?} response not ingested: {error}"),
                    None => format!("response not ingested: {error}"),
                });
            }
        }

        if let Some(txn_id) = send_owner {
            if let Some(response) = &terminal_response {
                self.advance_send_on_success(&txn_id, &request_id, kind, response, now_ms);
            } else if let Some(errcode) = failed_errcode {
                self.fail_send(&txn_id, errcode, now_ms);
            }
        }

        self.drain_events()
    }

    /// Feeds a transport-level failure back in (a timeout, a connection
    /// reset, ...) — always resolves to a retry with this core's own
    /// backoff (`crate::outgoing_queue`'s own doc); a no-op if `request_id`
    /// is not (or no longer) pending.
    pub fn on_transport_error(&mut self, request_id: &RequestId, now_ms: i64) {
        let _ = self.outgoing.on_transport_error(request_id, now_ms, self.jitter.as_mut());
    }

    fn handle_terminal_success(
        &mut self,
        request_id: &RequestId,
        kind: Option<OutgoingRequestKind>,
        room_messages_room: Option<RoomId>,
        create_room_kind: Option<CreateRoomKind>,
        response: &HttpResponseDescriptor,
    ) -> Result<(), MessengerError> {
        match kind {
            Some(OutgoingRequestKind::Sync) => {
                let parsed = parse_sync_response(&response.body)?;
                self.ingest_sync(&parsed)?;
            }
            Some(OutgoingRequestKind::KeysUpload) => {
                self.account.on_keys_upload_response(&mut self.store)?;
            }
            Some(OutgoingRequestKind::KeysQuery) => {
                let outcome = DeviceTracker::on_keys_query_response(&mut self.store, &response.body)?;
                for change in outcome.key_changes {
                    self.emit(MessengerEvent::DeviceKeyChanged { user_id: change.user_id, device_id: change.device_id });
                }
                self.retry_unknown_sender_queue()?;
            }
            Some(OutgoingRequestKind::RoomMessages) => {
                if let Some(room_id) = room_messages_room {
                    self.ingest_room_messages_response(&room_id, &response.body)?;
                }
            }
            Some(OutgoingRequestKind::CreateRoom) => {
                if let Some(kind) = create_room_kind {
                    self.on_create_room_response(kind, response)?;
                }
            }
            // A response to a search this account has already moved past (a
            // later `SearchPublicRooms` was dispatched since) fails the
            // guard and is dropped -- only the LATEST search's own result
            // set is ever visible (this module's own doc).
            Some(OutgoingRequestKind::PublicRooms) if self.latest_public_rooms_request.as_ref() == Some(request_id) => {
                let body: PublicRoomsResponseBody = serde_json::from_slice(&response.body)?;
                self.public_rooms_result = body
                    .chunk
                    .into_iter()
                    .map(|entry| PublicRoomsResultEntry {
                        room_id: entry.room_id,
                        name: entry.name,
                        topic: entry.topic,
                        num_joined_members: entry.num_joined_members,
                    })
                    .collect();
                self.emit(MessengerEvent::PublicRoomsChanged);
            }
            // Same supersession rule as `PublicRooms` above.
            Some(OutgoingRequestKind::UserDirectorySearch) if self.latest_user_search_request.as_ref() == Some(request_id) => {
                let body: UserDirectorySearchResponseBody = serde_json::from_slice(&response.body)?;
                self.user_search_result = body
                    .results
                    .into_iter()
                    .map(|entry| UserDirectoryResultEntry { user_id: entry.user_id, display_name: entry.display_name })
                    .collect();
                self.emit(MessengerEvent::UserSearchChanged);
            }
            _ => {}
        }
        Ok(())
    }

    /// A `POST /createRoom` succeeded. For [`CreateRoomKind::Dm`], also
    /// merges the new room into this account's own `m.direct` account data
    /// (M13b send-pipeline doc: "DM also merges `m.direct` account data")
    /// — every other kind needs nothing further here (room state/timeline
    /// populate off the next `/sync`, same as any other room).
    fn on_create_room_response(&mut self, kind: CreateRoomKind, response: &HttpResponseDescriptor) -> Result<(), MessengerError> {
        let CreateRoomKind::Dm { peer } = kind else { return Ok(()) };
        let body: CreateRoomResponseBody = serde_json::from_slice(&response.body)?;
        self.merge_direct_account_data(body.room_id, peer)
    }

    /// Merges `room_id` into this account's own `m.direct` account data
    /// under `peer`, optimistically, then sends the full updated value
    /// (the account-data endpoint replaces the whole value, same as
    /// [`MessengerCore::enqueue_tag_update`]'s own doc). Shared by
    /// [`MessengerCore::on_create_room_response`] (the CREATOR side of a
    /// [`CreateRoomKind::Dm`]) and [`MessengerCommand::JoinRoom`]'s own
    /// dispatch arm (the INVITEE side, this module's own doc: a DM
    /// invite's `is_direct` flag is not carried forward once THIS
    /// account's own join overwrites that membership event, so `m.direct`
    /// is the only durable "this is a DM" signal this account keeps of
    /// its own past that point).
    fn merge_direct_account_data(&mut self, room_id: RoomId, peer: UserId) -> Result<(), MessengerError> {
        let mut direct = self.direct_account_data.clone().unwrap_or_default();
        let rooms_for_peer = direct.0.entry(peer).or_default();
        if !rooms_for_peer.contains(&room_id) {
            rooms_for_peer.push(room_id);
        }
        let value = serde_json::to_value(&direct)?;
        self.write_account_data(None, "m.direct".to_string(), value)
    }

    fn cached_account_data(&self, key: &AccountDataKey) -> Option<&serde_json::Value> {
        match &key.0 {
            Some(room_id) => self.room_account_data(room_id, &key.1),
            None => self.global_account_data(&key.1),
        }
    }

    /// Sets (`Some`) or removes (`None`) the cached value for `key`,
    /// keeping the typed `m.direct` view in step with it.
    fn store_account_data_cache(&mut self, key: &AccountDataKey, value: Option<serde_json::Value>) {
        if key.0.is_none() && key.1 == "m.direct" {
            self.direct_account_data = value.as_ref().and_then(|v| serde_json::from_value::<DirectContent>(v.clone()).ok());
        }
        match (&key.0, value) {
            (None, Some(v)) => {
                self.global_account_data.insert(key.1.clone(), v);
            }
            (None, None) => {
                self.global_account_data.remove(&key.1);
            }
            (Some(room_id), Some(v)) => {
                self.room_account_data.entry(room_id.clone()).or_default().insert(key.1.clone(), v);
            }
            (Some(room_id), None) => {
                if let Some(by_type) = self.room_account_data.get_mut(room_id) {
                    by_type.remove(&key.1);
                }
            }
        }
    }

    /// The one path every account-data write takes: builds the PUT, applies
    /// `value` to the cache optimistically (the next edit builds on it),
    /// guards the key against stale `/sync` echoes for as long as the
    /// write is outstanding ([`AccountDataGuard`]), and queues it on the
    /// strictly ordered [`Lane::AccountData`].
    fn write_account_data(&mut self, room_id: Option<RoomId>, event_type: String, value: serde_json::Value) -> Result<(), MessengerError> {
        let request_id = self.next_request_id()?;
        let request = match &room_id {
            Some(room_id) => OutgoingRequest::room_account_data(request_id.clone(), &self.config.user_id, room_id, &event_type, value.clone()),
            None => OutgoingRequest::account_data(request_id.clone(), &self.config.user_id, &event_type, value.clone()),
        };
        let key: AccountDataKey = (room_id, event_type);
        let known = self.cached_account_data(&key).cloned();
        let guard = self.account_data_guard.entry(key.clone()).or_insert(AccountDataGuard { pending: 0, server_value: known });
        guard.pending += 1;
        self.store_account_data_cache(&key, Some(value));
        match self.enqueue_request(request, Lane::AccountData) {
            Ok(()) => {
                self.account_data_write_keys.insert(request_id, key);
                Ok(())
            }
            Err(error) => {
                self.settle_account_data_write(&key, false);
                Err(error)
            }
        }
    }

    /// One outstanding write for `key` reached its end (`succeeded`: a 2xx;
    /// otherwise a terminal failure). Once the last one settles, a failure
    /// restores the server's value over the now-wrong optimistic cache and
    /// tells the UI to re-render; a success keeps the optimistic value.
    fn settle_account_data_write(&mut self, key: &AccountDataKey, succeeded: bool) {
        let Some(guard) = self.account_data_guard.get_mut(key) else { return };
        guard.pending = guard.pending.saturating_sub(1);
        if guard.pending > 0 {
            return;
        }
        let Some(guard) = self.account_data_guard.remove(key) else { return };
        if !succeeded {
            self.store_account_data_cache(key, guard.server_value);
            self.emit(MessengerEvent::RoomsChanged);
        }
    }

    /// Folds one account-data event `/sync` reported into the cache -- or,
    /// while writes for the same key are outstanding, only into that key's
    /// [`AccountDataGuard::server_value`].
    fn apply_synced_account_data(&mut self, room_id: Option<&RoomId>, event_type: &str, content: serde_json::Value) {
        let key: AccountDataKey = (room_id.cloned(), event_type.to_string());
        if let Some(guard) = self.account_data_guard.get_mut(&key) {
            guard.server_value = Some(content);
            return;
        }
        self.store_account_data_cache(&key, Some(content));
    }

    /// Drains everything dirtied since the previous call into one
    /// [`FlushBatch`] for a shell to write durably.
    pub fn take_flush_batch(&mut self) -> Option<FlushBatch> {
        if let Some(batch) = self.pending_flush_batches.pop_front() {
            return Some(batch);
        }
        self.store.take_flush_batch()
    }

    /// Acknowledges that batch `id` has been durably written.
    pub fn ack_flush(&mut self, id: u64) {
        self.store.ack_flush(id);
    }

    /// Drains every [`MessengerEvent`] queued since the last call to this
    /// method or to [`MessengerCore::on_response`].
    pub fn events(&mut self) -> Vec<MessengerEvent> {
        self.drain_events()
    }

    /// The last response this core failed to ingest, once (cleared by
    /// reading it) -- see the `ingest_error` field's own doc.
    pub fn take_ingest_error(&mut self) -> Option<String> {
        self.ingest_error.take()
    }

    /// Monotonically increasing count of visible changes — a cheap
    /// "did anything change at all since I last checked" signal for a
    /// provider that only wants to know whether to re-read its snapshot
    /// getters, without keeping its own copy of every [`MessengerEvent`].
    pub fn change_counter(&self) -> u64 {
        self.change_counter
    }

    /// Every room this core currently holds state for.
    pub fn room_ids(&self) -> impl Iterator<Item = &RoomId> {
        self.rooms.keys()
    }

    /// `room_id`'s current state, if this core has one.
    pub fn room_state(&self, room_id: &RoomId) -> Option<&RoomState> {
        self.rooms.get(room_id)
    }

    /// `room_id`'s current timeline, if this core has one.
    pub fn timeline(&self, room_id: &RoomId) -> Option<&Timeline> {
        self.timelines.get(room_id)
    }

    /// `room_id`'s derived [`RoomKind`] (plan manager decision #5's DM/
    /// channel/group precedence), using this core's current global
    /// `m.direct` account data.
    pub fn room_kind(&self, room_id: &RoomId) -> Option<RoomKind> {
        self.rooms.get(room_id).map(|state| state.derive_room_kind(room_id, self.direct_account_data.as_ref()))
    }

    /// Every user currently typing in `room_id`, per the most recent
    /// `/sync` ephemeral batch — empty if none, or if this core has never
    /// seen a typing event for this room.
    pub fn typing_users(&self, room_id: &RoomId) -> &[UserId] {
        self.typing.get(room_id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// `room_id`'s most recently received `m.receipt` account data, if any.
    pub fn receipts(&self, room_id: &RoomId) -> Option<&ReceiptContent> {
        self.receipts.get(room_id)
    }

    /// One piece of `room_id`'s room-scoped account data (e.g.
    /// `"m.fully_read"`), if this core has seen one.
    pub fn room_account_data(&self, room_id: &RoomId, event_type: &str) -> Option<&serde_json::Value> {
        self.room_account_data.get(room_id).and_then(|by_type| by_type.get(event_type))
    }

    /// One piece of this account's own global account data, if this core
    /// has seen one.
    pub fn global_account_data(&self, event_type: &str) -> Option<&serde_json::Value> {
        self.global_account_data.get(event_type)
    }

    /// This account's own user id, exactly as configured at
    /// [`MessengerCore::open`] -- a UI-facing adapter needs this to tell
    /// its own account apart from every other room member (a DM's peer, a
    /// reaction's `by_me`, a typing-user list minus self, ...).
    pub fn user_id(&self) -> &UserId {
        &self.config.user_id
    }

    /// Whether this core currently has at least one verified device on
    /// file for `user_id` (`/keys/query` results already persisted by
    /// [`crate::crypto::device_tracker::DeviceTracker`]) -- a UI-facing
    /// adapter's own "has a messaging key" check for a member list, without
    /// duplicating that module's storage format.
    pub fn has_tracked_device(&self, user_id: &UserId) -> bool {
        DeviceTracker::devices_for_user(&self.store, user_id).map(|devices| !devices.is_empty()).unwrap_or(false)
    }

    /// The latest [`MessengerCommand::SearchPublicRooms`] result set, empty
    /// until one has landed.
    pub fn public_rooms_result(&self) -> &[PublicRoomsResultEntry] {
        &self.public_rooms_result
    }

    /// The latest [`MessengerCommand::SearchUsers`] result set, empty until
    /// one has landed.
    pub fn user_search_result(&self) -> &[UserDirectoryResultEntry] {
        &self.user_search_result
    }

    /// The Matrix `errcode` a failed send (`txn_id`) ended with, if
    /// `txn_id` currently names a [`crate::room::timeline::SendState::Failed`]
    /// send this core is still tracking — `None` for a send that never
    /// failed, already succeeded, or that this core has never seen.
    pub fn send_failure_reason(&self, txn_id: &TxnId) -> Option<&str> {
        match self.send_state.get(txn_id).map(|pending| &pending.phase) {
            Some(SendPhase::Failed { errcode }) => Some(errcode.as_str()),
            _ => None,
        }
    }

    /// The "in" edge — mailbox command (single-writer-core doctrine's Law
    /// 3). See [`MessengerCommand`]'s own doc for every variant this piece
    /// implements. `now_ms` is this call's own clock reading (this crate's
    /// "no clock inside" rule) — used for a fresh send's local-echo
    /// timestamp, [`MessengerCommand::SetTyping`]'s debounce window, and
    /// Megolm rotation timing.
    pub fn dispatch(&mut self, cmd: MessengerCommand, now_ms: i64) -> Result<(), MessengerError> {
        match cmd {
            MessengerCommand::SendMessage { room_id, message, txn_id } => {
                if let Some(edit_of) = &message.edit_of {
                    let owned = self
                        .timelines
                        .get(&room_id)
                        .and_then(|timeline| timeline.item_by_event_id(edit_of))
                        .is_some_and(|item| item.sender == self.config.user_id);
                    if !owned {
                        return Err(MessengerError::EditNotOwned { event_id: edit_of.clone() });
                    }
                }
                self.start_new_send(room_id, SendPayload::Message(message), txn_id, now_ms)?;
            }
            MessengerCommand::Forward { from_room, event_id, to_room, txn_id } => {
                let payload = self.build_forward_payload(&from_room, &event_id, &to_room)?;
                self.start_new_send(to_room, payload, txn_id, now_ms)?;
            }
            MessengerCommand::React { room_id, target, key } => {
                self.start_new_send(room_id, SendPayload::Reaction { target, key }, None, now_ms)?;
            }
            MessengerCommand::Redact { room_id, target, reason } => {
                self.start_new_send(room_id, SendPayload::Redaction { target, reason }, None, now_ms)?;
            }
            MessengerCommand::RetrySend { room_id, txn_id } => {
                self.retry_send(&room_id, &txn_id, now_ms)?;
            }
            MessengerCommand::CreateRoom { kind } => {
                self.dispatch_create_room(kind)?;
            }
            MessengerCommand::JoinRoom { room_id } => {
                let request_id = self.next_request_id()?;
                let request = OutgoingRequest::join_room(request_id, room_id.as_str());
                self.enqueue_request(request, Lane::Other)?;

                // A DM invite's `is_direct` flag lives on this account's own
                // invite membership event and is overwritten by the join
                // itself, so accepting it records the room in this account's
                // own `m.direct` (same as the creator side does on
                // `/createRoom`) -- otherwise the invitee's room kind falls
                // back to Group once the join lands.
                let dm_peer = self.rooms.get(&room_id).and_then(|room| {
                    let invited_as_direct = room.members.get(&self.config.user_id).is_some_and(|member| member.is_direct);
                    if !invited_as_direct {
                        return None;
                    }
                    room.members.keys().find(|user_id| **user_id != self.config.user_id).cloned()
                });
                if let Some(peer) = dm_peer {
                    self.merge_direct_account_data(room_id, peer)?;
                }
            }
            MessengerCommand::LeaveRoom { room_id } => {
                let request_id = self.next_request_id()?;
                let request = OutgoingRequest::leave_room(request_id, &room_id);
                self.enqueue_request(request, Lane::Other)?;
            }
            MessengerCommand::Invite { room_id, user_id } => {
                let request_id = self.next_request_id()?;
                let request = OutgoingRequest::invite(request_id, &room_id, &user_id);
                self.enqueue_request(request, Lane::Other)?;
            }
            MessengerCommand::Kick { room_id, user_id, reason } => {
                let request_id = self.next_request_id()?;
                let request = OutgoingRequest::kick(request_id, &room_id, &user_id, reason.as_deref());
                self.enqueue_request(request, Lane::Other)?;
            }
            MessengerCommand::SetTag { room_id, tag, order } => {
                let mut content = self.current_tag_content(&room_id);
                content.tags.insert(tag, TagInfo { order });
                self.enqueue_tag_update(room_id, content)?;
            }
            MessengerCommand::RemoveTag { room_id, tag } => {
                let mut content = self.current_tag_content(&room_id);
                content.tags.remove(&tag);
                self.enqueue_tag_update(room_id, content)?;
            }
            MessengerCommand::MarkRead { room_id, event_id } => {
                let request_id = self.next_request_id()?;
                let body = serde_json::json!({ "m.fully_read": event_id.as_str(), "m.read": event_id.as_str() });
                let request = OutgoingRequest::read_markers(request_id, &room_id, body);
                self.enqueue_request(request, Lane::Other)?;
            }
            MessengerCommand::SetTyping { room_id, typing } => {
                if typing {
                    let should_send = match self.typing_debounce.get(&room_id) {
                        Some(&last_sent_ms) => now_ms.saturating_sub(last_sent_ms) >= TYPING_DEBOUNCE_MS,
                        None => true,
                    };
                    if !should_send {
                        return Ok(());
                    }
                    self.typing_debounce.insert(room_id.clone(), now_ms);
                } else {
                    self.typing_debounce.remove(&room_id);
                }
                let request_id = self.next_request_id()?;
                let timeout_ms = typing.then_some(TYPING_TIMEOUT_MS);
                let request = OutgoingRequest::typing(request_id, &room_id, &self.config.user_id, typing, timeout_ms);
                self.enqueue_request(request, Lane::Other)?;
            }
            MessengerCommand::RetryDecryption { room_id, event_id } => {
                if self.retry_decrypt_one(&room_id, &event_id) {
                    self.emit(MessengerEvent::TimelineChanged { room_id });
                }
            }
            MessengerCommand::LoadOlder { room_id } => {
                let from = self
                    .timelines
                    .get(&room_id)
                    .and_then(|timeline| {
                        timeline
                            .older_token()
                            .map(str::to_string)
                            .or_else(|| timeline.gap().and_then(|gap| gap.prev_batch.clone()))
                    })
                    // A known room with no pagination token yet -- a resumed
                    // session, whose timelines are not persisted and whose
                    // first `/sync` carries only what is new -- pages back
                    // from its own sync position (a `/sync` `next_batch` token
                    // is a valid `/messages` `from`).
                    .or_else(|| {
                        if self.rooms.contains_key(&room_id) {
                            self.store.sync_token().ok().flatten().map(str::to_string)
                        } else {
                            None
                        }
                    });
                let Some(from) = from else { return Ok(()) };
                let request_id = self.next_request_id()?;
                let request =
                    OutgoingRequest::room_messages(request_id.clone(), &room_id, &from, "b", Some(LOAD_OLDER_PAGE_SIZE));
                self.enqueue_request(request, Lane::Room(room_id.clone()))?;
                self.pending_room_messages.insert(request_id, room_id);
            }
            MessengerCommand::SetAccountData { event_type, content } => {
                self.write_account_data(None, event_type, content)?;
            }
            MessengerCommand::SetRoomAccountData { room_id, event_type, content } => {
                self.write_account_data(Some(room_id), event_type, content)?;
            }
            MessengerCommand::SearchPublicRooms { term } => {
                let request_id = self.next_request_id()?;
                let body = serde_json::json!({ "filter": { "generic_search_term": term }, "limit": 50 });
                let request = OutgoingRequest::public_rooms(request_id.clone(), body);
                self.latest_public_rooms_request = Some(request_id);
                self.enqueue_request(request, Lane::Other)?;
            }
            MessengerCommand::SearchUsers { term } => {
                let request_id = self.next_request_id()?;
                let body = serde_json::json!({ "search_term": term, "limit": 20 });
                let request = OutgoingRequest::user_directory_search(request_id.clone(), body);
                self.latest_user_search_request = Some(request_id);
                self.enqueue_request(request, Lane::Other)?;
            }
        }
        Ok(())
    }

    /// `POST /createRoom`'s own body per [`CreateRoomKind`] (server plan
    /// §5: the server derives `kind`/power levels from `visibility`+
    /// `is_direct` itself — a client only ever sends those two fields plus
    /// `invite`/`name`/`topic`).
    fn dispatch_create_room(&mut self, kind: CreateRoomKind) -> Result<(), MessengerError> {
        let body = match &kind {
            CreateRoomKind::Dm { peer } => serde_json::json!({
                "is_direct": true,
                "invite": [peer.as_str()],
            }),
            CreateRoomKind::Group { name, invite, members_can_invite } => serde_json::json!({
                "visibility": "private",
                "is_direct": false,
                "name": name,
                "invite": invite.iter().map(UserId::as_str).collect::<Vec<_>>(),
                "members_can_invite": members_can_invite,
            }),
            CreateRoomKind::Channel { name, topic } => {
                let mut value = serde_json::json!({
                    "visibility": "public",
                    "is_direct": false,
                    "name": name,
                });
                if let Some(topic) = topic {
                    value["topic"] = serde_json::Value::String(topic.clone());
                }
                value
            }
        };
        let request_id = self.next_request_id()?;
        let request = OutgoingRequest::create_room(request_id.clone(), body);
        self.pending_create_room.insert(request_id.clone(), kind);
        self.enqueue_request(request, Lane::Other)?;
        Ok(())
    }

    /// `room_id`'s current `m.tag` content, or an empty one if this core
    /// has never seen one — [`MessengerCommand::SetTag`]/`RemoveTag` both
    /// mutate a full copy of this (the account-data endpoint replaces the
    /// whole value, there is no partial-update verb).
    fn current_tag_content(&self, room_id: &RoomId) -> TagContent {
        self.room_account_data(room_id, "m.tag")
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .unwrap_or_default()
    }

    /// Optimistic and guarded like every account-data write
    /// ([`MessengerCore::write_account_data`]): the very next tag edit must
    /// build on THIS content, not on whatever `/sync` last echoed, or two
    /// back-to-back edits would each start from the same stale copy and the
    /// later PUT would drop the earlier one's change.
    fn enqueue_tag_update(&mut self, room_id: RoomId, content: TagContent) -> Result<(), MessengerError> {
        let value = serde_json::to_value(&content)?;
        self.write_account_data(Some(room_id), "m.tag".to_string(), value)
    }

    /// The [`SendPayload::Event`] a [`MessengerCommand::Forward`] sends: the
    /// source item's current decrypted content, stripped and marked
    /// ([`forwardable_content`]) per that command's own rules, or the
    /// refusal naming `event_id`.
    fn build_forward_payload(
        &self,
        from_room: &RoomId,
        event_id: &EventId,
        to_room: &RoomId,
    ) -> Result<SendPayload, MessengerError> {
        let refuse = |reason: &dyn std::fmt::Display| {
            MessengerError::IntentRefused(format!("cannot forward {event_id} from {from_room}: {reason}"))
        };
        if !self.rooms.contains_key(to_room) {
            return Err(refuse(&format!("the target room {to_room} is unknown")));
        }
        let source = match self.timelines.get(from_room) {
            Some(timeline) => timeline.forward_source(event_id),
            None => Err(ForwardRefusal::Missing),
        }
        .map_err(|reason| refuse(&reason))?;
        let (marker_key, marker) = self.forward_marker(from_room);
        Ok(SendPayload::Event {
            event_type: source.event_type,
            content: forwardable_content(source.content, marker_key, marker),
        })
    }

    /// The marker a forward out of `from_room` carries: the bare `forwarded:
    /// true` unless that room is positively known to be unencrypted, in which
    /// case `forwarded_from` names it. An unknown room is treated as
    /// encrypted -- the fail-safe direction.
    fn forward_marker(&self, from_room: &RoomId) -> (&'static str, serde_json::Value) {
        let public = self.rooms.get(from_room).is_some_and(|room| room.encryption.is_none());
        if public {
            let room_name = self.forward_room_name(from_room);
            (KEY_FORWARDED_FROM, serde_json::json!({ "room_id": from_room.as_str(), "room_name": room_name }))
        } else {
            (KEY_FORWARDED, serde_json::Value::Bool(true))
        }
    }

    /// `room_id`'s name as a forward attribution: its `m.room.name`, or a
    /// generic label by kind. Never the members' names an unnamed room's
    /// chat-list row would list -- an attribution goes to third parties.
    fn forward_room_name(&self, room_id: &RoomId) -> String {
        if let Some(name) = self.rooms.get(room_id).and_then(|room| room.name.clone()) {
            return name;
        }
        match self.room_kind(room_id) {
            Some(RoomKind::Dm) => "Direct",
            Some(RoomKind::Channel) => "Channel",
            Some(RoomKind::Group) | None => "Group",
        }
        .to_string()
    }

    /// Re-attempts decrypting one currently-pending Megolm item, applying
    /// the result to its timeline on success. Returns `true` iff the item
    /// was found and successfully decrypted (i.e. something a caller should
    /// treat as a visible change) — `false` for an unknown item or a
    /// decrypt that still fails.
    fn retry_decrypt_one(&mut self, room_id: &RoomId, event_id: &EventId) -> bool {
        let Some(item) = self.pending_decrypt.get(room_id).and_then(|by_event| by_event.get(event_id)).cloned() else {
            return false;
        };
        let Ok(plaintext) =
            GroupSessionManager::decrypt_event(&mut self.store, room_id, event_id, item.origin_server_ts, &item.sender, &item.content)
        else {
            return false;
        };
        self.apply_decrypted_plaintext(room_id, event_id, &item.sender, item.origin_server_ts, &plaintext);
        if let Some(by_event) = self.pending_decrypt.get_mut(room_id) {
            by_event.remove(event_id);
        }
        true
    }

    /// Applies one successfully-decrypted Megolm plaintext to `room_id`'s
    /// timeline entry for `event_id` — as an ordinary message
    /// ([`Timeline::set_decrypted`]), or, when the plaintext itself carries
    /// an `m.annotation`/`m.replace` relation, via
    /// [`Timeline::apply_decrypted_relation`] instead (`room::timeline`'s
    /// own doc: an encrypted relation's real content — its `m.new_content`
    /// — only exists post-decrypt, unlike its `m.relates_to` pointer, which
    /// the outer envelope already copies in cleartext; a still-ciphertext
    /// event is therefore always given an ordinary placeholder row first,
    /// and this is the one place that later resolves what it actually was).
    /// Shared by forward decrypt ([`MessengerCore::decrypt_new_timeline_events`])
    /// and [`MessengerCore::retry_decrypt_one`].
    fn apply_decrypted_plaintext(
        &mut self,
        room_id: &RoomId,
        event_id: &EventId,
        sender: &UserId,
        origin_server_ts: i64,
        plaintext: &RoomEventPlaintext,
    ) {
        let Some(timeline) = self.timelines.get_mut(room_id) else { return };
        if let Some(relation) = RelatesTo::from_content(&plaintext.content) {
            if matches!(relation, RelatesTo::Annotation { .. } | RelatesTo::Replace { .. }) {
                let new_content = plaintext.content.get("m.new_content").cloned();
                timeline.apply_decrypted_relation(event_id, sender.clone(), origin_server_ts, relation, new_content);
                return;
            }
        }
        timeline.set_decrypted_event(event_id, &plaintext.event_type, &plaintext.content);
    }

    fn retry_pending_for_session(&mut self, room_id: &RoomId, session_id: &str) {
        let Some(by_event) = self.pending_decrypt.get(room_id) else { return };
        let candidates: Vec<EventId> =
            by_event.iter().filter(|(_, item)| item.session_id == session_id).map(|(event_id, _)| event_id.clone()).collect();
        let mut changed = false;
        for event_id in candidates {
            if self.retry_decrypt_one(room_id, &event_id) {
                changed = true;
            }
        }
        if changed {
            self.emit(MessengerEvent::TimelineChanged { room_id: room_id.clone() });
        }
    }

    fn ingest_sync(&mut self, response: &crate::wire::sync::SyncResponse) -> Result<(), MessengerError> {
        let mut newly_received_sessions: Vec<(RoomId, String)> = Vec::new();

        // 1. to-device.
        for event in &response.to_device.events {
            self.process_to_device_event(event, &mut newly_received_sessions)?;
        }

        // 2. device_lists.
        DeviceTracker::on_device_lists(&mut self.store, &response.device_lists.changed, &response.device_lists.left)?;

        // 3. OTK counts / unused fallback types.
        let published_otk_count = response.device_one_time_keys_count.get("signed_curve25519").copied().unwrap_or(0);
        self.account.on_sync_counts(&mut self.store, published_otk_count, &response.device_unused_fallback_key_types)?;
        let keys_upload_request_id = self.next_request_id()?;
        if let Some(request) =
            self.account.keys_upload_request(keys_upload_request_id, &self.config.user_id, &self.config.device_id)?
        {
            self.enqueue_request(request, Lane::Other)?;
        }

        // 4. any outdated tracked user -> one keys/query.
        let outdated_before_rooms = self.outdated_tracked_users()?;
        if !outdated_before_rooms.is_empty() {
            self.enqueue_keys_query()?;
        }

        // 5. rooms.
        let rooms_touched =
            !response.rooms.join.is_empty() || !response.rooms.invite.is_empty() || !response.rooms.leave.is_empty();
        for (room_id, joined) in &response.rooms.join {
            self.ingest_joined_room(room_id, joined)?;
        }
        for (room_id, invited) in &response.rooms.invite {
            self.ingest_invited_room(room_id, invited)?;
        }
        for (room_id, left) in &response.rooms.leave {
            self.ingest_left_room(room_id, left)?;
        }
        if rooms_touched {
            self.emit(MessengerEvent::RoomsChanged);
        }
        // 5b. A member who joined an encrypted room was marked outdated while
        // the room was ingested (`track_joined_members`): query them now, not
        // at the next sync or send.
        if !self.outdated_tracked_users()?.is_subset(&outdated_before_rooms) {
            self.enqueue_keys_query()?;
        }

        // 6. global account data.
        for event in &response.account_data.events {
            self.apply_synced_account_data(None, &event.event_type, event.content.clone());
        }

        for (room_id, session_id) in &newly_received_sessions {
            self.retry_pending_for_session(room_id, session_id);
        }

        // 7. the new sync token is persisted LAST -- see this module's own
        // doc for why every earlier `?` above matters for this ordering.
        self.store.save_sync_token(response.next_batch.clone())?;
        Ok(())
    }

    fn process_to_device_event(
        &mut self,
        event: &ToDeviceEvent,
        newly_received_sessions: &mut Vec<(RoomId, String)>,
    ) -> Result<(), MessengerError> {
        if event.event_type != "m.room.encrypted" {
            return Ok(());
        }
        let Ok(RoomEncryptedContent::Olm(content)) = serde_json::from_value::<RoomEncryptedContent>(event.content.clone())
        else {
            return Ok(());
        };
        match OlmSessionManager::decrypt_to_device(&mut self.store, &mut self.account, &self.config.user_id, &event.sender, &content) {
            Ok(decrypted) => self.route_decrypted_to_device(decrypted, newly_received_sessions),
            Err(OlmDecryptError::UnknownSenderDevice { .. }) => {
                self.queue_unknown_sender_retry(event.clone());
                Ok(())
            }
            // Every other reason (a replay, a malformed envelope, a
            // payload-binding mismatch, ...) is dropped silently -- this
            // module's own doc, and `crypto::olm_sessions`'s: a redelivered
            // to-device message after a crash is legitimate, and this
            // crate has no logging dependency to report a genuine attack
            // attempt through instead.
            Err(_) => Ok(()),
        }
    }

    fn route_decrypted_to_device(
        &mut self,
        decrypted: crate::crypto::olm_sessions::DecryptedToDevice,
        newly_received_sessions: &mut Vec<(RoomId, String)>,
    ) -> Result<(), MessengerError> {
        match decrypted.event_type.as_str() {
            "m.room_key" => {
                if let Ok(content) = serde_json::from_value::<RoomKeyContent>(decrypted.content.clone()) {
                    if content.algorithm == "m.megolm.v1.aes-sha2" {
                        GroupSessionManager::receive_room_key(
                            &mut self.store,
                            &decrypted.sender,
                            decrypted.sender_device_curve25519,
                            decrypted.sender_ed25519,
                            &content,
                        )?;
                        newly_received_sessions.push((content.room_id, content.session_id));
                    }
                }
            }
            // Hooks for `crypto::withheld`'s key-request/re-share flow
            // (M8) -- this module's own doc: intentionally a no-op here.
            "m.room_key.withheld" | "m.room_key_request" | "m.forwarded_room_key" => {}
            _ => {}
        }
        Ok(())
    }

    fn queue_unknown_sender_retry(&mut self, event: ToDeviceEvent) {
        self.unknown_sender_retry.push_back(event);
        while self.unknown_sender_retry.len() > UNKNOWN_SENDER_RETRY_CAPACITY {
            self.unknown_sender_retry.pop_front();
        }
    }

    fn retry_unknown_sender_queue(&mut self) -> Result<(), MessengerError> {
        let pending: Vec<ToDeviceEvent> = std::mem::take(&mut self.unknown_sender_retry).into_iter().collect();
        let mut newly_received_sessions = Vec::new();
        for event in pending {
            self.process_to_device_event(&event, &mut newly_received_sessions)?;
        }
        for (room_id, session_id) in &newly_received_sessions {
            self.retry_pending_for_session(room_id, session_id);
        }
        Ok(())
    }

    /// Every tracked user whose device list is currently outdated.
    fn outdated_tracked_users(&self) -> Result<BTreeSet<UserId>, MessengerError> {
        Ok(self.store.tracked_users()?.into_iter().filter_map(|(user_id, outdated)| outdated.then_some(user_id)).collect())
    }

    /// Enqueues one `/keys/query` for every outdated tracked user (nothing if none is).
    fn enqueue_keys_query(&mut self) -> Result<(), MessengerError> {
        let request_id = self.next_request_id()?;
        if let Some(request) = DeviceTracker::keys_query_request(&self.store, request_id)? {
            self.enqueue_request(request, Lane::Other)?;
        }
        Ok(())
    }

    /// Marks every other member that `events` show joining `room_id` (an
    /// encrypted room) as a tracked user with an outdated device list. The
    /// server answers `/keys/query` only for users who share a JOINED room with
    /// the caller and reports a device list in `device_lists.changed` only when
    /// it changes -- never when a user merely starts sharing a room. So a peer
    /// asked about while still only invited comes back with no devices and
    /// would otherwise stay "up to date" with none after joining, and no later
    /// message would ever be shared with them.
    fn track_joined_members<'a>(&mut self, room_id: &RoomId, events: impl Iterator<Item = &'a RawEvent>) -> Result<(), MessengerError> {
        if self.rooms.get(room_id).is_none_or(|room| room.encryption.is_none()) {
            return Ok(());
        }
        let joined: Vec<UserId> = events
            .filter(|event| event.event_type == "m.room.member")
            .filter(|event| event.content.get("membership").and_then(serde_json::Value::as_str) == Some("join"))
            .filter_map(|event| event.state_key.as_deref().and_then(|state_key| UserId::parse(state_key).ok()))
            .filter(|user_id| *user_id != self.config.user_id)
            .collect();
        if joined.is_empty() {
            return Ok(());
        }
        DeviceTracker::on_device_lists(&mut self.store, &joined, &[])
    }

    fn ingest_joined_room(&mut self, room_id: &RoomId, joined: &JoinedRoom) -> Result<(), MessengerError> {
        for event in joined.state.events.iter().chain(joined.timeline.events.iter()) {
            self.rooms.entry(room_id.clone()).or_default().apply_state_event(event)?;
        }

        self.track_joined_members(room_id, joined.state.events.iter().chain(joined.timeline.events.iter()))?;

        let unread_before = self.rooms.get(room_id).map(RoomState::unread_count);
        self.rooms.entry(room_id.clone()).or_default().apply_summary(&joined.summary, &joined.unread_notifications);
        let unread_after = self.rooms.get(room_id).map(RoomState::unread_count);
        if unread_before != unread_after {
            self.emit(MessengerEvent::UnreadChanged { room_id: room_id.clone() });
        }

        for event in &joined.account_data.events {
            self.apply_synced_account_data(Some(room_id), &event.event_type, event.content.clone());
        }

        if let Some(typing_event) = joined.ephemeral.events.iter().find(|event| event.event_type == "m.typing") {
            if let Ok(typing) = serde_json::from_value::<TypingContent>(typing_event.content.clone()) {
                self.typing.insert(room_id.clone(), typing.user_ids);
                self.emit(MessengerEvent::TypingChanged { room_id: room_id.clone() });
            }
        }
        if let Some(receipt_event) = joined.ephemeral.events.iter().find(|event| event.event_type == "m.receipt") {
            if let Ok(receipts) = serde_json::from_value::<ReceiptContent>(receipt_event.content.clone()) {
                self.receipts.insert(room_id.clone(), receipts);
                self.emit(MessengerEvent::ReceiptsChanged { room_id: room_id.clone() });
            }
        }

        if !joined.timeline.events.is_empty() {
            self.timelines.entry(room_id.clone()).or_default().apply_timeline_batch(
                &joined.timeline.events,
                joined.timeline.limited,
                joined.timeline.prev_batch.clone(),
            );
            self.decrypt_new_timeline_events(room_id, &joined.timeline.events);
            self.emit(MessengerEvent::TimelineChanged { room_id: room_id.clone() });
        }

        self.persist_room_state(room_id)
    }

    fn ingest_invited_room(&mut self, room_id: &RoomId, invited: &InvitedRoom) -> Result<(), MessengerError> {
        for stripped in &invited.invite_state.events {
            let synthetic = stripped_state_to_raw_event(stripped);
            self.rooms.entry(room_id.clone()).or_default().apply_state_event(&synthetic)?;
        }
        self.persist_room_state(room_id)
    }

    fn ingest_left_room(&mut self, room_id: &RoomId, left: &LeftRoom) -> Result<(), MessengerError> {
        for event in left.state.events.iter().chain(left.timeline.events.iter()) {
            self.rooms.entry(room_id.clone()).or_default().apply_state_event(event)?;
        }
        for event in &left.account_data.events {
            self.apply_synced_account_data(Some(room_id), &event.event_type, event.content.clone());
        }
        if !left.timeline.events.is_empty() {
            self.timelines.entry(room_id.clone()).or_default().apply_timeline_batch(
                &left.timeline.events,
                left.timeline.limited,
                left.timeline.prev_batch.clone(),
            );
            self.decrypt_new_timeline_events(room_id, &left.timeline.events);
            self.emit(MessengerEvent::TimelineChanged { room_id: room_id.clone() });
        }
        self.persist_room_state(room_id)
    }

    fn persist_room_state(&mut self, room_id: &RoomId) -> Result<(), MessengerError> {
        let Some(state) = self.rooms.get(room_id) else { return Ok(()) };
        let bytes = serde_json::to_vec(state)
            .map_err(|source| MessengerError::Crypto(format!("encode room state for {room_id}: {source}")))?;
        self.store.save_room_state(room_id, bytes)?;
        Ok(())
    }

    /// Attempts to decrypt every well-formed Megolm `m.room.encrypted`
    /// event in `events` (already applied to `room_id`'s timeline as
    /// `Encrypted{session_id}` placeholders by the caller), patching each
    /// one in place via [`MessengerCore::apply_decrypted_plaintext`] — shared
    /// by forward sync ([`MessengerCore::ingest_joined_room`]/
    /// [`MessengerCore::ingest_left_room`]) and back-pagination
    /// ([`MessengerCore::ingest_room_messages_response`]).
    fn decrypt_new_timeline_events(&mut self, room_id: &RoomId, events: &[RawEvent]) {
        for event in events {
            if event.event_type != "m.room.encrypted" || event.state_key.is_some() || event.unsigned.redacted_because.is_some() {
                continue;
            }
            let Ok(RoomEncryptedContent::Megolm(content)) = serde_json::from_value::<RoomEncryptedContent>(event.content.clone())
            else {
                continue;
            };
            match GroupSessionManager::decrypt_event(
                &mut self.store,
                room_id,
                &event.event_id,
                event.origin_server_ts,
                &event.sender,
                &content,
            ) {
                Ok(plaintext) => {
                    self.apply_decrypted_plaintext(room_id, &event.event_id, &event.sender, event.origin_server_ts, &plaintext);
                    if let Some(by_event) = self.pending_decrypt.get_mut(room_id) {
                        by_event.remove(&event.event_id);
                    }
                }
                Err(err) => {
                    // Stored as the coarse `UtdReason` variant's own name
                    // (never the full, per-error-variant `Display` message)
                    // -- this is the only place a UI-facing adapter can
                    // recover which of the crate's own [`crate::crypto::
                    // group_sessions::UtdReason`] variants this failure
                    // maps to (`GroupDecryptError::utd_reason`'s own doc),
                    // since [`ItemContent::Undecryptable`] carries a plain
                    // `String`, not the enum itself.
                    let reason = format!("{:?}", err.utd_reason());
                    if let Some(timeline) = self.timelines.get_mut(room_id) {
                        timeline.set_decrypted(&event.event_id, ItemContent::Undecryptable { reason });
                    }
                    self.pending_decrypt.entry(room_id.clone()).or_default().insert(
                        event.event_id.clone(),
                        PendingDecryptItem {
                            session_id: content.session_id.clone(),
                            sender: event.sender.clone(),
                            origin_server_ts: event.origin_server_ts,
                            content,
                        },
                    );
                }
            }
        }
    }

    fn ingest_room_messages_response(&mut self, room_id: &RoomId, body: &[u8]) -> Result<(), MessengerError> {
        let parsed: RoomMessagesResponseBody = serde_json::from_slice(body)?;
        let mut events = parsed.chunk;
        events.reverse();
        self.timelines.entry(room_id.clone()).or_default().prepend_back_page(&events, parsed.end);
        self.decrypt_new_timeline_events(room_id, &events);
        self.emit(MessengerEvent::TimelineChanged { room_id: room_id.clone() });
        self.persist_room_state(room_id)
    }
}

impl MessengerCore<SealedRecordCodec> {
    /// The production entry point (M14): opens a core whose store seals
    /// every record with AES-256-GCM under `secrets.store_seal_key` — the
    /// constructor a shell calls, in place of the generic
    /// [`MessengerCore::open`] this crate's own tests use with
    /// [`crate::store::InsecurePlainCodecForTests`].
    ///
    /// Fails with [`MessengerError::Crypto`] if `secrets.store_seal_key` is
    /// `None`. The caller supplies that key. There is no unsealed fallback
    /// here by design (an unsealed messenger record store is exactly what
    /// [`SealedRecordCodec`] exists to keep off disk).
    pub fn open_sealed(
        records: impl IntoIterator<Item = SealedRecord>,
        secrets: CoreSecrets,
        config: CoreConfig,
        now_ms: i64,
        jitter: Box<dyn Jitter>,
    ) -> Result<Self, MessengerError> {
        let seal_key = secrets.store_seal_key.clone().ok_or_else(|| {
            MessengerError::Crypto(
                "MessengerCore::open_sealed requires CoreSecrets::store_seal_key"
                    .to_string(),
            )
        })?;
        let codec = SealedRecordCodec::new(seal_key);
        Self::open(records, codec, config, secrets, now_ms, jitter)
    }
}

/// A stable, always-well-formed placeholder [`EventId`] for a synthetic
/// [`RawEvent`] built from an invite's [`StrippedStateEvent`] (which itself
/// carries no event id) — [`RoomState::apply_state_event`] never reads
/// `event_id` at all, so its exact value is irrelevant; it only has to
/// parse.
fn stripped_placeholder_event_id() -> EventId {
    EventId::parse("$stripped-preview").expect("this literal is a well-formed, hardcoded $-prefixed opaque id")
}

/// Reshapes one invite-preview [`StrippedStateEvent`] into the
/// [`RawEvent`] shape [`RoomState::apply_state_event`] accepts —
/// `origin_server_ts`/`unsigned`/`event_id` are unused by that method for a
/// state event, so a placeholder is enough (this function's own doc).
fn stripped_state_to_raw_event(stripped: &StrippedStateEvent) -> RawEvent {
    RawEvent {
        event_id: stripped_placeholder_event_id(),
        event_type: stripped.event_type.clone(),
        sender: stripped.sender.clone(),
        origin_server_ts: 0,
        state_key: Some(stripped.state_key.clone()),
        content: stripped.content.clone(),
        unsigned: Unsigned::default(),
    }
}

/// `content` as a forward re-sends it: `m.relates_to` (a reply or edit
/// pointer into the source room), `m.mentions` and `m.new_content` removed,
/// any forward marker the source itself carried replaced by this hop's own
/// (`marker_key: marker`) -- so an earlier hop's origin never travels on.
/// Everything else (including an unrecognized `msgtype`'s own fields) passes
/// through untouched.
fn forwardable_content(mut content: serde_json::Value, marker_key: &str, marker: serde_json::Value) -> serde_json::Value {
    if let Some(object) = content.as_object_mut() {
        for key in ["m.relates_to", "m.mentions", "m.new_content", KEY_FORWARDED, KEY_FORWARDED_FROM] {
            object.remove(key);
        }
        object.insert(marker_key.to_string(), marker);
    }
    content
}

/// The local-echo [`ItemContent`] for a not-yet-sent [`OutgoingMessage`] —
/// always the plain new body, regardless of `reply_to`/`edit_of` (this
/// crate's timeline has no dedicated "echo of an edit" rendering; the
/// confirmed event, once it arrives back off `/sync`, carries the full
/// `m.relates_to`-aware rendering via the ordinary
/// [`crate::room::relations`] aggregation — this module's own doc).
fn message_local_echo_content(message: &OutgoingMessage) -> ItemContent {
    let body = TextLikeMessageContent { body: message.body.clone(), format: None, formatted_body: None };
    match message.kind {
        MessageKind::Text => ItemContent::Text(body),
        MessageKind::Notice => ItemContent::Notice(body),
        MessageKind::Emote => ItemContent::Emote(body),
    }
}

/// The `m.room.message` wire content for `message` — plain
/// `{msgtype, body}` for an ordinary send; a reply adds the legacy
/// `m.in_reply_to` pointer; an edit instead prefixes the outer `body` with
/// `"* "` (the client-side fallback convention for a client that does not
/// understand `m.replace`) and carries the real replacement under
/// `m.new_content`, with `m.relates_to: m.replace` naming the edited event
/// (research doc §1.3; `reply_to` and `edit_of` are mutually exclusive at
/// the wire level — [`OutgoingMessage`]'s own doc).
fn message_wire_content(message: &OutgoingMessage) -> serde_json::Value {
    let msgtype = message.kind.msgtype();
    let new_content = serde_json::json!({ "msgtype": msgtype, "body": message.body });
    let mut content = new_content.clone();
    if let Some(edit_of) = &message.edit_of {
        content["body"] = serde_json::Value::String(format!("* {}", message.body));
        content["m.new_content"] = new_content;
        content["m.relates_to"] = serde_json::json!({ "rel_type": "m.replace", "event_id": edit_of.as_str() });
    } else if let Some(reply_to) = &message.reply_to {
        content["m.relates_to"] = serde_json::json!({ "m.in_reply_to": { "event_id": reply_to.as_str() } });
    }
    content
}

/// The outer, unencrypted-envelope `m.relates_to` a Megolm-encrypted
/// `message` must carry alongside its ciphertext (`crate::wire::events::
/// MegolmEncryptedContent`'s own doc: copied verbatim from the cleartext
/// plaintext's own relation, so the server can index it without ever
/// decrypting). `None` for a plain send with neither a reply nor an edit.
fn message_relates_to(message: &OutgoingMessage) -> Option<RelatesTo> {
    if let Some(edit_of) = &message.edit_of {
        Some(RelatesTo::Replace { event_id: edit_of.clone() })
    } else {
        message.reply_to.clone().map(|event_id| RelatesTo::InReplyTo(InReplyTo { event_id }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::room::timeline::Forwarded;
    use crate::store::InsecurePlainCodecForTests;
    use crate::wire::HttpMethod;

    struct FixedJitter(f64);

    impl Jitter for FixedJitter {
        fn next_unit(&mut self) -> f64 {
            self.0
        }
    }

    fn device_id() -> DeviceId {
        DeviceId::parse("DEV1").expect("valid device id")
    }

    fn user_id() -> UserId {
        UserId::parse("@alice:example.org").expect("valid user id")
    }

    fn test_config() -> CoreConfig {
        CoreConfig { user_id: user_id(), device_id: device_id(), server_name: "example.org".to_string() }
    }

    fn open_fresh_core() -> MessengerCore<InsecurePlainCodecForTests> {
        MessengerCore::open(Vec::new(), InsecurePlainCodecForTests, test_config(), CoreSecrets::default(), 0, Box::new(FixedJitter(0.0)))
            .expect("open succeeds on a brand-new device")
    }

    /// Drains and acks every currently-pending flush batch -- the same
    /// "persist, then ack" tick a real shell performs once per loop
    /// iteration. Tests call this explicitly wherever they need a
    /// mutation's own flush epoch satisfied before checking
    /// [`MessengerCore::releasable_requests`] (the flush-before-send
    /// barrier, `crate::persist`'s own doc, applies just as much to a
    /// counter bump as to an Olm/Megolm ratchet advance).
    fn flush_and_ack(core: &mut MessengerCore<InsecurePlainCodecForTests>) {
        while let Some(batch) = core.take_flush_batch() {
            core.ack_flush(batch.id);
        }
    }

    #[test]
    fn counters_survive_restart_and_never_repeat_txn_ids() {
        let device = device_id();
        let mut store = Store::new(device.clone(), InsecurePlainCodecForTests);
        store.save_counters(Counters { next_request_id: 3, next_txn_id: 7 }).expect("save");
        let batch = store.take_flush_batch().expect("counters dirtied the store");
        store.ack_flush(batch.id);

        let reloaded = Store::load(batch.records, InsecurePlainCodecForTests, device).expect("reload");
        let restored = reloaded.counters().expect("no error").expect("counters were persisted");
        assert_eq!(restored.next_txn_id, 7, "a restart resumes the txn-id sequence exactly where it left off");
        assert_eq!(restored.next_request_id, 3);

        // The restore rule itself: a request still pending with a HIGHER
        // seed than whatever was last durably persisted must push the
        // resumed counter past it too, so a freshly minted id can never
        // collide with one already embedded in an in-flight request.
        assert_eq!(restore_counter(3, Some(10)), 11, "resumes past the highest pending id, never repeating it");
        assert_eq!(restore_counter(3, None), 3, "nothing pending: the persisted value alone is authoritative");
    }

    #[test]
    fn open_restores_the_request_counter_past_a_still_pending_requests_id() {
        let device = device_id();
        let mut store = Store::new(device.clone(), InsecurePlainCodecForTests);
        let mut queue = OutgoingQueue::new();
        let pending = OutgoingRequest::sync(RequestId::next(5), None, None);
        queue.enqueue(&mut store, pending, Lane::Sync).expect("enqueue");
        // A stale, lower counter value -- as if the process crashed after
        // minting seed 5 but before this record was ever written.
        store.save_counters(Counters { next_request_id: 2, next_txn_id: 0 }).expect("save");
        let batch = store.take_flush_batch().expect("pending");
        store.ack_flush(batch.id);

        let core = MessengerCore::open(
            batch.records,
            InsecurePlainCodecForTests,
            test_config(),
            CoreSecrets::default(),
            0,
            Box::new(FixedJitter(0.0)),
        )
        .expect("open succeeds");
        assert_eq!(
            core.counters.next_request_id, 6,
            "resumes past the highest id already in flight, not the stale persisted value"
        );
    }

    #[test]
    fn sync_token_persisted_after_everything_it_covers() {
        let mut core = open_fresh_core();
        flush_and_ack(&mut core);
        // The first call mints and enqueues the sync request, which itself
        // dirties the counter record -- not releasable until that flush is
        // acked (the flush-before-send barrier). The second call, after
        // acking, actually returns it.
        core.releasable_requests(0);
        flush_and_ack(&mut core);
        let requests = core.releasable_requests(0);
        let sync_request = requests.iter().find(|r| r.kind == OutgoingRequestKind::Sync).expect("a sync request was enqueued");

        assert!(core.store.sync_token().expect("no error").is_none(), "no token before the first response");

        let body = serde_json::json!({
            "next_batch": "s1",
            "device_one_time_keys_count": { "signed_curve25519": 0 },
            "device_unused_fallback_key_types": []
        })
        .to_string();
        core.on_response(sync_request.id.clone(), HttpResponseDescriptor { status: 200, body: body.into_bytes() }, 0);

        assert_eq!(core.store.sync_token().expect("no error"), Some("s1"));
    }

    #[test]
    fn only_one_sync_in_flight() {
        let mut core = open_fresh_core();
        flush_and_ack(&mut core);
        core.releasable_requests(0);
        flush_and_ack(&mut core);
        let first = core.releasable_requests(0);
        assert_eq!(first.iter().filter(|r| r.kind == OutgoingRequestKind::Sync).count(), 1);

        // Calling again before any response arrives must not mint a
        // second `/sync` -- the lane is occupied and this core's own
        // `sync_request_id` tracking prevents a duplicate enqueue too.
        let second = core.releasable_requests(0);
        assert!(second.iter().all(|r| r.kind != OutgoingRequestKind::Sync), "no second sync request released");
    }

    #[test]
    fn first_sync_of_a_session_never_long_polls_then_the_loop_does() {
        let mut core = open_fresh_core();
        flush_and_ack(&mut core);
        core.releasable_requests(0);
        flush_and_ack(&mut core);
        let first = core.releasable_requests(0);
        let first_sync = first.iter().find(|r| r.kind == OutgoingRequestKind::Sync).expect("a sync request was enqueued");
        assert!(first_sync.query.contains(&("timeout".to_string(), "0".to_string())), "the initial sync must answer at once");
        assert!(first_sync.query.iter().all(|(key, _)| key != "since"), "a fresh device has no since token");

        let body = serde_json::json!({
            "next_batch": "s1",
            "device_one_time_keys_count": { "signed_curve25519": 0 },
            "device_unused_fallback_key_types": []
        })
        .to_string();
        core.on_response(first_sync.id.clone(), HttpResponseDescriptor { status: 200, body: body.into_bytes() }, 0);
        flush_and_ack(&mut core);

        // The next `/sync` is minted lazily (then needs its own flush round
        // before it is releasable) -- and only now does it long-poll.
        core.releasable_requests(0);
        flush_and_ack(&mut core);
        let second = core.releasable_requests(0);
        let second_sync = second.iter().find(|r| r.kind == OutgoingRequestKind::Sync).expect("the follow-up sync was enqueued");
        assert!(second_sync.query.contains(&("since".to_string(), "s1".to_string())));
        assert!(second_sync.query.contains(&("timeout".to_string(), SYNC_TIMEOUT_MS.to_string())), "once caught up the loop long-polls");
    }

    #[test]
    fn room_key_arrival_retries_undecryptable_items() {
        use crate::crypto::group_sessions::GroupSessionManager;
        use mail4agent_vodozemac::megolm::{GroupSession, SessionConfig};
        use mail4agent_vodozemac::olm::Account;

        let mut core = open_fresh_core();
        let room_id = RoomId::parse("!r:example.org").expect("valid room id");
        let sender = UserId::parse("@bob:example.org").expect("valid user id");
        let identity = Account::new().identity_keys();

        let mut group_session = GroupSession::new(SessionConfig::version_1());
        let session_id = group_session.session_id();
        // Captured BEFORE encrypting: Megolm's ratchet only advances
        // forward, so a `session_key` exported AFTER `encrypt` would only
        // let a recipient decrypt messages from that later point onward,
        // never the one encrypted just before it.
        let session_key = group_session.session_key();
        let plaintext = crate::crypto::group_sessions::RoomEventPlaintext {
            event_type: "m.room.message".to_string(),
            content: serde_json::json!({ "msgtype": "m.text", "body": "hi" }),
            room_id: room_id.clone(),
        };
        let message = group_session.encrypt(serde_json::to_vec(&plaintext).expect("valid JSON"));

        let event: RawEvent = serde_json::from_value(serde_json::json!({
            "event_id": "$evt:example.org",
            "type": "m.room.encrypted",
            "sender": sender.as_str(),
            "origin_server_ts": 1,
            "content": {
                "algorithm": "m.megolm.v1.aes-sha2",
                "ciphertext": message.to_base64(),
                "session_id": session_id,
            }
        }))
        .expect("valid event");

        // The event arrives with no session known yet -- it lands as
        // `Undecryptable`. `apply_timeline_batch` first, exactly like
        // `ingest_joined_room` does, since `decrypt_new_timeline_events`
        // only ever patches an item [`Timeline::set_decrypted`] already
        // knows about -- it never inserts one itself.
        let mut timeline = Timeline::new();
        timeline.apply_timeline_batch(std::slice::from_ref(&event), false, None);
        core.timelines.insert(room_id.clone(), timeline);
        core.decrypt_new_timeline_events(&room_id, std::slice::from_ref(&event));
        {
            let timeline = core.timeline(&room_id).expect("timeline exists");
            let item = timeline.item_by_event_id(&EventId::parse("$evt:example.org").expect("valid event id")).expect("item present");
            assert!(matches!(item.content, ItemContent::Undecryptable { .. }));
        }

        // The room key now arrives (e.g. via a to-device `m.room_key`) --
        // simulated directly against the manager, mirroring what
        // `route_decrypted_to_device` itself does.
        let content = RoomKeyContent {
            algorithm: "m.megolm.v1.aes-sha2".to_string(),
            room_id: room_id.clone(),
            session_id: session_id.clone(),
            session_key: session_key.to_base64(),
        };
        GroupSessionManager::receive_room_key(&mut core.store, &sender, identity.curve25519, identity.ed25519, &content)
            .expect("receive room key");
        core.retry_pending_for_session(&room_id, &session_id);

        let timeline = core.timeline(&room_id).expect("timeline exists");
        let item = timeline.item_by_event_id(&EventId::parse("$evt:example.org").expect("valid event id")).expect("item present");
        match &item.content {
            ItemContent::Text(text) => assert_eq!(text.body, "hi"),
            other => panic!("expected the retried decrypt to succeed, got {other:?}"),
        }
    }

    #[test]
    fn redelivered_to_device_after_restart_is_dropped_silently() {
        use crate::crypto::olm_sessions::OlmSessionManager;

        // Alice's own store/account -- the sender.
        let alice_user = UserId::parse("@alice:example.org").expect("valid user id");
        let alice_device = DeviceId::parse("ALICEDEV").expect("valid device id");
        let mut alice_store = Store::new(alice_device.clone(), InsecurePlainCodecForTests);
        let alice_account = OlmAccountState::load_or_create(&mut alice_store).expect("create alice's account");
        // Signed once, up front -- see `unknown_sender_device_is_retried_after_keys_query`'s
        // own comment on this same call for why the order matters here.
        let alice_device_keys =
            alice_account.device_keys_json(&alice_user, &alice_device).expect("sign alice's device_keys");

        // Bob's core is the one under test.
        let mut bob_store = Store::new(device_id(), InsecurePlainCodecForTests);
        let mut bob_account = OlmAccountState::load_or_create(&mut bob_store).expect("create bob's account");
        bob_account.on_sync_counts(&mut bob_store, 0, &["signed_curve25519".to_string()]).expect("top up bob's OTKs");
        let upload = bob_account
            .keys_upload_request(RequestId::next(0), &user_id(), &device_id())
            .expect("builds a request")
            .expect("something to upload");
        let one_time_keys = upload.body.expect("upload has a body");
        let one_time_keys = one_time_keys.get("one_time_keys").and_then(serde_json::Value::as_object).expect("OTKs present");
        let (key_id, key_value) = one_time_keys.iter().next().expect("at least one OTK");
        let claim_body = serde_json::to_vec(&serde_json::json!({
            "one_time_keys": { user_id().as_str(): { device_id().as_str(): { key_id: key_value } } }
        }))
        .expect("valid JSON");
        let bob_device_stored = crate::crypto::device_tracker::StoredDevice {
            user_id: user_id(),
            device_id: device_id(),
            curve25519: bob_account.identity_keys().curve25519,
            ed25519: bob_account.identity_keys().ed25519,
            algorithms: vec!["m.olm.v1.curve25519-aes-sha2".to_string(), "m.megolm.v1.aes-sha2".to_string()],
            display_name: None,
            verified: false,
            blocked: false,
        };
        OlmSessionManager::on_keys_claim_response(&mut alice_store, &alice_account, &[&bob_device_stored], &claim_body)
            .expect("alice establishes a session with bob");

        // Bob learns alice's device ahead of time, so the FIRST decrypt
        // below is a genuine, fully-validated success (not merely an
        // `Ok(())` a caller can't tell apart from a silently-dropped
        // failure) -- this test's whole point is a real replay, not an
        // incidental one.
        DeviceTracker::on_keys_query_response(
            &mut bob_store,
            &serde_json::to_vec(&serde_json::json!({
                "device_keys": { alice_user.as_str(): { alice_device.as_str(): alice_device_keys } }
            }))
            .expect("valid JSON"),
        )
        .expect("bob learns alice's device");

        let room_id = RoomId::parse("!r:example.org").expect("valid room id");
        let group_session = mail4agent_vodozemac::megolm::GroupSession::new(mail4agent_vodozemac::megolm::SessionConfig::version_1());
        let room_key_content = RoomKeyContent {
            algorithm: "m.megolm.v1.aes-sha2".to_string(),
            room_id,
            session_id: group_session.session_id(),
            session_key: group_session.session_key().to_base64(),
        };
        let encrypted = OlmSessionManager::encrypt_to_device(
            &mut alice_store,
            &alice_account,
            &alice_user,
            &alice_device,
            &bob_device_stored,
            "m.room_key",
            serde_json::to_value(&room_key_content).expect("valid JSON"),
        )
        .expect("encrypt to bob");
        let to_device_event = ToDeviceEvent {
            sender: alice_user.clone(),
            event_type: "m.room.encrypted".to_string(),
            content: serde_json::to_value(RoomEncryptedContent::Olm(encrypted)).expect("valid JSON"),
        };

        let mut core =
            MessengerCore::open(Vec::new(), InsecurePlainCodecForTests, test_config(), CoreSecrets::default(), 0, Box::new(FixedJitter(0.0)))
                .expect("open succeeds");
        core.store = bob_store;
        core.account = bob_account;

        let mut sessions = Vec::new();
        core.process_to_device_event(&to_device_event, &mut sessions).expect("first decrypt succeeds");
        assert_eq!(
            sessions,
            vec![(room_key_content.room_id.clone(), room_key_content.session_id.clone())],
            "the first, genuine delivery is fully validated and accepted"
        );

        // Simulate a restart: flush, ack, and rebuild the store/account
        // from just the durable records -- the exact scenario a redelivery
        // after a crash looks like.
        let batch = core.store.take_flush_batch().expect("decrypting dirtied the store");
        core.store.ack_flush(batch.id);
        let reloaded_store = Store::load(batch.records, InsecurePlainCodecForTests, device_id()).expect("reload succeeds");
        core.store = reloaded_store;
        core.account = OlmAccountState::load_or_create(&mut core.store).expect("reload reuses the persisted account");

        // The exact same to-device event, redelivered -- must not error the
        // whole ingestion path, and must not resurrect a second plaintext
        // anywhere a caller could observe.
        let mut sessions_after_restart = Vec::new();
        let result = core.process_to_device_event(&to_device_event, &mut sessions_after_restart);
        assert!(result.is_ok(), "a redelivered to-device event is dropped, not surfaced as an ingestion error");
        assert!(sessions_after_restart.is_empty(), "the replay never produces a second accepted room key");
    }

    #[test]
    fn unknown_sender_device_is_retried_after_keys_query() {
        use crate::crypto::olm_sessions::OlmSessionManager;

        // Alice's own store/account -- the sender.
        let alice_user = UserId::parse("@alice:example.org").expect("valid user id");
        let alice_device = DeviceId::parse("ALICEDEV").expect("valid device id");
        let mut alice_store = Store::new(alice_device.clone(), InsecurePlainCodecForTests);
        let alice_account = OlmAccountState::load_or_create(&mut alice_store).expect("create alice's account");
        // Signed once now (not only later, right before building the
        // `/keys/query` response) -- this is the exact same signed
        // `device_keys` payload either way, computed here so bob's own
        // `/keys/claim` handshake below observes it already having
        // happened, matching the sequencing every other multi-device e2e
        // test in this crate (`crypto::olm_sessions`'s own
        // `olm_session_rejects_out_of_order_ratchet_message`) already uses.
        let alice_device_keys =
            alice_account.device_keys_json(&alice_user, &alice_device).expect("sign alice's device_keys");

        // Bob's own store/account -- a genuinely distinct user (not this
        // module's shared `user_id()`/`device_id()` test fixture, which is
        // "alice" for every OTHER test in this file) -- built standalone
        // first (same order as
        // `redelivered_to_device_after_restart_is_dropped_silently`) and
        // only assigned into a `MessengerCore` once the whole Olm handshake
        // is done.
        let bob_user = UserId::parse("@bob:example.org").expect("valid user id");
        let bob_device = DeviceId::parse("BOBDEV").expect("valid device id");
        let mut bob_store = Store::new(bob_device.clone(), InsecurePlainCodecForTests);
        let mut bob_account = OlmAccountState::load_or_create(&mut bob_store).expect("create bob's account");
        bob_account.on_sync_counts(&mut bob_store, 0, &["signed_curve25519".to_string()]).expect("top up bob's OTKs");
        let upload = bob_account
            .keys_upload_request(RequestId::next(0), &bob_user, &bob_device)
            .expect("builds a request")
            .expect("something to upload");
        let one_time_keys = upload.body.expect("upload has a body");
        let one_time_keys = one_time_keys.get("one_time_keys").and_then(serde_json::Value::as_object).expect("OTKs present");
        let (key_id, key_value) = one_time_keys.iter().next().expect("at least one OTK");
        let claim_body = serde_json::to_vec(&serde_json::json!({
            "one_time_keys": { bob_user.as_str(): { bob_device.as_str(): { key_id: key_value } } }
        }))
        .expect("valid JSON");
        let bob_device_stored = crate::crypto::device_tracker::StoredDevice {
            user_id: bob_user.clone(),
            device_id: bob_device.clone(),
            curve25519: bob_account.identity_keys().curve25519,
            ed25519: bob_account.identity_keys().ed25519,
            algorithms: vec!["m.olm.v1.curve25519-aes-sha2".to_string(), "m.megolm.v1.aes-sha2".to_string()],
            display_name: None,
            verified: false,
            blocked: false,
        };
        OlmSessionManager::on_keys_claim_response(&mut alice_store, &alice_account, &[&bob_device_stored], &claim_body)
            .expect("alice establishes a session with bob");
        let encrypted = OlmSessionManager::encrypt_to_device(
            &mut alice_store,
            &alice_account,
            &alice_user,
            &alice_device,
            &bob_device_stored,
            "m.dummy",
            serde_json::json!({}),
        )
        .expect("encrypt to bob");
        let to_device_event = ToDeviceEvent {
            sender: alice_user.clone(),
            event_type: "m.room.encrypted".to_string(),
            content: serde_json::to_value(RoomEncryptedContent::Olm(encrypted)).expect("valid JSON"),
        };

        let bob_config = CoreConfig { user_id: bob_user.clone(), device_id: bob_device.clone(), server_name: "example.org".to_string() };
        let mut core =
            MessengerCore::open(Vec::new(), InsecurePlainCodecForTests, bob_config, CoreSecrets::default(), 0, Box::new(FixedJitter(0.0)))
                .expect("open succeeds");
        core.store = bob_store;
        core.account = bob_account;

        // Bob does not know alice's device yet: the decrypt is refused with
        // `UnknownSenderDevice` before any session is created, and the event
        // is queued for a retry.
        let mut sessions = Vec::new();
        core.process_to_device_event(&to_device_event, &mut sessions).expect("queues for retry, does not error");
        assert_eq!(core.unknown_sender_retry.len(), 1, "queued for a retry after the next keys/query");
        let alice_curve = alice_account.identity_keys().curve25519.to_base64();
        assert!(
            core.store.olm_sessions_for_device(&alice_curve).expect("no error").is_empty(),
            "the refused attempt created no Olm session (it would have consumed the one-time key)"
        );

        // Bob learns alice's device via a `/keys/query` response --
        // `MessengerCore::handle_terminal_success`'s own `KeysQuery` arm
        // calls `retry_unknown_sender_queue` exactly once, right after
        // applying the response.
        let query_body = serde_json::to_vec(&serde_json::json!({
            "device_keys": { alice_user.as_str(): { alice_device.as_str(): alice_device_keys } }
        }))
        .expect("valid JSON");
        DeviceTracker::on_keys_query_response(&mut core.store, &query_body).expect("bob learns alice's device");
        core.retry_unknown_sender_queue().expect("no error");
        assert!(core.unknown_sender_retry.is_empty(), "the queued entry is drained by the retry attempt");
        assert_eq!(
            core.store.olm_sessions_for_device(&alice_curve).expect("no error").len(),
            1,
            "the retry decrypted the very same pre-key message and established the inbound session"
        );
    }

    #[test]
    fn dispatch_load_older_produces_an_outgoing_request() {
        let mut core = open_fresh_core();
        let room_id = RoomId::parse("!r:example.org").expect("valid room id");
        let mut timeline = Timeline::new();
        let event: RawEvent = serde_json::from_value(serde_json::json!({
            "event_id": "$1:example.org",
            "type": "m.room.message",
            "sender": "@alice:example.org",
            "origin_server_ts": 1,
            "content": { "msgtype": "m.text", "body": "hi" }
        }))
        .expect("valid event");
        timeline.apply_timeline_batch(&[event], true, Some("t1".to_string()));
        core.timelines.insert(room_id.clone(), timeline);
        flush_and_ack(&mut core);

        core.dispatch(MessengerCommand::LoadOlder { room_id: room_id.clone() }, 0).expect("dispatch succeeds");
        flush_and_ack(&mut core);
        let requests = core.releasable_requests(0);
        let load_older = requests.iter().find(|r| r.kind == OutgoingRequestKind::RoomMessages);
        assert!(load_older.is_some(), "a RoomMessages request was enqueued using the room's own gap token");
    }

    #[test]
    fn load_older_on_a_resumed_room_pages_back_from_the_sync_token() {
        let mut core = open_fresh_core();
        let room_id = RoomId::parse("!r:example.org").expect("valid room id");
        core.store.save_sync_token("s42_7".to_string()).expect("save the sync token");
        flush_and_ack(&mut core);

        // Unknown room and no timeline: nothing to page.
        core.dispatch(MessengerCommand::LoadOlder { room_id: room_id.clone() }, 0).expect("dispatch succeeds");
        flush_and_ack(&mut core);
        assert!(core.releasable_requests(0).iter().all(|r| r.kind != OutgoingRequestKind::RoomMessages));

        // The room is known (its state record was replayed) but its timeline is empty.
        core.rooms.insert(room_id.clone(), RoomState::default());
        core.dispatch(MessengerCommand::LoadOlder { room_id: room_id.clone() }, 0).expect("dispatch succeeds");
        flush_and_ack(&mut core);
        let requests = core.releasable_requests(0);
        let load_older = requests.iter().find(|r| r.kind == OutgoingRequestKind::RoomMessages).expect("a RoomMessages request was enqueued");
        assert!(load_older.query.contains(&("from".to_string(), "s42_7".to_string())), "pages back from the sync token: {:?}", load_older.query);
    }

    /// A `/sync` body: `!r:example.org` where bob is seen joining, with an
    /// `m.room.encryption` state event only if `encrypted`.
    fn bob_joins_room_body(encrypted: bool) -> serde_json::Value {
        let mut state = Vec::new();
        if encrypted {
            state.push(serde_json::json!({
                "event_id": "$enc:example.org", "type": "m.room.encryption", "sender": "@alice:example.org",
                "origin_server_ts": 1, "state_key": "", "content": { "algorithm": "m.megolm.v1.aes-sha2" }
            }));
        }
        serde_json::json!({
            "next_batch": "s1",
            "rooms": { "join": { "!r:example.org": {
                "state": { "events": state },
                "timeline": { "events": [{
                    "event_id": "$join:example.org", "type": "m.room.member", "sender": "@bob:example.org",
                    "origin_server_ts": 2, "state_key": "@bob:example.org", "content": { "membership": "join" }
                }] }
            } } }
        })
    }

    #[test]
    fn a_member_joining_an_encrypted_room_is_tracked_and_queried_right_away() {
        let mut core = open_fresh_core();
        let bob = UserId::parse("@bob:example.org").expect("valid user id");
        deliver_sync(&mut core, bob_joins_room_body(true));
        let tracked = core.store.tracked_users().expect("no error");
        assert!(tracked.iter().any(|(user_id, outdated)| *user_id == bob && *outdated), "bob is tracked with an outdated device list: {tracked:?}");

        flush_and_ack(&mut core);
        let requests = core.releasable_requests(0);
        let query = requests.iter().find(|r| r.kind == OutgoingRequestKind::KeysQuery).expect("a /keys/query was enqueued for the new member");
        assert!(query.body.as_ref().is_some_and(|body| body["device_keys"].get(bob.as_str()).is_some()), "the query names bob: {:?}", query.body);
    }

    #[test]
    fn a_member_joining_a_plaintext_room_is_not_tracked() {
        let mut core = open_fresh_core();
        deliver_sync(&mut core, bob_joins_room_body(false));
        assert!(core.store.tracked_users().expect("no error").is_empty());
        flush_and_ack(&mut core);
        assert!(core.releasable_requests(0).iter().all(|r| r.kind != OutgoingRequestKind::KeysQuery));
    }

    #[test]
    fn dispatch_mark_read_and_set_typing_produce_outgoing_requests() {
        let mut core = open_fresh_core();
        flush_and_ack(&mut core);
        let room_id = RoomId::parse("!r:example.org").expect("valid room id");
        let event_id = EventId::parse("$1:example.org").expect("valid event id");

        core.dispatch(MessengerCommand::MarkRead { room_id: room_id.clone(), event_id }, 0).expect("dispatch succeeds");
        core.dispatch(MessengerCommand::SetTyping { room_id: room_id.clone(), typing: true }, 0).expect("dispatch succeeds");
        flush_and_ack(&mut core);

        let requests = core.releasable_requests(0);
        assert!(requests.iter().any(|r| r.kind == OutgoingRequestKind::ReadMarkers));
        assert!(requests.iter().any(|r| r.kind == OutgoingRequestKind::Typing));
    }

    #[test]
    fn snapshot_reflects_the_latest_applied_sync() {
        let mut core = open_fresh_core();
        flush_and_ack(&mut core);
        core.releasable_requests(0);
        flush_and_ack(&mut core);
        let requests = core.releasable_requests(0);
        let sync_request = requests.iter().find(|r| r.kind == OutgoingRequestKind::Sync).expect("sync enqueued");

        let body = serde_json::json!({
            "next_batch": "s1",
            "rooms": {
                "join": {
                    "!r:example.org": {
                        "state": { "events": [] },
                        "timeline": {
                            "events": [
                                {
                                    "event_id": "$1:example.org",
                                    "type": "m.room.message",
                                    "sender": "@alice:example.org",
                                    "origin_server_ts": 1,
                                    "content": { "msgtype": "m.text", "body": "hi" }
                                }
                            ]
                        },
                        "unread_notifications": { "notification_count": 1, "highlight_count": 0 }
                    }
                }
            }
        })
        .to_string();
        let events = core.on_response(sync_request.id.clone(), HttpResponseDescriptor { status: 200, body: body.into_bytes() }, 0);

        assert!(events.contains(&MessengerEvent::RoomsChanged));
        let room_id = RoomId::parse("!r:example.org").expect("valid room id");
        assert!(events.contains(&MessengerEvent::TimelineChanged { room_id: room_id.clone() }));
        assert!(events.contains(&MessengerEvent::UnreadChanged { room_id: room_id.clone() }));

        let timeline = core.timeline(&room_id).expect("timeline present");
        assert_eq!(timeline.items().len(), 1);
        assert_eq!(core.room_state(&room_id).expect("room present").unread_count(), 1);
        assert_eq!(core.change_counter(), events.len() as u64);
        // `events()`/`on_response`'s own inline return share one queue --
        // nothing left to drain right after.
        assert!(core.events().is_empty());
    }

    #[test]
    fn dispatch_set_account_data_updates_optimistically_and_sends_a_put() {
        let mut core = open_fresh_core();
        flush_and_ack(&mut core);
        let content = serde_json::json!({ "note": "keep" });
        core.dispatch(
            MessengerCommand::SetAccountData { event_type: "com.example.prefs".to_string(), content: content.clone() },
            0,
        )
        .expect("dispatch succeeds");

        assert_eq!(
            core.global_account_data("com.example.prefs"),
            Some(&content),
            "SetAccountData updates the core's own cache before any round trip"
        );

        flush_and_ack(&mut core);
        let requests = core.releasable_requests(0);
        let request = requests.iter().find(|r| r.kind == OutgoingRequestKind::AccountData).expect("an AccountData request was enqueued");
        assert_eq!(request.method, HttpMethod::Put);
        assert_eq!(request.path, "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/com.example.prefs");
        assert_eq!(request.body.as_ref(), Some(&content));
    }

    #[test]
    fn dispatch_set_room_account_data_updates_optimistically_and_sends_a_put() {
        let mut core = open_fresh_core();
        flush_and_ack(&mut core);
        let room_id = RoomId::parse("!r:example.org").expect("valid room id");
        let content = serde_json::json!({ "flag": true });
        core.dispatch(
            MessengerCommand::SetRoomAccountData {
                room_id: room_id.clone(),
                event_type: "com.example.flag".to_string(),
                content: content.clone(),
            },
            0,
        )
        .expect("dispatch succeeds");

        assert_eq!(
            core.room_account_data(&room_id, "com.example.flag"),
            Some(&content),
            "SetRoomAccountData updates the core's own cache before any round trip"
        );

        flush_and_ack(&mut core);
        let requests = core.releasable_requests(0);
        let request =
            requests.iter().find(|r| r.kind == OutgoingRequestKind::RoomAccountData).expect("a RoomAccountData request was enqueued");
        assert_eq!(request.method, HttpMethod::Put);
        assert_eq!(
            request.path,
            "/_matrix/client/v3/user/%40alice%3Aexample.org/rooms/%21r%3Aexample.org/account_data/com.example.flag"
        );
        assert_eq!(request.body.as_ref(), Some(&content));
    }

    #[test]
    fn dispatch_search_public_rooms_sends_the_expected_request() {
        let mut core = open_fresh_core();
        flush_and_ack(&mut core);
        core.dispatch(MessengerCommand::SearchPublicRooms { term: "trading".to_string() }, 0).expect("dispatch succeeds");
        flush_and_ack(&mut core);
        let requests = core.releasable_requests(0);
        let request = requests.iter().find(|r| r.kind == OutgoingRequestKind::PublicRooms).expect("a PublicRooms request was enqueued");
        assert_eq!(request.method, HttpMethod::Post);
        assert_eq!(request.path, "/_matrix/client/v3/publicRooms");
        assert_eq!(request.body, Some(serde_json::json!({ "filter": { "generic_search_term": "trading" }, "limit": 50 })));
    }

    #[test]
    fn dispatch_search_users_sends_the_expected_request() {
        let mut core = open_fresh_core();
        flush_and_ack(&mut core);
        core.dispatch(MessengerCommand::SearchUsers { term: "bob".to_string() }, 0).expect("dispatch succeeds");
        flush_and_ack(&mut core);
        let requests = core.releasable_requests(0);
        let request =
            requests.iter().find(|r| r.kind == OutgoingRequestKind::UserDirectorySearch).expect("a UserDirectorySearch request was enqueued");
        assert_eq!(request.method, HttpMethod::Post);
        assert_eq!(request.path, "/_matrix/client/v3/user_directory/search");
        assert_eq!(request.body, Some(serde_json::json!({ "search_term": "bob", "limit": 20 })));
    }

    #[test]
    fn public_rooms_response_superseded_by_a_later_search_is_dropped() {
        let mut core = open_fresh_core();
        flush_and_ack(&mut core);
        core.dispatch(MessengerCommand::SearchPublicRooms { term: "first".to_string() }, 0).expect("dispatch succeeds");
        flush_and_ack(&mut core);
        let first_request = core
            .releasable_requests(0)
            .into_iter()
            .find(|r| r.kind == OutgoingRequestKind::PublicRooms)
            .expect("the first search's own request");

        // A second search supersedes the first before the first's response
        // ever lands.
        core.dispatch(MessengerCommand::SearchPublicRooms { term: "second".to_string() }, 0).expect("dispatch succeeds");
        flush_and_ack(&mut core);
        let second_request = core
            .releasable_requests(0)
            .into_iter()
            .find(|r| r.kind == OutgoingRequestKind::PublicRooms)
            .expect("the second search's own request");

        // The stale response (naming the FIRST request id) is dropped.
        let stale_body = serde_json::json!({ "chunk": [{ "room_id": "!stale:example.org", "num_joined_members": 1 }] });
        core.on_response(first_request.id, HttpResponseDescriptor { status: 200, body: serde_json::to_vec(&stale_body).expect("json") }, 0);
        assert!(core.public_rooms_result().is_empty(), "a response to a superseded search is dropped");

        // The current response is applied.
        let fresh_body = serde_json::json!({ "chunk": [{ "room_id": "!fresh:example.org", "num_joined_members": 2 }] });
        core.on_response(second_request.id, HttpResponseDescriptor { status: 200, body: serde_json::to_vec(&fresh_body).expect("json") }, 0);
        assert_eq!(core.public_rooms_result().len(), 1);
        assert_eq!(core.public_rooms_result()[0].room_id, RoomId::parse("!fresh:example.org").expect("valid room id"));
    }

    fn is_account_data_write(request: &OutgoingRequest) -> bool {
        matches!(request.kind, OutgoingRequestKind::AccountData | OutgoingRequestKind::RoomAccountData)
    }

    #[test]
    fn pin_then_archive_back_to_back_keeps_both_tags() {
        let mut core = open_fresh_core();
        flush_and_ack(&mut core);
        let room_id = RoomId::parse("!r:example.org").expect("valid room id");
        for tag in ["m.favourite", "u.mlc.archived"] {
            core.dispatch(MessengerCommand::SetTag { room_id: room_id.clone(), tag: tag.to_string(), order: None }, 0)
                .expect("dispatch succeeds");
        }

        // Optimistic: the cache already holds both tags, before any round trip.
        let cached = core.room_account_data(&room_id, "m.tag").expect("m.tag cached");
        assert!(cached["tags"].get("m.favourite").is_some());
        assert!(cached["tags"].get("u.mlc.archived").is_some());

        flush_and_ack(&mut core);
        let first_release = core.releasable_requests(0);
        let first_writes: Vec<&OutgoingRequest> = first_release.iter().filter(|r| is_account_data_write(r)).collect();
        assert_eq!(first_writes.len(), 1, "the second PUT is not released while the first is in flight");
        let first_body = first_writes[0].body.clone().expect("a body");
        assert!(first_body["tags"].get("m.favourite").is_some());
        assert!(first_body["tags"].get("u.mlc.archived").is_none(), "the first PUT carries only what existed when it was built");

        core.on_response(first_writes[0].id.clone(), HttpResponseDescriptor { status: 200, body: b"{}".to_vec() }, 0);
        flush_and_ack(&mut core);
        let second_release = core.releasable_requests(0);
        let second = second_release.iter().find(|r| is_account_data_write(r)).expect("the second PUT is released after the first completed");
        let second_body = second.body.clone().expect("a body");
        assert!(second_body["tags"].get("m.favourite").is_some(), "the later PUT still carries the earlier tag");
        assert!(second_body["tags"].get("u.mlc.archived").is_some());
    }

    #[test]
    fn account_data_lane_is_fifo_single_flight() {
        let mut core = open_fresh_core();
        flush_and_ack(&mut core);
        let room_id = RoomId::parse("!r:example.org").expect("valid room id");
        core.dispatch(MessengerCommand::SetAccountData { event_type: "org.t.one".to_string(), content: serde_json::json!({}) }, 0)
            .expect("dispatch succeeds");
        core.dispatch(
            MessengerCommand::SetRoomAccountData {
                room_id: room_id.clone(),
                event_type: "org.t.two".to_string(),
                content: serde_json::json!({}),
            },
            0,
        )
        .expect("dispatch succeeds");
        core.dispatch(MessengerCommand::SetAccountData { event_type: "org.t.three".to_string(), content: serde_json::json!({}) }, 0)
            .expect("dispatch succeeds");
        core.dispatch(MessengerCommand::RemoveTag { room_id: room_id.clone(), tag: "m.favourite".to_string() }, 0)
            .expect("dispatch succeeds");
        flush_and_ack(&mut core);

        let mut released_paths = Vec::new();
        for _ in 0..4 {
            let release = core.releasable_requests(0);
            let writes: Vec<&OutgoingRequest> = release.iter().filter(|r| is_account_data_write(r)).collect();
            assert_eq!(writes.len(), 1, "exactly one account-data write in flight at a time");
            released_paths.push(writes[0].path.clone());
            core.on_response(writes[0].id.clone(), HttpResponseDescriptor { status: 200, body: b"{}".to_vec() }, 0);
            flush_and_ack(&mut core);
        }
        assert!(released_paths[0].ends_with("/account_data/org.t.one"));
        assert!(released_paths[1].ends_with("/account_data/org.t.two"));
        assert!(released_paths[2].ends_with("/account_data/org.t.three"));
        assert!(released_paths[3].ends_with("/account_data/m.tag"));
        assert!(core.releasable_requests(0).iter().all(|r| !is_account_data_write(r)), "the lane is drained");
    }

    /// Answers the outstanding `/sync` request with `body` (minting and
    /// flushing it first if needed) and returns every OTHER request the
    /// rounds released, unanswered -- the tests below keep account-data
    /// writes pending on purpose.
    fn deliver_sync(core: &mut MessengerCore<InsecurePlainCodecForTests>, body: serde_json::Value) -> Vec<OutgoingRequest> {
        let mut others = Vec::new();
        for _ in 0..3 {
            flush_and_ack(core);
            let mut sync_request = None;
            for request in core.releasable_requests(0) {
                if request.kind == OutgoingRequestKind::Sync && sync_request.is_none() {
                    sync_request = Some(request);
                } else {
                    others.push(request);
                }
            }
            if let Some(sync_request) = sync_request {
                let body = serde_json::to_vec(&body).expect("valid JSON");
                core.on_response(sync_request.id, HttpResponseDescriptor { status: 200, body }, 0);
                return others;
            }
        }
        panic!("no sync request became releasable");
    }

    fn tag_sync_body(room_id: &str, tags: serde_json::Value, next_batch: &str) -> serde_json::Value {
        let mut join = serde_json::Map::new();
        join.insert(
            room_id.to_string(),
            serde_json::json!({ "account_data": { "events": [{ "type": "m.tag", "content": { "tags": tags } }] } }),
        );
        serde_json::json!({ "next_batch": next_batch, "rooms": { "join": serde_json::Value::Object(join) } })
    }

    fn ok_response() -> HttpResponseDescriptor {
        HttpResponseDescriptor { status: 200, body: b"{}".to_vec() }
    }

    #[test]
    fn sync_echo_of_an_older_tag_write_does_not_clobber_a_newer_optimistic_value() {
        let mut core = open_fresh_core();
        let room_id = RoomId::parse("!r:example.org").expect("valid room id");
        for tag in ["m.favourite", "u.mlc.archived"] {
            core.dispatch(MessengerCommand::SetTag { room_id: room_id.clone(), tag: tag.to_string(), order: None }, 0)
                .expect("dispatch succeeds");
        }

        // The server echoes the FIRST write only, while both are outstanding.
        let released = deliver_sync(&mut core, tag_sync_body("!r:example.org", serde_json::json!({ "m.favourite": {} }), "s1"));
        let cached = core.room_account_data(&room_id, "m.tag").expect("m.tag cached");
        assert!(cached["tags"].get("u.mlc.archived").is_some(), "the older echo must not clobber the newer optimistic value");
        assert!(cached["tags"].get("m.favourite").is_some());
        let key = (Some(room_id.clone()), "m.tag".to_string());
        assert_eq!(
            core.account_data_guard.get(&key).expect("writes are outstanding").server_value,
            Some(serde_json::json!({ "tags": { "m.favourite": {} } })),
            "the echo is remembered as the server's value"
        );

        // Both writes settle; the optimistic value survives (it is what the
        // server holds now) and the guard is gone.
        let first = released.iter().find(|r| r.kind == OutgoingRequestKind::RoomAccountData).expect("first write released");
        core.on_response(first.id.clone(), ok_response(), 0);
        flush_and_ack(&mut core);
        let second = core
            .releasable_requests(0)
            .into_iter()
            .find(|r| r.kind == OutgoingRequestKind::RoomAccountData)
            .expect("second write released after the first");
        core.on_response(second.id, ok_response(), 0);
        assert!(core.account_data_guard.is_empty());
        let cached = core.room_account_data(&room_id, "m.tag").expect("m.tag cached");
        assert!(cached["tags"].get("m.favourite").is_some() && cached["tags"].get("u.mlc.archived").is_some());

        // With nothing outstanding, sync applies normally again.
        deliver_sync(
            &mut core,
            tag_sync_body("!r:example.org", serde_json::json!({ "m.favourite": {}, "u.mlc.archived": {} }), "s2"),
        );
        let cached = core.room_account_data(&room_id, "m.tag").expect("m.tag cached");
        assert!(cached["tags"].get("u.mlc.archived").is_some());
    }

    #[test]
    fn terminal_account_data_failure_restores_the_server_value() {
        let mut core = open_fresh_core();
        let room_id = RoomId::parse("!r:example.org").expect("valid room id");
        deliver_sync(&mut core, tag_sync_body("!r:example.org", serde_json::json!({ "m.favourite": {} }), "s1"));

        core.dispatch(MessengerCommand::SetTag { room_id: room_id.clone(), tag: "u.mlc.archived".to_string(), order: None }, 0)
            .expect("dispatch succeeds");
        assert!(core.room_account_data(&room_id, "m.tag").expect("cached")["tags"].get("u.mlc.archived").is_some());
        flush_and_ack(&mut core);
        let write = core
            .releasable_requests(0)
            .into_iter()
            .find(|r| r.kind == OutgoingRequestKind::RoomAccountData)
            .expect("the write is released");

        let counter_before = core.change_counter();
        let forbidden =
            HttpResponseDescriptor { status: 403, body: br#"{"errcode":"M_FORBIDDEN","error":"nope"}"#.to_vec() };
        let events = core.on_response(write.id, forbidden, 0);
        assert!(core.account_data_guard.is_empty());
        let restored = core.room_account_data(&room_id, "m.tag").expect("the server's value is back");
        assert!(restored["tags"].get("u.mlc.archived").is_none(), "the failed write's optimistic value is gone");
        assert!(restored["tags"].get("m.favourite").is_some());
        assert!(events.contains(&MessengerEvent::RoomsChanged));
        assert!(core.change_counter() > counter_before, "the UI is told to re-render");

        // A failure while a later write is still outstanding leaves the cache
        // alone (the later write carries the full content anyway); once that
        // one succeeds its value stands.
        for tag in ["u.a", "u.b"] {
            core.dispatch(MessengerCommand::SetTag { room_id: room_id.clone(), tag: tag.to_string(), order: None }, 0)
                .expect("dispatch succeeds");
        }
        flush_and_ack(&mut core);
        let first = core
            .releasable_requests(0)
            .into_iter()
            .find(|r| r.kind == OutgoingRequestKind::RoomAccountData)
            .expect("first write released");
        let forbidden =
            HttpResponseDescriptor { status: 403, body: br#"{"errcode":"M_FORBIDDEN","error":"nope"}"#.to_vec() };
        core.on_response(first.id, forbidden, 0);
        let cached = core.room_account_data(&room_id, "m.tag").expect("cached");
        assert!(cached["tags"].get("u.a").is_some() && cached["tags"].get("u.b").is_some(), "cache untouched while a write is pending");
        flush_and_ack(&mut core);
        let second = core
            .releasable_requests(0)
            .into_iter()
            .find(|r| r.kind == OutgoingRequestKind::RoomAccountData)
            .expect("second write released");
        core.on_response(second.id, ok_response(), 0);
        let cached = core.room_account_data(&room_id, "m.tag").expect("cached");
        assert!(cached["tags"].get("u.b").is_some(), "the last write succeeded: its optimistic value stands");
    }

    #[test]
    fn pending_account_data_writes_rebuild_their_guard_after_a_restart() {
        let mut core = open_fresh_core();
        let room_id = RoomId::parse("!r:example.org").expect("valid room id");
        core.dispatch(MessengerCommand::SetTag { room_id: room_id.clone(), tag: "m.favourite".to_string(), order: None }, 0)
            .expect("dispatch succeeds");
        core.dispatch(
            MessengerCommand::SetAccountData { event_type: "org.t.one".to_string(), content: serde_json::json!({ "n": 1 }) },
            0,
        )
        .expect("dispatch succeeds");

        // Everything dirtied so far, including both pending PUT records.
        let mut records = Vec::new();
        while let Some(batch) = core.take_flush_batch() {
            records.extend(batch.records.clone());
            core.ack_flush(batch.id);
        }
        let reopened = MessengerCore::open(
            records,
            InsecurePlainCodecForTests,
            test_config(),
            CoreSecrets::default(),
            0,
            Box::new(FixedJitter(0.0)),
        )
        .expect("reopen succeeds");

        assert_eq!(reopened.account_data_guard.len(), 2, "one guard per key with a pending write");
        assert!(reopened.account_data_guard.values().all(|guard| guard.pending == 1 && guard.server_value.is_none()));
        assert_eq!(reopened.global_account_data("org.t.one"), Some(&serde_json::json!({ "n": 1 })));
        assert!(reopened.room_account_data(&room_id, "m.tag").expect("cached")["tags"].get("m.favourite").is_some());
    }

    // -----------------------------------------------------------------
    // Stickers and forwarding
    // -----------------------------------------------------------------

    type TestCore = MessengerCore<InsecurePlainCodecForTests>;

    fn room(id: &str) -> RoomId {
        RoomId::parse(id).expect("valid room id")
    }

    fn event(id: &str) -> EventId {
        EventId::parse(id).expect("valid event id")
    }

    /// Registers `room_id` in `core`: Megolm-encrypted or not, optionally
    /// named, with an (empty) timeline.
    fn add_room(core: &mut TestCore, room_id: &RoomId, encrypted: bool, name: Option<&str>) {
        let mut state = RoomState::new();
        if encrypted {
            state.encryption = Some(crate::wire::events::RoomEncryptionContent {
                algorithm: "m.megolm.v1.aes-sha2".to_string(),
                rotation_period_ms: 604_800_000,
                rotation_period_msgs: 100,
            });
        }
        state.name = name.map(str::to_string);
        core.rooms.insert(room_id.clone(), state);
        core.timelines.entry(room_id.clone()).or_default();
    }

    fn raw_event(event_id: &str, event_type: &str, sender: &str, content: serde_json::Value) -> RawEvent {
        serde_json::from_value(serde_json::json!({
            "event_id": event_id,
            "type": event_type,
            "sender": sender,
            "origin_server_ts": 1,
            "content": content,
        }))
        .expect("valid raw event")
    }

    /// An event that arrived in `room_id` as plaintext.
    fn seed_plain(core: &mut TestCore, room_id: &RoomId, event_id: &str, sender: &str, event_type: &str, content: serde_json::Value) {
        let raw = raw_event(event_id, event_type, sender, content);
        core.timelines.entry(room_id.clone()).or_default().apply_timeline_batch(&[raw], false, None);
    }

    /// A Megolm envelope that arrived in `room_id` and has not been opened.
    fn seed_sealed(core: &mut TestCore, room_id: &RoomId, event_id: &str, sender: &str) {
        let content = serde_json::json!({ "algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "AAAA", "session_id": "s1" });
        seed_plain(core, room_id, event_id, sender, "m.room.encrypted", content);
    }

    /// A Megolm envelope that arrived in `room_id` and decrypted to
    /// `{event_type, content}`.
    fn seed_decrypted(
        core: &mut TestCore,
        room_id: &RoomId,
        event_id_str: &str,
        sender: &str,
        event_type: &str,
        content: serde_json::Value,
    ) {
        seed_sealed(core, room_id, event_id_str, sender);
        if let Some(timeline) = core.timelines.get_mut(room_id) {
            timeline.set_decrypted_event(&event(event_id_str), event_type, &content);
        }
    }

    /// Flushes, releases, and returns the `(path, body)` of the one
    /// `RoomSend` the core just queued -- after answering it with a fresh
    /// event id, so the room's next send is free to start.
    fn sent_room_event(core: &mut TestCore) -> (String, serde_json::Value) {
        flush_and_ack(core);
        let request = core
            .releasable_requests(0)
            .into_iter()
            .find(|request| request.kind == OutgoingRequestKind::RoomSend)
            .expect("a room send is releasable");
        let confirmed = format!("$sent{}:example.org", core.counters.next_request_id);
        let body = serde_json::json!({ "event_id": confirmed }).to_string().into_bytes();
        core.on_response(request.id.clone(), HttpResponseDescriptor { status: 200, body }, 0);
        (request.path, request.body.expect("a room send has a body"))
    }

    fn forward(core: &mut TestCore, from: &RoomId, event_id: &str, to: &RoomId) -> Result<(), MessengerError> {
        core.dispatch(
            MessengerCommand::Forward { from_room: from.clone(), event_id: event(event_id), to_room: to.clone(), txn_id: None },
            0,
        )
    }

    fn last_item(core: &TestCore, room_id: &RoomId) -> crate::room::timeline::TimelineItem {
        core.timeline(room_id).and_then(|timeline| timeline.items().last()).expect("the room has an item").clone()
    }

    #[test]
    fn forward_from_encrypted_room_carries_only_the_forwarded_flag() {
        let mut core = open_fresh_core();
        let dm = room("!dm:example.org");
        let target = room("!target:example.org");
        add_room(&mut core, &dm, true, Some("Secret DM name"));
        add_room(&mut core, &target, false, None);
        seed_decrypted(
            &mut core,
            &dm,
            "$src:example.org",
            "@bob:example.org",
            "m.room.message",
            serde_json::json!({
                "msgtype": "m.text",
                "body": "quarterly numbers",
                "m.relates_to": { "m.in_reply_to": { "event_id": "$parent:example.org" } },
                "m.mentions": { "user_ids": ["@carol:example.org"] },
            }),
        );

        forward(&mut core, &dm, "$src:example.org", &target).expect("a decrypted message is forwardable");

        let (path, body) = sent_room_event(&mut core);
        assert!(path.contains("/send/m.room.message/"), "the event type is kept: {path}");
        assert_eq!(
            body,
            serde_json::json!({ "msgtype": "m.text", "body": "quarterly numbers", "forwarded": true }),
            "the text plus the bare flag; the reply pointer and the mentions are stripped"
        );
        let wire = body.to_string();
        for leaked in ["bob", "carol", "!dm", "Secret DM name", "$parent"] {
            assert!(!wire.contains(leaked), "{leaked:?} must not travel with a forward out of an encrypted room: {wire}");
        }
        let echo = last_item(&core, &target);
        assert_eq!(echo.forwarded, Some(Forwarded::Hidden), "the forwarder's own echo shows the same marker");
    }

    #[test]
    fn forward_from_public_channel_carries_room_id_and_name_no_sender() {
        let mut core = open_fresh_core();
        let channel = room("!chan:example.org");
        let target = room("!target:example.org");
        add_room(&mut core, &channel, false, Some("Announcements"));
        add_room(&mut core, &target, false, None);
        seed_plain(
            &mut core,
            &channel,
            "$post:example.org",
            "@dave:example.org",
            "m.room.message",
            serde_json::json!({
                "msgtype": "m.text",
                "body": "BTC breaks out",
                "m.mentions": { "room": true },
                "m.relates_to": { "m.in_reply_to": { "event_id": "$older:example.org" } },
            }),
        );

        forward(&mut core, &channel, "$post:example.org", &target).expect("a channel post is forwardable");

        let (_, body) = sent_room_event(&mut core);
        assert_eq!(
            body,
            serde_json::json!({
                "msgtype": "m.text",
                "body": "BTC breaks out",
                "forwarded_from": { "room_id": "!chan:example.org", "room_name": "Announcements" },
            })
        );
        assert!(!body.to_string().contains("dave"), "the original sender never travels");
        assert_eq!(
            last_item(&core, &target).forwarded,
            Some(Forwarded::Channel { room_id: channel.clone(), room_name: "Announcements".to_string() })
        );
    }

    #[test]
    fn forward_from_an_unnamed_room_never_lists_member_names() {
        let mut core = open_fresh_core();
        let channel = room("!chan:example.org");
        let target = room("!target:example.org");
        add_room(&mut core, &channel, false, None);
        if let Some(state) = core.rooms.get_mut(&channel) {
            state.members.insert(
                UserId::parse("@erin:example.org").expect("valid user id"),
                crate::room::state::MemberState {
                    membership: Membership::Join,
                    displayname: Some("Erin Private".to_string()),
                    is_direct: false,
                },
            );
        }
        add_room(&mut core, &target, false, None);
        seed_plain(&mut core, &channel, "$post:example.org", "@erin:example.org", "m.room.message", serde_json::json!({ "msgtype": "m.text", "body": "hi" }));

        forward(&mut core, &channel, "$post:example.org", &target).expect("forwardable");

        let (_, body) = sent_room_event(&mut core);
        let name = body["forwarded_from"]["room_name"].as_str().expect("a name is sent");
        assert!(!name.contains("Erin"), "an unnamed room is attributed by a generic label, not by its members: {name}");
    }

    #[test]
    fn forward_replaces_the_sources_own_forward_marker() {
        let mut core = open_fresh_core();
        let dm = room("!dm:example.org");
        let target = room("!target:example.org");
        add_room(&mut core, &dm, true, None);
        add_room(&mut core, &target, false, None);
        seed_decrypted(
            &mut core,
            &dm,
            "$src:example.org",
            "@bob:example.org",
            "m.room.message",
            serde_json::json!({
                "msgtype": "m.text",
                "body": "second hop",
                "forwarded_from": { "room_id": "!older:example.org", "room_name": "Older channel" },
            }),
        );

        forward(&mut core, &dm, "$src:example.org", &target).expect("forwardable");

        let (_, body) = sent_room_event(&mut core);
        assert_eq!(body, serde_json::json!({ "msgtype": "m.text", "body": "second hop", "forwarded": true }));
    }

    #[test]
    fn forward_of_edited_item_sends_the_latest_text() {
        let mut core = open_fresh_core();
        let channel = room("!chan:example.org");
        let dm = room("!dm:example.org");
        let target = room("!target:example.org");
        add_room(&mut core, &channel, false, Some("Announcements"));
        add_room(&mut core, &dm, true, None);
        add_room(&mut core, &target, false, None);

        // Plaintext room: the edit is an ordinary event folded onto its target.
        seed_plain(&mut core, &channel, "$orig:example.org", "@dave:example.org", "m.room.message", serde_json::json!({ "msgtype": "m.text", "body": "typo text" }));
        seed_plain(
            &mut core,
            &channel,
            "$edit:example.org",
            "@dave:example.org",
            "m.room.message",
            serde_json::json!({
                "msgtype": "m.text",
                "body": "* fixed text",
                "m.new_content": { "msgtype": "m.text", "body": "fixed text" },
                "m.relates_to": { "rel_type": "m.replace", "event_id": "$orig:example.org" },
            }),
        );
        forward(&mut core, &channel, "$orig:example.org", &target).expect("forwardable");
        let (_, body) = sent_room_event(&mut core);
        assert_eq!(body["body"], "fixed text", "the latest edit's text, not the original and not the `* ` fallback");
        assert!(body.get("m.new_content").is_none() && body.get("m.relates_to").is_none());

        // Encrypted room: the edit is only recognised once decrypted.
        seed_decrypted(&mut core, &dm, "$secret:example.org", "@bob:example.org", "m.room.message", serde_json::json!({ "msgtype": "m.text", "body": "typo secret" }));
        seed_sealed(&mut core, &dm, "$secret-edit:example.org", "@bob:example.org");
        let applied = core.timelines.get_mut(&dm).expect("timeline").apply_decrypted_relation(
            &event("$secret-edit:example.org"),
            UserId::parse("@bob:example.org").expect("valid user id"),
            2,
            RelatesTo::Replace { event_id: event("$secret:example.org") },
            Some(serde_json::json!({ "msgtype": "m.text", "body": "fixed secret" })),
        );
        assert!(applied, "the decrypted edit folds onto its target");
        forward(&mut core, &dm, "$secret:example.org", &target).expect("forwardable");
        let (_, body) = sent_room_event(&mut core);
        assert_eq!(body, serde_json::json!({ "msgtype": "m.text", "body": "fixed secret", "forwarded": true }));
    }

    #[test]
    fn forward_of_unknown_msgtype_keeps_its_fields() {
        let mut core = open_fresh_core();
        let dm = room("!dm:example.org");
        let target = room("!target:example.org");
        add_room(&mut core, &dm, true, None);
        add_room(&mut core, &target, false, None);
        let card = serde_json::json!({
            "msgtype": "com.example.card",
            "body": "opaque",
            "note": "kept raw",
        });
        seed_decrypted(&mut core, &dm, "$card:example.org", "@bob:example.org", "m.room.message", card.clone());

        forward(&mut core, &dm, "$card:example.org", &target).expect("an unrecognized msgtype is still an m.room.message");

        let (path, body) = sent_room_event(&mut core);
        assert!(path.contains("/send/m.room.message/"));
        let mut expected = card;
        expected["forwarded"] = serde_json::Value::Bool(true);
        assert_eq!(body, expected, "unrecognized msgtype fields pass through plus the marker");
        assert!(matches!(last_item(&core, &target).content, ItemContent::Unknown), "the echo does not invent a card type");
    }

    #[test]
    fn forward_refuses_redacted_sealed_unknown_and_missing() {
        let mut core = open_fresh_core();
        let dm = room("!dm:example.org");
        let target = room("!target:example.org");
        add_room(&mut core, &dm, true, None);
        add_room(&mut core, &target, false, None);

        seed_decrypted(&mut core, &dm, "$redacted:example.org", "@bob:example.org", "m.room.message", serde_json::json!({ "msgtype": "m.text", "body": "gone" }));
        core.timelines.get_mut(&dm).expect("timeline").apply_redaction(&event("$redacted:example.org"));
        seed_sealed(&mut core, &dm, "$sealed:example.org", "@bob:example.org");
        seed_sealed(&mut core, &dm, "$utd:example.org", "@bob:example.org");
        core.timelines
            .get_mut(&dm)
            .expect("timeline")
            .set_decrypted(&event("$utd:example.org"), ItemContent::Undecryptable { reason: "MissingSession".to_string() });
        seed_plain(&mut core, &dm, "$call:example.org", "@bob:example.org", "m.call.invite", serde_json::json!({ "call_id": "c1" }));

        for id in ["$redacted:example.org", "$sealed:example.org", "$utd:example.org", "$call:example.org", "$missing:example.org"] {
            match forward(&mut core, &dm, id, &target) {
                Err(MessengerError::IntentRefused(reason)) => {
                    assert!(reason.contains(id), "the refusal names the event {id}: {reason}");
                }
                other => panic!("forwarding {id} must be refused, got {other:?}"),
            }
        }
        match forward(&mut core, &room("!nowhere:example.org"), "$redacted:example.org", &target) {
            Err(MessengerError::IntentRefused(reason)) => assert!(reason.contains("$redacted:example.org"), "{reason}"),
            other => panic!("an unknown source room means a missing event, got {other:?}"),
        }
        match forward(&mut core, &dm, "$sealed:example.org", &room("!nowhere:example.org")) {
            Err(MessengerError::IntentRefused(reason)) => assert!(reason.contains("unknown"), "{reason}"),
            other => panic!("an unknown target room is refused, got {other:?}"),
        }

        assert!(core.send_state.is_empty(), "a refused forward queues nothing");
        assert!(core.timeline(&target).is_some_and(|timeline| timeline.items().is_empty()), "and leaves no echo");
    }
}
