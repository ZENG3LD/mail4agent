//! `mail4agent-messenger` — sans-I/O Matrix Client-Server-subset sync + E2EE
//! (Olm/Megolm) engine. Shells execute [`wire::OutgoingRequest`] and persist
//! the sealed records this crate exports. No network and no disk inside the
//! library.
//!
//! # Contract
//!
//! This crate performs **no I/O of any kind**: no network sockets, no
//! filesystem access, no browser storage calls, and no `async`/`.await`
//! anywhere in its source (plan §0). Every side effect crosses the
//! boundary as plain data:
//!
//! - **Network**: the core hands out [`wire::OutgoingRequest`] values; a
//!   shell (native or web) performs the actual HTTP call and feeds the
//!   result back in as an [`wire::HttpResponseDescriptor`]. The core never
//!   opens a socket itself.
//! - **Disk/persistence**: the core owns an in-memory working set and
//!   marks records dirty as it mutates state; [`persist::FlushGate`]
//!   batches dirty/deleted records into [`persist::FlushBatch`] values a
//!   shell writes to durable storage (the filesystem on native, IndexedDB
//!   on web) and acks back in. The core never calls a storage API itself.
//!
//! # Flush-before-send barrier
//!
//! [`persist::FlushEpoch`] is the barrier the plan's manager decision #3
//! requires: a state mutation (an Olm/Megolm ratchet advance, most
//! critically) must be durably flushed and acknowledged *before* the
//! ciphertext that used it is allowed to leave the process — scoped
//! per-request (M12's [`persist::RequiredSeq`] epoch) rather than as one
//! global barrier, so an unrelated `/sync` or typing indicator is never
//! held behind it. See `persist`'s module doc for the exact ordering
//! guarantee this makes, with a worked example.
//!
//! # Synchronous by construction
//!
//! No function in this crate's public API returns a `Future` or is
//! declared `async fn`. This is what lets the same source compile and
//! unit-test identically on native and `wasm32-unknown-unknown`: the only
//! platform-divergent code is which transport/executor a *shell* wires in,
//! never this crate.
//!
//! # Pieces landed so far (M1, M2)
//!
//! **M1** — the wire-boundary primitives: Matrix identifier newtypes
//! ([`ids`]), this crate's error type ([`error`]), the
//! `OutgoingRequest`/`HttpResponseDescriptor` shapes ([`wire`]), and the
//! flush-before-send barrier's data structures ([`persist`]).
//!
//! **M2** — the working-set store ([`store`]): [`store::Store`], the
//! in-memory `CryptoStore`/`StateStore` implementation later pieces
//! (crypto, room, sync engine) code against, sealed for export through
//! [`persist::FlushGate`] by a [`store::RecordCodec`] (this piece ships only
//! `store::InsecurePlainCodecForTests`, gated behind the `test-support`
//! Cargo feature; the real AES-256-GCM codec is a later piece, M14).
//!
//! **M3** — the `/sync` and event wire types ([`wire::events`],
//! [`wire::sync`]): [`wire::sync::SyncResponse`] and
//! [`wire::sync::parse_sync_response`], the Matrix event envelope
//! ([`wire::events::RawEvent`], [`wire::events::StrippedStateEvent`],
//! [`wire::events::ToDeviceEvent`]), relation aggregation
//! ([`wire::events::RelatesTo`]), and typed content for the state/timeline/
//! to-device/account-data/ephemeral event types this crate reads.
//!
//! **M5** — Matrix canonical-JSON signing ([`canonical_json`]:
//! [`canonical_json::sign_json`], [`canonical_json::verify_json_signature`])
//! and the device's own Olm account ([`crypto::account::OlmAccountState`]):
//! generate-once-and-persist identity, one-time/fallback key maintenance off
//! `/sync`'s own counters, and the signed `device_keys`/`/keys/upload`
//! request bodies built from it.
//!
//! **M4** — room state, timeline assembly, and relation aggregation
//! ([`room`]): [`room::RoomState`] folded from `m.room.*` state events plus
//! [`room::RoomKind`] derivation, [`room::Timeline`] assembled from `/sync`
//! windows and `/messages` back-pages with local-echo reconciliation and
//! live v11-allow-list redaction, and [`room::RelationsBundle`] aggregation
//! (reactions, edits, replies, threads).
//!
//! **M6** — device-list tracking ([`crypto::device_tracker`]) and per-device
//! Olm 1:1 sessions ([`crypto::olm_sessions`]): `/keys/query`/`/keys/claim`
//! request building and response validation, to-device encryption/
//! decryption with full payload binding, and the security checks that keep
//! a key change or an unverified device from being silently trusted.
//!
//! **M7** — Megolm group sessions ([`crypto::group_sessions`]): lazy
//! outbound-session creation and rotation, room-key sharing batched over
//! Olm to-device, and inbound decrypt with bound-sender authentication and
//! message-index replay protection.
//!
//! **M12** — the outgoing request queue ([`outgoing_queue`]):
//! [`outgoing_queue::OutgoingQueue`] tracks pending requests per
//! [`outgoing_queue::Lane`] (`Sync`/`ToDevice`/`Room`/`Other`), replaying
//! them idempotently with capped exponential backoff
//! ([`outgoing_queue::ResponseOutcome`]) and surviving a crash via
//! [`store::StateStore::pending_requests`]. [`persist::FlushGate`] gained a
//! per-request flush epoch ([`persist::FlushEpoch`], [`persist::RequiredSeq`])
//! replacing its earlier global barrier — see `persist`'s module doc.
//!
//! **M13a** — the single-writer kernel and the RECEIVE path
//! ([`core::MessengerCore`]): `open`/restart restore (including the
//! [`core::Counters`] sequence that backs every future
//! [`ids::RequestId`]/[`ids::TxnId`]), the single-flight `/sync` loop, full
//! ingestion order (to-device decrypt and `m.room_key` routing,
//! device-list/OTK/`keys/query` bookkeeping, room state/timeline/Megolm
//! decrypt, ephemeral/account-data folding), and the receive-side
//! [`core::MessengerCommand`] variants (`MarkRead`, `SetTyping`,
//! `RetryDecryption`, `LoadOlder`).
//!
//! **M13b** — the SEND path, in the same module ([`core::MessengerCore`]):
//! a per-room ordered send pipeline for [`core::MessengerCommand::SendMessage`]/
//! `React`/`Redact`/`RetrySend` (key-query → key-claim → key-share → the
//! room event itself, for an encrypted room; straight to the wire
//! otherwise — key sharing is always awaited before the room event that
//! needs it), plus every room-membership/tag/typing command
//! (`CreateRoom`, `JoinRoom`, `LeaveRoom`, `Invite`, `Kick`, `SetTag`,
//! `RemoveTag`, `SetTyping`'s own debounce). Plan §3's separate
//! `sync_engine.rs` never materialized as its own module — everything it
//! described lives directly in [`core`] instead, alongside the kernel it
//! would otherwise have had to be threaded through anyway.
//!
//! **M14** — at-rest sealing ([`store::sealed::SealedRecordCodec`]): the
//! production [`store::RecordCodec`], AES-256-GCM under a caller-supplied
//! 32-byte [`core::CoreSecrets::store_seal_key`], binding each record's own
//! storage key as AAD. [`core::MessengerCore::open_sealed`] is the
//! constructor a shell calls; [`core::MessengerCore::open`] stays generic so
//! this crate's own tests keep using [`store::InsecurePlainCodecForTests`].
//! The session private key is the Olm account
//! [`crypto::account::OlmAccountState`] already generates. This crate does
//! not derive keys, read a passphrase, or own an identity scheme.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod canonical_json;
pub mod core;
pub mod crypto;
pub mod error;
pub mod ids;
pub mod outgoing_queue;
pub mod persist;
pub mod persist_log;
pub mod room;
pub mod store;
pub mod wire;

pub use canonical_json::{sign_json, verify_json_signature, CanonicalJsonError};
pub use core::{
    CoreConfig, CoreSecrets, Counters, CreateRoomKind, MessageKind, MessengerCommand, MessengerCore, MessengerEvent,
    OutgoingMessage, PublicRoomsResultEntry, UserDirectoryResultEntry,
};
pub use crypto::account::OlmAccountState;
pub use crypto::device_tracker::{DeviceKeyChanged, DeviceTracker, DroppedDevice, KeysQueryOutcome, StoredDevice};
pub use crypto::group_sessions::{
    GroupDecryptError, GroupSessionManager, OutboundSessionUpdate, RoomEventPlaintext, UtdReason,
    MAX_DEVICES_PER_SEND_TO_DEVICE_REQUEST,
};
pub use crypto::olm_sessions::{
    DecryptedToDevice, KeysClaimOutcome, KeysClaimRefusal, OlmDecryptError, OlmSessionManager,
};
pub use error::MessengerError;
pub use ids::{DeviceId, EventId, RequestId, RoomId, TxnId, UserId};
pub use outgoing_queue::{Jitter, Lane, OutgoingQueue, PendingRequest, ResponseOutcome};
pub use persist::{FlushBatch, FlushEpoch, FlushGate, RecordKey, RequiredSeq, SealedRecord};
pub use room::{
    aggregate_relation, highlight, last_preview, recompute_bundle, EditRecord, Forwarded, GapMarker, ItemContent,
    MemberRole, MemberState, RelatingEvent, RelationsBundle, RoomKind, RoomState, SendState, StateChangeSummary,
    Timeline, TimelineItem,
};
pub use store::sealed::SealedRecordCodec;
pub use store::{CryptoStore, RecordCodec, StateStore, Store, StoreError};
pub use wire::{HttpMethod, HttpResponseDescriptor, OutgoingRequest, OutgoingRequestKind};
