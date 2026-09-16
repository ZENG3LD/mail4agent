//! The mail4agent mailbox engine: participants, addressing, delivery,
//! acknowledgement and the storage boundary. No HTTP, no framework -- see
//! `mail4agent/CLAUDE.md` for this crate's place in the workspace.
//!
//! This crate owns the registry (who a participant is, what it may do, and
//! -- since 2026-09-17 -- which live sessions exist under it) and the mail
//! operations (send, inbox, ack, message lookup, plus unread counting).
//! Persistence is a separate task: what lives here is the [`MailStore`]
//! trait a persistent implementation will satisfy, and [`InMemoryStore`],
//! the implementation this crate's own tests run against.
//!
//! **The rule that defines the mailbox** (`mail4agent/CLAUDE.md`): a sender
//! is never a field the caller fills in. [`MailboxEngine::authenticate`] is
//! the only way a [`mail4agent_api::ParticipantId`] (an *account*) enters
//! the engine from the outside, and [`MailboxEngine::ensure_session`] is the
//! only way one of its sessions does; every other operation takes an
//! already-resolved [`mail4agent_api::Address`] as an argument, never one
//! read out of a request. A session *is* a participant, not a new concept
//! beside one -- see `MailboxEngine`'s own doc comments on `send`, `inbox`
//! and `ack` for exactly how it inherits its account's permissions and
//! reads its account's mail
//! (`docs/gate4agent/plans/mailbox-service-extraction-and-signed-session-identity-2026-09-16.md`
//! §5e).

mod engine;
mod store;

pub use engine::{LivenessCheck, MailboxEngine, ParticipantPermissions, SECRET_HEX_LEN};
pub use store::{
    InMemoryStore, InsertMessageOutcome, MailStore, ParticipantRecord, ParticipantSummary, RoomRecord, RoomSummary,
    SecretDigest, SessionRecord, StoreError,
};

#[cfg(test)]
mod tests;
