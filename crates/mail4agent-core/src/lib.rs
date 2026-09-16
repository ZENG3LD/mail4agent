//! The mail4agent mailbox engine: participants, addressing, delivery,
//! acknowledgement and the storage boundary. No HTTP, no framework -- see
//! `mail4agent/CLAUDE.md` for this crate's place in the workspace.
//!
//! This crate owns the registry (who a participant is, what it may do) and
//! the four mail operations (send, inbox, ack, message lookup, plus unread
//! counting). Persistence is a separate task: what lives here is the
//! [`MailStore`] trait a persistent implementation will satisfy, and
//! [`InMemoryStore`], the implementation this crate's own tests run
//! against.
//!
//! **The rule that defines the mailbox** (`mail4agent/CLAUDE.md`): a sender
//! is never a field the caller fills in. [`MailboxEngine::authenticate`] is
//! the only way a [`mail4agent_api::ParticipantId`] enters the engine from
//! the outside; every other operation takes that already-verified id as an
//! argument, never one read out of a request.

mod engine;
mod store;

pub use engine::{MailboxEngine, ParticipantPermissions, SECRET_HEX_LEN};
pub use store::{InMemoryStore, InsertMessageOutcome, MailStore, ParticipantRecord, RoomRecord, SecretDigest, StoreError};

#[cfg(test)]
mod tests;
