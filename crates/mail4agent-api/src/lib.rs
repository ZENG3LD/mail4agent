//! Wire types for the mail4agent mailbox: addresses, messages, requests and
//! named refusals.
//!
//! This crate is the wire contract only -- serde and nothing else. It knows
//! about participants, addresses and messages; it knows nothing about tasks,
//! schedulers, runs, grants, workspaces, nodes, or any particular system that
//! happens to run agents (see `mail4agent/CLAUDE.md`).
//!
//! Ported from `gate4agent-harness-protocol`'s mail surface
//! (`docs/gate4agent/research/mailbox-code-inventory-2026-09-16.md` section
//! 1.1): the discipline is kept -- bounded, validated on both encode and
//! decode, versioned by convention, legacy-tolerant on read -- while every
//! name that leaked a harness/task-kernel concept (`HarnessRecordRef`,
//! `HarnessMailAddressV1::Session`/`Task`, `task_id`) is replaced by a
//! general shape a standalone mailbox can own outright.
//!
//! **The rule that defines this service**: a sender is never a field the
//! caller fills in. See [`SendRequest`].

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

/// Prefix every [`MessageId`] carries. Mirrors `HarnessMailMessageId`'s own
/// `hmail_` prefix, renamed so a value can never be mistaken for a harness
/// message id from the crate this was ported out of.
pub const MESSAGE_ID_PREFIX: &str = "m4a_";

/// Length, in lower-hex characters, of a [`MessageId`]'s body after its
/// prefix. Same width as the source's `opaque_id!` ids.
pub const MESSAGE_ID_HEX_LEN: usize = 24;

/// Bound shared by every selector-shaped id ([`ParticipantId`], [`RoomId`],
/// [`MessageRef::kind`]): ASCII, 1..=128 bytes. Ported from
/// `HARNESS_SELECTOR_MAX_BYTES` / `validate_selector`.
pub const SELECTOR_MAX_BYTES: usize = 128;

/// Maximum size of [`Message::subject`] / [`SendRequest::subject`], in bytes
/// (not characters).
pub const SUBJECT_MAX_BYTES: usize = 512;

/// Maximum size of [`Message::body`] / [`SendRequest::body`], in bytes (not
/// characters).
pub const BODY_MAX_BYTES: usize = 65_536;

/// Maximum number of entries in [`Message::refs`] / [`SendRequest::refs`].
/// Ported verbatim from `HARNESS_MAIL_REFS_MAX`: a message names a handful
/// of dereferenceable results, never a manifest.
pub const REFS_MAX: usize = 8;

/// Maximum size of [`MessageRef::locator`], in bytes.
pub const REF_LOCATOR_MAX_BYTES: usize = 512;

/// Maximum length of [`MessageRef::digest`], in lower-hex characters, when
/// present. Unlike [`MESSAGE_ID_HEX_LEN`] this is a ceiling, not an exact
/// width: the mailbox never interprets a digest, so it does not know (and
/// must not assume) which hash algorithm produced it.
pub const REF_DIGEST_MAX_CHARS: usize = 128;

/// Maximum value accepted for [`InboxRequest::limit`].
pub const INBOX_LIMIT_MAX: u16 = 256;

/// Value [`InboxRequest::limit`] defaults to when a caller's JSON omits it.
pub const INBOX_LIMIT_DEFAULT: u16 = 50;

fn default_inbox_limit() -> u16 {
    INBOX_LIMIT_DEFAULT
}

/// A named refusal. Every variant names its inputs so a caller learns what
/// was refused and why from the refusal alone -- never a bare `Internal`
/// (the crate contract's own discipline; see `mail4agent/CLAUDE.md`).
///
/// `UnknownParticipant`/`UnknownRoom` carry the offending id even though the
/// task's own sketch of this enum omitted their fields: an "unknown X"
/// refusal that does not say which X is exactly the unnamed-refusal failure
/// mode the crate contract calls out by name.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MailError {
    /// No participant is registered under this id.
    UnknownParticipant { participant: ParticipantId },
    /// No room is registered under this id.
    UnknownRoom { room: RoomId },
    /// No session is registered under this id -- it has never been named in
    /// an [`Address::Session`] that reached [`Address::Session`]'s
    /// registering call, `MailboxEngine::ensure_session`.
    UnknownSession { session: SessionId },
    /// `session` is registered, but under a different account than the one
    /// presented alongside it in an [`Address::Session`]. Refused rather
    /// than silently resolved either way, because either party being wrong
    /// about which account owns a session is exactly the confusion the
    /// account/session split exists to prevent.
    SessionAccountMismatch { session: SessionId, expected: ParticipantId, presented: ParticipantId },
    /// No message is stored under this id.
    UnknownMessage { message_id: MessageId },
    /// The message exists, but was not sent to the caller (not their direct
    /// address, and not a room they belong to).
    NotAddressedToYou { message_id: MessageId },
    /// The caller's credential does not carry the capability the operation
    /// needs. `need` names the missing capability, e.g. `"mail:send"`.
    PermissionDenied { need: String },
    /// A field failed structural validation. `reason` says how.
    Malformed { field: String, reason: String },
    /// A field exceeded its bound. Carries both the bound and what was sent
    /// so the caller can act without a second round trip.
    TooLarge { field: String, limit: usize, actual: usize },
    /// The storage layer could not complete `operation` (a filesystem
    /// error, a lock, a corrupt row -- never a domain refusal). Names only
    /// the operation, never the underlying cause: that cause is logged
    /// server-side for the operator, so a caller learns *what* failed
    /// without a path or a driver's error text leaving the process.
    StoreUnavailable { operation: String },
}

impl fmt::Display for MailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownParticipant { participant } => {
                write!(f, "unknown participant \"{participant}\"")
            }
            Self::UnknownRoom { room } => write!(f, "unknown room \"{room}\""),
            Self::UnknownSession { session } => write!(f, "unknown session \"{session}\""),
            Self::SessionAccountMismatch { session, expected, presented } => write!(
                f,
                "session \"{session}\" belongs to account \"{expected}\", not \"{presented}\""
            ),
            Self::UnknownMessage { message_id } => write!(f, "unknown message \"{message_id}\""),
            Self::NotAddressedToYou { message_id } => {
                write!(f, "message \"{message_id}\" is not addressed to you")
            }
            Self::PermissionDenied { need } => write!(f, "permission denied: need \"{need}\""),
            Self::Malformed { field, reason } => {
                write!(f, "field \"{field}\" is malformed: {reason}")
            }
            Self::TooLarge { field, limit, actual } => {
                write!(f, "field \"{field}\" is too large: limit {limit}, actual {actual}")
            }
            Self::StoreUnavailable { operation } => {
                write!(f, "the store could not complete \"{operation}\"")
            }
        }
    }
}

impl std::error::Error for MailError {}

/// `min_hex_len`/`max_hex_len` let one function serve both a fixed-width id
/// ([`MessageId`], `min == max`) and a variable-width one ([`SessionId`],
/// which has no fixed width because it is derived by the *caller* from a
/// process identity, never invented by this crate).
fn validate_opaque_id(
    label: &'static str,
    value: &str,
    prefix: &str,
    min_hex_len: usize,
    max_hex_len: usize,
) -> Result<(), MailError> {
    let Some(hex) = value.strip_prefix(prefix) else {
        return Err(MailError::Malformed {
            field: label.to_string(),
            reason: format!("must start with \"{prefix}\""),
        });
    };
    if hex.len() < min_hex_len
        || hex.len() > max_hex_len
        || !hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        let width = if min_hex_len == max_hex_len {
            min_hex_len.to_string()
        } else {
            format!("{min_hex_len}..={max_hex_len}")
        };
        return Err(MailError::Malformed {
            field: label.to_string(),
            reason: format!("body after \"{prefix}\" must be {width} lowercase hex characters"),
        });
    }
    Ok(())
}

fn validate_selector(label: &'static str, value: &str) -> Result<(), MailError> {
    if value.is_empty() {
        return Err(MailError::Malformed {
            field: label.to_string(),
            reason: "must not be empty".to_string(),
        });
    }
    if value.len() > SELECTOR_MAX_BYTES {
        return Err(MailError::TooLarge {
            field: label.to_string(),
            limit: SELECTOR_MAX_BYTES,
            actual: value.len(),
        });
    }
    if !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@' | b'+'))
    {
        return Err(MailError::Malformed {
            field: label.to_string(),
            reason: "must be ASCII from the set [A-Za-z0-9._@+-]".to_string(),
        });
    }
    Ok(())
}

/// Bound shared by every free-text field that is otherwise unstructured:
/// [`Message::subject`]/[`SendRequest::subject`], a participant's or
/// directory entry's `label`, and every free-text field a [`SessionCard`]
/// carries (an executable path, a provider session id, a model name, a
/// working directory, a role, a one-line description of what a session is
/// working on). One rule, one place, so the bound and the "no control
/// characters" rule cannot drift between the fields that share it.
fn validate_bounded_text(field: &'static str, value: &str) -> Result<(), MailError> {
    if value.len() > SUBJECT_MAX_BYTES {
        return Err(MailError::TooLarge {
            field: field.to_string(),
            limit: SUBJECT_MAX_BYTES,
            actual: value.len(),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(MailError::Malformed {
            field: field.to_string(),
            reason: "must not contain control characters".to_string(),
        });
    }
    Ok(())
}

fn validate_subject(value: &str) -> Result<(), MailError> {
    validate_bounded_text("subject", value)
}

fn validate_body(value: &str) -> Result<(), MailError> {
    if value.len() > BODY_MAX_BYTES {
        return Err(MailError::TooLarge {
            field: "body".to_string(),
            limit: BODY_MAX_BYTES,
            actual: value.len(),
        });
    }
    if value.chars().any(|character| character.is_control() && !matches!(character, '\n' | '\t')) {
        return Err(MailError::Malformed {
            field: "body".to_string(),
            reason: "must not contain control characters other than newline and tab".to_string(),
        });
    }
    Ok(())
}

/// `correlation` has no bound in the source (`task_id` there was a
/// fixed-width opaque id, not free text) but this crate's own discipline is
/// "bounded, validated" throughout, so it reuses the subject bound rather
/// than going unbounded.
fn validate_correlation(value: &str) -> Result<(), MailError> {
    if value.len() > SUBJECT_MAX_BYTES {
        return Err(MailError::TooLarge {
            field: "correlation".to_string(),
            limit: SUBJECT_MAX_BYTES,
            actual: value.len(),
        });
    }
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(MailError::Malformed {
            field: "correlation".to_string(),
            reason: "must be non-empty and free of control characters".to_string(),
        });
    }
    Ok(())
}

fn validate_refs(refs: &[MessageRef]) -> Result<(), MailError> {
    if refs.len() > REFS_MAX {
        return Err(MailError::TooLarge {
            field: "refs".to_string(),
            limit: REFS_MAX,
            actual: refs.len(),
        });
    }
    for reference in refs {
        reference.validate()?;
    }
    Ok(())
}

/// Defines an opaque, prefixed, fixed-width hex id: `Display`, `FromStr`,
/// and serde as a plain string, rejecting a bad prefix or a bad body on
/// both `new()` and decode. Ported from `gate4agent-harness-protocol`'s
/// `opaque_id!` macro (`gate4agent-harness-protocol/src/lib.rs:50-97`).
macro_rules! opaque_id {
    ($name:ident, $prefix:expr, $label:literal, $min_hex:expr, $max_hex:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            pub fn new(value: impl Into<String>) -> Result<Self, MailError> {
                let value = value.into();
                validate_opaque_id($label, &value, Self::PREFIX, $min_hex, $max_hex)?;
                Ok(Self(value))
            }

            pub fn validate(&self) -> Result<(), MailError> {
                validate_opaque_id($label, &self.0, Self::PREFIX, $min_hex, $max_hex)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = MailError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

/// Defines a bounded selector id: ASCII, 1..=128 bytes, charset
/// `[A-Za-z0-9._@+-]`. Ported from `HarnessSelectorV1`'s validation
/// (`validate_selector`, `gate4agent-harness-protocol/src/lib.rs:2910-2917`).
/// Unlike the source type, each caller of this macro gets `Display` and
/// `FromStr` too: the source's `HarnessSelectorV1` had neither, but this
/// crate's ids are used as map keys and address components and are worth
/// being able to print and parse directly.
macro_rules! selector_id {
    ($name:ident, $label:literal, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, MailError> {
                let value = value.into();
                validate_selector($label, &value)?;
                Ok(Self(value))
            }

            pub fn validate(&self) -> Result<(), MailError> {
                validate_selector($label, &self.0)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = MailError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

opaque_id!(
    MessageId,
    MESSAGE_ID_PREFIX,
    "message id",
    MESSAGE_ID_HEX_LEN,
    MESSAGE_ID_HEX_LEN,
    "Opaque, prefixed, fixed-width hex id for a stored [`Message`]. Ported \
     from `HarnessMailMessageId` (prefix `hmail_` there, `m4a_` here so a \
     value can never be mistaken for a harness message id from the crate \
     this was ported out of)."
);

/// Prefix every [`SessionId`] carries, chosen so a printed address like
/// `claude/s-7f3a...` reads unambiguously as "an account, then one of its
/// sessions" -- see [`Address`]'s `Display`/`FromStr`.
pub const SESSION_ID_PREFIX: &str = "s-";

/// Minimum length, in lower-hex characters, of a [`SessionId`]'s body after
/// its prefix -- a floor against an accidentally-empty id, not an exact
/// width (see [`SESSION_ID_HEX_MAX_CHARS`] for why there is no exact
/// width).
pub const SESSION_ID_HEX_MIN_CHARS: usize = 8;

/// Maximum length, in lower-hex characters, of a [`SessionId`]'s body.
/// Unlike [`MessageId`], a session id is derived by the *caller* from a
/// process identity (`mail4agent-attest::PeerProcess`'s `(pid,
/// started_at_unix_ms)` pair, typically hashed) and handed to this crate
/// already formed, so it has no width this crate gets to fix -- this bound
/// is generous enough for a SHA-256 hex digest (64 characters), a
/// reasonable way to derive one.
pub const SESSION_ID_HEX_MAX_CHARS: usize = 64;

opaque_id!(
    SessionId,
    SESSION_ID_PREFIX,
    "session id",
    SESSION_ID_HEX_MIN_CHARS,
    SESSION_ID_HEX_MAX_CHARS,
    "Opaque id for one live session under a [`ParticipantId`] account. \
     Derived by the caller from a process identity and handed to this \
     crate already formed -- `MailboxEngine::ensure_session` registers one, \
     it never invents one."
);

selector_id!(
    ParticipantId,
    "participant id",
    "Addresses one participant directly. Distinct from [`RoomId`] on \
     purpose: a room id must never be accepted where a participant id is \
     meant, and a shared alias would let one slip into the other's slot."
);

selector_id!(
    RoomId,
    "room id",
    "Addresses a named group of participants the mailbox itself tracks. \
     Distinct from [`ParticipantId`] on purpose (see there)."
);

/// Where a message goes, or who it is from: one account directly, one of
/// that account's live sessions, or a room the mailbox tracks membership
/// for. Serde-tagged on `kind` (`"direct"` / `"session"` / `"room"`).
///
/// Replaces the source's `HarnessMailAddressV1::Session`/`Task`: a room is
/// a named group of participants the mailbox itself tracks, with no
/// relationship to any task system -- unlike `Task`, which addressed every
/// grant able to read a given `task_id` in a foreign task kernel this crate
/// must never learn about. [`Self::Session`] is this crate's own addition
/// (`mailbox-service-extraction-and-signed-session-identity-2026-09-16.md`
/// §5e): a session *is* a participant, not a new concept beside one, so it
/// is a third shape of the same address type rather than a parallel id.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Address {
    Direct { participant: ParticipantId },
    Session { participant: ParticipantId, session: SessionId },
    Room { room: RoomId },
}

impl Address {
    pub fn validate(&self) -> Result<(), MailError> {
        match self {
            Self::Direct { participant } => participant.validate(),
            Self::Session { participant, session } => {
                participant.validate()?;
                session.validate()
            }
            Self::Room { room } => room.validate(),
        }
    }

    /// The account this address ultimately names: itself for [`Self::Direct`],
    /// the owning account for [`Self::Session`], `None` for [`Self::Room`]
    /// (a room has no owning account).
    pub fn account(&self) -> Option<&ParticipantId> {
        match self {
            Self::Direct { participant } | Self::Session { participant, .. } => Some(participant),
            Self::Room { .. } => None,
        }
    }
}

/// Shared by [`Message::validate`] (`from`) and [`Ack::validate`]
/// (`reader`) and [`SendResponse::validate`] (`from`): an address that
/// identifies *someone*, never somewhere mail merely goes. A room fails
/// this even though [`Address::validate`] alone would accept it -- nobody
/// sends mail "from" a room or acknowledges one "as" a room, so the field
/// itself, not just its components, must not be one.
fn validate_participant_address(field: &'static str, address: &Address) -> Result<(), MailError> {
    address.validate()?;
    if address.account().is_none() {
        return Err(MailError::Malformed {
            field: field.to_string(),
            reason: "must be a participant address (direct or session), not a room".to_string(),
        });
    }
    Ok(())
}

impl fmt::Display for Address {
    /// The shape a human or a tool argument writes -- `claude` for the
    /// account, `claude/s-7f3a...` for one of its sessions, `#room-1` for a
    /// room -- not the wire shape. The wire shape stays the tagged JSON
    /// object [`Serialize`]/[`Deserialize`] above produce; this is a second,
    /// display-only encoding, chosen to match
    /// `mailbox-service-extraction-and-signed-session-identity-2026-09-16.md`
    /// §5e's own example.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct { participant } => write!(f, "{participant}"),
            Self::Session { participant, session } => write!(f, "{participant}/{session}"),
            Self::Room { room } => write!(f, "#{room}"),
        }
    }
}

impl std::str::FromStr for Address {
    type Err = MailError;

    /// Parses the same shape [`Display`] writes: a leading `#` names a
    /// room; one `/` splits an account from one of its sessions; anything
    /// else is the account address directly. A room id and a participant id
    /// share the same charset (see their own `new` methods), so the
    /// leading `#` is what disambiguates a room from an account whose name
    /// happens to look the same -- neither charset permits `#` or `/`, so
    /// there is nothing for either component to accidentally supply.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(room) = value.strip_prefix('#') {
            return Ok(Self::Room { room: RoomId::new(room)? });
        }
        match value.split_once('/') {
            Some((participant, session)) => {
                Ok(Self::Session { participant: ParticipantId::new(participant)?, session: SessionId::new(session)? })
            }
            None => Ok(Self::Direct { participant: ParticipantId::new(value)? }),
        }
    }
}

/// Names a reference a message carries: a `kind` (a selector), a `locator`
/// (an opaque pointer, meaningful only to the calling application), and an
/// optional `digest` (a lower-hex content hash of whatever the locator
/// names).
///
/// Replaces the source's four structured `HarnessMailRefV1` variants
/// (`Run`/`ContextPack`/`Result`/`WorkspacePath`), each of which named a
/// harness-specific entity this crate must never learn about.
///
/// **The mailbox stores a ref and returns it verbatim; it never resolves
/// one.** Resolving a reference is the calling application's job, because
/// only that application knows what its own references mean.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageRef {
    pub kind: String,
    pub locator: String,
    pub digest: Option<String>,
}

impl MessageRef {
    pub fn validate(&self) -> Result<(), MailError> {
        validate_selector("ref kind", &self.kind)?;
        if self.locator.len() > REF_LOCATOR_MAX_BYTES {
            return Err(MailError::TooLarge {
                field: "ref locator".to_string(),
                limit: REF_LOCATOR_MAX_BYTES,
                actual: self.locator.len(),
            });
        }
        if self.locator.is_empty() || self.locator.chars().any(char::is_control) {
            return Err(MailError::Malformed {
                field: "ref locator".to_string(),
                reason: "must be non-empty and free of control characters".to_string(),
            });
        }
        if let Some(digest) = &self.digest {
            if digest.len() > REF_DIGEST_MAX_CHARS {
                return Err(MailError::TooLarge {
                    field: "ref digest".to_string(),
                    limit: REF_DIGEST_MAX_CHARS,
                    actual: digest.len(),
                });
            }
            if digest.is_empty()
                || !digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(MailError::Malformed {
                    field: "ref digest".to_string(),
                    reason: "must be non-empty lowercase hex".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// A stored message. `refs` defaults on decode
/// (`harness_mail_message_old_shape_without_refs_deserializes`'s own
/// forward-compatibility property, kept here) so a message written before a
/// future field addition still deserializes with an empty ref list rather
/// than failing decode.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub message_id: MessageId,
    /// The session's own address if a session sent this, the account's
    /// address if an account did -- never a room (see
    /// [`validate_participant_address`]).
    pub from: Address,
    pub to: Address,
    pub subject: String,
    pub body: String,
    pub reply_to: Option<MessageId>,
    /// Replaces the source's `task_id`. Correlation only: the mailbox never
    /// reads it to decide anything. It exists so a caller can group
    /// messages by whatever grouping concept it owns -- a task, a run, a
    /// conversation -- without the mailbox needing to know what that concept
    /// is.
    pub correlation: Option<String>,
    #[serde(default)]
    pub refs: Vec<MessageRef>,
    pub created_at_unix_ms: u64,
}

impl Message {
    pub fn validate(&self) -> Result<(), MailError> {
        self.message_id.validate()?;
        validate_participant_address("from", &self.from)?;
        self.to.validate()?;
        validate_subject(&self.subject)?;
        validate_body(&self.body)?;
        if let Some(reply_to) = &self.reply_to {
            reply_to.validate()?;
            if reply_to == &self.message_id {
                return Err(MailError::Malformed {
                    field: "reply_to".to_string(),
                    reason: "must not reference its own message_id".to_string(),
                });
            }
        }
        if let Some(correlation) = &self.correlation {
            validate_correlation(correlation)?;
        }
        validate_refs(&self.refs)?;
        if self.created_at_unix_ms == 0 {
            return Err(MailError::Malformed {
                field: "created_at_unix_ms".to_string(),
                reason: "must not be zero".to_string(),
            });
        }
        Ok(())
    }
}

/// Per-reader acknowledgement. Dedup key is `(message_id, reader)`, never
/// the message alone -- a room-addressed message has one ack per reader,
/// not one total. Ported from `HarnessMailAckV1`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub message_id: MessageId,
    /// The exact address that acknowledged: a session's own address if a
    /// session acked, the account's if an account did -- so two sessions of
    /// the same account track their own read state independently, the way
    /// Matrix scopes read markers to a `(user_id, device_id)` pair rather
    /// than to the account alone.
    pub reader: Address,
    pub acked_at_unix_ms: u64,
}

impl Ack {
    pub fn validate(&self) -> Result<(), MailError> {
        self.message_id.validate()?;
        validate_participant_address("reader", &self.reader)?;
        if self.acked_at_unix_ms == 0 {
            return Err(MailError::Malformed {
                field: "acked_at_unix_ms".to_string(),
                reason: "must not be zero".to_string(),
            });
        }
        Ok(())
    }
}

/// A value corroborated from a source that is real but not proof -- read
/// out of a process's own command line, for instance, rather than attested
/// by the kernel. Mirrors `mail4agent-attest::Declared`, which this crate
/// cannot depend on directly: `mail4agent/CLAUDE.md` keeps this crate's
/// dependency list empty of everything that is not serialisation, and that
/// crate links Windows process APIs to do its job. Getting the inner value
/// means calling [`Declared::into_inner`] or [`Declared::as_ref`], never a
/// plain field read, so a caller cannot treat a corroborated fact with the
/// same weight as an attested one by accident. See [`SessionCard`] for
/// where the split this type exists to preserve actually matters.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Declared<T>(T);

impl<T> Declared<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Consumes the wrapper and returns the declared value.
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Borrows the declared value without consuming the wrapper.
    pub fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: fmt::Display> fmt::Display for Declared<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Proved by the kernel at the moment the connection carrying this
/// session's request was accepted -- never rewritable by the process it
/// describes. Mirrors the three kernel-sourced fields of
/// `mail4agent-attest::PeerProcess` (`pid`, `started_at_unix_ms`, `exe`);
/// this crate cannot depend on that one directly (see [`Declared`]), so
/// this is the wire shape of the same three facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAttested {
    pub pid: u32,
    pub started_at_unix_ms: u64,
    pub exe: Option<String>,
}

impl SessionAttested {
    pub fn validate(&self) -> Result<(), MailError> {
        if let Some(exe) = &self.exe {
            validate_bounded_text("attested exe", exe)?;
        }
        Ok(())
    }
}

/// Read out of the process's own command line (or a CLI hook) -- real in
/// the sense that *some* process held this in memory at read time, and
/// never proof of what that process actually is or was launched with. Each
/// field is [`Declared`] for that reason; see its doc comment before
/// treating any of these with the same weight as [`SessionAttested`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCorroborated {
    pub provider_session_id: Option<Declared<String>>,
    pub model: Option<Declared<String>>,
    pub cwd: Option<Declared<String>>,
}

impl SessionCorroborated {
    pub fn validate(&self) -> Result<(), MailError> {
        if let Some(value) = &self.provider_session_id {
            validate_bounded_text("corroborated provider_session_id", value.as_ref())?;
        }
        if let Some(value) = &self.model {
            validate_bounded_text("corroborated model", value.as_ref())?;
        }
        if let Some(value) = &self.cwd {
            validate_bounded_text("corroborated cwd", value.as_ref())?;
        }
        Ok(())
    }
}

/// Said by the session about itself -- the weakest tier, and the only one a
/// session can write at all: see `MailboxEngine::set_declared`, the sole
/// way this group is ever set.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionDeclared {
    pub working_on: Option<String>,
    pub role: Option<String>,
    /// Which session spawned this one, said by this session about itself --
    /// not verified against the registry, the same way the rest of this
    /// group is not.
    pub parent: Option<SessionId>,
}

impl SessionDeclared {
    pub fn validate(&self) -> Result<(), MailError> {
        if let Some(value) = &self.working_on {
            validate_bounded_text("declared working_on", value)?;
        }
        if let Some(value) = &self.role {
            validate_bounded_text("declared role", value)?;
        }
        if let Some(parent) = &self.parent {
            parent.validate()?;
        }
        Ok(())
    }
}

/// What the mailbox knows about one session, split by how sure it can be:
/// [`SessionAttested`] from the kernel, [`SessionCorroborated`] from the
/// process's own command line, [`SessionDeclared`] said by the session
/// about itself. Kept as three distinct nested structs -- never flattened
/// into one -- so the provenance of every field is visible in the type and
/// survives into the JSON exactly as it should be trusted. See
/// `mailbox-service-extraction-and-signed-session-identity-2026-09-16.md`
/// §5e.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCard {
    pub attested: SessionAttested,
    pub corroborated: SessionCorroborated,
    pub declared: SessionDeclared,
}

impl SessionCard {
    pub fn validate(&self) -> Result<(), MailError> {
        self.attested.validate()?;
        self.corroborated.validate()?;
        self.declared.validate()
    }
}

/// One session under an account, as the mailbox's directory reports it.
/// `live` is filled by the mailbox from a liveness check it is *given*, not
/// one it performs itself -- `mail4agent-core` learns nothing about
/// processes or Windows; see `MailboxEngine::directory`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionEntry {
    pub id: SessionId,
    pub card: SessionCard,
    pub last_seen_unix_ms: u64,
    pub live: bool,
}

impl SessionEntry {
    pub fn validate(&self) -> Result<(), MailError> {
        self.id.validate()?;
        self.card.validate()
    }
}

/// A registered participant. `label` is display metadata set when the
/// participant registers; it is never accepted on a send -- a sender's
/// identity comes from its credential, not from a caller-supplied field
/// (see [`SendRequest`]).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Participant {
    pub id: ParticipantId,
    pub label: Option<String>,
}

impl Participant {
    pub fn validate(&self) -> Result<(), MailError> {
        self.id.validate()?;
        if let Some(label) = &self.label {
            validate_label(label)?;
        }
        Ok(())
    }
}

/// Shared by [`Participant::validate`] and [`DirectoryEntry::validate`]:
/// both carry the exact same `label` shape (an optional display string,
/// bounded like a subject, no control characters), and a directory entry
/// is nothing more than a participant's id and label with the rest of
/// [`Participant`] stripped away -- see [`DirectoryEntry`]'s own doc
/// comment for why.
fn validate_label(value: &str) -> Result<(), MailError> {
    validate_bounded_text("label", value)
}

/// One **account** in the mailbox's directory, with its live sessions
/// nested under it -- the XMPP/Matrix shape (an account, then its
/// individually addressable sessions), not a flat list of CLI brands. See
/// `mailbox-service-extraction-and-signed-session-identity-2026-09-16.md`
/// §5e. **Never carries a secret digest or a permission bit** -- a
/// directory answers "who exists", not "what may they do" or anything that
/// would help forge them, and a type that structurally has no such field
/// cannot leak one even by accident (mirrors
/// `mail4agent_core::store::ParticipantSummary`, the store-side type this
/// is assembled from). `sessions` defaults to empty on decode so a payload
/// written before this field existed still deserializes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntry {
    pub id: ParticipantId,
    pub label: Option<String>,
    #[serde(default)]
    pub sessions: Vec<SessionEntry>,
}

impl DirectoryEntry {
    pub fn validate(&self) -> Result<(), MailError> {
        self.id.validate()?;
        if let Some(label) = &self.label {
            validate_label(label)?;
        }
        for session in &self.sessions {
            session.validate()?;
        }
        Ok(())
    }
}

/// One room in the mailbox's directory: its id, and whether the caller
/// who asked for the directory currently belongs to it. `member` is
/// relative to that one caller -- two different callers reading the
/// directory at the same moment see the same [`RoomEntry::id`] with
/// whatever [`RoomEntry::member`] value is true for each of them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomEntry {
    pub id: RoomId,
    pub member: bool,
}

impl RoomEntry {
    pub fn validate(&self) -> Result<(), MailError> {
        self.id.validate()
    }
}

/// Answers a directory request: every participant the mailbox has
/// registered and every room it tracks, from the point of view of
/// whoever asked (see [`RoomEntry::member`]). The whole mailbox's
/// population in one call, deliberately unpaginated -- this is a small,
/// local directory, not a social graph (`mail4agent/CLAUDE.md`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    pub participants: Vec<DirectoryEntry>,
    pub rooms: Vec<RoomEntry>,
}

impl Directory {
    pub fn validate(&self) -> Result<(), MailError> {
        for participant in &self.participants {
            participant.validate()?;
        }
        for room in &self.rooms {
            room.validate()?;
        }
        Ok(())
    }
}

/// Requests a send. **Has no `from` field and must never grow one.** The
/// sender is whoever the presented credential authenticated as; the
/// mailbox derives `from` from the verified identity, never from a field
/// the caller filled in.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    pub to: Address,
    pub subject: String,
    pub body: String,
    pub reply_to: Option<MessageId>,
    pub correlation: Option<String>,
    #[serde(default)]
    pub refs: Vec<MessageRef>,
    /// Scopes a retry: a repeat [`SendRequest`] from the same participant
    /// carrying the same key returns the original [`SendResponse`] and
    /// creates nothing (`mail4agent-core`'s `MailboxEngine::send`).
    /// Optional and defaulted on decode so a payload written before this
    /// field existed still deserializes.
    ///
    /// **Without a key, a repeat send is a second message, and that is
    /// correct** -- sending the same text twice on purpose should produce
    /// two messages. This field opts a caller into dedup; it is never
    /// inferred from content.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

impl SendRequest {
    pub fn validate(&self) -> Result<(), MailError> {
        self.to.validate()?;
        validate_subject(&self.subject)?;
        validate_body(&self.body)?;
        if let Some(reply_to) = &self.reply_to {
            reply_to.validate()?;
        }
        if let Some(correlation) = &self.correlation {
            validate_correlation(correlation)?;
        }
        validate_refs(&self.refs)?;
        if let Some(idempotency_key) = &self.idempotency_key {
            validate_selector("idempotency_key", idempotency_key)?;
        }
        Ok(())
    }
}

/// Requests a page of the caller's inbox. `limit` defaults to
/// [`INBOX_LIMIT_DEFAULT`] when a caller's JSON omits it, and is bounded by
/// [`INBOX_LIMIT_MAX`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboxRequest {
    pub since_unix_ms: Option<u64>,
    #[serde(default = "default_inbox_limit")]
    pub limit: u16,
}

impl InboxRequest {
    pub fn validate(&self) -> Result<(), MailError> {
        if self.limit == 0 {
            return Err(MailError::Malformed {
                field: "limit".to_string(),
                reason: "must be at least 1".to_string(),
            });
        }
        if self.limit > INBOX_LIMIT_MAX {
            return Err(MailError::TooLarge {
                field: "limit".to_string(),
                limit: usize::from(INBOX_LIMIT_MAX),
                actual: usize::from(self.limit),
            });
        }
        Ok(())
    }
}

/// Requests an acknowledgement be recorded for `message_id`, on behalf of
/// whoever the presented credential authenticated as (same discipline as
/// [`SendRequest`]: no reader field to fill in).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckRequest {
    pub message_id: MessageId,
}

impl AckRequest {
    pub fn validate(&self) -> Result<(), MailError> {
        self.message_id.validate()
    }
}

/// Requests one message by id.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageGetRequest {
    pub message_id: MessageId,
}

impl MessageGetRequest {
    pub fn validate(&self) -> Result<(), MailError> {
        self.message_id.validate()
    }
}

/// Requests the unread count for `target` -- an account or one of its
/// sessions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnreadCountRequest {
    pub target: Address,
}

impl UnreadCountRequest {
    pub fn validate(&self) -> Result<(), MailError> {
        validate_participant_address("target", &self.target)
    }
}

/// Answers a [`SendRequest`]. Returns the caller its own address so a
/// participant that just wrote immediately knows where it can be answered.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendResponse {
    pub message_id: MessageId,
    pub from: Address,
}

impl SendResponse {
    pub fn validate(&self) -> Result<(), MailError> {
        self.message_id.validate()?;
        validate_participant_address("from", &self.from)
    }
}

/// A page of a caller's inbox.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboxPage {
    pub messages: Vec<Message>,
    pub unread: u32,
}

impl InboxPage {
    pub fn validate(&self) -> Result<(), MailError> {
        for message in &self.messages {
            message.validate()?;
        }
        Ok(())
    }
}

/// Answers an [`AckRequest`]. Carries the recorded [`Ack`] back so the
/// caller has the exact reader identity and timestamp the mailbox stamped,
/// mirroring how [`SendResponse`] hands the caller its own address.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckResponse {
    pub ack: Ack,
}

impl AckResponse {
    pub fn validate(&self) -> Result<(), MailError> {
        self.ack.validate()
    }
}

/// Answers an [`UnreadCountRequest`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnreadCount {
    pub target: Address,
    pub unread: u32,
}

impl UnreadCount {
    pub fn validate(&self) -> Result<(), MailError> {
        validate_participant_address("target", &self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_MESSAGE_ID: &str = "m4a_0123456789abcdef01234567";

    fn participant(value: &str) -> ParticipantId {
        ParticipantId::new(value).expect("test participant id is valid")
    }

    fn message_id() -> MessageId {
        MessageId::new(VALID_MESSAGE_ID).expect("test message id is valid")
    }

    fn session_id(value: &str) -> SessionId {
        SessionId::new(value).expect("test session id is valid")
    }

    fn sample_message() -> Message {
        Message {
            message_id: message_id(),
            from: Address::Direct { participant: participant("alice") },
            to: Address::Direct { participant: participant("bob") },
            subject: "hi".to_string(),
            body: "hi".to_string(),
            reply_to: None,
            correlation: None,
            refs: Vec::new(),
            created_at_unix_ms: 1,
        }
    }

    #[test]
    fn message_id_round_trips_through_display_from_str_and_serde() {
        let id: MessageId = VALID_MESSAGE_ID.parse().expect("valid id parses");
        assert_eq!(id.to_string(), VALID_MESSAGE_ID);
        assert_eq!(id.as_str(), VALID_MESSAGE_ID);

        let json = serde_json::to_string(&id).expect("id serializes");
        assert_eq!(json, format!("\"{VALID_MESSAGE_ID}\""));
        let decoded: MessageId = serde_json::from_str(&json).expect("id deserializes");
        assert_eq!(decoded, id);
    }

    #[test]
    fn message_id_rejects_wrong_prefix() {
        let err = MessageId::new("wrong_0123456789abcdef01234567").expect_err("wrong prefix must be rejected");
        assert!(matches!(err, MailError::Malformed { field, .. } if field == "message id"));
    }

    #[test]
    fn message_id_rejects_short_body() {
        let err = MessageId::new("m4a_0123456789abcdef").expect_err("short body must be rejected");
        assert!(matches!(err, MailError::Malformed { field, .. } if field == "message id"));
    }

    #[test]
    fn message_id_rejects_non_hex_body() {
        let err = MessageId::new("m4a_0123456789abcdef0123456g").expect_err("non-hex body must be rejected");
        assert!(matches!(err, MailError::Malformed { field, .. } if field == "message id"));
    }

    #[test]
    fn participant_id_rejects_empty() {
        let err = ParticipantId::new("").expect_err("empty selector must be rejected");
        assert!(matches!(err, MailError::Malformed { field, .. } if field == "participant id"));
    }

    #[test]
    fn participant_id_rejects_129_bytes() {
        let value = "a".repeat(129);
        let err = ParticipantId::new(value).expect_err("129-byte selector must be rejected");
        assert!(matches!(err, MailError::TooLarge { field, limit, actual }
            if field == "participant id" && limit == SELECTOR_MAX_BYTES && actual == 129));
    }

    #[test]
    fn participant_id_accepts_exactly_128_bytes() {
        let value = "a".repeat(SELECTOR_MAX_BYTES);
        ParticipantId::new(value).expect("128-byte selector is accepted");
    }

    #[test]
    fn participant_id_rejects_non_ascii() {
        let err = ParticipantId::new("héllo").expect_err("non-ASCII selector must be rejected");
        assert!(matches!(err, MailError::Malformed { field, .. } if field == "participant id"));
    }

    #[test]
    fn participant_id_rejects_disallowed_characters() {
        for value in ["a/b", "a b"] {
            let err = ParticipantId::new(value).expect_err("disallowed character must be rejected");
            assert!(matches!(err, MailError::Malformed { field, .. } if field == "participant id"));
        }
    }

    #[test]
    fn room_id_and_participant_id_are_distinct_types() {
        // This is a compile-time property: `RoomId` and `ParticipantId` are
        // separate newtypes, so a room id can never be passed where a
        // participant id is expected. Exercised here by constructing both
        // from the same valid selector text and confirming they still
        // compare unequal in kind (different types entirely -- this test
        // documents the intent even though the type system already enforces
        // it at every call site).
        let room = RoomId::new("shared-name").expect("valid room id");
        let participant = ParticipantId::new("shared-name").expect("valid participant id");
        assert_eq!(room.as_str(), participant.as_str());
    }

    #[test]
    fn subject_is_accepted_at_exactly_the_byte_limit() {
        let subject = "a".repeat(SUBJECT_MAX_BYTES);
        validate_subject(&subject).expect("exactly at the limit is accepted");
    }

    #[test]
    fn subject_is_rejected_one_byte_over_the_limit() {
        let subject = "a".repeat(SUBJECT_MAX_BYTES + 1);
        let err = validate_subject(&subject).expect_err("one byte over the limit must be rejected");
        assert!(matches!(err, MailError::TooLarge { field, limit, actual }
            if field == "subject" && limit == SUBJECT_MAX_BYTES && actual == SUBJECT_MAX_BYTES + 1));
    }

    #[test]
    fn subject_byte_limit_counts_bytes_not_chars_for_multi_byte_utf8() {
        // U+1F600 is 4 bytes in UTF-8 but a single `char`.
        let subject: String = std::iter::repeat('\u{1F600}').take(200).collect();
        assert!(subject.chars().count() < SUBJECT_MAX_BYTES, "under the byte bound counted as chars");
        assert!(subject.len() > SUBJECT_MAX_BYTES, "over the byte bound counted as bytes");
        let err = validate_subject(&subject).expect_err("byte length must govern, not char count");
        assert!(matches!(err, MailError::TooLarge { field, .. } if field == "subject"));
    }

    #[test]
    fn body_is_accepted_at_exactly_the_byte_limit() {
        let body = "a".repeat(BODY_MAX_BYTES);
        validate_body(&body).expect("exactly at the limit is accepted");
    }

    #[test]
    fn body_is_rejected_one_byte_over_the_limit() {
        let body = "a".repeat(BODY_MAX_BYTES + 1);
        let err = validate_body(&body).expect_err("one byte over the limit must be rejected");
        assert!(matches!(err, MailError::TooLarge { field, limit, actual }
            if field == "body" && limit == BODY_MAX_BYTES && actual == BODY_MAX_BYTES + 1));
    }

    #[test]
    fn body_byte_limit_counts_bytes_not_chars_for_multi_byte_utf8() {
        let body: String = std::iter::repeat('\u{1F600}').take(20_000).collect();
        assert!(body.chars().count() < BODY_MAX_BYTES, "under the byte bound counted as chars");
        assert!(body.len() > BODY_MAX_BYTES, "over the byte bound counted as bytes");
        let err = validate_body(&body).expect_err("byte length must govern, not char count");
        assert!(matches!(err, MailError::TooLarge { field, .. } if field == "body"));
    }

    #[test]
    fn message_rejects_reply_to_referencing_its_own_message_id() {
        let mut message = sample_message();
        message.reply_to = Some(message.message_id.clone());
        let err = message.validate().expect_err("self reply_to must be rejected");
        assert!(matches!(err, MailError::Malformed { field, .. } if field == "reply_to"));
    }

    #[test]
    fn message_rejects_more_refs_than_the_bound() {
        let mut message = sample_message();
        message.refs = (0..=REFS_MAX)
            .map(|index| MessageRef {
                kind: "note".to_string(),
                locator: format!("loc-{index}"),
                digest: None,
            })
            .collect();
        let err = message.validate().expect_err("refs over the bound must be rejected");
        assert!(matches!(err, MailError::TooLarge { field, limit, actual }
            if field == "refs" && limit == REFS_MAX && actual == REFS_MAX + 1));
    }

    #[test]
    fn message_accepts_exactly_refs_max_refs() {
        let mut message = sample_message();
        message.refs = (0..REFS_MAX)
            .map(|index| MessageRef {
                kind: "note".to_string(),
                locator: format!("loc-{index}"),
                digest: None,
            })
            .collect();
        message.validate().expect("exactly the bound is accepted");
    }

    #[test]
    fn message_json_without_refs_key_still_deserializes() {
        let json = format!(
            r#"{{
                "message_id": "{VALID_MESSAGE_ID}",
                "from": {{"kind": "direct", "participant": "alice"}},
                "to": {{"kind": "direct", "participant": "bob"}},
                "subject": "hi",
                "body": "hi",
                "reply_to": null,
                "correlation": null,
                "created_at_unix_ms": 1
            }}"#
        );
        let message: Message = serde_json::from_str(&json).expect("old shape without refs must still deserialize");
        assert!(message.refs.is_empty());
        message.validate().expect("decoded message is otherwise valid");
    }

    #[test]
    fn address_serialises_to_the_tagged_kind_form_and_round_trips() {
        let direct = Address::Direct { participant: participant("alice") };
        let json = serde_json::to_value(&direct).expect("direct address serializes");
        assert_eq!(json, serde_json::json!({"kind": "direct", "participant": "alice"}));
        let decoded: Address = serde_json::from_value(json).expect("direct address deserializes");
        assert_eq!(decoded, direct);

        let session = Address::Session { participant: participant("claude"), session: session_id("s-7f3a0000") };
        let json = serde_json::to_value(&session).expect("session address serializes");
        assert_eq!(
            json,
            serde_json::json!({"kind": "session", "participant": "claude", "session": "s-7f3a0000"})
        );
        let decoded: Address = serde_json::from_value(json).expect("session address deserializes");
        assert_eq!(decoded, session);

        let room = Address::Room { room: RoomId::new("room-1").expect("valid room id") };
        let json = serde_json::to_value(&room).expect("room address serializes");
        assert_eq!(json, serde_json::json!({"kind": "room", "room": "room-1"}));
        let decoded: Address = serde_json::from_value(json).expect("room address deserializes");
        assert_eq!(decoded, room);
    }

    #[test]
    fn address_display_and_from_str_use_the_familiar_shape() {
        let direct = Address::Direct { participant: participant("claude") };
        assert_eq!(direct.to_string(), "claude");
        assert_eq!("claude".parse::<Address>().expect("direct address parses"), direct);

        let session = Address::Session { participant: participant("claude"), session: session_id("s-7f3a0000") };
        assert_eq!(session.to_string(), "claude/s-7f3a0000");
        assert_eq!("claude/s-7f3a0000".parse::<Address>().expect("session address parses"), session);

        let room = Address::Room { room: RoomId::new("room-1").expect("valid room id") };
        assert_eq!(room.to_string(), "#room-1");
        assert_eq!("#room-1".parse::<Address>().expect("room address parses"), room);
    }

    #[test]
    fn address_account_names_the_owning_account_and_none_for_a_room() {
        let alice = participant("alice");
        assert_eq!(Address::Direct { participant: alice.clone() }.account(), Some(&alice));
        assert_eq!(
            Address::Session { participant: alice.clone(), session: session_id("s-7f3a0000") }.account(),
            Some(&alice)
        );
        assert_eq!(Address::Room { room: RoomId::new("room-1").expect("valid room id") }.account(), None);
    }

    #[test]
    fn message_and_ack_and_send_response_refuse_a_room_as_the_participant_address() {
        let room = Address::Room { room: RoomId::new("room-1").expect("valid room id") };

        let mut message = sample_message();
        message.from = room.clone();
        let err = message.validate().expect_err("a room must not be accepted as `from`");
        assert!(matches!(err, MailError::Malformed { field, .. } if field == "from"));

        let ack = Ack { message_id: message_id(), reader: room.clone(), acked_at_unix_ms: 1 };
        let err = ack.validate().expect_err("a room must not be accepted as `reader`");
        assert!(matches!(err, MailError::Malformed { field, .. } if field == "reader"));

        let response = SendResponse { message_id: message_id(), from: room };
        let err = response.validate().expect_err("a room must not be accepted as `from`");
        assert!(matches!(err, MailError::Malformed { field, .. } if field == "from"));
    }

    #[test]
    fn session_id_round_trips_and_rejects_a_short_body() {
        let id: SessionId = "s-7f3a0000".parse().expect("valid session id parses");
        assert_eq!(id.to_string(), "s-7f3a0000");

        let err = SessionId::new("s-abc").expect_err("a body shorter than the minimum must be rejected");
        assert!(matches!(err, MailError::Malformed { field, .. } if field == "session id"));

        let err = SessionId::new("wrong-7f3a0000").expect_err("a wrong prefix must be rejected");
        assert!(matches!(err, MailError::Malformed { field, .. } if field == "session id"));
    }

    #[test]
    fn session_card_validates_every_group_and_rejects_a_control_character_anywhere() {
        let mut card = SessionCard {
            attested: SessionAttested { pid: 4242, started_at_unix_ms: 1, exe: Some("claude.exe".to_string()) },
            corroborated: SessionCorroborated {
                provider_session_id: Some(Declared::new("prov-1".to_string())),
                model: Some(Declared::new("opus".to_string())),
                cwd: None,
            },
            declared: SessionDeclared { working_on: Some("parity work".to_string()), role: None, parent: None },
        };
        card.validate().expect("a well-formed card validates");

        card.corroborated.model = Some(Declared::new("bad\u{0007}model".to_string()));
        let err = card.validate().expect_err("a control character in a corroborated field must be rejected");
        assert!(matches!(err, MailError::Malformed { field, .. } if field == "corroborated model"));
    }

    #[test]
    fn directory_entry_nests_its_sessions_and_defaults_to_none_on_decode() {
        let entry = DirectoryEntry {
            id: participant("claude"),
            label: None,
            sessions: vec![SessionEntry {
                id: session_id("s-7f3a0000"),
                card: SessionCard {
                    attested: SessionAttested { pid: 1, started_at_unix_ms: 1, exe: None },
                    corroborated: SessionCorroborated { provider_session_id: None, model: None, cwd: None },
                    declared: SessionDeclared::default(),
                },
                last_seen_unix_ms: 1,
                live: true,
            }],
        };
        entry.validate().expect("a well-formed entry with a session validates");

        let json = serde_json::json!({"id": "claude", "label": null});
        let decoded: DirectoryEntry = serde_json::from_value(json).expect("an entry without sessions still decodes");
        assert!(decoded.sessions.is_empty());
    }

    #[test]
    fn inbox_request_defaults_limit_when_json_omits_it() {
        let request: InboxRequest = serde_json::from_str(r#"{"since_unix_ms": null}"#)
            .expect("inbox request without limit still deserializes");
        assert_eq!(request.limit, INBOX_LIMIT_DEFAULT);
        request.validate().expect("default limit is valid");
    }

    #[test]
    fn inbox_request_rejects_limit_over_the_max() {
        let request = InboxRequest { since_unix_ms: None, limit: INBOX_LIMIT_MAX + 1 };
        let err = request.validate().expect_err("limit over the max must be rejected");
        assert!(matches!(err, MailError::TooLarge { field, .. } if field == "limit"));
    }

    #[test]
    fn inbox_request_rejects_zero_limit() {
        let request = InboxRequest { since_unix_ms: None, limit: 0 };
        let err = request.validate().expect_err("zero limit must be rejected");
        assert!(matches!(err, MailError::Malformed { field, .. } if field == "limit"));
    }

    #[test]
    fn message_ref_rejects_more_than_the_digest_bound() {
        let reference = MessageRef {
            kind: "note".to_string(),
            locator: "loc".to_string(),
            digest: Some("a".repeat(REF_DIGEST_MAX_CHARS + 1)),
        };
        let err = reference.validate().expect_err("digest over the bound must be rejected");
        assert!(matches!(err, MailError::TooLarge { field, .. } if field == "ref digest"));
    }

    #[test]
    fn a_send_request_carrying_only_its_required_fields_decodes() {
        // serde defaults an absent Option field to None, so the optional
        // fields need no attribute to be omittable. This test exists because
        // that is easy to doubt, and doubting it invites a second set of
        // argument structs that can drift from these.
        let json = r#"{"to":{"kind":"direct","participant":"bob"},"subject":"s","body":"b"}"#;
        let req: SendRequest = serde_json::from_str(json).expect("minimal send request decodes");
        assert!(req.reply_to.is_none());
        assert!(req.correlation.is_none());
        assert!(req.idempotency_key.is_none());
        assert!(req.refs.is_empty());
        req.validate().expect("and it validates");
    }

    #[test]
    fn an_inbox_request_carrying_nothing_decodes_with_the_default_limit() {
        let req: InboxRequest = serde_json::from_str("{}").expect("empty inbox request decodes");
        assert!(req.since_unix_ms.is_none());
        assert_eq!(req.limit, INBOX_LIMIT_DEFAULT);
    }

    #[test]
    fn send_request_old_shape_without_idempotency_key_still_deserializes_and_validates() {
        let json = serde_json::json!({
            "to": {"kind": "direct", "participant": "bob"},
            "subject": "hi",
            "body": "hi",
            "reply_to": null,
            "correlation": null
        });
        let request: SendRequest = serde_json::from_value(json)
            .expect("old shape without idempotency_key must still deserialize");
        assert_eq!(request.idempotency_key, None);
        request.validate().expect("decoded request is otherwise valid");
    }

    #[test]
    fn directory_entry_serialises_with_id_label_and_sessions() {
        let entry = DirectoryEntry { id: participant("alice"), label: Some("Alice".to_string()), sessions: Vec::new() };
        let json = serde_json::to_value(&entry).expect("directory entry serializes");
        assert_eq!(json, serde_json::json!({"id": "alice", "label": "Alice", "sessions": []}));
        let decoded: DirectoryEntry = serde_json::from_value(json).expect("directory entry deserializes");
        assert_eq!(decoded, entry);
    }

    #[test]
    fn directory_entry_rejects_a_control_character_label() {
        let entry =
            DirectoryEntry { id: participant("alice"), label: Some("bad\u{0007}label".to_string()), sessions: Vec::new() };
        let err = entry.validate().expect_err("control character in label must be rejected");
        assert!(matches!(err, MailError::Malformed { field, .. } if field == "label"));
    }

    #[test]
    fn room_entry_round_trips_its_member_flag() {
        let entry = RoomEntry { id: RoomId::new("room-1").expect("valid room id"), member: true };
        let json = serde_json::to_value(&entry).expect("room entry serializes");
        assert_eq!(json, serde_json::json!({"id": "room-1", "member": true}));
        let decoded: RoomEntry = serde_json::from_value(json).expect("room entry deserializes");
        assert_eq!(decoded, entry);
    }

    #[test]
    fn directory_validates_every_entry_it_carries() {
        let directory = Directory {
            participants: vec![DirectoryEntry { id: participant("alice"), label: None, sessions: Vec::new() }],
            rooms: vec![RoomEntry { id: RoomId::new("room-1").expect("valid room id"), member: false }],
        };
        directory.validate().expect("a directory of otherwise-valid entries validates");
    }

    #[test]
    fn message_ref_rejects_non_hex_digest() {
        let reference = MessageRef {
            kind: "note".to_string(),
            locator: "loc".to_string(),
            digest: Some("not-hex".to_string()),
        };
        let err = reference.validate().expect_err("non-hex digest must be rejected");
        assert!(matches!(err, MailError::Malformed { field, .. } if field == "ref digest"));
    }
}
