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

fn validate_opaque_id(label: &'static str, value: &str, prefix: &str) -> Result<(), MailError> {
    let Some(hex) = value.strip_prefix(prefix) else {
        return Err(MailError::Malformed {
            field: label.to_string(),
            reason: format!("must start with \"{prefix}\""),
        });
    };
    if hex.len() != MESSAGE_ID_HEX_LEN
        || !hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MailError::Malformed {
            field: label.to_string(),
            reason: format!(
                "body after \"{prefix}\" must be {MESSAGE_ID_HEX_LEN} lowercase hex characters"
            ),
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

fn validate_subject(value: &str) -> Result<(), MailError> {
    if value.len() > SUBJECT_MAX_BYTES {
        return Err(MailError::TooLarge {
            field: "subject".to_string(),
            limit: SUBJECT_MAX_BYTES,
            actual: value.len(),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(MailError::Malformed {
            field: "subject".to_string(),
            reason: "must not contain control characters".to_string(),
        });
    }
    Ok(())
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
    ($name:ident, $prefix:expr, $label:literal, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            pub fn new(value: impl Into<String>) -> Result<Self, MailError> {
                let value = value.into();
                validate_opaque_id($label, &value, Self::PREFIX)?;
                Ok(Self(value))
            }

            pub fn validate(&self) -> Result<(), MailError> {
                validate_opaque_id($label, &self.0, Self::PREFIX)
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
    "Opaque, prefixed, fixed-width hex id for a stored [`Message`]. Ported \
     from `HarnessMailMessageId` (prefix `hmail_` there, `m4a_` here so a \
     value can never be mistaken for a harness message id from the crate \
     this was ported out of)."
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

/// Where a message goes: one participant directly, or a room the mailbox
/// tracks membership for. Serde-tagged on `kind` (`"direct"` / `"room"`).
///
/// Replaces the source's `HarnessMailAddressV1::Session`/`Task`: a room is
/// a named group of participants the mailbox itself tracks, with no
/// relationship to any task system -- unlike `Task`, which addressed every
/// grant able to read a given `task_id` in a foreign task kernel this crate
/// must never learn about.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Address {
    Direct { participant: ParticipantId },
    Room { room: RoomId },
}

impl Address {
    pub fn validate(&self) -> Result<(), MailError> {
        match self {
            Self::Direct { participant } => participant.validate(),
            Self::Room { room } => room.validate(),
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
    pub from: ParticipantId,
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
        self.from.validate()?;
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
    pub reader: ParticipantId,
    pub acked_at_unix_ms: u64,
}

impl Ack {
    pub fn validate(&self) -> Result<(), MailError> {
        self.message_id.validate()?;
        self.reader.validate()?;
        if self.acked_at_unix_ms == 0 {
            return Err(MailError::Malformed {
                field: "acked_at_unix_ms".to_string(),
                reason: "must not be zero".to_string(),
            });
        }
        Ok(())
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
            if label.len() > SUBJECT_MAX_BYTES {
                return Err(MailError::TooLarge {
                    field: "label".to_string(),
                    limit: SUBJECT_MAX_BYTES,
                    actual: label.len(),
                });
            }
            if label.chars().any(char::is_control) {
                return Err(MailError::Malformed {
                    field: "label".to_string(),
                    reason: "must not contain control characters".to_string(),
                });
            }
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

/// Requests the unread count for `participant`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnreadCountRequest {
    pub participant: ParticipantId,
}

impl UnreadCountRequest {
    pub fn validate(&self) -> Result<(), MailError> {
        self.participant.validate()
    }
}

/// Answers a [`SendRequest`]. Returns the caller its own address so a
/// participant that just wrote immediately knows where it can be answered.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendResponse {
    pub message_id: MessageId,
    pub from: ParticipantId,
}

impl SendResponse {
    pub fn validate(&self) -> Result<(), MailError> {
        self.message_id.validate()?;
        self.from.validate()
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
    pub participant: ParticipantId,
    pub unread: u32,
}

impl UnreadCount {
    pub fn validate(&self) -> Result<(), MailError> {
        self.participant.validate()
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

    fn sample_message() -> Message {
        Message {
            message_id: message_id(),
            from: participant("alice"),
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
                "from": "alice",
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

        let room = Address::Room { room: RoomId::new("room-1").expect("valid room id") };
        let json = serde_json::to_value(&room).expect("room address serializes");
        assert_eq!(json, serde_json::json!({"kind": "room", "room": "room-1"}));
        let decoded: Address = serde_json::from_value(json).expect("room address deserializes");
        assert_eq!(decoded, room);
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
