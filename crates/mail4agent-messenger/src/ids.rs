//! Matrix identifier newtypes.
//!
//! [`UserId`], [`RoomId`] and [`EventId`] validate the shape the Matrix
//! Client-Server API mandates for their respective sigils (`@local:server`,
//! `!opaque:server`, `$opaque`) without parsing further into
//! protocol-specific structure beyond that split. [`DeviceId`] is a plain
//! opaque, server-assigned string with no sigil.
//!
//! This module never hardcodes a server name. Every id is either supplied
//! whole by a caller (who read it off the wire) or built from a localpart
//! plus a server name the *core* is
//! configured with (`MessengerCore::new`, a later piece), never a constant
//! baked in here.
//!
//! [`TxnId`] and [`RequestId`] are client-minted, not parsed off the wire:
//! [`TxnId::new`]/[`RequestId::next`] mint values from an explicit,
//! caller-supplied monotonic sequence number rather than a global counter,
//! so this sans-I/O crate carries no hidden shared mutable state (no
//! `static`/`OnceLock`) — the owner of a sequence (typically
//! `MessengerCore`, one counter per device session) decides how the
//! sequence is seeded (e.g. a random `u64` at process start) and threads it
//! through explicitly.

use crate::error::MessengerError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Splits a `<sigil><localpart>:<server_name>` identifier into its
/// localpart and server-name halves, used by [`UserId`] and [`RoomId`].
///
/// The split happens at the FIRST `:` after the sigil, not the last,
/// because `server_name` may itself carry a `:port` suffix while
/// `localpart` never contains `:` (matches the Matrix spec's own
/// `user_id`/`room_id` grammar).
fn split_sigil_id<'a>(
    kind: &'static str,
    value: &'a str,
    sigil: char,
) -> Result<(&'a str, &'a str), MessengerError> {
    let invalid = |reason: &str| MessengerError::InvalidId {
        kind,
        value: value.to_string(),
        reason: reason.to_string(),
    };
    let rest = value
        .strip_prefix(sigil)
        .ok_or_else(|| invalid(&format!("must start with '{sigil}'")))?;
    let (localpart, server) = rest
        .split_once(':')
        .ok_or_else(|| invalid("missing ':' separating localpart and server name"))?;
    if localpart.is_empty() {
        return Err(invalid("localpart must not be empty"));
    }
    if server.is_empty() {
        return Err(invalid("server name must not be empty"));
    }
    if localpart.chars().any(char::is_whitespace) || server.chars().any(char::is_whitespace) {
        return Err(invalid("must not contain whitespace"));
    }
    Ok((localpart, server))
}

/// A Matrix user id: `@localpart:server_name` (client-server API's own
/// `user_id` grammar).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(String);

impl UserId {
    /// Validates `value` as `@localpart:server_name`.
    pub fn parse(value: impl Into<String>) -> Result<Self, MessengerError> {
        let value = value.into();
        split_sigil_id("UserId", &value, '@')?;
        Ok(Self(value))
    }

    /// The id's own string form, e.g. `"@alice:example.org"`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A Matrix room id: `!opaque:server_name` (client-server API's own
/// `room_id` grammar — opaque per spec, never derived from the room's own
/// alias or name).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RoomId(String);

impl RoomId {
    /// Validates `value` as `!opaque:server_name`.
    pub fn parse(value: impl Into<String>) -> Result<Self, MessengerError> {
        let value = value.into();
        split_sigil_id("RoomId", &value, '!')?;
        Ok(Self(value))
    }

    /// The id's own string form, e.g. `"!abc123:example.org"`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RoomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A Matrix event id: `$opaque` (room version 3+ shape — no server-name
/// suffix; the opaque part is itself a content hash in most room
/// versions, but this crate does not interpret it further).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(String);

impl EventId {
    /// Validates `value` as `$opaque`.
    pub fn parse(value: impl Into<String>) -> Result<Self, MessengerError> {
        let value = value.into();
        let opaque = value.strip_prefix('$').ok_or_else(|| MessengerError::InvalidId {
            kind: "EventId",
            value: value.clone(),
            reason: "must start with '$'".to_string(),
        })?;
        if opaque.is_empty() || opaque.chars().any(char::is_whitespace) {
            return Err(MessengerError::InvalidId {
                kind: "EventId",
                value,
                reason: "opaque part must be non-empty and contain no whitespace".to_string(),
            });
        }
        Ok(Self(value))
    }

    /// The id's own string form, e.g. `"$abc123"`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A device id: an opaque, server-assigned string with no sigil, one per
/// authenticated session (plan §3.1's `MessengerCore::device_id`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(String);

impl DeviceId {
    /// Validates `value` as a non-empty, whitespace-free opaque string.
    pub fn parse(value: impl Into<String>) -> Result<Self, MessengerError> {
        let value = value.into();
        if value.is_empty() || value.chars().any(char::is_whitespace) {
            return Err(MessengerError::InvalidId {
                kind: "DeviceId",
                value,
                reason: "must be non-empty and contain no whitespace".to_string(),
            });
        }
        Ok(Self(value))
    }

    /// The id's own string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A client-chosen transaction id, scoping one request as idempotent from
/// the server's point of view (client-server API's own `txnId` path
/// parameter) and used locally to reconcile a local echo against its
/// server-confirmed event (`unsigned.transaction_id`, a later piece).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TxnId(String);

impl TxnId {
    /// Mints a transaction id from an explicit monotonic sequence value.
    /// This crate keeps no global/static counter (see the module doc) —
    /// the caller supplies a fresh, strictly increasing `seed` on every
    /// call (e.g. a `u64` field on `MessengerCore`, itself seeded once from
    /// any entropy source at construction).
    pub fn new(seed: u64) -> Self {
        Self(format!("m.txn.{seed:016x}"))
    }

    /// The id's own string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Recovers the monotonic seed this id was minted from via
    /// [`TxnId::new`], or `None` if `self` was not built by this crate's
    /// own minter (e.g. an opaque value read off the wire via
    /// [`TxnId::from`]). Used by [`crate::core::MessengerCore::open`] to
    /// restore its counter past every id already in flight — see that
    /// module's doc for why a restart must never reissue an id.
    pub fn as_seed(&self) -> Option<u64> {
        self.0.strip_prefix("m.txn.").and_then(|hex| u64::from_str_radix(hex, 16).ok())
    }
}

impl fmt::Display for TxnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for TxnId {
    /// Wraps a transaction id read back off the wire (e.g.
    /// `unsigned.transaction_id` on a `/sync` timeline event) without
    /// re-validating it — the server already accepted it once as the id
    /// this client itself minted via [`TxnId::new`].
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// This crate's own internal request-correlation id — never sent over the
/// wire, only used to key an [`crate::wire::HttpResponseDescriptor`] (or a
/// crash-restart replay entry, a later piece) back to the
/// [`crate::wire::OutgoingRequest`] that produced it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(String);

impl RequestId {
    /// Mints the next id from an explicit monotonic sequence value — see
    /// [`TxnId::new`]'s doc for why this crate takes an explicit `seed`
    /// instead of keeping a global counter.
    pub fn next(seed: u64) -> Self {
        Self(format!("req.{seed:016x}"))
    }

    /// The id's own string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Recovers the monotonic seed this id was minted from via
    /// [`RequestId::next`], or `None` if `self` was not built by this
    /// crate's own minter. See [`TxnId::as_seed`]'s doc — same purpose, the
    /// other counter.
    pub fn as_seed(&self) -> Option<u64> {
        self.0.strip_prefix("req.").and_then(|hex| u64::from_str_radix(hex, 16).ok())
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for RequestId {
    /// Wraps a request id read back out of a persisted record's storage key
    /// (`store`'s `pending/{request_id}` layout, a later piece) without
    /// re-validating it -- the value being decoded is one this process
    /// itself minted via [`RequestId::next`] on an earlier run.
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_id_accepts_a_well_formed_sigil() {
        let id = UserId::parse("@alice:example.org").expect("valid user id");
        assert_eq!(id.as_str(), "@alice:example.org");
        assert_eq!(id.to_string(), "@alice:example.org");
    }

    #[test]
    fn user_id_accepts_a_server_name_with_a_port() {
        let id = UserId::parse("@alice:example.org:8448").expect("port suffix is part of server_name");
        assert_eq!(id.as_str(), "@alice:example.org:8448");
    }

    #[test]
    fn user_id_rejects_a_missing_sigil() {
        let err = UserId::parse("alice:example.org").unwrap_err();
        assert!(matches!(err, MessengerError::InvalidId { kind: "UserId", .. }));
    }

    #[test]
    fn user_id_rejects_a_missing_server_name() {
        assert!(UserId::parse("@alice").is_err());
        assert!(UserId::parse("@alice:").is_err());
    }

    #[test]
    fn user_id_rejects_an_empty_localpart() {
        assert!(UserId::parse("@:example.org").is_err());
    }

    #[test]
    fn room_id_accepts_a_well_formed_sigil() {
        let id = RoomId::parse("!abc123:example.org").expect("valid room id");
        assert_eq!(id.as_str(), "!abc123:example.org");
    }

    #[test]
    fn room_id_rejects_a_missing_sigil() {
        assert!(RoomId::parse("abc123:example.org").is_err());
    }

    #[test]
    fn event_id_accepts_a_well_formed_sigil() {
        let id = EventId::parse("$abc123").expect("valid event id");
        assert_eq!(id.as_str(), "$abc123");
    }

    #[test]
    fn event_id_rejects_a_missing_sigil() {
        assert!(EventId::parse("abc123").is_err());
    }

    #[test]
    fn event_id_rejects_an_empty_opaque_part() {
        assert!(EventId::parse("$").is_err());
    }

    #[test]
    fn device_id_rejects_empty_and_whitespace() {
        assert!(DeviceId::parse("").is_err());
        assert!(DeviceId::parse("has space").is_err());
        assert!(DeviceId::parse("ABCDEFGH").is_ok());
    }

    #[test]
    fn txn_id_and_request_id_are_monotonic_and_distinct_namespaces() {
        let a = TxnId::new(0);
        let b = TxnId::new(1);
        assert_ne!(a, b);
        assert!(a.as_str() < b.as_str(), "fixed-width hex keeps lexicographic order monotonic");

        let r0 = RequestId::next(0);
        let r1 = RequestId::next(1);
        assert_ne!(r0, r1);
        assert_ne!(TxnId::new(0).as_str(), RequestId::next(0).as_str());
    }

    #[test]
    fn request_id_from_string_round_trips_a_previously_minted_value() {
        let minted = RequestId::next(7);
        let recovered = RequestId::from(minted.as_str().to_string());
        assert_eq!(minted, recovered);
    }

    #[test]
    fn as_seed_recovers_the_minting_seed() {
        assert_eq!(TxnId::new(42).as_seed(), Some(42));
        assert_eq!(RequestId::next(42).as_seed(), Some(42));
        assert_eq!(TxnId::from("opaque-server-value".to_string()).as_seed(), None);
        assert_eq!(RequestId::from("opaque-value".to_string()).as_seed(), None);
    }

    #[test]
    fn ids_round_trip_through_serde_as_a_bare_string() {
        let id = RoomId::parse("!abc:example.org").expect("valid room id");
        let json = serde_json::to_string(&id).expect("serialize");
        assert_eq!(json, "\"!abc:example.org\"");
        let back: RoomId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, id);
    }
}
