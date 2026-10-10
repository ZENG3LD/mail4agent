//! Matrix event layer, spike stage (F3.0).
//!
//! What it does: builds room events of room version 11 the way a foreign Matrix server expects
//! them: no `event_id` on the wire, a content hash, an ed25519 signature over the redacted form,
//! and an event id that is COMPUTED (`$` + url-safe unpadded base64 of the reference hash). It
//! checks every new event against the room's auth rules before accepting it, and wraps
//! `ruma-state-res` for state resolution over forked state.
//!
//! What it is not: no HTTP, no storage, no federation transport. Keys come in through a closure,
//! so the crate does not care which ed25519 implementation the caller uses. All ruma types stay
//! behind this crate's own small surface.

mod builder;
pub mod dag;
mod pdu;
mod resolve;
mod signer;

pub use builder::{BuildError, RoomBuilder, SignedEvent};
pub use pdu::Pdu;
pub use resolve::{auth_chain, auth_chain_with, resolve_state, resolve_state_with, ResolveError};
pub use signer::Signer;

pub use ruma_common::IdParseError as IdError;
pub use ruma_common::{OwnedEventId, OwnedRoomId, OwnedUserId, RoomVersionId};
pub use ruma_state_res::StateMap;
pub use ruma_signatures::PublicKeyMap;
pub use ruma_common::{CanonicalJsonObject, room_version_rules::RoomVersionRules};

/// The room version this spike emits.
pub const ROOM_VERSION: RoomVersionId = RoomVersionId::V11;

pub use ruma_common::{CanonicalJsonValue, EventId};
pub use ruma_events::StateEventType;

/// A signing key as ruma wants it, from standard base64 (padded or not).
pub fn key_from_b64(b64: &str) -> Result<ruma_common::serde::Base64, String> {
    ruma_common::serde::Base64::parse(b64).map_err(|e| e.to_string())
}

/// Standard base64 of public key bytes.
pub fn key_to_b64(bytes: &[u8]) -> String {
    ruma_common::serde::Base64::<ruma_common::serde::base64::Standard>::new(bytes.to_vec()).encode()
}
