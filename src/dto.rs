//! HTTP-only wire types that `mail4agent-api` does not define -- either
//! because they are pure display shapes derived from state the engine
//! already exposes elsewhere ([`WhoAmIResponse`]), or because they belong
//! to this daemon's own admin surface, which `mail4agent-api` (deliberately
//! generic: serde and nothing else, no HTTP framework, no admin-specific
//! shapes) has no reason to carry. `mail4agent-api` ships the wire
//! contract for mail transport itself; this module is what layers the
//! registry admin surface on top, entirely inside the daemon that owns it.

use mail4agent_api::{Address, ParticipantId, RoomId, SessionCard};
use mail4agent_core::ParticipantPermissions;
use serde::{Deserialize, Serialize};

/// Answers `POST /mail/whoami`: the caller's own SESSION address, its
/// account's label, its room memberships, and its own card -- so a session
/// that has not written yet still knows where it can be answered, and can
/// see what the mailbox knows about it (which parts are attested and which
/// are not).
#[derive(Debug, Serialize)]
pub struct WhoAmIResponse {
    pub address: Address,
    pub label: Option<String>,
    pub rooms: Vec<RoomId>,
    /// `None` only if `address` is somehow not a session -- every
    /// `/mail/*` and `/mcp` caller is session-resolved by construction
    /// (`crate::identity`), so in practice this is always `Some`.
    pub card: Option<SessionCard>,
}

/// Answers `POST /mail/status`: the session's own card after the update,
/// so the caller can confirm what was recorded.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub card: SessionCard,
}

/// Body for `POST /admin/participant`.
#[derive(Debug, Deserialize)]
pub struct RegisterParticipantRequest {
    pub id: ParticipantId,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub may_send: bool,
    #[serde(default)]
    pub may_read: bool,
    #[serde(default)]
    pub operator: bool,
}

impl RegisterParticipantRequest {
    pub fn permissions(&self) -> ParticipantPermissions {
        ParticipantPermissions {
            may_send: self.may_send,
            may_read: self.may_read,
            operator: self.operator,
        }
    }
}

/// Answers `POST /admin/participant` and `POST /admin/participant/rotate`
/// -- the secret is returned exactly ONCE; only its digest is kept
/// (`mail4agent_core::MailboxEngine::register_participant`'s own doc
/// comment).
#[derive(Debug, Serialize)]
pub struct SecretResponse {
    pub id: ParticipantId,
    pub secret: String,
}

/// Body for `POST /admin/participant/rotate` and
/// `POST /admin/participant/remove`.
#[derive(Debug, Deserialize)]
pub struct ParticipantIdRequest {
    pub id: ParticipantId,
}

/// Body for `POST /admin/room`.
#[derive(Debug, Deserialize)]
pub struct RoomIdRequest {
    pub id: RoomId,
}

/// Body for `POST /admin/room/member/add` and
/// `POST /admin/room/member/remove`.
#[derive(Debug, Deserialize)]
pub struct RoomMemberRequest {
    pub room: RoomId,
    pub participant: ParticipantId,
}

/// A body-less acknowledgement for admin mutations with nothing else to
/// report (deregister, room create, membership add/remove).
#[derive(Debug, Serialize)]
pub struct EmptyResponse {}

/// Body for `POST /admin/listener`: registers (or replaces) the URL the
/// mailbox POSTs a `mail4agent_api::DeliveryNotification` to whenever mail
/// arrives for `account` or any of its sessions. `url`'s own shape (bounded,
/// loopback-only) is validated by `mail4agent_core::MailboxEngine::set_listener`,
/// not here -- this daemon's admin bodies carry no validation logic of
/// their own, the same way every other request in this module forwards
/// straight into the engine (see `RegisterParticipantRequest`).
#[derive(Debug, Deserialize)]
pub struct SetListenerRequest {
    pub account: ParticipantId,
    pub url: String,
}

/// Body for `POST /admin/listener/remove`.
#[derive(Debug, Deserialize)]
pub struct RemoveListenerRequest {
    pub account: ParticipantId,
}
