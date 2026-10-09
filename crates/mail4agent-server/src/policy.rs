//! Neutral policy hook. The server asks the hook before an action; the
//! default allows everything. The server defines no tariff or tier: the
//! product's assertion carries opaque claims (see [`claims_from`]) and the
//! hook decides what they mean.

use std::collections::BTreeMap;

use crate::store::RoomKind;

/// Opaque product claims for one caller.
pub type Claims = BTreeMap<String, String>;

/// Claims for a caller admitted by a signed assertion: `flag` ("0"/"1", opaque).
pub fn claims_from(paid_flag: u8) -> Claims {
    let mut c = Claims::new();
    c.insert("flag".into(), paid_flag.to_string());
    c
}

/// Things the server asks about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    CreateRoom,
    Invite,
    JoinRoom,
    SendEvent,
    UploadMedia,
}

#[derive(Debug, Clone)]
pub struct PolicyContext<'a> {
    pub claims: &'a Claims,
    pub action: Action,
    /// Known when the action concerns a room kind.
    pub room_kind: Option<RoomKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Refuse with a human-readable reason (shown in `M4A_POLICY_DENIED`).
    Deny(String),
}

pub trait PolicyHook: Send + Sync {
    fn decide(&self, ctx: &PolicyContext<'_>) -> Decision;
}

/// Allows everything.
pub struct AllowAll;

impl PolicyHook for AllowAll {
    fn decide(&self, _ctx: &PolicyContext<'_>) -> Decision {
        Decision::Allow
    }
}

/// Run the hook and turn a denial into the API error.
pub fn enforce(hook: &dyn PolicyHook, claims: &Claims, action: Action, room_kind: Option<RoomKind>) -> Result<(), crate::error::MatrixError> {
    match hook.decide(&PolicyContext { claims, action, room_kind }) {
        Decision::Allow => Ok(()),
        Decision::Deny(why) => Err(crate::error::MatrixError::policy_denied(why)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DenyFlaglessChannels;
    impl PolicyHook for DenyFlaglessChannels {
        fn decide(&self, c: &PolicyContext<'_>) -> Decision {
            if c.action == Action::CreateRoom && c.room_kind == Some(RoomKind::Channel) && c.claims.get("flag").map(String::as_str) != Some("1") {
                Decision::Deny("not available".into())
            } else {
                Decision::Allow
            }
        }
    }

    #[test]
    fn default_allows_and_custom_hook_denies_with_policy_error() {
        let c0 = claims_from(0);
        assert!(enforce(&AllowAll, &c0, Action::CreateRoom, Some(RoomKind::Channel)).is_ok());
        let e = enforce(&DenyFlaglessChannels, &c0, Action::CreateRoom, Some(RoomKind::Channel)).unwrap_err();
        assert_eq!((e.status, e.errcode), (403, "M4A_POLICY_DENIED"));
        assert!(enforce(&DenyFlaglessChannels, &c0, Action::CreateRoom, Some(RoomKind::Dm)).is_ok());
        assert!(enforce(&DenyFlaglessChannels, &claims_from(1), Action::CreateRoom, Some(RoomKind::Channel)).is_ok());
    }
}
