//! Neutral policy hook. The server asks the hook before an account-initiated
//! action; the default allows everything. No tariff, tier or price is
//! defined here: a deployment plugs its own [`PolicyHook`] and decides what
//! `authenticated` and `paid` mean.

use crate::account_source::AccountFacts;
use crate::store::RoomKind;

/// Things the server asks about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    CreateRoom,
    Invite,
    JoinRoom,
    SendEvent,
    UploadMedia,
    SetNick,
}

#[derive(Debug, Clone)]
pub struct PolicyContext<'a> {
    pub facts: &'a AccountFacts,
    pub action: Action,
    /// Known when the action concerns an existing or requested room.
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
pub fn enforce(hook: &dyn PolicyHook, facts: &AccountFacts, action: Action, room_kind: Option<RoomKind>) -> Result<(), crate::error::MatrixError> {
    match hook.decide(&PolicyContext { facts, action, room_kind }) {
        Decision::Allow => Ok(()),
        Decision::Deny(why) => Err(crate::error::MatrixError::policy_denied(why)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DenyUnpaidChannels;
    impl PolicyHook for DenyUnpaidChannels {
        fn decide(&self, c: &PolicyContext<'_>) -> Decision {
            if c.action == Action::CreateRoom && c.room_kind == Some(RoomKind::Channel) && !c.facts.paid {
                Decision::Deny("not available".into())
            } else {
                Decision::Allow
            }
        }
    }

    #[test]
    fn default_allows_and_custom_hook_denies_with_policy_error() {
        let f = AccountFacts::local();
        assert!(enforce(&AllowAll, &f, Action::CreateRoom, Some(RoomKind::Channel)).is_ok());
        let e = enforce(&DenyUnpaidChannels, &f, Action::CreateRoom, Some(RoomKind::Channel)).unwrap_err();
        assert_eq!((e.status, e.errcode), (403, "M4A_POLICY_DENIED"));
        assert!(enforce(&DenyUnpaidChannels, &f, Action::CreateRoom, Some(RoomKind::Dm)).is_ok());
    }
}
