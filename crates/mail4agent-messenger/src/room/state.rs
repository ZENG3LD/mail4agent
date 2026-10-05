//! [`RoomState`] -- a room's current state, folded from `m.room.*` state
//! events (research doc §1.2, §1.4's `state.events`/`invite_state.events`),
//! plus [`RoomKind`] derivation and this crate's own coarse [`MemberRole`]
//! mapping.
//!
//! # Forward compatible by default
//!
//! [`RoomState::apply_state_event`] never fails on a state event type it
//! does not model (the same doctrine `crate::wire::events` already
//! follows) -- it only returns an error when a *recognized* type's
//! `content` fails to parse against the shape `crate::wire::events` already
//! defines for it.

use crate::error::MessengerError;
use crate::ids::{EventId, RoomId, UserId};
use crate::wire::events::{
    DirectContent, HistoryVisibility, JoinRule, Membership, RawEvent, RoomCreateContent, RoomEncryptionContent,
    RoomHistoryVisibilityContent, RoomJoinRulesContent, RoomMemberContent, RoomNameContent, RoomPinnedEventsContent,
    RoomPowerLevelsContent, RoomPowerLevelsNotifications, RoomTopicContent,
};
use crate::wire::sync::{RoomSummary as SyncRoomSummary, UnreadNotifications};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const EVENT_ROOM_CREATE: &str = "m.room.create";
const EVENT_ROOM_MEMBER: &str = "m.room.member";
const EVENT_ROOM_POWER_LEVELS: &str = "m.room.power_levels";
const EVENT_ROOM_JOIN_RULES: &str = "m.room.join_rules";
const EVENT_ROOM_HISTORY_VISIBILITY: &str = "m.room.history_visibility";
const EVENT_ROOM_NAME: &str = "m.room.name";
const EVENT_ROOM_TOPIC: &str = "m.room.topic";
const EVENT_ROOM_ENCRYPTION: &str = "m.room.encryption";
const EVENT_ROOM_PINNED_EVENTS: &str = "m.room.pinned_events";

/// Coarse role from a member's power level. A public room's read-only
/// follower has no power level to derive a role from, so that case is not
/// modeled here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberRole {
    /// Power level >= 100 -- room-creator/admin tier.
    Owner,
    /// Power level >= 50 -- moderator tier.
    Admin,
    /// Everyone else.
    Member,
}

impl MemberRole {
    /// Maps a raw power level to its coarse role. Thresholds match the
    /// Matrix convention cited in this type's own doc: `100` = owner, `50`
    /// = admin, anything else = plain member.
    pub fn from_power_level(power_level: i64) -> Self {
        if power_level >= 100 {
            MemberRole::Owner
        } else if power_level >= 50 {
            MemberRole::Admin
        } else {
            MemberRole::Member
        }
    }
}

/// What kind of room this is, derived from its current state -- never a
/// separately stored flag (see [`RoomState::derive_room_kind`]'s own doc
/// for the precedence between the two possible signals).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoomKind {
    /// A 1:1 conversation.
    Dm,
    /// A room with no channel signal -- an ordinary multi-person
    /// conversation.
    Group,
    /// A public, announcement-style room: anyone may join, but only a
    /// power level above `users_default` may post.
    Channel,
}

/// One user's membership-derived state within a room (`m.room.member`'s
/// content, research doc §1.2), keyed by that user's id in
/// [`RoomState::members`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberState {
    /// The subject's current membership.
    pub membership: Membership,
    /// The subject's display name, if set.
    pub displayname: Option<String>,
    /// `true` when this membership was flagged as part of a direct-message
    /// room at invite time -- one of [`RoomState::derive_room_kind`]'s two
    /// DM signals.
    pub is_direct: bool,
}

/// One room's current state, folded from every state event
/// [`RoomState::apply_state_event`] has been given so far. `Serialize`/
/// `Deserialize` back this type's own persisted record
/// (`crate::store`'s `room_state/{room_id}` key, restored by
/// [`crate::core::MessengerCore::open`]) — unlike [`crate::room::timeline::Timeline`],
/// which is never persisted and is always re-fetched instead (that type's
/// own module doc).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoomState {
    /// `m.room.create`'s content, once seen. Immutable once set: a room's
    /// creation event is never legitimately resent with different content,
    /// so [`RoomState::apply_state_event`] only ever accepts the first
    /// one.
    pub create: Option<RoomCreateContent>,
    /// Every user this room has ever recorded a membership state for,
    /// keyed by user id. A user who left/was banned stays in this map
    /// (with that membership) rather than being removed -- their history
    /// is still relevant (e.g. a past member's messages still need a
    /// sender to resolve against).
    pub members: BTreeMap<UserId, MemberState>,
    /// The room's current permission table, spec-defaulted until an
    /// `m.room.power_levels` event overrides it (`RoomPowerLevelsContent`'s
    /// own field docs list each default).
    pub power_levels: RoomPowerLevelsContent,
    /// `m.room.join_rules`'s content, if set.
    pub join_rules: Option<RoomJoinRulesContent>,
    /// `m.room.history_visibility`'s value, if set.
    pub history_visibility: Option<HistoryVisibility>,
    /// `m.room.name`'s value, if set.
    pub name: Option<String>,
    /// `m.room.topic`'s value, if set.
    pub topic: Option<String>,
    /// `m.room.encryption`'s content, once set -- see
    /// [`RoomState::apply_state_event`]'s doc for why this never changes
    /// once `Some`.
    pub encryption: Option<RoomEncryptionContent>,
    /// How many times [`RoomState::apply_state_event`] has seen an
    /// `m.room.encryption` event that tried to change an already-set
    /// value to something different -- `0` in the overwhelming common
    /// case. This crate has no logging dependency, so a nonzero count IS
    /// the flag a caller acts on (a misbehaving or compromised server),
    /// rather than the attempt being silently swallowed.
    pub encryption_tamper_attempts: u32,
    /// `m.room.pinned_events`'s content, in pin order.
    pub pinned_events: Vec<EventId>,
    /// `rooms.join.{room}.summary.m.heroes` from the most recent `/sync`
    /// response that included this room's summary (research doc §1.4) --
    /// up to five other members' user ids, used to synthesize a display
    /// name when [`RoomState::name`] is unset.
    pub heroes: Vec<UserId>,
    /// `summary.m.joined_member_count`, if the server included it.
    pub joined_member_count: Option<u64>,
    /// `summary.m.invited_member_count`, if the server included it.
    pub invited_member_count: Option<u64>,
    /// The room's server-computed unread counters (research doc §1.4) --
    /// [`RoomState::unread_count`] is a plain passthrough of
    /// `notification_count`; real highlight detection for an encrypted
    /// room is [`crate::room::timeline::highlight`], computed client-side
    /// after decryption (plan manager decision #5).
    pub unread_notifications: UnreadNotifications,
}

impl Default for RoomState {
    fn default() -> Self {
        Self {
            create: None,
            members: BTreeMap::new(),
            power_levels: RoomPowerLevelsContent {
                ban: 50,
                events: BTreeMap::new(),
                events_default: 0,
                invite: 50,
                kick: 50,
                redact: 50,
                state_default: 50,
                users: BTreeMap::new(),
                users_default: 0,
                notifications: RoomPowerLevelsNotifications::default(),
            },
            join_rules: None,
            history_visibility: None,
            name: None,
            topic: None,
            encryption: None,
            encryption_tamper_attempts: 0,
            pinned_events: Vec::new(),
            heroes: Vec::new(),
            joined_member_count: None,
            invited_member_count: None,
            unread_notifications: UnreadNotifications::default(),
        }
    }
}

impl RoomState {
    /// An empty room state: no state events folded yet, spec-default power
    /// levels (matches a room whose `m.room.power_levels` has never been
    /// sent).
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds one state event into this room's state. A no-op, not an
    /// error, for a timeline (non-state) event or a state event type this
    /// module does not model (module doc's forward-compatibility
    /// doctrine). Returns an error only when a recognized type's `content`
    /// fails to parse.
    pub fn apply_state_event(&mut self, event: &RawEvent) -> Result<(), MessengerError> {
        let Some(state_key) = event.state_key.as_deref() else { return Ok(()) };
        match event.event_type.as_str() {
            EVENT_ROOM_CREATE if self.create.is_none() => {
                self.create = Some(serde_json::from_value(event.content.clone())?);
            }
            EVENT_ROOM_MEMBER => {
                let Ok(user_id) = UserId::parse(state_key) else { return Ok(()) };
                let content: RoomMemberContent = serde_json::from_value(event.content.clone())?;
                self.members.insert(
                    user_id,
                    MemberState {
                        membership: content.membership,
                        displayname: content.displayname,
                        is_direct: content.is_direct.unwrap_or(false),
                    },
                );
            }
            EVENT_ROOM_POWER_LEVELS => {
                self.power_levels = serde_json::from_value(event.content.clone())?;
            }
            EVENT_ROOM_JOIN_RULES => {
                self.join_rules = Some(serde_json::from_value(event.content.clone())?);
            }
            EVENT_ROOM_HISTORY_VISIBILITY => {
                let content: RoomHistoryVisibilityContent = serde_json::from_value(event.content.clone())?;
                self.history_visibility = Some(content.history_visibility);
            }
            EVENT_ROOM_NAME => {
                let content: RoomNameContent = serde_json::from_value(event.content.clone())?;
                self.name = Some(content.name);
            }
            EVENT_ROOM_TOPIC => {
                let content: RoomTopicContent = serde_json::from_value(event.content.clone())?;
                self.topic = Some(content.topic);
            }
            EVENT_ROOM_ENCRYPTION => {
                let content: RoomEncryptionContent = serde_json::from_value(event.content.clone())?;
                match &self.encryption {
                    None => self.encryption = Some(content),
                    Some(current) if current != &content => {
                        // Spec invariant: once set, `m.room.encryption` is
                        // never unset or changed to a different algorithm/
                        // rotation policy (research doc §1.2). Enforcing
                        // that server-side is not this crate's job, but the
                        // client never adopts a later, different value --
                        // it only counts the attempt (this type's own
                        // doc).
                        self.encryption_tamper_attempts += 1;
                    }
                    Some(_) => {} // identical resend -- not a tamper attempt
                }
            }
            EVENT_ROOM_PINNED_EVENTS => {
                let content: RoomPinnedEventsContent = serde_json::from_value(event.content.clone())?;
                self.pinned_events = content.pinned;
            }
            _ => {}
        }
        Ok(())
    }

    /// Records this room's most recent `/sync` summary (heroes, member
    /// counts) and unread counters (research doc §1.4) -- called once per
    /// sync response that included this room, independent of
    /// [`RoomState::apply_state_event`] since a summary/`unread_
    /// notifications` block is not itself a state event.
    pub fn apply_summary(&mut self, summary: &SyncRoomSummary, unread: &UnreadNotifications) {
        self.heroes = summary.heroes.clone();
        self.joined_member_count = summary.joined_member_count;
        self.invited_member_count = summary.invited_member_count;
        self.unread_notifications = unread.clone();
    }

    /// The room's server-reported unread notification count -- a plain
    /// passthrough (plan manager decision #5: `notification_count` comes
    /// from the server; only *highlight* is computed client-side).
    pub fn unread_count(&self) -> u64 {
        self.unread_notifications.notification_count
    }

    /// `user_id`'s effective power level: their own entry in
    /// `power_levels.users`, or `power_levels.users_default` if they have
    /// none.
    pub fn power_level_for(&self, user_id: &UserId) -> i64 {
        self.power_levels.users.get(user_id).copied().unwrap_or(self.power_levels.users_default)
    }

    /// `user_id`'s coarse role, derived from [`RoomState::power_level_for`]
    /// via [`MemberRole::from_power_level`].
    pub fn member_role(&self, user_id: &UserId) -> MemberRole {
        MemberRole::from_power_level(self.power_level_for(user_id))
    }

    /// How many members currently hold an active (join or invite)
    /// membership -- used by [`RoomState::derive_room_kind`]'s DM check,
    /// and generally useful for a room-list "N members" line.
    pub fn active_member_count(&self) -> usize {
        self.members.values().filter(|member| matches!(member.membership, Membership::Join | Membership::Invite)).count()
    }

    /// Derives this room's [`RoomKind`] from its current state.
    ///
    /// **Precedence: DM first, channel second, group as the fallback.** DM
    /// wins over channel because it is the more deliberate, identity-scoped
    /// signal (an explicit `m.direct` account-data entry, or an invite
    /// that was explicitly flagged `is_direct` and never grew past two
    /// members) -- a room's power-level shape (the channel signal) says
    /// nothing about whether it was *intended* as a 1:1, so a 2-person room
    /// that happens to also be public with a raised `events_default`
    /// should still read as a DM, not a channel of one.
    ///
    /// `direct_account_data` is the account-wide `m.direct` content
    /// ([`DirectContent`]) -- global account data, not room state, so it is
    /// not a field of this type and must be threaded in by the caller (the
    /// sync engine, a later piece, already holds it after folding the
    /// top-level `account_data` section).
    pub fn derive_room_kind(&self, room_id: &RoomId, direct_account_data: Option<&DirectContent>) -> RoomKind {
        if self.is_direct(room_id, direct_account_data) {
            RoomKind::Dm
        } else if self.is_channel() {
            RoomKind::Channel
        } else {
            RoomKind::Group
        }
    }

    fn is_direct(&self, room_id: &RoomId, direct_account_data: Option<&DirectContent>) -> bool {
        let listed_in_account_data =
            direct_account_data.is_some_and(|direct| direct.0.values().any(|rooms| rooms.contains(room_id)));
        let invite_flagged_and_still_a_pair =
            self.active_member_count() == 2 && self.members.values().any(|member| member.is_direct);
        listed_in_account_data || invite_flagged_and_still_a_pair
    }

    fn is_channel(&self) -> bool {
        let is_public =
            matches!(self.join_rules.as_ref().map(|join_rules| &join_rules.join_rule), Some(JoinRule::Public));
        is_public && self.power_levels.events_default > self.power_levels.users_default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_event(event_type: &str, state_key: &str, sender: &str, content: serde_json::Value) -> RawEvent {
        serde_json::from_value(serde_json::json!({
            "event_id": "$e:example.org",
            "type": event_type,
            "sender": sender,
            "origin_server_ts": 1,
            "state_key": state_key,
            "content": content,
        }))
        .expect("valid state event")
    }

    #[test]
    fn derive_room_kind_dm_vs_group_vs_channel() {
        let room_id = RoomId::parse("!room:example.org").expect("valid room id");

        // Group: three joined members, no direct flag, no channel-shaped
        // power levels.
        let mut group = RoomState::new();
        for user in ["@alice:example.org", "@bob:example.org", "@carol:example.org"] {
            group
                .apply_state_event(&state_event("m.room.member", user, user, serde_json::json!({ "membership": "join" })))
                .expect("valid member event");
        }
        assert_eq!(group.derive_room_kind(&room_id, None), RoomKind::Group);

        // DM: two joined members, one of whom was invited with `is_direct`.
        let mut dm = RoomState::new();
        dm.apply_state_event(&state_event(
            "m.room.member",
            "@alice:example.org",
            "@alice:example.org",
            serde_json::json!({ "membership": "join" }),
        ))
        .expect("valid member event");
        dm.apply_state_event(&state_event(
            "m.room.member",
            "@bob:example.org",
            "@alice:example.org",
            serde_json::json!({ "membership": "join", "is_direct": true }),
        ))
        .expect("valid member event");
        assert_eq!(dm.derive_room_kind(&room_id, None), RoomKind::Dm);

        // Channel: public join rule, `events_default` raised above
        // `users_default` (research doc §1.2's announcement-only pattern).
        let mut channel = RoomState::new();
        channel
            .apply_state_event(&state_event(
                "m.room.join_rules",
                "",
                "@alice:example.org",
                serde_json::json!({ "join_rule": "public" }),
            ))
            .expect("valid join rules event");
        channel
            .apply_state_event(&state_event(
                "m.room.power_levels",
                "",
                "@alice:example.org",
                serde_json::json!({ "events_default": 50 }),
            ))
            .expect("valid power levels event");
        assert_eq!(channel.derive_room_kind(&room_id, None), RoomKind::Channel);
    }

    #[test]
    fn derive_room_kind_dm_via_account_data_overrides_channel_shape() {
        let room_id = RoomId::parse("!room:example.org").expect("valid room id");
        let alice = UserId::parse("@alice:example.org").expect("valid user id");

        let mut room = RoomState::new();
        room.apply_state_event(&state_event(
            "m.room.join_rules",
            "",
            "@alice:example.org",
            serde_json::json!({ "join_rule": "public" }),
        ))
        .expect("valid join rules event");
        room.apply_state_event(&state_event(
            "m.room.power_levels",
            "",
            "@alice:example.org",
            serde_json::json!({ "events_default": 50 }),
        ))
        .expect("valid power levels event");

        // Structurally this looks like a channel, but an explicit
        // `m.direct` account-data entry takes precedence (this type's own
        // doc: DM wins).
        let mut direct_rooms: BTreeMap<UserId, Vec<RoomId>> = BTreeMap::new();
        direct_rooms.insert(alice, vec![room_id.clone()]);
        let direct_content = DirectContent(direct_rooms);

        assert_eq!(room.derive_room_kind(&room_id, Some(&direct_content)), RoomKind::Dm);
        assert_eq!(room.derive_room_kind(&room_id, None), RoomKind::Channel);
    }

    #[test]
    fn encryption_state_cannot_be_unset() {
        let mut room = RoomState::new();
        let megolm = serde_json::json!({ "algorithm": "m.megolm.v1.aes-sha2" });
        room.apply_state_event(&state_event("m.room.encryption", "", "@alice:example.org", megolm.clone()))
            .expect("valid encryption event");
        let original = room.encryption.clone().expect("encryption set");
        assert_eq!(room.encryption_tamper_attempts, 0);

        // A later attempt to change the rotation policy is ignored.
        let tampered = serde_json::json!({ "algorithm": "m.megolm.v1.aes-sha2", "rotation_period_msgs": 1 });
        room.apply_state_event(&state_event("m.room.encryption", "", "@mallory:example.org", tampered))
            .expect("valid encryption event");
        assert_eq!(room.encryption, Some(original));
        assert_eq!(room.encryption_tamper_attempts, 1);

        // Resending the exact same content is not counted as a tamper
        // attempt.
        room.apply_state_event(&state_event("m.room.encryption", "", "@alice:example.org", megolm))
            .expect("valid encryption event");
        assert_eq!(room.encryption_tamper_attempts, 1);
    }

    #[test]
    fn member_role_uses_the_matrix_thresholds() {
        let mut room = RoomState::new();
        let owner = UserId::parse("@owner:example.org").expect("valid user id");
        let admin = UserId::parse("@admin:example.org").expect("valid user id");
        let plain = UserId::parse("@plain:example.org").expect("valid user id");
        room.apply_state_event(&state_event(
            "m.room.power_levels",
            "",
            "@owner:example.org",
            serde_json::json!({ "users": { "@owner:example.org": 100, "@admin:example.org": 50 } }),
        ))
        .expect("valid power levels event");

        assert_eq!(room.member_role(&owner), MemberRole::Owner);
        assert_eq!(room.member_role(&admin), MemberRole::Admin);
        assert_eq!(room.member_role(&plain), MemberRole::Member);
    }
}
