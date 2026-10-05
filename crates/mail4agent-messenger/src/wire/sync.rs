//! `GET /sync` response shape — research doc §1.4, refined by the server
//! plan's §3 (`/sync` algorithm) and manager decision #1 (spec v1.19).
//!
//! Every field below is either mandatory (`next_batch` only) or defaulted,
//! so a maximally sparse incremental sync response (`{"next_batch": "..."}`,
//! the shape an empty long-poll wake returns per server plan §3.1) parses
//! to a [`SyncResponse`] with every section empty rather than failing or
//! requiring a caller to special-case "field absent". `presence` is
//! deliberately not modeled at all — research doc §1.6/§2 item 4 and the
//! server plan both drop room-broadcast presence for v1.

use crate::error::MessengerError;
use crate::ids::{RoomId, UserId};
use crate::wire::events::{BasicEvent, RawEvent, StrippedStateEvent, ToDeviceEvent};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Parses a raw `/sync` response body into a [`SyncResponse`].
pub fn parse_sync_response(body: &[u8]) -> Result<SyncResponse, MessengerError> {
    Ok(serde_json::from_slice(body)?)
}

/// A room's `m.heroes`/member-count summary (research doc §1.4, server plan
/// §3.4).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RoomSummary {
    /// Up to five other members' user ids, used to synthesize a display
    /// name for a room with no `m.room.name`.
    #[serde(default, rename = "m.heroes")]
    pub heroes: Vec<UserId>,
    /// Total joined member count, if the server chose to include it (spec
    /// makes this optional; the server plan always computes it, but a
    /// caller of this type should not assume that of every server).
    #[serde(default, rename = "m.joined_member_count", skip_serializing_if = "Option::is_none")]
    pub joined_member_count: Option<u64>,
    /// Total invited member count, same optionality as
    /// `joined_member_count`.
    #[serde(default, rename = "m.invited_member_count", skip_serializing_if = "Option::is_none")]
    pub invited_member_count: Option<u64>,
}

/// A room's `state.events` block: full current state on an initial or
/// `limited` sync, or the delta since `since` on a non-limited incremental
/// sync (research doc §1.4, server plan §3.3's lazy-loading + gap rule).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct StateSection {
    /// The state events themselves.
    #[serde(default)]
    pub events: Vec<RawEvent>,
}

/// A room's `timeline` block.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TimelineSection {
    /// Timeline events in this window, oldest first.
    #[serde(default)]
    pub events: Vec<RawEvent>,
    /// `true` when there is a gap between `since` and this window — the
    /// client fell behind, or this is the room's first sync (research doc
    /// §1.4, server plan §3.2). A `limited` window's accompanying `state`
    /// includes the gap-rule membership backfill (server plan §3.3).
    #[serde(default)]
    pub limited: bool,
    /// The pagination token for `GET /rooms/{roomId}/messages?from=
    /// <prev_batch>&dir=b` to page further back than this window. Absent
    /// only when the window covers the room's entire history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_batch: Option<String>,
}

/// A room's `ephemeral.events` block: `m.typing`/`m.receipt`, batched per
/// sync tick rather than streamed (research doc §1.6, §2).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EphemeralSection {
    /// The ephemeral events themselves.
    #[serde(default)]
    pub events: Vec<BasicEvent>,
}

/// An `account_data.events` block — used both globally (top level of
/// [`SyncResponse`]) and per room ([`JoinedRoom::account_data`]).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AccountDataSection {
    /// The account-data events themselves.
    #[serde(default)]
    pub events: Vec<BasicEvent>,
}

/// A room's `unread_notifications` block (research doc §1.4, server plan
/// §3.5). `highlight_count` is server-computed and, per the server plan,
/// this server always reports `0` for it (no push-rule engine in v1) — this
/// type only models the wire shape, it does not assume either field's
/// value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnreadNotifications {
    /// Events since the caller's own read receipt, excluding their own.
    #[serde(default)]
    pub notification_count: u64,
    /// The subset of `notification_count` that would trigger a highlight.
    /// Always `<= notification_count`.
    #[serde(default)]
    pub highlight_count: u64,
}

/// One room this account is (or was) a member of, under `rooms.join`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct JoinedRoom {
    /// The room's summary (heroes, member counts).
    #[serde(default)]
    pub summary: RoomSummary,
    /// The room's state, per `StateSection`'s own doc for what's included.
    #[serde(default)]
    pub state: StateSection,
    /// The room's timeline window.
    #[serde(default)]
    pub timeline: TimelineSection,
    /// Ephemeral events (typing, receipts) for this room.
    #[serde(default)]
    pub ephemeral: EphemeralSection,
    /// Room-scoped account data (e.g. `m.fully_read`).
    #[serde(default)]
    pub account_data: AccountDataSection,
    /// Unread notification counters for this room.
    #[serde(default)]
    pub unread_notifications: UnreadNotifications,
}

/// The stripped-state preview block under `rooms.invite`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct InviteStateSection {
    /// The stripped state events themselves.
    #[serde(default)]
    pub events: Vec<StrippedStateEvent>,
}

/// One room this account has been invited to, under `rooms.invite`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct InvitedRoom {
    /// A stripped preview of the room's state, enough to render an invite
    /// without having joined.
    #[serde(default)]
    pub invite_state: InviteStateSection,
}

/// One room this account has left (or been banned/kicked from), under
/// `rooms.leave`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LeftRoom {
    /// State as of leaving (or the delta since `since`, for an account that
    /// left before `since` and is only now being reported due to a gap).
    #[serde(default)]
    pub state: StateSection,
    /// Timeline up to the point of leaving.
    #[serde(default)]
    pub timeline: TimelineSection,
    /// Room-scoped account data as of leaving.
    #[serde(default)]
    pub account_data: AccountDataSection,
}

/// The `rooms` block: every room this account has any relationship with,
/// partitioned by that relationship.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RoomsSection {
    /// Rooms currently joined.
    #[serde(default)]
    pub join: BTreeMap<RoomId, JoinedRoom>,
    /// Rooms currently invited to.
    #[serde(default)]
    pub invite: BTreeMap<RoomId, InvitedRoom>,
    /// Rooms left (or whose leave/ban/kick happened since `since`).
    #[serde(default)]
    pub leave: BTreeMap<RoomId, LeftRoom>,
}

/// The `to_device.events` block: to-device delivery, batched through the
/// same `/sync` channel as everything else (research doc §3.3).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ToDeviceSection {
    /// The to-device events themselves.
    #[serde(default)]
    pub events: Vec<ToDeviceEvent>,
}

/// The `device_lists` block: which users (sharing a joined room with the
/// caller) had a device-list change since `since` (research doc §3.2).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DeviceListsSection {
    /// Users whose device list changed.
    #[serde(default)]
    pub changed: Vec<UserId>,
    /// Users who no longer share any room with the caller as of this sync,
    /// and so are no longer tracked.
    #[serde(default)]
    pub left: Vec<UserId>,
}

/// A parsed `GET /sync` response (research doc §1.4). See the module doc
/// for why every field but `next_batch` is defaulted.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SyncResponse {
    /// The cursor to pass as `since` on the next call.
    pub next_batch: String,
    /// Rooms this account has any relationship with.
    #[serde(default)]
    pub rooms: RoomsSection,
    /// Global (not room-scoped) account data.
    #[serde(default)]
    pub account_data: AccountDataSection,
    /// To-device events delivered to this device.
    #[serde(default)]
    pub to_device: ToDeviceSection,
    /// Device-list change notifications for users sharing a room with this
    /// account.
    #[serde(default)]
    pub device_lists: DeviceListsSection,
    /// Remaining one-time-key count per algorithm (research doc §3.2) —
    /// keyed by algorithm name (e.g. `"signed_curve25519"`).
    #[serde(default)]
    pub device_one_time_keys_count: BTreeMap<String, u64>,
    /// Fallback-key algorithms this device has published that the server
    /// has not yet consumed one of (research doc §3.2) — a non-empty entry
    /// here means "unused", an *empty* list means "top one up".
    #[serde(default)]
    pub device_unused_fallback_key_types: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::EventId;
    use crate::wire::events::RoomKeyContent;

    #[test]
    fn parses_incremental_sync_with_only_next_batch() {
        let body = br#"{"next_batch":"s72595_4483_1934"}"#;
        let response = parse_sync_response(body).expect("sparse sync response parses");
        assert_eq!(response.next_batch, "s72595_4483_1934");
        assert!(response.rooms.join.is_empty());
        assert!(response.rooms.invite.is_empty());
        assert!(response.rooms.leave.is_empty());
        assert!(response.to_device.events.is_empty());
        assert!(response.device_lists.changed.is_empty());
        assert!(response.device_one_time_keys_count.is_empty());
        assert!(response.device_unused_fallback_key_types.is_empty());
    }

    #[test]
    fn parses_sync_response_with_limited_timeline() {
        let body = serde_json::json!({
            "next_batch": "s999",
            "rooms": {
                "join": {
                    "!room:example.org": {
                        "summary": {
                            "m.heroes": ["@bob:example.org"],
                            "m.joined_member_count": 3,
                            "m.invited_member_count": 0
                        },
                        "state": { "events": [] },
                        "timeline": {
                            "events": [
                                {
                                    "event_id": "$1:example.org",
                                    "type": "m.room.message",
                                    "sender": "@alice:example.org",
                                    "origin_server_ts": 1_700_000_000_000i64,
                                    "content": { "msgtype": "m.text", "body": "hi" }
                                }
                            ],
                            "limited": true,
                            "prev_batch": "t111_222"
                        },
                        "ephemeral": { "events": [] },
                        "account_data": { "events": [] },
                        "unread_notifications": { "notification_count": 2, "highlight_count": 0 }
                    }
                }
            }
        })
        .to_string();

        let response = parse_sync_response(body.as_bytes()).expect("valid sync response");
        assert_eq!(response.next_batch, "s999");
        let room_id = RoomId::parse("!room:example.org").expect("valid room id");
        let room = response.rooms.join.get(&room_id).expect("room present");
        assert!(room.timeline.limited);
        assert_eq!(room.timeline.prev_batch.as_deref(), Some("t111_222"));
        assert_eq!(room.timeline.events.len(), 1);
        assert_eq!(room.timeline.events[0].event_type, "m.room.message");
        assert_eq!(room.summary.joined_member_count, Some(3));
        assert_eq!(room.unread_notifications.notification_count, 2);
        assert_eq!(room.unread_notifications.highlight_count, 0);
    }

    #[test]
    fn parses_sync_response_with_to_device_events() {
        let body = serde_json::json!({
            "next_batch": "s2",
            "to_device": {
                "events": [
                    {
                        "sender": "@bob:example.org",
                        "type": "m.room_key",
                        "content": {
                            "algorithm": "m.megolm.v1.aes-sha2",
                            "room_id": "!r:example.org",
                            "session_id": "session-abc",
                            "session_key": "session-key-b64"
                        }
                    }
                ]
            },
            "device_one_time_keys_count": { "signed_curve25519": 42 },
            "device_unused_fallback_key_types": []
        })
        .to_string();

        let response = parse_sync_response(body.as_bytes()).expect("valid sync response");
        assert_eq!(response.to_device.events.len(), 1);
        let event = &response.to_device.events[0];
        assert_eq!(event.event_type, "m.room_key");
        let content: RoomKeyContent = serde_json::from_value(event.content.clone()).expect("valid room_key content");
        assert_eq!(content.session_id, "session-abc");
        assert_eq!(content.room_id, RoomId::parse("!r:example.org").expect("valid room id"));
        assert_eq!(response.device_one_time_keys_count.get("signed_curve25519"), Some(&42));
        assert!(response.device_unused_fallback_key_types.is_empty());
    }

    #[test]
    fn parses_invite_and_leave_room_sections() {
        let body = serde_json::json!({
            "next_batch": "s3",
            "rooms": {
                "invite": {
                    "!invited:example.org": {
                        "invite_state": {
                            "events": [
                                {
                                    "type": "m.room.member",
                                    "state_key": "@me:example.org",
                                    "sender": "@bob:example.org",
                                    "content": { "membership": "invite" }
                                }
                            ]
                        }
                    }
                },
                "leave": {
                    "!left:example.org": {
                        "timeline": { "events": [] },
                        "state": { "events": [] }
                    }
                }
            }
        })
        .to_string();

        let response = parse_sync_response(body.as_bytes()).expect("valid sync response");
        let invited_id = RoomId::parse("!invited:example.org").expect("valid room id");
        let invited = response.rooms.invite.get(&invited_id).expect("invited room present");
        assert_eq!(invited.invite_state.events.len(), 1);
        assert_eq!(invited.invite_state.events[0].state_key, "@me:example.org");

        let left_id = RoomId::parse("!left:example.org").expect("valid room id");
        assert!(response.rooms.leave.contains_key(&left_id));
    }

    #[test]
    fn ephemeral_and_account_data_events_use_the_basic_shape() {
        let body = serde_json::json!({
            "next_batch": "s4",
            "rooms": {
                "join": {
                    "!room:example.org": {
                        "ephemeral": {
                            "events": [
                                { "type": "m.typing", "content": { "user_ids": ["@alice:example.org"] } }
                            ]
                        },
                        "account_data": {
                            "events": [
                                { "type": "m.fully_read", "content": { "event_id": "$last:example.org" } }
                            ]
                        }
                    }
                }
            }
        })
        .to_string();

        let response = parse_sync_response(body.as_bytes()).expect("valid sync response");
        let room_id = RoomId::parse("!room:example.org").expect("valid room id");
        let room = response.rooms.join.get(&room_id).expect("room present");
        assert_eq!(room.ephemeral.events[0].event_type, "m.typing");
        let fully_read: crate::wire::events::FullyReadContent =
            serde_json::from_value(room.account_data.events[0].content.clone()).expect("valid fully_read content");
        assert_eq!(fully_read.event_id, EventId::parse("$last:example.org").expect("valid event id"));
    }
}
