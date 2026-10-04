//! Matrix event envelope, relation aggregation, and typed event `content`
//! shapes — research doc §1.1 (envelope), §1.2 (state events), §1.3
//! (timeline events + relations), §3.1-§3.3 (E2EE to-device payloads),
//! §1.6-§1.7 (ephemeral + account data), and the server plan's manager
//! decision #1 (spec v1.19, room version 11). An event type this module
//! does not model stays a raw [`serde_json::Value`] on [`RawEvent`].
//!
//! # Never fails on an unrecognized event
//!
//! [`RawEvent::content`] is always a plain [`serde_json::Value`] — parsing a
//! `RawEvent` off the wire never depends on recognizing its `type`. Every
//! typed content struct in this module (`RoomMessageContent`,
//! `RoomEncryptedContent`, `WithheldCode`, ...) is something a caller
//! deserializes from that `content` value *on demand*, once it already knows
//! which type it is dealing with; an unrecognized `msgtype`/`algorithm`/
//! `code` inside one of those typed shapes falls back to an `Unknown`
//! variant carrying the raw value rather than failing to deserialize — same
//! "forward compatible by default" doctrine `crate::store`'s record-key
//! parser already follows.

use crate::ids::{DeviceId, EventId, RoomId, UserId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------
// Event envelope (research §1.1)
// ---------------------------------------------------------------------

/// One state or timeline event exactly as the client-server API represents
/// it (research doc §1.1's envelope). `state_key` present means this is a
/// state event; absent means a timeline/message event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RawEvent {
    /// The event's own id.
    pub event_id: EventId,
    /// The event type (`"m.room.message"`, `"m.room.member"`, ...). Never
    /// validated against a known set — see the module doc.
    #[serde(rename = "type")]
    pub event_type: String,
    /// The event's sender.
    pub sender: UserId,
    /// Milliseconds since the Unix epoch, server-assigned.
    pub origin_server_ts: i64,
    /// Present for a state event (the state's key, often empty or a user
    /// id); absent for a timeline/message event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_key: Option<String>,
    /// The event's type-specific payload, kept untyped at this layer.
    #[serde(default)]
    pub content: serde_json::Value,
    /// Server-attached metadata not part of the event's own signed content.
    #[serde(default)]
    pub unsigned: Unsigned,
}

impl RawEvent {
    /// Parses this event's `content["m.relates_to"]` field, if present. See
    /// [`RelatesTo::from_content`] for what happens when the field is
    /// present but doesn't match a shape this crate recognizes.
    pub fn relates_to(&self) -> Option<RelatesTo> {
        RelatesTo::from_content(&self.content)
    }
}

/// `unsigned`, research doc §1.1: metadata the server attaches to an event
/// that is not part of what the event's own signature covers.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Unsigned {
    /// Milliseconds since `origin_server_ts` that have elapsed on the
    /// server, as of the response that carried this event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age: Option<i64>,
    /// Echoed back to the sender's own client: the `txnId` it used to send
    /// this event, letting a local echo reconcile against the confirmed
    /// event (a later piece, `room::timeline`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    /// Present once this event has been redacted: the redaction event
    /// itself. Boxed because a redaction event can, recursively, carry its
    /// own (empty) `unsigned`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_because: Option<Box<RawEvent>>,
    /// For a state event, the state's content immediately before this
    /// event, if the requesting client asked for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_content: Option<serde_json::Value>,
    /// The `m.relations` bundle (aggregated reactions, the latest edit,
    /// thread summary, ...) the server attaches to an event other events
    /// relate to. Kept as a raw value: aggregation shape varies by relation
    /// kind and this crate does not need to interpret the bundle itself to
    /// parse the envelope (`room::relations`, a later piece, is where this
    /// gets used).
    #[serde(rename = "m.relations", default, skip_serializing_if = "Option::is_none")]
    pub relations: Option<serde_json::Value>,
}

/// A stripped-down state event as sent in an invite's `invite_state`
/// preview (research doc §1.4) — the same fields an `m.room.member`/etc.
/// state event carries, minus everything that would require the recipient
/// to already have joined the room to make sense of (`event_id`,
/// `origin_server_ts`, `unsigned`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StrippedStateEvent {
    /// The state event's type.
    #[serde(rename = "type")]
    pub event_type: String,
    /// The state event's key.
    pub state_key: String,
    /// The state event's sender.
    pub sender: UserId,
    /// The state event's content, untyped at this layer (see the module
    /// doc).
    #[serde(default)]
    pub content: serde_json::Value,
}

/// The minimal `{type, content}` shape shared by ephemeral (`m.typing`,
/// `m.receipt`) and account-data (`m.tag`, `m.direct`, `m.fully_read`, ...)
/// events (research doc §1.6/§1.7) — unlike [`RawEvent`], these carry no
/// `event_id`, `sender`, or `origin_server_ts` on the wire.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BasicEvent {
    /// The event's type.
    #[serde(rename = "type")]
    pub event_type: String,
    /// The event's content, untyped at this layer (see the module doc).
    #[serde(default)]
    pub content: serde_json::Value,
}

/// A to-device event (research doc §3.3): delivered out-of-band from any
/// room's timeline, one per `(user, device)`. Carries no `event_id` or
/// `origin_server_ts` on the wire.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToDeviceEvent {
    /// The sending user.
    pub sender: UserId,
    /// The event's type (`"m.room_key"`, `"m.room.encrypted"`, ...).
    #[serde(rename = "type")]
    pub event_type: String,
    /// The event's content, untyped at this layer (see the module doc).
    #[serde(default)]
    pub content: serde_json::Value,
}

// ---------------------------------------------------------------------
// Relations (research §1.3)
// ---------------------------------------------------------------------

/// One event's `m.relates_to` field, parsed into the shape its `rel_type`
/// (or, for the legacy reply pointer, the absence of one) implies. Never
/// fails to parse: an `m.relates_to` value that matches none of the shapes
/// below becomes [`RelatesTo::Unknown`], carrying the raw value.
#[derive(Clone, Debug, PartialEq)]
pub enum RelatesTo {
    /// `m.annotation` (reactions): `key` is the reaction's own content
    /// (e.g. an emoji), `event_id` the event being reacted to.
    Annotation {
        /// The event being annotated.
        event_id: EventId,
        /// The annotation's key (an emoji, for `m.reaction`).
        key: String,
    },
    /// `m.replace` (edits, MSC2676): `event_id` is the event being
    /// replaced. The replacement content itself lives at the top level of
    /// the *edit* event's own content, under `m.new_content` — not part of
    /// this type, since that key sits alongside `m.relates_to`, not inside
    /// it.
    Replace {
        /// The event being replaced.
        event_id: EventId,
    },
    /// `m.thread` (MSC3440).
    Thread {
        /// The thread's root event.
        event_id: EventId,
        /// `true` if this reply also sets `m.in_reply_to` purely for
        /// clients without threading UI, and should not be shown twice by
        /// a client that does understand threads.
        is_falling_back: bool,
        /// The specific event within the thread this one is a rich reply
        /// to, if any.
        in_reply_to: Option<InReplyTo>,
    },
    /// The legacy rich-reply pointer (`m.in_reply_to` with no `rel_type`
    /// alongside it) — still sent for backward compatibility even when an
    /// event carries a "real" relation.
    InReplyTo(InReplyTo),
    /// An `m.relates_to` value present but not matching any shape above —
    /// kept verbatim rather than rejected (module doc).
    Unknown(serde_json::Value),
}

impl RelatesTo {
    /// Extracts and parses `content["m.relates_to"]`, if present. Returns
    /// `None` only when the field itself is absent — most events don't
    /// relate to anything. See this type's own doc for what happens when
    /// the field is present but unrecognized.
    pub fn from_content(content: &serde_json::Value) -> Option<Self> {
        content.get("m.relates_to").map(RelatesTo::from_value)
    }

    fn from_value(value: &serde_json::Value) -> Self {
        let rel_type = value.get("rel_type").and_then(serde_json::Value::as_str);
        match rel_type {
            Some("m.annotation") => {
                let event_id = value.get("event_id").and_then(serde_json::Value::as_str).and_then(|s| EventId::parse(s).ok());
                let key = value.get("key").and_then(serde_json::Value::as_str);
                if let (Some(event_id), Some(key)) = (event_id, key) {
                    return RelatesTo::Annotation { event_id, key: key.to_string() };
                }
            }
            Some("m.replace") => {
                if let Some(event_id) =
                    value.get("event_id").and_then(serde_json::Value::as_str).and_then(|s| EventId::parse(s).ok())
                {
                    return RelatesTo::Replace { event_id };
                }
            }
            Some("m.thread") => {
                if let Some(event_id) =
                    value.get("event_id").and_then(serde_json::Value::as_str).and_then(|s| EventId::parse(s).ok())
                {
                    let is_falling_back =
                        value.get("is_falling_back").and_then(serde_json::Value::as_bool).unwrap_or(false);
                    let in_reply_to = value.get("m.in_reply_to").and_then(InReplyTo::from_value);
                    return RelatesTo::Thread { event_id, is_falling_back, in_reply_to };
                }
            }
            None => {
                if let Some(in_reply_to) = value.get("m.in_reply_to").and_then(InReplyTo::from_value) {
                    return RelatesTo::InReplyTo(in_reply_to);
                }
            }
            Some(_) => {}
        }
        RelatesTo::Unknown(value.clone())
    }
}

impl Serialize for RelatesTo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = match self {
            RelatesTo::Annotation { event_id, key } => {
                serde_json::json!({ "rel_type": "m.annotation", "event_id": event_id.as_str(), "key": key })
            }
            RelatesTo::Replace { event_id } => {
                serde_json::json!({ "rel_type": "m.replace", "event_id": event_id.as_str() })
            }
            RelatesTo::Thread { event_id, is_falling_back, in_reply_to } => {
                let mut value = serde_json::json!({
                    "rel_type": "m.thread",
                    "event_id": event_id.as_str(),
                    "is_falling_back": is_falling_back,
                });
                if let Some(in_reply_to) = in_reply_to {
                    value["m.in_reply_to"] = serde_json::json!({ "event_id": in_reply_to.event_id.as_str() });
                }
                value
            }
            RelatesTo::InReplyTo(reply) => {
                serde_json::json!({ "m.in_reply_to": { "event_id": reply.event_id.as_str() } })
            }
            RelatesTo::Unknown(value) => value.clone(),
        };
        value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RelatesTo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        Ok(RelatesTo::from_value(&value))
    }
}

/// The `m.in_reply_to` pointer, either standalone (legacy reply) or nested
/// inside an [`RelatesTo::Thread`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InReplyTo {
    /// The event being replied to.
    pub event_id: EventId,
}

impl InReplyTo {
    fn from_value(value: &serde_json::Value) -> Option<Self> {
        let event_id = value.get("event_id")?.as_str()?;
        EventId::parse(event_id).ok().map(|event_id| InReplyTo { event_id })
    }
}

/// Reserializes `inner` and injects `tag_field: tag_value` into the result
/// — the shared shape [`RoomMessageContent`] and [`RoomEncryptedContent`]
/// both serialize through, so a discriminant field derived structs don't
/// carry (`msgtype`, `algorithm`) round-trips correctly.
fn serialize_tagged<S, T>(serializer: S, tag_field: &str, tag_value: &str, inner: &T) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: Serialize,
{
    let mut value = serde_json::to_value(inner).map_err(serde::ser::Error::custom)?;
    if let serde_json::Value::Object(map) = &mut value {
        map.insert(tag_field.to_string(), serde_json::Value::String(tag_value.to_string()));
    }
    value.serialize(serializer)
}

// ---------------------------------------------------------------------
// State event content (research §1.2, server plan §1 room version 11)
// ---------------------------------------------------------------------

fn default_room_version() -> String {
    "11".to_string()
}

fn default_true() -> bool {
    true
}

fn default_power_level_50() -> i64 {
    50
}

fn default_rotation_period_ms() -> i64 {
    604_800_000
}

fn default_rotation_period_msgs() -> i64 {
    100
}

/// `m.room.create` content. Room version 11 dropped the `creator` field (the
/// creator is the event's own sender), so `creator` is optional: a required
/// field would make every `/sync` that carried a version-11 create event
/// fail to decode.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoomCreateContent {
    /// The room's creator, only present on pre-v11 rooms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator: Option<UserId>,
    /// The room version this room was created with.
    #[serde(default = "default_room_version")]
    pub room_version: String,
    /// Whether users on other servers may join (`m.federate`) — meaningless
    /// for a single, non-federated server (research doc §1.2) but kept for
    /// wire-shape fidelity.
    #[serde(rename = "m.federate", default = "default_true")]
    pub federate: bool,
    /// The room this one replaced via a room upgrade, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor: Option<RoomCreatePredecessor>,
}

/// `m.room.create`'s `predecessor` field.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoomCreatePredecessor {
    /// The predecessor room's id.
    pub room_id: RoomId,
    /// The last known event id in the predecessor room.
    pub event_id: EventId,
}

/// A room membership value (`m.room.member`'s `membership` field).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Membership {
    /// Invited, not yet joined.
    Invite,
    /// Currently a member.
    Join,
    /// Requested to join a room with a restrictive join rule.
    Knock,
    /// Left (or never joined and the invite/knock was withdrawn).
    Leave,
    /// Banned.
    Ban,
    /// A membership value this crate does not recognize yet — kept rather
    /// than failing the surrounding event's parse (module doc).
    #[serde(other)]
    Unknown,
}

/// `m.room.member` content, keyed by `state_key = user_id`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoomMemberContent {
    /// The subject's membership state.
    pub membership: Membership,
    /// The subject's display name, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub displayname: Option<String>,
    /// `true` when this invite/join is part of a direct-message room.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_direct: Option<bool>,
}

/// `m.room.power_levels`'s `notifications` sub-object. Defaults to `{room:
/// 50}` per spec, not to zero — hence a hand-written [`Default`] rather than
/// a derived one.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoomPowerLevelsNotifications {
    /// The power level required to trigger an `@room` notification.
    #[serde(default = "default_power_level_50")]
    pub room: i64,
}

impl Default for RoomPowerLevelsNotifications {
    fn default() -> Self {
        Self { room: 50 }
    }
}

/// `m.room.power_levels` content, every field defaulted per spec (research
/// doc §1.2) so a sparse power-levels event (including `{}`) parses to the
/// spec's own baseline permission table.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoomPowerLevelsContent {
    /// Power level required to ban a user. Default `50`.
    #[serde(default = "default_power_level_50")]
    pub ban: i64,
    /// Per-event-type power level overrides (event type → required level).
    #[serde(default)]
    pub events: BTreeMap<String, i64>,
    /// Power level required to send an event whose type has no entry in
    /// `events`. Default `0`.
    #[serde(default)]
    pub events_default: i64,
    /// Power level required to invite a user. Default `50`.
    #[serde(default = "default_power_level_50")]
    pub invite: i64,
    /// Power level required to kick a user. Default `50`.
    #[serde(default = "default_power_level_50")]
    pub kick: i64,
    /// Power level required to redact an event. Default `50`.
    #[serde(default = "default_power_level_50")]
    pub redact: i64,
    /// Power level required to send a state event whose type has no entry
    /// in `events`. Default `50`.
    #[serde(default = "default_power_level_50")]
    pub state_default: i64,
    /// Per-user power level overrides (user id → level).
    #[serde(default)]
    pub users: BTreeMap<UserId, i64>,
    /// Power level a user has when absent from `users`. Default `0`.
    #[serde(default)]
    pub users_default: i64,
    /// Power levels required to trigger a notification.
    #[serde(default)]
    pub notifications: RoomPowerLevelsNotifications,
}

/// `m.room.join_rules`'s `join_rule` value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinRule {
    /// Anyone may join without an invite.
    Public,
    /// Only invited users may join.
    Invite,
    /// Anyone may request to join (subject to approval).
    Knock,
    /// Only invited users may join (alias historically distinct from
    /// `invite` in some client UIs; kept distinct per spec, not collapsed).
    Private,
    /// Anyone satisfying one of `allow`'s conditions may join without an
    /// invite.
    Restricted,
    /// Like `restricted`, but falls back to `knock` for users not
    /// satisfying any `allow` condition.
    KnockRestricted,
    /// A join rule value this crate does not recognize yet.
    #[serde(other)]
    Unknown,
}

/// One condition in `m.room.join_rules`'s `allow` list (used by `restricted`
/// / `knock_restricted`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRuleAllow {
    /// The condition's type (spec currently defines only
    /// `"m.room_membership"`).
    #[serde(rename = "type")]
    pub allow_type: String,
    /// For `"m.room_membership"`: membership in this room satisfies the
    /// condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_id: Option<RoomId>,
}

/// `m.room.join_rules` content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomJoinRulesContent {
    /// The room's join rule.
    pub join_rule: JoinRule,
    /// Conditions under which a `restricted`/`knock_restricted` room may be
    /// joined without an explicit invite.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<JoinRuleAllow>,
}

/// `m.room.history_visibility`'s `history_visibility` value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryVisibility {
    /// Visible to anyone invited, from the point they were invited onward.
    Invited,
    /// Visible to anyone joined, from the point they joined onward.
    Joined,
    /// Visible to anyone joined, including history from before they
    /// joined.
    Shared,
    /// Visible to anyone, even without joining.
    WorldReadable,
    /// A value this crate does not recognize yet.
    #[serde(other)]
    Unknown,
}

/// `m.room.history_visibility` content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomHistoryVisibilityContent {
    /// The room's history visibility.
    pub history_visibility: HistoryVisibility,
}

/// `m.room.name` content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomNameContent {
    /// The room's display name.
    pub name: String,
}

/// `m.room.topic` content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomTopicContent {
    /// The room's topic.
    pub topic: String,
}

/// `m.room.encryption` content — once set on a room, this event is never
/// removed or changed to a different algorithm (spec invariant; this crate
/// does not enforce that, it only models the shape).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoomEncryptionContent {
    /// The room's encryption algorithm (spec currently defines only
    /// `"m.megolm.v1.aes-sha2"`).
    pub algorithm: String,
    /// How long an outbound Megolm session may live before rotation, in
    /// milliseconds. Default one week.
    #[serde(default = "default_rotation_period_ms")]
    pub rotation_period_ms: i64,
    /// How many messages an outbound Megolm session may encrypt before
    /// rotation. Default `100`.
    #[serde(default = "default_rotation_period_msgs")]
    pub rotation_period_msgs: i64,
}

/// `m.room.pinned_events` content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomPinnedEventsContent {
    /// The pinned event ids, in the order they were pinned.
    pub pinned: Vec<EventId>,
}

// ---------------------------------------------------------------------
// Timeline event content (research §1.3, §3.1)
// ---------------------------------------------------------------------

/// The shared `m.text`/`m.notice`/`m.emote` shape: a plain body plus an
/// optional formatted (HTML) rendering.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextLikeMessageContent {
    /// The plain-text body.
    pub body: String,
    /// The formatting used by `formatted_body` (spec currently defines only
    /// `"org.matrix.custom.html"`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// The formatted rendering of `body`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatted_body: Option<String>,
}

/// `m.room.message` content. `msgtype` selects the shape; an `msgtype` this
/// crate does not model is kept as [`RoomMessageContent::Unknown`] rather
/// than failing to parse (module doc).
#[derive(Clone, Debug, PartialEq)]
pub enum RoomMessageContent {
    /// `msgtype: "m.text"`.
    Text(TextLikeMessageContent),
    /// `msgtype: "m.notice"` — like `m.text`, but conventionally suppressed
    /// from push notifications (bot/automation output).
    Notice(TextLikeMessageContent),
    /// `msgtype: "m.emote"` — an "/me" action message.
    Emote(TextLikeMessageContent),
    /// Any other `msgtype` (`m.image`, `m.file`, ...), kept as the raw
    /// content value.
    Unknown(serde_json::Value),
}

impl Serialize for RoomMessageContent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            RoomMessageContent::Text(inner) => serialize_tagged(serializer, "msgtype", "m.text", inner),
            RoomMessageContent::Notice(inner) => serialize_tagged(serializer, "msgtype", "m.notice", inner),
            RoomMessageContent::Emote(inner) => serialize_tagged(serializer, "msgtype", "m.emote", inner),
            RoomMessageContent::Unknown(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for RoomMessageContent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let msgtype = value.get("msgtype").and_then(serde_json::Value::as_str).map(str::to_owned);
        match msgtype.as_deref() {
            Some("m.text") => serde_json::from_value(value).map(RoomMessageContent::Text).map_err(serde::de::Error::custom),
            Some("m.notice") => {
                serde_json::from_value(value).map(RoomMessageContent::Notice).map_err(serde::de::Error::custom)
            }
            Some("m.emote") => {
                serde_json::from_value(value).map(RoomMessageContent::Emote).map_err(serde::de::Error::custom)
            }
            _ => Ok(RoomMessageContent::Unknown(value)),
        }
    }
}

/// `m.room.encrypted`'s Megolm shape (`algorithm:
/// "m.megolm.v1.aes-sha2"`) — the only algorithm ever used for a *timeline*
/// `m.room.encrypted` event (research doc §3.1). `sender_key`/`device_id`
/// are spec-deprecated but still sent for back-compat. `Eq` is not derived
/// here (unlike this struct's siblings): `relates_to`'s `RelatesTo` type
/// only implements `PartialEq` (its `Unknown` variant carries a
/// `serde_json::Value`), so this struct follows suit.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MegolmEncryptedContent {
    /// The Megolm ciphertext, base64-encoded.
    pub ciphertext: String,
    /// The Megolm session this was encrypted with.
    pub session_id: String,
    /// The sender device's Curve25519 identity key (deprecated, still
    /// sent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_key: Option<String>,
    /// The sender device's id (deprecated, still sent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    /// Copied verbatim from the cleartext plaintext's own `m.relates_to`
    /// (Megolm-encrypted rooms binding rule): the server indexes
    /// relations (reactions, edits, threads) without ever decrypting, so
    /// the relation pointer rides alongside the ciphertext at the outer,
    /// unencrypted envelope level too, not only inside the plaintext this
    /// crate's `crypto::group_sessions` encrypts.
    #[serde(rename = "m.relates_to", default, skip_serializing_if = "Option::is_none")]
    pub relates_to: Option<RelatesTo>,
}

/// One recipient device's ciphertext inside an Olm `m.room.encrypted`
/// envelope's `ciphertext` map.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OlmCiphertextInfo {
    /// The Olm message type (`0` = pre-key message, `1` = normal message).
    #[serde(rename = "type")]
    pub message_type: u8,
    /// The Olm ciphertext, base64-encoded.
    pub body: String,
}

/// `m.room.encrypted`'s Olm shape (`algorithm:
/// "m.olm.v1.curve25519-aes-sha2"`) — used only for to-device delivery
/// (room keys, verification, ...), never in a room timeline (research doc
/// §3.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OlmEncryptedContent {
    /// The sender device's Curve25519 identity key.
    pub sender_key: String,
    /// Ciphertext keyed by each recipient device's Curve25519 identity key.
    pub ciphertext: BTreeMap<String, OlmCiphertextInfo>,
}

/// `m.room.encrypted` content, either shape research doc §3.1 describes. An
/// `algorithm` this crate does not recognize is kept as
/// [`RoomEncryptedContent::Unknown`] (module doc).
#[derive(Clone, Debug, PartialEq)]
pub enum RoomEncryptedContent {
    /// `algorithm: "m.megolm.v1.aes-sha2"`.
    Megolm(MegolmEncryptedContent),
    /// `algorithm: "m.olm.v1.curve25519-aes-sha2"`.
    Olm(OlmEncryptedContent),
    /// Any other `algorithm`, kept as the raw content value.
    Unknown(serde_json::Value),
}

impl Serialize for RoomEncryptedContent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            RoomEncryptedContent::Megolm(inner) => {
                serialize_tagged(serializer, "algorithm", "m.megolm.v1.aes-sha2", inner)
            }
            RoomEncryptedContent::Olm(inner) => {
                serialize_tagged(serializer, "algorithm", "m.olm.v1.curve25519-aes-sha2", inner)
            }
            RoomEncryptedContent::Unknown(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for RoomEncryptedContent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let algorithm = value.get("algorithm").and_then(serde_json::Value::as_str).map(str::to_owned);
        match algorithm.as_deref() {
            Some("m.megolm.v1.aes-sha2") => {
                serde_json::from_value(value).map(RoomEncryptedContent::Megolm).map_err(serde::de::Error::custom)
            }
            Some("m.olm.v1.curve25519-aes-sha2") => {
                serde_json::from_value(value).map(RoomEncryptedContent::Olm).map_err(serde::de::Error::custom)
            }
            _ => Ok(RoomEncryptedContent::Unknown(value)),
        }
    }
}

/// `m.reaction` content: an annotation-relation, key is typically an emoji.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReactionContent {
    /// The annotation this reaction carries.
    #[serde(rename = "m.relates_to")]
    pub relates_to: RelatesTo,
}

/// `m.room.redaction` content (room v11: `redacts` moved from the event's
/// top level into `content`, server plan manager decision #1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionContent {
    /// The event being redacted.
    pub redacts: EventId,
    /// Why the event was redacted, if given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------
// To-device payloads (research §3.1, §3.3)
// ---------------------------------------------------------------------

/// `m.room_key`: an Olm-to-device-delivered Megolm session key (research
/// doc §3.1). Never appears in a room timeline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomKeyContent {
    /// The Megolm algorithm (`"m.megolm.v1.aes-sha2"`).
    pub algorithm: String,
    /// The room this session key is for.
    pub room_id: RoomId,
    /// The Megolm session id.
    pub session_id: String,
    /// The Megolm session key, base64-encoded.
    pub session_key: String,
}

/// `m.forwarded_room_key`: like [`RoomKeyContent`], plus provenance fields
/// so the recipient's client can show the "this key was shared with you"
/// warning research doc §3.3 describes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardedRoomKeyContent {
    /// The Megolm algorithm (`"m.megolm.v1.aes-sha2"`).
    pub algorithm: String,
    /// The room this session key is for.
    pub room_id: RoomId,
    /// The Megolm session id.
    pub session_id: String,
    /// The Megolm session key, base64-encoded.
    pub session_key: String,
    /// The original sender device's Curve25519 identity key.
    pub sender_key: String,
    /// The original sender device's claimed Ed25519 signing key, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_claimed_ed25519_key: Option<String>,
    /// Every device's Curve25519 key this key was forwarded through, in
    /// order, oldest first.
    #[serde(default)]
    pub forwarding_curve25519_key_chain: Vec<String>,
}

/// `m.room_key_request`'s `action` value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoomKeyRequestAction {
    /// Ask a peer device to (re-)share a session key.
    Request,
    /// Withdraw an earlier `request`.
    RequestCancellation,
    /// An action value this crate does not recognize yet.
    #[serde(other)]
    Unknown,
}

/// `m.room_key_request`'s `body` field: which session is being requested.
/// Absent for a `request_cancellation`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomKeyRequestBody {
    /// The Megolm algorithm (`"m.megolm.v1.aes-sha2"`).
    pub algorithm: String,
    /// The room the requested session is for.
    pub room_id: RoomId,
    /// The requested Megolm session id.
    pub session_id: String,
    /// The requested session's sender device Curve25519 identity key.
    pub sender_key: String,
}

/// `m.room_key_request` content (research doc §3.3). Only auto-serviced
/// from the requester's own verified devices — this crate's own policy, not
/// something this type enforces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomKeyRequestContent {
    /// Whether this is a request or a cancellation of an earlier one.
    pub action: RoomKeyRequestAction,
    /// Which session is being requested; absent for a cancellation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<RoomKeyRequestBody>,
    /// The requester's own id for this request, echoed back on
    /// cancellation.
    pub request_id: String,
    /// The requesting device.
    pub requesting_device_id: DeviceId,
}

/// `m.room_key.withheld`'s `code` value — why a device did not (or will
/// not) receive a requested session key. An unrecognized code is kept
/// verbatim in [`WithheldCode::Unknown`] rather than failing to parse
/// (module doc).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WithheldCode {
    /// The requesting device is on the sender's block list.
    Blacklisted,
    /// The requesting device has not been verified.
    Unverified,
    /// The requesting user is not authorized to receive this key.
    Unauthorised,
    /// No session exists yet to share.
    Unavailable,
    /// The sender could not establish an Olm session with the requester.
    NoOlm,
    /// A code this crate does not recognize yet, kept verbatim.
    Unknown(String),
}

impl WithheldCode {
    /// This code's own wire string.
    pub fn as_str(&self) -> &str {
        match self {
            WithheldCode::Blacklisted => "m.blacklisted",
            WithheldCode::Unverified => "m.unverified",
            WithheldCode::Unauthorised => "m.unauthorised",
            WithheldCode::Unavailable => "m.unavailable",
            WithheldCode::NoOlm => "m.no_olm",
            WithheldCode::Unknown(raw) => raw.as_str(),
        }
    }
}

impl Serialize for WithheldCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for WithheldCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(match raw.as_str() {
            "m.blacklisted" => WithheldCode::Blacklisted,
            "m.unverified" => WithheldCode::Unverified,
            "m.unauthorised" => WithheldCode::Unauthorised,
            "m.unavailable" => WithheldCode::Unavailable,
            "m.no_olm" => WithheldCode::NoOlm,
            _ => WithheldCode::Unknown(raw),
        })
    }
}

/// `m.room_key.withheld` content (research doc §3.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomKeyWithheldContent {
    /// The Megolm algorithm (`"m.megolm.v1.aes-sha2"`).
    pub algorithm: String,
    /// The room the withheld session was for, if the sender chose to say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_id: Option<RoomId>,
    /// The withheld Megolm session id, if the sender chose to say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// The sender device's Curve25519 identity key.
    pub sender_key: String,
    /// Why the key was withheld.
    pub code: WithheldCode,
    /// A human-readable explanation, if given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `m.dummy` content — always empty; sent purely to advance an Olm ratchet
/// without a meaningful payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DummyContent {}

// ---------------------------------------------------------------------
// Account data (research §1.6, §1.7)
// ---------------------------------------------------------------------

/// `m.direct` content: direct-message room ids, keyed by the peer user.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DirectContent(pub BTreeMap<UserId, Vec<RoomId>>);

/// One entry in `m.tag`'s `tags` map.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TagInfo {
    /// Sort order among sibling tags, lower sorts first. No fixed range or
    /// uniqueness requirement per spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<f64>,
}

/// `m.tag` content: per-room, per-user tags.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TagContent {
    /// Tag name → tag metadata.
    #[serde(default)]
    pub tags: BTreeMap<String, TagInfo>,
}

/// `m.fully_read` content, set via `/rooms/{roomId}/read_markers` (research
/// doc §1.6): the "read up to here for UI purposes" position, decoupled
/// from the receipt broadcast.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullyReadContent {
    /// The last event the user has read, for UI purposes.
    pub event_id: EventId,
}

// ---------------------------------------------------------------------
// Ephemeral (research §1.6)
// ---------------------------------------------------------------------

/// `m.typing` content: one merged event per room per `/sync` (research doc
/// §1.6), not a discrete event per keystroke.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypingContent {
    /// Every user currently typing in the room.
    #[serde(default)]
    pub user_ids: Vec<UserId>,
}

/// One user's receipt entry inside [`ReceiptContent`]'s nested map.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptEntry {
    /// Milliseconds since the Unix epoch when the receipt was sent.
    pub ts: i64,
    /// The thread this receipt applies to, if the client scoped it to one
    /// (unscoped receipts apply to the room's main timeline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
}

/// `m.receipt` content: `event_id -> receipt_type -> user_id -> entry`
/// (research doc §1.6) — one coalesced state per room per sync tick, not a
/// stream of discrete "read" packets.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReceiptContent(pub BTreeMap<EventId, BTreeMap<String, BTreeMap<UserId, ReceiptEntry>>>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_create_content_decodes_without_a_creator_field() {
        // Room version 11 has no `creator`; the pre-v11 shape still decodes too.
        let v11: RoomCreateContent = serde_json::from_value(serde_json::json!({ "room_version": "11" })).expect("v11 create content decodes");
        assert_eq!(v11.creator, None);
        assert_eq!(v11.room_version, "11");
        let v10: RoomCreateContent =
            serde_json::from_value(serde_json::json!({ "creator": "@a:example.org", "room_version": "10" })).expect("v10 create content decodes");
        assert_eq!(v10.creator.as_ref().map(UserId::as_str), Some("@a:example.org"));
    }

    #[test]
    fn parses_relates_to_annotation_replace_thread() {
        let annotation = serde_json::json!({
            "m.relates_to": { "rel_type": "m.annotation", "event_id": "$target:example.org", "key": "👍" }
        });
        match RelatesTo::from_content(&annotation) {
            Some(RelatesTo::Annotation { event_id, key }) => {
                assert_eq!(event_id.as_str(), "$target:example.org");
                assert_eq!(key, "👍");
            }
            other => panic!("expected Annotation, got {other:?}"),
        }

        let replace = serde_json::json!({
            "m.relates_to": { "rel_type": "m.replace", "event_id": "$original:example.org" },
            "m.new_content": { "msgtype": "m.text", "body": "edited" }
        });
        match RelatesTo::from_content(&replace) {
            Some(RelatesTo::Replace { event_id }) => assert_eq!(event_id.as_str(), "$original:example.org"),
            other => panic!("expected Replace, got {other:?}"),
        }

        let thread = serde_json::json!({
            "m.relates_to": {
                "rel_type": "m.thread",
                "event_id": "$root:example.org",
                "is_falling_back": true,
                "m.in_reply_to": { "event_id": "$latest:example.org" }
            }
        });
        match RelatesTo::from_content(&thread) {
            Some(RelatesTo::Thread { event_id, is_falling_back, in_reply_to }) => {
                assert_eq!(event_id.as_str(), "$root:example.org");
                assert!(is_falling_back);
                assert_eq!(in_reply_to.expect("in_reply_to present").event_id.as_str(), "$latest:example.org");
            }
            other => panic!("expected Thread, got {other:?}"),
        }

        let legacy_reply = serde_json::json!({
            "m.relates_to": { "m.in_reply_to": { "event_id": "$legacy:example.org" } }
        });
        match RelatesTo::from_content(&legacy_reply) {
            Some(RelatesTo::InReplyTo(reply)) => assert_eq!(reply.event_id.as_str(), "$legacy:example.org"),
            other => panic!("expected InReplyTo, got {other:?}"),
        }

        let no_relation = serde_json::json!({ "msgtype": "m.text", "body": "plain" });
        assert_eq!(RelatesTo::from_content(&no_relation), None);
    }

    #[test]
    fn unrecognized_relation_shape_becomes_unknown_not_a_parse_failure() {
        let content = serde_json::json!({ "m.relates_to": { "rel_type": "org.example.future_relation", "foo": "bar" } });
        match RelatesTo::from_content(&content) {
            Some(RelatesTo::Unknown(value)) => {
                assert_eq!(value["rel_type"], "org.example.future_relation");
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn unknown_event_type_is_kept_raw() {
        let json = serde_json::json!({
            "event_id": "$abc:example.org",
            "type": "org.example.made_up_event",
            "sender": "@alice:example.org",
            "origin_server_ts": 1_700_000_000_000i64,
            "content": { "whatever": ["this", "is"], "n": 3 },
            "unsigned": { "age": 12 }
        });
        let event: RawEvent = serde_json::from_value(json).expect("unrecognized type still parses");
        assert_eq!(event.event_type, "org.example.made_up_event");
        assert_eq!(event.content["whatever"][0], "this");
        assert_eq!(event.content["n"], 3);
        assert_eq!(event.unsigned.age, Some(12));
        assert_eq!(event.state_key, None);
    }

    #[test]
    fn redacted_because_nests_the_redaction_event() {
        let json = serde_json::json!({
            "event_id": "$abc:example.org",
            "type": "m.room.message",
            "sender": "@alice:example.org",
            "origin_server_ts": 1,
            "content": {},
            "unsigned": {
                "redacted_because": {
                    "event_id": "$redaction:example.org",
                    "type": "m.room.redaction",
                    "sender": "@mod:example.org",
                    "origin_server_ts": 2,
                    "content": { "redacts": "$abc:example.org" }
                }
            }
        });
        let event: RawEvent = serde_json::from_value(json).expect("valid event");
        let redaction = event.unsigned.redacted_because.expect("redacted_because present");
        assert_eq!(redaction.event_type, "m.room.redaction");
        let redaction_content: RedactionContent =
            serde_json::from_value(redaction.content.clone()).expect("valid redaction content");
        assert_eq!(redaction_content.redacts.as_str(), "$abc:example.org");
    }

    #[test]
    fn encrypted_content_parses_megolm_and_olm_shapes() {
        let megolm = serde_json::json!({
            "algorithm": "m.megolm.v1.aes-sha2",
            "ciphertext": "cipher-bytes-b64",
            "session_id": "session-1",
            "sender_key": "sender-curve25519",
            "device_id": "DEVICE1"
        });
        match serde_json::from_value::<RoomEncryptedContent>(megolm).expect("valid megolm content") {
            RoomEncryptedContent::Megolm(inner) => {
                assert_eq!(inner.ciphertext, "cipher-bytes-b64");
                assert_eq!(inner.session_id, "session-1");
                assert_eq!(inner.sender_key.as_deref(), Some("sender-curve25519"));
                assert_eq!(inner.device_id.map(|d| d.as_str().to_string()), Some("DEVICE1".to_string()));
            }
            other => panic!("expected Megolm, got {other:?}"),
        }

        let olm = serde_json::json!({
            "algorithm": "m.olm.v1.curve25519-aes-sha2",
            "sender_key": "sender-curve25519",
            "ciphertext": {
                "recipient-curve25519": { "type": 0, "body": "prekey-message-b64" }
            }
        });
        match serde_json::from_value::<RoomEncryptedContent>(olm).expect("valid olm content") {
            RoomEncryptedContent::Olm(inner) => {
                assert_eq!(inner.sender_key, "sender-curve25519");
                let entry = inner.ciphertext.get("recipient-curve25519").expect("recipient entry present");
                assert_eq!(entry.message_type, 0);
                assert_eq!(entry.body, "prekey-message-b64");
            }
            other => panic!("expected Olm, got {other:?}"),
        }

        let unknown = serde_json::json!({ "algorithm": "org.example.future-algorithm", "opaque": true });
        match serde_json::from_value::<RoomEncryptedContent>(unknown).expect("unrecognized algorithm still parses") {
            RoomEncryptedContent::Unknown(value) => assert_eq!(value["opaque"], true),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn room_message_unknown_msgtype_is_kept_raw() {
        let image = serde_json::json!({ "msgtype": "m.image", "body": "cat.png", "url": "mxc://example.org/abc" });
        match serde_json::from_value::<RoomMessageContent>(image).expect("unrecognized msgtype still parses") {
            RoomMessageContent::Unknown(value) => assert_eq!(value["url"], "mxc://example.org/abc"),
            other => panic!("expected Unknown, got {other:?}"),
        }

        let text = serde_json::json!({ "msgtype": "m.text", "body": "hi", "formatted_body": "<b>hi</b>", "format": "org.matrix.custom.html" });
        match serde_json::from_value::<RoomMessageContent>(text).expect("valid text content") {
            RoomMessageContent::Text(inner) => {
                assert_eq!(inner.body, "hi");
                assert_eq!(inner.formatted_body.as_deref(), Some("<b>hi</b>"));
            }
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn power_levels_defaults_apply() {
        let content: RoomPowerLevelsContent = serde_json::from_value(serde_json::json!({})).expect("empty object parses");
        assert_eq!(content.ban, 50);
        assert_eq!(content.invite, 50);
        assert_eq!(content.kick, 50);
        assert_eq!(content.redact, 50);
        assert_eq!(content.state_default, 50);
        assert_eq!(content.events_default, 0);
        assert_eq!(content.users_default, 0);
        assert_eq!(content.notifications.room, 50);
        assert!(content.events.is_empty());
        assert!(content.users.is_empty());
    }

    #[test]
    fn power_levels_overrides_the_spec_defaults() {
        let content: RoomPowerLevelsContent = serde_json::from_value(serde_json::json!({
            "ban": 100,
            "users": { "@admin:example.org": 100 },
            "events": { "m.room.name": 50 }
        }))
        .expect("valid power levels");
        assert_eq!(content.ban, 100);
        let admin = UserId::parse("@admin:example.org").expect("valid user id");
        assert_eq!(content.users.get(&admin), Some(&100));
        assert_eq!(content.events.get("m.room.name"), Some(&50));
        // Untouched fields keep the spec default.
        assert_eq!(content.invite, 50);
    }

    #[test]
    fn receipt_content_parses_nested_map() {
        let json = serde_json::json!({
            "$event1:example.org": {
                "m.read": {
                    "@alice:example.org": { "ts": 1_436_451_550_453i64, "thread_id": "main" }
                },
                "m.read.private": {
                    "@alice:example.org": { "ts": 1_436_451_551_000i64 }
                }
            }
        });
        let receipts: ReceiptContent = serde_json::from_value(json).expect("valid receipt content");
        let event_id = EventId::parse("$event1:example.org").expect("valid event id");
        let alice = UserId::parse("@alice:example.org").expect("valid user id");
        let by_type = receipts.0.get(&event_id).expect("event present");
        let read = by_type.get("m.read").expect("m.read present").get(&alice).expect("alice present");
        assert_eq!(read.ts, 1_436_451_550_453);
        assert_eq!(read.thread_id.as_deref(), Some("main"));
        let read_private =
            by_type.get("m.read.private").expect("m.read.private present").get(&alice).expect("alice present");
        assert_eq!(read_private.ts, 1_436_451_551_000);
        assert_eq!(read_private.thread_id, None);
    }

    #[test]
    fn withheld_codes_parse_including_unknown() {
        let cases = [
            ("m.blacklisted", WithheldCode::Blacklisted),
            ("m.unverified", WithheldCode::Unverified),
            ("m.unauthorised", WithheldCode::Unauthorised),
            ("m.unavailable", WithheldCode::Unavailable),
            ("m.no_olm", WithheldCode::NoOlm),
        ];
        for (wire, expected) in cases {
            let parsed: WithheldCode = serde_json::from_value(serde_json::json!(wire)).expect("known code parses");
            assert_eq!(parsed, expected);
            assert_eq!(parsed.as_str(), wire);
        }

        let unknown: WithheldCode =
            serde_json::from_value(serde_json::json!("m.some_future_code")).expect("unknown code still parses");
        assert_eq!(unknown, WithheldCode::Unknown("m.some_future_code".to_string()));
        assert_eq!(unknown.as_str(), "m.some_future_code");

        let content: RoomKeyWithheldContent = serde_json::from_value(serde_json::json!({
            "algorithm": "m.megolm.v1.aes-sha2",
            "room_id": "!room:example.org",
            "session_id": "session-1",
            "sender_key": "sender-curve25519",
            "code": "m.unverified",
            "reason": "device not verified"
        }))
        .expect("valid withheld content");
        assert_eq!(content.code, WithheldCode::Unverified);
        assert_eq!(content.reason.as_deref(), Some("device not verified"));
    }

}
