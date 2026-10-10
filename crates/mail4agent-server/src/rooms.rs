//! Room and membership decisions over an open messenger connection.
//! The builder supplies user ids, mxids, and display names, and enforces
//! entitlements before it calls in. Nothing here authenticates, bills, or
//! wakes a socket.

use std::collections::HashSet;

use rusqlite::Connection;

use crate::error::MatrixError;
use crate::store::{HistoryVisibility, JoinRule, Membership, PowerAction, Room, RoomKind};

// ============================================================================
// Request bodies
// ============================================================================

#[derive(serde::Deserialize, Default)]
pub struct CreateRoomRequest {
    #[serde(default)]
    pub visibility: Option<String>,
    #[serde(default)]
    pub is_direct: bool,
    #[serde(default)]
    pub invite: Vec<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub power_level_content_override: Option<serde_json::Value>,
    /// No room-alias namespace exists at all (plan §10 item 4) — a non-empty
    /// value is refused outright rather than silently dropped, so a client
    /// never believes an alias was actually set.
    #[serde(default)]
    pub room_alias_name: Option<String>,
    /// Only `type: "m.space"` is honored; any other `type` is refused.
    #[serde(default)]
    pub creation_content: Option<serde_json::Value>,
    // `preset`/`initial_state` are intentionally NOT fields here: every
    // bootstrap state event is server-derived from `kind` (§5), never
    // client-declared, and serde ignores unrecognized JSON keys by default
    // (no `deny_unknown_fields`) — so a client that still sends them (many
    // Matrix SDKs send `preset` unconditionally) is silently unaffected
    // rather than needing a field this struct would otherwise never read.
}


#[derive(serde::Deserialize)]
pub struct UserIdBody {
    pub user_id: String,
}


#[derive(serde::Deserialize)]
pub struct KickBanBody {
    pub user_id: String,
    #[serde(default)]
    pub reason: Option<String>,
}


#[derive(serde::Deserialize, Default)]
pub struct MembersQuery {
    pub membership: Option<String>,
    pub at: Option<i64>,
}


// ============================================================================
// Pure decision functions — no DB, no `MatrixCaller`, unit-tested directly
// ============================================================================

/// Kind derivation (plan P5 correction): `is_direct: true` requires EXACTLY
/// ONE `invite[]` entry (the peer; the creator is the other member) or
/// refuses with `M_INVALID_PARAM`; otherwise `visibility == "public"` ->
/// `channel`; otherwise `group`.
pub fn derive_room_kind(is_direct: bool, invite_count: usize, visibility_public: bool) -> Result<RoomKind, MatrixError> {
    if is_direct {
        return if invite_count == 1 {
            Ok(RoomKind::Dm)
        } else {
            Err(MatrixError::invalid_param("is_direct requires exactly one invite target"))
        };
    }
    if visibility_public {
        return Ok(RoomKind::Channel);
    }
    Ok(RoomKind::Group)
}


/// `content` with the user's `displayname` stamped in. The server owns this
/// field of every `join`/`invite` member event it writes (the Matrix
/// convention): a client names a DM after the peer's member-event
/// `displayname` and lists members by it, falling back to the mxid localpart
/// (the 32-hex public id) when it is absent. An empty `displayname` (no
/// identity row behind the user) leaves the field out rather than stamping
/// an empty name.
pub fn with_displayname(mut content: serde_json::Value, displayname: &str) -> serde_json::Value {
    if !displayname.is_empty() {
        content["displayname"] = serde_json::Value::String(displayname.to_string());
    }
    content
}


/// The `content` of a `join` `m.room.member` event for a user whose
/// effective label is `displayname` (see [`with_displayname`]).
/// `pub(crate)` — the legacy-DM migration's bootstrap writes the same event.
pub fn join_member_content(displayname: &str) -> serde_json::Value {
    with_displayname(serde_json::json!({ "membership": "join" }), displayname)
}


/// The `content` of the invitee's `m.room.member` invite event, carrying the
/// invitee's own effective label as `displayname`. A DM invite also carries
/// `is_direct: true` (the Matrix convention): the invitee's client reads it
/// from `invite_state` to classify the room as a DM and record it in
/// `m.direct`; without it the room would surface as a group. Every other
/// kind carries the membership and the `displayname` only.
pub fn invite_member_content(kind: RoomKind, displayname: &str) -> serde_json::Value {
    let mut content = with_displayname(serde_json::json!({ "membership": "invite" }), displayname);
    if kind == RoomKind::Dm {
        content["is_direct"] = serde_json::Value::Bool(true);
    }
    content
}


/// A joined user's own `m.room.member` update (`PUT state`, the profile-update
/// exception in [`check_state_event_type_allowed`]) with `displayname`
/// forced to the effective label: the nick is the source of truth (`PUT
/// /profile/{userId}/displayname` is refused for the same reason), so a
/// client-chosen name is overwritten, and dropped when there is no label to
/// stamp instead. Every other field of the client's content is kept.
pub fn stamp_own_member_displayname(content: &str, displayname: &str) -> Result<String, MatrixError> {
    let mut value: serde_json::Value = serde_json::from_str(content)?;
    let Some(fields) = value.as_object_mut() else {
        return Err(MatrixError::invalid_param("m.room.member content must be an object"));
    };
    if displayname.is_empty() {
        fields.remove("displayname");
    } else {
        fields.insert("displayname".to_string(), serde_json::Value::String(displayname.to_string()));
    }
    Ok(value.to_string())
}


/// The creator's `join` and every invitee's `invite` `m.room.member` state
/// events of a fresh room, each stamped with its own user's effective label
/// (`invitees` is `(mxid, label)` per invited user). The creator's event
/// comes first: `m.room.power_levels` must follow the member events it
/// refers to (see [`crate::store::create_room_with_state`]).
pub fn bootstrap_member_events(kind: RoomKind, creator: (i64, &str, &str), invitees: &[(String, String)]) -> Vec<crate::store::NewStateEvent> {
    let (creator_user_id, creator_mxid, creator_label) = creator;
    let mut events = vec![state_event("m.room.member", creator_mxid, creator_user_id, join_member_content(creator_label))];
    for (mxid, label) in invitees {
        events.push(state_event("m.room.member", mxid, creator_user_id, invite_member_content(kind, label)));
    }
    events
}


/// `join_rule`, `history_visibility`, `is_encrypted` for a fresh room.
/// DM and group are E2E (`shared`). A Channel is PUBLIC PLAINTEXT
/// (`world_readable`, not encrypted; project decision): its posts live
/// in the separate public store ([`crate::public_channels`]), never in the
/// closed `events` table and never under [`crate::retention`]. Rooms that
/// were already created encrypted stay encrypted.
/// `pub(crate)` — also the P12 legacy-DM migration's bootstrap builder.
pub fn room_kind_settings(kind: RoomKind) -> (JoinRule, HistoryVisibility, bool) {
    match kind {
        RoomKind::Dm => (JoinRule::Invite, HistoryVisibility::Shared, true),
        RoomKind::Group => (JoinRule::Invite, HistoryVisibility::Shared, true),
        RoomKind::Channel => (JoinRule::Public, HistoryVisibility::WorldReadable, false),
    }
}


/// `power_level_content_override` validation (P5 correction): accepted with
/// ONLY the `invite` key (value `0` or `50`), and only for `group` rooms
/// ("members can add people," §5). Any other key, an out-of-range value, or
/// use on a non-group room is refused with `M_INVALID_PARAM`. Returns the
/// override value to apply (`None` if the object was absent/empty).
pub fn validate_power_level_override(kind: RoomKind, override_value: &Option<serde_json::Value>) -> Result<Option<i64>, MatrixError> {
    let Some(value) = override_value else { return Ok(None) };
    let obj = value.as_object().ok_or_else(|| MatrixError::invalid_param("power_level_content_override must be an object"))?;
    if obj.keys().any(|k| k != "invite") {
        return Err(MatrixError::invalid_param("power_level_content_override only accepts the 'invite' key"));
    }
    let Some(invite_value) = obj.get("invite") else { return Ok(None) };
    if kind != RoomKind::Group {
        return Err(MatrixError::invalid_param("power_level_content_override is only accepted for group rooms"));
    }
    match invite_value.as_i64() {
        Some(0) => Ok(Some(0)),
        Some(50) => Ok(Some(50)),
        _ => Err(MatrixError::invalid_param("power_level_content_override.invite must be 0 or 50")),
    }
}


/// `power_levels.invite` for a fresh room (plan §5): `dm`/`channel` are
/// fixed at `50`; `group` defaults to `50` unless
/// [`validate_power_level_override`] returned an explicit override.
/// `pub(crate)` — also used by the P12 legacy-DM migration.
pub fn invite_power_level(kind: RoomKind, override_value: Option<i64>) -> i64 {
    match kind {
        RoomKind::Dm | RoomKind::Channel => 50,
        RoomKind::Group => override_value.unwrap_or(50),
    }
}


/// The `m.room.power_levels` content for a fresh room (plan §5): the
/// creator at `100`, every other field at the table's fixed defaults except
/// `events_default` (raised to `50` for a `channel` — announcement-only).
/// `pub(crate)` — reused verbatim by the P12 legacy-DM migration, so a
/// migrated room's power levels are byte-for-byte what a native `createRoom`
/// call would have produced.
pub fn power_levels_content(creator_mxid: &str, kind: RoomKind, invite_level: i64) -> serde_json::Value {
    let events_default = if kind == RoomKind::Channel { 50 } else { 0 };
    serde_json::json!({
        "users": { creator_mxid: 100 },
        "users_default": 0,
        "events_default": events_default,
        "state_default": 50,
        "ban": 50,
        "kick": 50,
        "redact": 50,
        "invite": invite_level,
    })
}


/// `PUT state/{eventType}/{stateKey}`'s `m.room.encryption` rule: refuse
/// changing/removing an EXISTING encryption event. Enabling encryption on
/// a still-unencrypted room (including a public channel) is allowed — all
/// room kinds are E2E. `join_rule` is retained for call-site compatibility.
pub fn check_encryption_state_change(event_type: &str, join_rule: JoinRule, already_encrypted: bool) -> Result<(), MatrixError> {
    let _ = join_rule;
    if event_type != "m.room.encryption" {
        return Ok(());
    }
    if already_encrypted {
        return Err(MatrixError::forbidden("encryption cannot be changed once set"));
    }
    Ok(())
}


/// `PUT state` must never touch `m.room.create` or `m.room.member` (manager
/// review, 2026-09-24 — a real gap: the generic `PUT state/{type}/{key}`
/// route had no type-specific refusal at all, so a Member with enough
/// `state_default` power could rewrite `m.room.create`'s content, or
/// silently kick/invite/ban a target by PUTting their `m.room.member`
/// event directly, bypassing every kick/ban/invite-specific rule this
/// module otherwise enforces (target-level checks, txn-dedup, the right
/// wake set, ...). The ONE exception: a joined user updating their OWN
/// `m.room.member` event while its `membership` stays `join` (a profile
/// update; [`put_state_inner`] then forces its `displayname` to the nick's
/// effective label via [`stamp_own_member_displayname`], so the client's own
/// name never sticks) — membership itself only ever changes through
/// join/leave/invite/kick/ban.
pub fn check_state_event_type_allowed(event_type: &str, state_key: &str, caller_mxid: &str, content_str: &str) -> Result<(), MatrixError> {
    if event_type == "m.room.create" {
        return Err(MatrixError::forbidden("m.room.create cannot be modified"));
    }
    if event_type == "m.space.child" || event_type == "m.space.parent" {
        let value: serde_json::Value = serde_json::from_str(content_str)?;
        crate::spaces::validate_space_state(event_type, &value)?;
    }
    if event_type == "m.room.member" {
        let membership: Option<String> = serde_json::from_str::<serde_json::Value>(content_str)
            .ok()
            .and_then(|v| v.get("membership").and_then(|m| m.as_str()).map(str::to_string));
        let is_own_join_update = state_key == caller_mxid && membership.as_deref() == Some("join");
        if !is_own_join_update {
            return Err(MatrixError::forbidden(
                "m.room.member only changes via join/leave/invite/kick/ban, except your own profile update while still joined",
            ));
        }
    }
    Ok(())
}


/// `(lo, hi)`-ordered pair key for a DM between two internal user ids — the
/// same trick `dm_conversations` already uses (`dm_db.rs`), reused here for
/// `rooms.dm_pair_key`. `pub(crate)` — also used by the P12 legacy-DM
/// migration.
pub fn dm_pair_key(a: i64, b: i64) -> String {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    format!("{lo}:{hi}")
}


/// `pub(crate)` — also used by the P12 legacy-DM migration to build its own
/// bootstrap state events through the same helper `create_room` uses.
pub fn state_event(event_type: &str, state_key: &str, sender_user_id: i64, content: serde_json::Value) -> crate::store::NewStateEvent {
    crate::store::NewStateEvent {
        event_id: crate::store::new_event_id(),
        sender_user_id,
        event_type: event_type.to_string(),
        state_key: state_key.to_string(),
        content: content.to_string(),
    }
}


// ============================================================================
// DB-only gate/read helpers — `&Connection`, no `MatrixCaller`
// ============================================================================

/// `m.room.power_levels`' content, or the empty object (every threshold then
/// resolves to its Matrix default via [`crate::store::user_level`]/
/// [`crate::store::event_level`]) if the room has never had one applied.
pub fn power_levels_of(conn: &Connection, room_id: &str) -> Result<serde_json::Value, MatrixError> {
    match crate::store::current_state_event(conn, room_id, "m.room.power_levels", "")? {
        Some(event) => Ok(serde_json::from_str(&event.content)?),
        None => Ok(serde_json::json!({})),
    }
}


/// The plan §4 "Member" gate: a `room_members` row with `membership='join'`.
pub fn require_member(membership: Option<Membership>) -> Result<(), MatrixError> {
    match membership {
        Some(Membership::Join) => Ok(()),
        _ => Err(MatrixError::forbidden("not a member of this room")),
    }
}


pub fn require_power(power_levels: &serde_json::Value, mxid: &str, action: PowerAction) -> Result<(), MatrixError> {
    if crate::store::can(power_levels, action, mxid) {
        Ok(())
    } else {
        Err(MatrixError::forbidden("insufficient power level for this action"))
    }
}


/// kick/ban/unban's own gate (manager review, 2026-09-24): beyond the flat
/// [`require_power`] threshold, the caller's level must be STRICTLY
/// GREATER than the target's current level — see
/// [`crate::store::can_act_on`]'s own doc for why a level-50 admin must
/// never be able to touch a level-100 owner or an equal-level peer.
pub fn require_power_over_target(power_levels: &serde_json::Value, caller_mxid: &str, target_mxid: &str, action: PowerAction, self_leave: bool) -> Result<(), MatrixError> {
    if crate::store::can_act_on(power_levels, action, caller_mxid, target_mxid, self_leave) {
        Ok(())
    } else {
        Err(MatrixError::forbidden("insufficient power level for this action"))
    }
}


/// The plan §4 "PubRead" gate: Member, OR any signed-in caller when the
/// room is a public, world-readable channel.
pub fn require_pub_read(conn: &Connection, room: &Room, user_id: i64) -> Result<(), MatrixError> {
    let membership = crate::store::room_member(conn, &room.id, user_id)?.map(|m| m.membership);
    if matches!(membership, Some(Membership::Join)) {
        return Ok(());
    }
    if room.join_rule == JoinRule::Public && room.history_visibility == HistoryVisibility::WorldReadable {
        return Ok(());
    }
    Err(MatrixError::forbidden("no read access to this room"))
}


/// Every user id currently `join`ed OR `invite`d in `room_id` — the wake
/// fan-out set for a write that affects the whole room (plan §3.1/§4:
/// "wakes every joined AND invited member"). `pub(crate)` (not `pub(super)`)
/// so both `routes::matrix::messaging` (P6) and `routes::dm`'s legacy-DM
/// bridge (P15, outside this module tree) reuse the SAME wake-set
/// computation rather than a second copy — see each module's own doc.
pub fn member_and_invited_ids(conn: &Connection, room_id: &str) -> rusqlite::Result<HashSet<i64>> {
    let mut ids = HashSet::new();
    for member in crate::store::room_members(conn, room_id, Some(Membership::Join))? {
        ids.insert(member.user_id);
    }
    for member in crate::store::room_members(conn, room_id, Some(Membership::Invite))? {
        ids.insert(member.user_id);
    }
    Ok(ids)
}


/// The DM-reuse lookup (plan P5 correction): if `pair_key` currently names a
/// room, return its id when it is STILL a live DM for both `user_a` and
/// `user_b` (both `join`/`invite`, neither `leave`d out); otherwise free the
/// pair key on that dead room (`rooms.dm_pair_key` is `UNIQUE`, so a fresh
/// room reusing this pair key needs the slot released first) and return
/// `None`, telling the caller to mint a new room. `pub(crate)` — the legacy-DM
/// migration adopts a live native DM through the same lookup.
pub fn find_reusable_dm_room(conn: &Connection, pair_key: &str, user_a: i64, user_b: i64) -> rusqlite::Result<Option<String>> {
    let Some(existing) = crate::store::room_by_dm_pair_key(conn, pair_key)? else {
        return Ok(None);
    };
    let members = crate::store::room_members(conn, &existing.id, None)?;
    let alive = |uid: i64| members.iter().any(|m| m.user_id == uid && matches!(m.membership, Membership::Join | Membership::Invite));
    if alive(user_a) && alive(user_b) {
        return Ok(Some(existing.id));
    }
    crate::store::clear_dm_pair_key(conn, &existing.id)?;
    Ok(None)
}


// ============================================================================
// DB-only action cores — `&mut Connection`, no `MatrixCaller`, unit-tested
// directly against an in-memory `matrix_store` fixture
// ============================================================================

/// The invitee of [`apply_invite`]: the resolved internal user id and the
/// effective label to stamp into their invite event as `displayname`.
#[derive(Debug, Clone, Copy)]
pub struct InviteTarget<'a> {
    pub user_id: i64,
    pub displayname: &'a str,
}

/// The invite action's whole DB-side decision + write (plan §4's `invite`
/// row: Member + PowerCheck(invite), refuses an already-invited/joined or
/// banned target), used by both the real handler (after resolving
/// `target_user_id` via [`resolve_target_user`], which needs the identity
/// connection this function deliberately does NOT take) and this module's
/// own tests. Returns the wake set (every joined+invited member, including
/// the new invitee).
///
/// The invite event carries the invitee's `displayname` (`target`), resolved
/// by the caller from the identity database BEFORE it takes the messenger
/// connection this function writes through.
pub fn apply_invite(
    conn: &mut Connection,
    room_id: &str,
    caller_user_id: i64,
    caller_mxid: &str,
    target: InviteTarget<'_>,
    now: &str,
    origin_ts: i64,
) -> Result<HashSet<i64>, MatrixError> {
    let target_user_id = target.user_id;
    let room = crate::store::get_room(conn, room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
    let caller_membership = crate::store::room_member(conn, room_id, caller_user_id)?.map(|m| m.membership);
    require_member(caller_membership)?;
    let power_levels = power_levels_of(conn, room_id)?;
    require_power(&power_levels, caller_mxid, PowerAction::Invite)?;

    let target_membership = crate::store::room_member(conn, room_id, target_user_id)?.map(|m| m.membership);
    match target_membership {
        Some(Membership::Join) | Some(Membership::Invite) => return Err(MatrixError::invalid_param("user is already invited or joined")),
        Some(Membership::Ban) => return Err(MatrixError::forbidden("user is banned from this room")),
        Some(Membership::Leave) | None => {}
    }

    let target_mxid = crate::store::mxid_of(conn, target_user_id)?.ok_or_else(MatrixError::internal)?;
    crate::store::apply_state_event(
        conn,
        &crate::store::StateEventWrite {
            event_id: &crate::store::new_event_id(),
            room_id,
            sender_user_id: caller_user_id,
            event_type: "m.room.member",
            state_key: &target_mxid,
            content: &invite_member_content(room.kind, target.displayname).to_string(),
            origin_server_ts: origin_ts,
            now,
        },
    )?;

    let mut ids = member_and_invited_ids(conn, room_id)?;
    ids.insert(target_user_id);
    Ok(ids)
}

/// What state a kick/ban/unban target must currently be in for the action
/// to proceed. `pub(super)` — also `routes::matrix::moderation`'s (P11) own
/// room-power fallback path reuses this exact rule set, so a kick/ban/unban
/// reached through `/api/matrix-admin/.../moderate` never drifts from the
/// same action reached through this module's own `/kick`/`/ban`/`/unban`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetStateRule {
    /// kick: the target must currently be an active member (`join`/`invite`).
    MustBeActiveMember,
    /// ban: any current state is fine (banning a non-member pre-empts a
    /// future join attempt).
    Any,
    /// unban: the target must currently be `ban`ned.
    MustBeBanned,
}


pub fn check_target_state_rule(rule: TargetStateRule, membership: Option<Membership>) -> Result<(), MatrixError> {
    match rule {
        TargetStateRule::MustBeActiveMember => {
            if matches!(membership, Some(Membership::Join) | Some(Membership::Invite)) {
                Ok(())
            } else {
                Err(MatrixError::not_found("user is not a member of this room"))
            }
        }
        TargetStateRule::MustBeBanned => {
            if membership == Some(Membership::Ban) {
                Ok(())
            } else {
                Err(MatrixError::invalid_param("user is not banned"))
            }
        }
        TargetStateRule::Any => Ok(()),
    }
}


/// The pieces [`apply_membership_power_action`] needs beyond the caller and
/// the connection — grouped so the function itself stays under a plain
/// four-parameter signature instead of needing
/// `#[allow(clippy::too_many_arguments)]`. `pub(super)` alongside
/// [`apply_membership_power_action`] — see that function's own doc for why.
pub struct MembershipPowerAction<'a> {
    pub room_id: &'a str,
    pub action: PowerAction,
    pub target_user_id: i64,
    pub target_rule: TargetStateRule,
    pub new_membership: Membership,
    pub reason: Option<&'a str>,
}

/// The shared core of kick/ban/unban (plan §4: Member + PowerCheck(kick/
/// ban)): checks the caller's own membership+power, checks
/// [`TargetStateRule`] against the target's current membership, then writes
/// the target's new `m.room.member` state event. `target_user_id` is
/// already resolved (identity-DB work happens in the handler, not here —
/// see the module doc's "testable cores" note). Returns the wake set
/// (post-write joined+invited members plus the target, even though the
/// target may no longer be one of those after this write).
///
/// `pub(super)` — `routes::matrix::moderation`'s (P11) room-power fallback
/// gate ("otherwise the caller needs the room's own power," plan §4's
/// `/moderate` row) reuses this verbatim rather than re-deriving the
/// `can_act_on` target-level rule a second time, matching this module's own
/// precedent for [`member_and_invited_ids`] (reused by `messaging.rs`).
pub fn apply_membership_power_action(
    conn: &mut Connection,
    caller_user_id: i64,
    caller_mxid: &str,
    action: MembershipPowerAction<'_>,
    now: &str,
    origin_ts: i64,
) -> Result<HashSet<i64>, MatrixError> {
    let room_id = action.room_id;
    let caller_membership = crate::store::room_member(conn, room_id, caller_user_id)?.map(|m| m.membership);
    require_member(caller_membership)?;
    let power_levels = power_levels_of(conn, room_id)?;

    let target_mxid = crate::store::mxid_of(conn, action.target_user_id)?.ok_or_else(MatrixError::internal)?;
    let self_leave = action.new_membership == Membership::Leave;
    require_power_over_target(&power_levels, caller_mxid, &target_mxid, action.action, self_leave)?;

    let target_membership = crate::store::room_member(conn, room_id, action.target_user_id)?.map(|m| m.membership);
    check_target_state_rule(action.target_rule, target_membership)?;

    let mut content = serde_json::json!({ "membership": action.new_membership.as_str() });
    if let Some(reason) = action.reason {
        content["reason"] = serde_json::Value::String(reason.to_string());
    }
    crate::store::apply_state_event(conn, &crate::store::StateEventWrite { event_id: &crate::store::new_event_id(), room_id, sender_user_id: caller_user_id, event_type: "m.room.member", state_key: &target_mxid, content: &content.to_string(), origin_server_ts: origin_ts, now })?;

    let mut ids = member_and_invited_ids(conn, room_id)?;
    ids.insert(action.target_user_id);
    Ok(ids)
}

/// `POST /join`'s write for an already-invited or newly-public-eligible
/// caller (idempotent-join and ban checks happen in the handler, before the
/// policy hook — see [`join_room`]). Returns the post-join wake set. The join
/// event carries the caller's effective label as `displayname`, resolved by
/// the caller BEFORE it takes the messenger connection this writes through.
pub fn apply_join(
    conn: &mut Connection,
    room_id: &str,
    caller_user_id: i64,
    caller_mxid: &str,
    displayname: &str,
    now: &str,
    origin_ts: i64,
) -> Result<HashSet<i64>, MatrixError> {
    crate::store::apply_state_event(
        conn,
        &crate::store::StateEventWrite {
            event_id: &crate::store::new_event_id(),
            room_id,
            sender_user_id: caller_user_id,
            event_type: "m.room.member",
            state_key: caller_mxid,
            content: &join_member_content(displayname).to_string(),
            origin_server_ts: origin_ts,
            now,
        },
    )?;
    Ok(member_and_invited_ids(conn, room_id)?)
}


/// `POST /leave`'s write (manager review, 2026-09-24: the plan's plain
/// "Member" gate table entry undersold this — Matrix's own spec behaviour
/// for `/leave` is "leave OR reject a pending invite," so an INVITED, not
/// yet joined, caller must be accepted too). Wake set is captured BEFORE
/// the leave lands, so the leaver's own other devices are included, and —
/// since [`member_and_invited_ids`] already covers every joined+invited
/// member — the inviter (who must be a joined member to have sent the
/// invite at all) is naturally woken as well.
pub fn apply_leave(conn: &mut Connection, room_id: &str, caller_user_id: i64, caller_mxid: &str, now: &str, origin_ts: i64) -> Result<HashSet<i64>, MatrixError> {
    let caller_membership = crate::store::room_member(conn, room_id, caller_user_id)?.map(|m| m.membership);
    if !matches!(caller_membership, Some(Membership::Join) | Some(Membership::Invite)) {
        return Err(MatrixError::forbidden("not a member or invitee of this room"));
    }
    let wake_ids = member_and_invited_ids(conn, room_id)?;
    crate::store::apply_state_event(
        conn,
        &crate::store::StateEventWrite {
            event_id: &crate::store::new_event_id(),
            room_id,
            sender_user_id: caller_user_id,
            event_type: "m.room.member",
            state_key: caller_mxid,
            content: &serde_json::json!({ "membership": "leave" }).to_string(),
            origin_server_ts: origin_ts,
            now,
        },
    )?;
    Ok(wake_ids)
}


/// Caller-supplied invitee. The mxid is already stored on `matrix_users`;
/// `displayname` is whatever the builder wants stamped into the member event.
pub struct RoomInvitee<'a> {
    pub user_id: i64,
    pub displayname: &'a str,
}

/// Inputs for [`apply_create_room`]. Identity, entitlement, and the HTTP
/// body parse stay with the builder. Invitees are already integer user ids.
pub struct RoomCreate<'a> {
    pub creator_user_id: i64,
    pub creator_mxid: &'a str,
    pub creator_displayname: &'a str,
    pub is_direct: bool,
    pub invitees: &'a [RoomInvitee<'a>],
    pub visibility_public: bool,
    pub power_level_content_override: Option<serde_json::Value>,
    pub name: Option<&'a str>,
    pub topic: Option<&'a str>,
    /// `creation_content.type`; only `m.space` is accepted (a domain).
    pub room_type: Option<&'a str>,
}

pub enum RoomCreation {
    Reused(String),
    Created { room_id: String, notify_user_ids: HashSet<i64> },
}

/// Create a room, or reuse the live DM for the same pair.
/// Returns the user ids the builder may notify. Does not wake anyone.
pub fn apply_create_room(
    conn: &mut Connection,
    req: RoomCreate<'_>,
    now: &str,
    origin_ts: i64,
) -> Result<RoomCreation, MatrixError> {
    if req.invitees.iter().any(|invitee| invitee.user_id == req.creator_user_id) {
        return Err(MatrixError::invalid_param("cannot invite yourself"));
    }
    let kind = derive_room_kind(req.is_direct, req.invitees.len(), req.visibility_public)?;
    let invite_override = validate_power_level_override(kind, &req.power_level_content_override)?;
    if kind == RoomKind::Dm {
        let peer_id = req.invitees[0].user_id;
        let pair_key = dm_pair_key(req.creator_user_id, peer_id);
        if let Some(existing) = find_reusable_dm_room(conn, &pair_key, req.creator_user_id, peer_id)? {
            return Ok(RoomCreation::Reused(existing));
        }
    }

    let room_id = crate::store::new_room_id();
    let (join_rule, history_visibility, is_encrypted) = room_kind_settings(kind);
    let invite_level = invite_power_level(kind, invite_override);
    let mut invitees = Vec::with_capacity(req.invitees.len());
    for invitee in req.invitees {
        let mxid = crate::store::mxid_of(conn, invitee.user_id)?.ok_or_else(MatrixError::internal)?;
        invitees.push((mxid, invitee.displayname.to_string()));
    }
    let mut state_events = vec![state_event(
        "m.room.create",
        "",
        req.creator_user_id,
        match req.room_type {
            Some(t) => serde_json::json!({ "room_version": crate::store::MATRIX_ROOM_VERSION, "type": t }),
            None => serde_json::json!({ "room_version": crate::store::MATRIX_ROOM_VERSION }),
        },
    )];
    state_events.extend(bootstrap_member_events(
        kind,
        (req.creator_user_id, req.creator_mxid, req.creator_displayname),
        &invitees,
    ));
    state_events.push(state_event(
        "m.room.power_levels",
        "",
        req.creator_user_id,
        power_levels_content(req.creator_mxid, kind, invite_level),
    ));
    state_events.push(state_event(
        "m.room.join_rules",
        "",
        req.creator_user_id,
        serde_json::json!({ "join_rule": join_rule.as_str() }),
    ));
    state_events.push(state_event(
        "m.room.history_visibility",
        "",
        req.creator_user_id,
        serde_json::json!({ "history_visibility": history_visibility.as_str() }),
    ));
    if let Some(name) = req.name {
        state_events.push(state_event(
            "m.room.name",
            "",
            req.creator_user_id,
            serde_json::json!({ "name": name }),
        ));
    }
    if let Some(topic) = req.topic {
        state_events.push(state_event(
            "m.room.topic",
            "",
            req.creator_user_id,
            serde_json::json!({ "topic": topic }),
        ));
    }
    if is_encrypted {
        state_events.push(state_event(
            "m.room.encryption",
            "",
            req.creator_user_id,
            serde_json::json!({ "algorithm": "m.megolm.v1.aes-sha2" }),
        ));
    }
    let dm_pair = (kind == RoomKind::Dm).then(|| dm_pair_key(req.creator_user_id, req.invitees[0].user_id));
    let bootstrap = crate::store::RoomBootstrap {
        room_id: &room_id,
        kind,
        creator_user_id: req.creator_user_id,
        created_at: now,
        is_encrypted,
        join_rule,
        history_visibility,
        dm_pair_key: dm_pair.as_deref(),
        legacy_dm_id: None,
    };
    crate::store::create_room_with_state(conn, bootstrap, &state_events, origin_ts)?;
    let mut notify_user_ids: HashSet<i64> = req.invitees.iter().map(|invitee| invitee.user_id).collect();
    notify_user_ids.insert(req.creator_user_id);
    Ok(RoomCreation::Created { room_id, notify_user_ids })
}

pub enum JoinDecision {
    AlreadyJoined,
    Joined(HashSet<i64>),
}

/// Join gate without an entitlement check. A banned user is refused.
/// A private room still requires an invite. The builder stamps `displayname`.
pub fn decide_and_apply_join(
    conn: &mut Connection,
    room_id: &str,
    caller_user_id: i64,
    caller_mxid: &str,
    displayname: &str,
    now: &str,
    origin_ts: i64,
) -> Result<JoinDecision, MatrixError> {
    let room = crate::store::get_room(conn, room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
    let current = crate::store::room_member(conn, room_id, caller_user_id)?.map(|member| member.membership);
    match current {
        Some(Membership::Join) => return Ok(JoinDecision::AlreadyJoined),
        Some(Membership::Ban) => return Err(MatrixError::forbidden("banned from this room")),
        Some(Membership::Invite) => {}
        Some(Membership::Leave) | None => {
            if room.join_rule != JoinRule::Public && !crate::spaces::restricted_allows(conn, room_id, caller_user_id)? {
                return Err(MatrixError::forbidden("no invitation to this room"));
            }
        }
    }
    let ids = apply_join(conn, room_id, caller_user_id, caller_mxid, displayname, now, origin_ts)?;
    Ok(JoinDecision::Joined(ids))
}

/// Write one state event. `content` is already final: the builder stamps
/// `displayname` on an own-member profile update before calling in.
/// Returns `(event_id, user ids the builder may notify)`.
pub fn apply_put_state(
    conn: &mut Connection,
    room_id: &str,
    sender_user_id: i64,
    sender_mxid: &str,
    event_type: &str,
    state_key: &str,
    content: &str,
    now: &str,
    origin_ts: i64,
) -> Result<(String, HashSet<i64>), MatrixError> {
    if content.len() > crate::store::MATRIX_EVENT_CONTENT_MAX_BYTES {
        return Err(MatrixError::invalid_param("event content too large"));
    }
    let room = crate::store::get_room(conn, room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
    let caller_membership = crate::store::room_member(conn, room_id, sender_user_id)?.map(|member| member.membership);
    require_member(caller_membership)?;
    check_state_event_type_allowed(event_type, state_key, sender_mxid, content)?;
    let already_encrypted = crate::store::current_state_event(conn, room_id, "m.room.encryption", "")?.is_some();
    check_encryption_state_change(event_type, room.join_rule, already_encrypted)?;
    let power_levels = power_levels_of(conn, room_id)?;
    if crate::store::user_level(&power_levels, sender_mxid) < crate::store::event_level(&power_levels, event_type, true) {
        return Err(MatrixError::forbidden("insufficient power level to set this state event"));
    }
    if event_type == "m.room.power_levels" {
        let new_power_levels: serde_json::Value = serde_json::from_str(content)?;
        crate::store::validate_power_levels_change(&power_levels, &new_power_levels, sender_mxid).map_err(MatrixError::forbidden)?;
    }
    let event = crate::store::apply_state_event(
        conn,
        &crate::store::StateEventWrite {
            event_id: &crate::store::new_event_id(),
            room_id,
            sender_user_id,
            event_type,
            state_key,
            content,
            origin_server_ts: origin_ts,
            now,
        },
    )?;
    let notify = member_and_invited_ids(conn, room_id)?;
    Ok((event.event_id, notify))
}

/// Forget a room the caller has already left.
pub fn apply_forget(conn: &Connection, room_id: &str, user_id: i64) -> Result<(), MatrixError> {
    let deleted = crate::store::forget_membership(conn, room_id, user_id)?;
    if deleted == 0 {
        return Err(MatrixError::forbidden("must have left the room before forgetting it"));
    }
    Ok(())
}


/// Enable Megolm on every still-plaintext room: write `m.room.encryption`
/// if missing, flip `rooms.is_encrypted`, and normalize
/// `history_visibility` to `shared` (public vs private = join_rule only).
/// Past timeline plaintext rows stay as historical `m.room.message`; new
/// sends must be encrypted. Idempotent. Returns how many rooms were changed.
pub fn migrate_plaintext_rooms_to_encrypted(
    conn: &mut Connection,
    now: &str,
    origin_ts: i64,
) -> Result<usize, MatrixError> {
    let plaintext: Vec<(String, i64, String)> = {
        let mut stmt = conn
            // Public plaintext channels are intentionally not encrypted; leave them.
            .prepare("SELECT id, creator_user_id, history_visibility FROM rooms WHERE is_encrypted = 0 AND kind != 'channel'")
            .map_err(|e| MatrixError::unknown(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|e| MatrixError::unknown(e.to_string()))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| MatrixError::unknown(e.to_string()))?
    };
    let mut changed = 0usize;
    for (room_id, creator_user_id, hv) in plaintext {
        let already = crate::store::current_state_event(conn, &room_id, "m.room.encryption", "")?.is_some();
        if !already {
            let event_id = crate::store::new_event_id();
            crate::store::apply_state_event(
                conn,
                &crate::store::StateEventWrite {
                    event_id: &event_id,
                    room_id: &room_id,
                    sender_user_id: creator_user_id,
                    event_type: "m.room.encryption",
                    state_key: "",
                    content: r#"{"algorithm":"m.megolm.v1.aes-sha2"}"#,
                    origin_server_ts: origin_ts,
                    now,
                },
            )?;
        }
        if hv == HistoryVisibility::WorldReadable.as_str() {
            let event_id = crate::store::new_event_id();
            crate::store::apply_state_event(
                conn,
                &crate::store::StateEventWrite {
                    event_id: &event_id,
                    room_id: &room_id,
                    sender_user_id: creator_user_id,
                    event_type: "m.room.history_visibility",
                    state_key: "",
                    content: r#"{"history_visibility":"shared"}"#,
                    origin_server_ts: origin_ts,
                    now,
                },
            )?;
            conn.execute(
                "UPDATE rooms SET history_visibility = ?1 WHERE id = ?2",
                rusqlite::params![HistoryVisibility::Shared.as_str(), room_id],
            )
            .map_err(|e| MatrixError::unknown(e.to_string()))?;
        }
        conn.execute(
            "UPDATE rooms SET is_encrypted = 1 WHERE id = ?1",
            rusqlite::params![room_id],
        )
        .map_err(|e| MatrixError::unknown(e.to_string()))?;
        changed += 1;
    }
    Ok(changed)
}

/// Drop empty `legacy_dm_message_map` (P12 scaffold). Refuses if any rows remain.
pub fn drop_legacy_dm_scaffold_if_empty(conn: &Connection) -> Result<bool, MatrixError> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='legacy_dm_message_map'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| MatrixError::unknown(e.to_string()))?;
    if count == 0 {
        return Ok(false);
    }
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM legacy_dm_message_map", [], |row| row.get(0))
        .map_err(|e| MatrixError::unknown(e.to_string()))?;
    if rows > 0 {
        return Err(MatrixError::forbidden("legacy_dm_message_map still has rows; refuse drop"));
    }
    conn.execute_batch("DROP TABLE IF EXISTS legacy_dm_message_map;")
        .map_err(|e| MatrixError::unknown(e.to_string()))?;
    Ok(true)
}

#[cfg(test)]
mod messenger_model_tests {
    use super::*;
    use crate::store::{self, HistoryVisibility, JoinRule, RoomKind};
    use rusqlite::Connection;

    const T0: &str = "2026-10-06T00:00:00+00:00";

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        store::create_matrix_schema(&conn).expect("schema");
        conn
    }

    #[test]
    fn dm_and_group_are_encrypted_channel_is_public_plaintext() {
        let (jr, hv, enc) = room_kind_settings(RoomKind::Dm);
        assert_eq!(jr, JoinRule::Invite);
        assert_eq!(hv, HistoryVisibility::Shared);
        assert!(enc);

        let (jr, hv, enc) = room_kind_settings(RoomKind::Group);
        assert_eq!(jr, JoinRule::Invite);
        assert_eq!(hv, HistoryVisibility::Shared);
        assert!(enc);

        let (jr, hv, enc) = room_kind_settings(RoomKind::Channel);
        assert_eq!(jr, JoinRule::Public);
        assert_eq!(hv, HistoryVisibility::WorldReadable);
        assert!(!enc, "public channels are plaintext in the public store");
    }

    #[test]
    fn encryption_may_be_enabled_on_a_public_room_but_never_changed() {
        check_encryption_state_change("m.room.encryption", JoinRule::Public, false).expect("enable ok");
        let err = check_encryption_state_change("m.room.encryption", JoinRule::Public, true).unwrap_err();
        assert!(format!("{err:?}").contains("changed") || format!("{err:?}").to_lowercase().contains("forbidden"));
    }

    #[test]
    fn public_channel_join_without_invite_private_group_requires_invite() {
        let mut conn = test_conn();
        store::ensure_matrix_user(&conn, 1, "alice000000000000000000000000001", T0).expect("alice");
        let bob_mxid = store::ensure_matrix_user(&conn, 2, "bob00000000000000000000000000002", T0).expect("bob");

        let channel = "!chan:example.org";
        let (jr, hv, enc) = room_kind_settings(RoomKind::Channel);
        store::create_room(&conn, channel, RoomKind::Channel, 1, T0, enc, jr, hv, None, None).expect("channel");
        match decide_and_apply_join(&mut conn, channel, 2, &bob_mxid, "bob", T0, 1_000).expect("join") {
            JoinDecision::Joined(_) => {}
            JoinDecision::AlreadyJoined => panic!("expected fresh join"),
        }

        let group = "!grp:example.org";
        let (jr, hv, enc) = room_kind_settings(RoomKind::Group);
        store::create_room(&conn, group, RoomKind::Group, 1, T0, enc, jr, hv, None, None).expect("group");
        match decide_and_apply_join(&mut conn, group, 2, &bob_mxid, "bob", T0, 2_000) {
            Err(err) => {
                let msg = format!("{err:?}").to_lowercase();
                assert!(msg.contains("invitation") || msg.contains("forbidden"), "{msg}");
            }
            Ok(_) => panic!("stranger must not join a private group without invite"),
        }
    }

    #[test]
    fn migration_encrypts_plaintext_group_but_leaves_public_channel_alone() {
        let mut conn = test_conn();
        store::ensure_matrix_user(&conn, 1, "alice000000000000000000000000001", T0).expect("alice");
        let channel = "!oldchan:example.org";
        store::create_room(&conn, channel, RoomKind::Channel, 1, T0, false, JoinRule::Public, HistoryVisibility::WorldReadable, None, None).expect("channel");
        let group = "!oldgrp:example.org";
        store::create_room(&conn, group, RoomKind::Group, 1, T0, false, JoinRule::Invite, HistoryVisibility::Shared, None, None).expect("group");
        let n = migrate_plaintext_rooms_to_encrypted(&mut conn, T0, 1_000).expect("migrate");
        assert_eq!(n, 1, "only the group is rewritten");
        let room = store::get_room(&conn, group).expect("get").expect("exists");
        assert!(room.is_encrypted);
        let chan = store::get_room(&conn, channel).expect("get").expect("exists");
        assert!(!chan.is_encrypted, "public channel stays plaintext");
        assert_eq!(chan.history_visibility, HistoryVisibility::WorldReadable);
        assert!(store::current_state_event(&conn, channel, "m.room.encryption", "").expect("state").is_none());
        let n2 = migrate_plaintext_rooms_to_encrypted(&mut conn, T0, 2_000).expect("idempotent");
        assert_eq!(n2, 0);
    }

    #[test]
    fn drop_legacy_dm_scaffold_when_empty() {
        let conn = test_conn();
        // Schema no longer creates the table; simulate an old DB.
        conn.execute_batch(
            "CREATE TABLE legacy_dm_message_map (
                legacy_message_id INTEGER PRIMARY KEY,
                event_id TEXT NOT NULL
            );",
        )
        .expect("old table");
        assert!(drop_legacy_dm_scaffold_if_empty(&conn).expect("drop"));
        assert!(!drop_legacy_dm_scaffold_if_empty(&conn).expect("already gone"));
    }
}
