//! Client-Server room routes. Paths have no `/_matrix` prefix.
//!
//! Each handler locks [`Homeserver::conn`] only inside `spawn_blocking`.
//! The guard is gone before the future resolves; the caller then
//! [`wake_users`] with the ids the write returned.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use rusqlite::Connection;

use super::{resolve_caller, wake_users, Caller, Homeserver};
use crate::error::MatrixError;
use crate::rooms::{
    apply_create_room, apply_forget, apply_invite, apply_leave, apply_membership_power_action, apply_put_state,
    decide_and_apply_join, derive_room_kind, require_pub_read, stamp_own_member_displayname, validate_power_level_override,
    InviteTarget, JoinDecision, MembershipPowerAction, RoomCreate, RoomCreation, RoomInvitee, TargetStateRule,
};
use crate::store::{Membership, PowerAction};

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new()
        .route("/client/v3/createRoom", post(create_room))
        .route("/client/v3/joined_rooms", get(joined_rooms))
        .route("/client/v3/rooms/{room_id}/join", post(join_room))
        .route("/client/v3/join/{room_id}", post(join_room))
        .route("/client/v3/rooms/{room_id}/leave", post(leave_room))
        .route("/client/v3/rooms/{room_id}/invite", post(invite_member))
        .route("/client/v3/rooms/{room_id}/kick", post(kick_member))
        .route("/client/v3/rooms/{room_id}/ban", post(ban_member))
        .route("/client/v3/rooms/{room_id}/unban", post(unban_member))
        .route("/client/v3/rooms/{room_id}/forget", post(forget_room))
        .route("/client/v3/rooms/{room_id}/state", get(get_state_all))
        .route("/client/v3/rooms/{room_id}/state/{event_type}", get(get_state_no_key).put(put_state_no_key))
        .route("/client/v3/rooms/{room_id}/state/{event_type}/", get(get_state_no_key).put(put_state_no_key))
        .route(
            "/client/v3/rooms/{room_id}/state/{event_type}/{state_key}",
            get(get_state).put(put_state),
        )
        .route("/client/v3/rooms/{room_id}/members", get(get_members))
        .route("/client/v3/rooms/{room_id}/joined_members", get(get_joined_members))
        .route("/client/v1/rooms/{room_id}/hierarchy", get(get_hierarchy))
}

#[derive(serde::Deserialize)]
struct HierarchyQuery {
    #[serde(default)]
    suggested_only: bool,
    limit: Option<usize>,
    max_depth: Option<usize>,
    from: Option<String>,
}

async fn get_hierarchy(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Query(q): Query<HierarchyQuery>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let from = match q.from.as_deref() {
        None => 0,
        Some(t) => t.strip_prefix('h').and_then(|n| n.parse::<usize>().ok()).ok_or_else(|| MatrixError::invalid_param("bad from token"))?,
    };
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let value = with_conn(&state, move |conn| {
        crate::spaces::hierarchy(conn, caller.user_id, &room_id, q.suggested_only, limit, q.max_depth, from)
    })
    .await?;
    value.map(Json).ok_or_else(|| MatrixError::not_found("room not found or not visible"))
}

/// Database work for one request. The mutex guard dies at the end of the
/// inner block, before `spawn_blocking` resolves.
async fn with_conn<T, F>(state: &Arc<Homeserver>, work: F) -> Result<T, MatrixError>
where
    T: Send + 'static,
    F: FnOnce(&mut Connection) -> Result<T, MatrixError> + Send + 'static,
{
    let state = Arc::clone(state);
    tokio::task::spawn_blocking(move || {
        let result = {
            state.conn_scope(|conn: &mut rusqlite::Connection| {
            work(&mut *conn)
            })
        };
        result
    })
    .await
    .map_err(|_| MatrixError::internal())?
}

fn now_stamp() -> (String, i64) {
    (chrono::Utc::now().to_rfc3339(), chrono::Utc::now().timestamp_millis())
}

fn known_user_id(conn: &Connection, mxid: &str, federated: bool) -> Result<i64, MatrixError> {
    match crate::store::user_id_of(conn, mxid)? {
        Some(id) => Ok(id),
        None if federated && crate::fed_rooms::is_remote_mxid(mxid) => {
            crate::fed_rooms::ensure_remote_user(conn, mxid, &chrono::Utc::now().to_rfc3339()).map_err(|_| MatrixError::invalid_param("invalid remote user id"))
        }
        None => Err(MatrixError::not_found(format!("Unknown user: {mxid}"))),
    }
}

fn require_room(conn: &Connection, room_id: &str) -> Result<crate::store::Room, MatrixError> {
    crate::store::get_room(conn, room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))
}

/// Own `join` profile update: the nick's effective label replaces a
/// client-supplied `displayname`. Every other body is left untouched so
/// [`apply_put_state`] can refuse it.
fn content_with_own_displayname(
    conn: &Connection,
    caller_user_id: i64,
    caller_mxid: &str,
    state_key: &str,
    content: &str,
) -> Result<String, MatrixError> {
    if state_key != caller_mxid {
        return Ok(content.to_string());
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
        return Ok(content.to_string());
    };
    if value.get("membership").and_then(|member| member.as_str()) != Some("join") {
        return Ok(content.to_string());
    }
    let label = crate::nick::effective_label(conn, caller_user_id)?;
    stamp_own_member_displayname(content, &label)
}

async fn create_room(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Json(req): Json<crate::rooms::CreateRoomRequest>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let visibility_public = req.visibility.as_deref() == Some("public");
    let kind = derive_room_kind(req.is_direct, req.invite.len(), visibility_public)?;
    state.check_policy(&caller, crate::policy::Action::CreateRoom, Some(kind))?;
    validate_power_level_override(kind, &req.power_level_content_override)?;
    let room_type: Option<&'static str> = match req.creation_content.as_ref().and_then(|c| c.get("type")) {
        None => None,
        Some(t) if t.as_str() == Some(crate::spaces::SPACE_TYPE) => Some(crate::spaces::SPACE_TYPE),
        Some(_) => return Err(MatrixError::invalid_param("only creation_content.type m.space is supported")),
    };
    if req.room_alias_name.as_deref().is_some_and(|alias| !alias.is_empty()) {
        return Err(MatrixError::invalid_param("room aliases are not supported"));
    }

    let federated = state.federation_enabled.get().is_some();
    let creation = with_conn(&state, move |conn| {
        crate::nick::require_nick(conn, caller.user_id, "choose a nick before creating a room")?;
        let creator_label = crate::nick::effective_label(conn, caller.user_id)?;
        let mut resolved = Vec::with_capacity(req.invite.len());
        for mxid in &req.invite {
            let user_id = known_user_id(conn, mxid, federated)?;
            let displayname = crate::nick::effective_label(conn, user_id)?;
            resolved.push((user_id, displayname));
        }
        let invitees: Vec<RoomInvitee<'_>> = resolved
            .iter()
            .map(|(user_id, displayname)| RoomInvitee { user_id: *user_id, displayname })
            .collect();
        let (now, origin_ts) = now_stamp();
        apply_create_room(
            conn,
            RoomCreate {
                creator_user_id: caller.user_id,
                creator_mxid: &caller.mxid,
                creator_displayname: &creator_label,
                is_direct: req.is_direct,
                invitees: &invitees,
                visibility_public,
                power_level_content_override: req.power_level_content_override,
                name: req.name.as_deref(),
                topic: req.topic.as_deref(),
                room_type,
                predecessor: None,
            },
            &now,
            origin_ts,
        )
    })
    .await?;

    let room_id = match creation {
        RoomCreation::Reused(room_id) => room_id,
        RoomCreation::Created { room_id, notify_user_ids } => {
            wake_users(&state, notify_user_ids);
            room_id
        }
    };
    Ok(Json(serde_json::json!({ "room_id": room_id })))
}

async fn join_room(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    state.check_policy(&caller, crate::policy::Action::JoinRoom, None)?;
    let room_id = if room_id.starts_with('#') { super::extras::resolve_alias(&state, &room_id).await?.0 } else { room_id };
    if state.federation_enabled.get().is_some() && super::fed_net::room_domain_is_remote(&room_id) {
        let ids = super::fed_net::federated_join(&state, &caller, &room_id).await?;
        wake_users(&state, ids);
        return Ok(Json(serde_json::json!({ "room_id": room_id })));
    }
    let room_for_db = room_id.clone();
    let decision = with_conn(&state, move |conn| {
        let displayname = crate::nick::effective_label(conn, caller.user_id)?;
        let (now, origin_ts) = now_stamp();
        decide_and_apply_join(conn, &room_for_db, caller.user_id, &caller.mxid, &displayname, &now, origin_ts)
    })
    .await?;
    if let JoinDecision::Joined(ids) = decision {
        wake_users(&state, ids);
    }
    Ok(Json(serde_json::json!({ "room_id": room_id })))
}

async fn leave_room(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let wake_ids = with_conn(&state, move |conn| {
        require_room(conn, &room_id)?;
        let (now, origin_ts) = now_stamp();
        apply_leave(conn, &room_id, caller.user_id, &caller.mxid, &now, origin_ts)
    })
    .await?;
    wake_users(&state, wake_ids);
    Ok(Json(serde_json::json!({})))
}

async fn invite_member(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Json(body): Json<crate::rooms::UserIdBody>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    state.check_policy(&caller, crate::policy::Action::Invite, None)?;
    let federated = state.federation_enabled.get().is_some();
    let wake_ids = with_conn(&state, move |conn| {
        crate::nick::require_nick(conn, caller.user_id, "choose a nick before inviting")?;
        require_room(conn, &room_id)?;
        let target_user_id = known_user_id(conn, &body.user_id, federated)?;
        if target_user_id == caller.user_id {
            return Err(MatrixError::invalid_param("cannot invite yourself"));
        }
        let displayname = crate::nick::effective_label(conn, target_user_id)?;
        let (now, origin_ts) = now_stamp();
        let target = InviteTarget { user_id: target_user_id, displayname: &displayname };
        apply_invite(conn, &room_id, caller.user_id, &caller.mxid, target, &now, origin_ts)
    })
    .await?;
    wake_users(&state, wake_ids);
    Ok(Json(serde_json::json!({})))
}

struct MembershipChange {
    room_id: String,
    target_mxid: String,
    reason: Option<String>,
    action: PowerAction,
    target_rule: TargetStateRule,
    new_membership: Membership,
}

async fn membership_change(
    state: Arc<Homeserver>,
    caller: Caller,
    change: MembershipChange,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let federated = state.federation_enabled.get().is_some();
    let wake_ids = with_conn(&state, move |conn| {
        require_room(conn, &change.room_id)?;
        let target_user_id = known_user_id(conn, &change.target_mxid, federated)?;
        let (now, origin_ts) = now_stamp();
        apply_membership_power_action(
            conn,
            caller.user_id,
            &caller.mxid,
            MembershipPowerAction {
                room_id: &change.room_id,
                action: change.action,
                target_user_id,
                target_rule: change.target_rule,
                new_membership: change.new_membership,
                reason: change.reason.as_deref(),
            },
            &now,
            origin_ts,
        )
    })
    .await?;
    wake_users(&state, wake_ids);
    Ok(Json(serde_json::json!({})))
}

async fn kick_member(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Json(body): Json<crate::rooms::KickBanBody>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    membership_change(
        state,
        caller,
        MembershipChange {
            room_id,
            target_mxid: body.user_id,
            reason: body.reason,
            action: PowerAction::Kick,
            target_rule: TargetStateRule::MustBeActiveMember,
            new_membership: Membership::Leave,
        },
    )
    .await
}

async fn ban_member(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Json(body): Json<crate::rooms::KickBanBody>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    membership_change(
        state,
        caller,
        MembershipChange {
            room_id,
            target_mxid: body.user_id,
            reason: body.reason,
            action: PowerAction::Ban,
            target_rule: TargetStateRule::Any,
            new_membership: Membership::Ban,
        },
    )
    .await
}

async fn unban_member(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Json(body): Json<crate::rooms::UserIdBody>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    membership_change(
        state,
        caller,
        MembershipChange {
            room_id,
            target_mxid: body.user_id,
            reason: None,
            action: PowerAction::Ban,
            target_rule: TargetStateRule::MustBeBanned,
            new_membership: Membership::Leave,
        },
    )
    .await
}

async fn forget_room(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    with_conn(&state, move |conn| apply_forget(conn, &room_id, caller.user_id)).await?;
    Ok(Json(serde_json::json!({})))
}

async fn joined_rooms(State(state): State<Arc<Homeserver>>, headers: HeaderMap) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let rooms = with_conn(&state, move |conn| {
        Ok(crate::store::rooms_for_user(conn, caller.user_id, Some(Membership::Join))?)
    })
    .await?;
    Ok(Json(serde_json::json!({ "joined_rooms": rooms })))
}

async fn get_state_all(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
) -> Result<Json<Vec<serde_json::Value>>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let events = with_conn(&state, move |conn| {
        let room = require_room(conn, &room_id)?;
        require_pub_read(conn, &room, caller.user_id)?;
        let stored = crate::store::current_state_all(conn, &room_id)?;
        let mut out = Vec::with_capacity(stored.len());
        for event in &stored {
            out.push(crate::events::client_event_json(conn, event, None)?);
        }
        Ok(out)
    })
    .await?;
    Ok(Json(events))
}

async fn get_state_inner(
    state: Arc<Homeserver>,
    headers: HeaderMap,
    room_id: String,
    event_type: String,
    state_key: String,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let content = with_conn(&state, move |conn| {
        let room = require_room(conn, &room_id)?;
        require_pub_read(conn, &room, caller.user_id)?;
        let event = crate::store::current_state_event(conn, &room_id, &event_type, &state_key)?
            .ok_or_else(|| MatrixError::not_found("no such state event"))?;
        Ok(serde_json::from_str(&event.content)?)
    })
    .await?;
    Ok(Json(content))
}

async fn get_state(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((room_id, event_type, state_key)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    get_state_inner(state, headers, room_id, event_type, state_key).await
}

async fn get_state_no_key(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((room_id, event_type)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    get_state_inner(state, headers, room_id, event_type, String::new()).await
}

async fn put_state_inner(
    state: Arc<Homeserver>,
    headers: HeaderMap,
    room_id: String,
    event_type: String,
    state_key: String,
    content: serde_json::Value,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let content_str = content.to_string();
    if content_str.len() > crate::store::MATRIX_EVENT_CONTENT_MAX_BYTES {
        return Err(MatrixError::invalid_param("event content too large"));
    }
    let (event_id, wake_ids) = with_conn(&state, move |conn| {
        let content_str = if event_type == "m.room.member" {
            content_with_own_displayname(conn, caller.user_id, &caller.mxid, &state_key, &content_str)?
        } else {
            content_str
        };
        let (now, origin_ts) = now_stamp();
        apply_put_state(
            conn,
            &room_id,
            caller.user_id,
            &caller.mxid,
            &event_type,
            &state_key,
            &content_str,
            &now,
            origin_ts,
        )
    })
    .await?;
    wake_users(&state, wake_ids);
    Ok(Json(serde_json::json!({ "event_id": event_id })))
}

async fn put_state(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((room_id, event_type, state_key)): Path<(String, String, String)>,
    Json(content): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    put_state_inner(state, headers, room_id, event_type, state_key, content).await
}

async fn put_state_no_key(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((room_id, event_type)): Path<(String, String)>,
    Json(content): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    put_state_inner(state, headers, room_id, event_type, String::new(), content).await
}

async fn get_members(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Query(query): Query<crate::rooms::MembersQuery>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let membership_filter = match query.membership.as_deref() {
        Some(raw) => Some(Membership::from_wire_name(raw).ok_or_else(|| MatrixError::invalid_param("unknown membership filter"))?),
        None => None,
    };
    let at = match query.at.as_deref() {
        Some(raw) => Some(match raw.parse::<i64>() {
            Ok(n) => n,
            Err(_) => crate::sync_token::parse(raw)?.stream_id,
        }),
        None => None,
    };
    let events = with_conn(&state, move |conn| {
        let room = require_room(conn, &room_id)?;
        require_pub_read(conn, &room, caller.user_id)?;
        let member_events = match at {
            Some(at_stream_id) => crate::store::state_events_of_type_at(conn, &room_id, "m.room.member", at_stream_id)?,
            None => crate::store::current_state_all(conn, &room_id)?
                .into_iter()
                .filter(|event| event.event_type == "m.room.member")
                .collect(),
        };
        let mut out = Vec::new();
        for event in member_events {
            if let Some(wanted) = membership_filter {
                let content: serde_json::Value = serde_json::from_str(&event.content)?;
                let membership = content.get("membership").and_then(|value| value.as_str()).and_then(Membership::from_wire_name);
                if membership != Some(wanted) {
                    continue;
                }
            }
            out.push(crate::events::client_event_json(conn, &event, None)?);
        }
        Ok(out)
    })
    .await?;
    Ok(Json(serde_json::json!({ "chunk": events })))
}

async fn get_joined_members(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let joined = with_conn(&state, move |conn| {
        let room = require_room(conn, &room_id)?;
        require_pub_read(conn, &room, caller.user_id)?;
        let members = crate::store::room_members(conn, &room_id, Some(Membership::Join))?;
        let mut joined = serde_json::Map::new();
        for member in members {
            let mxid = crate::store::mxid_of(conn, member.user_id)?.ok_or_else(MatrixError::internal)?;
            let label = crate::nick::effective_label(conn, member.user_id)?;
            joined.insert(mxid, serde_json::json!({ "display_name": label }));
        }
        Ok(joined)
    })
    .await?;
    Ok(Json(serde_json::json!({ "joined": joined })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
    use tower::ServiceExt;

    const NOW: &str = "2026-10-05T00:00:00+00:00";
    const PUBLIC_ID: &str = "alice000000000000000000000000a1";
    const RAW_TOKEN: &str = "alice-bearer-token";

    fn homeserver_with_bearer() -> Arc<Homeserver> {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        crate::store::create_matrix_schema(&conn).expect("matrix schema");
        crate::keys::create_matrix_keys_schema(&conn).expect("keys schema");
        crate::store::ensure_matrix_user(&conn, 1, PUBLIC_ID, NOW).expect("user");
        let hash = crate::http::hash_token(RAW_TOKEN);
        crate::keys::create_device(&conn, 1, crate::keys::CredentialKind::Bearer, &hash, NOW).expect("device");
        Arc::new(Homeserver::new(conn))
    }

    fn create_room_request(token: Option<&str>) -> Request<Body> {
        let mut builder = Request::post("/client/v3/createRoom").header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        builder.body(Body::from("{}")).expect("request")
    }

    #[tokio::test]
    async fn create_room_without_a_token_is_missing_token() {
        let state = homeserver_with_bearer();
        let response = crate::http::router(state)
            .oneshot(create_room_request(None))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(response.into_body(), usize::MAX).await.expect("body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(value["errcode"], "M_MISSING_TOKEN");
    }

    #[tokio::test]
    async fn create_room_requires_a_nick_then_returns_a_room_id() {
        let state = homeserver_with_bearer();
        let response = crate::http::router(Arc::clone(&state))
            .oneshot(create_room_request(Some(RAW_TOKEN)))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.expect("body");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("choose a nick"), "{text}");

        state.conn_async(|conn| crate::nick::set_nick(conn, 1, "alice_nick").expect("nick")).await;

        let response = crate::http::router(state)
            .oneshot(create_room_request(Some(RAW_TOKEN)))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.expect("body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let room_id = value["room_id"].as_str().expect("room_id");
        assert!(!room_id.is_empty());
    }
}
