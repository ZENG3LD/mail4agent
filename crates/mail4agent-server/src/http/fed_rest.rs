//! Server-server endpoints beyond the room-join core: single events, leaving (and refusing an
//! invite), the space hierarchy, timestamp lookup, and the ones this server does not offer
//! (knocking, third-party invites, identity-server callbacks, custom queries), which answer with
//! the spec's errors instead of a missing route.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{OriginalUri, Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde_json::{json, Value};

use super::federation::{after_ingest, authenticate, parse_body, require_enabled};
use super::{with_conn_pub, Homeserver};
use crate::error::MatrixError;
use crate::fed_rooms as fr;
use crate::federation as fed;

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new()
        .route("/federation/v1/event/{event_id}", get(event))
        .route("/federation/v1/make_leave/{room_id}/{user_id}", get(make_leave))
        .route("/federation/v2/send_leave/{room_id}/{event_id}", put(send_leave))
        .route("/federation/v1/hierarchy/{room_id}", get(hierarchy))
        .route("/federation/v1/timestamp_to_event/{room_id}", get(timestamp_to_event))
        .route("/federation/v1/make_knock/{room_id}/{user_id}", get(refuse_knock))
        .route("/federation/v1/send_knock/{room_id}/{event_id}", put(refuse_knock))
        .route("/federation/v1/exchange_third_party_invite/{room_id}", put(refuse_third_party))
        .route("/federation/v1/3pid/onbind", put(refuse_third_party))
        .route("/federation/v1/query/{query_type}", get(custom_query))
        .route("/federation/v1/members/{room_id}", post(no_members))
}

async fn refuse_knock(State(state): State<Arc<Homeserver>>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    Err(MatrixError::forbidden("no room on this server allows knocking"))
}

async fn refuse_third_party(State(state): State<Arc<Homeserver>>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    Err(MatrixError::forbidden("this server does not use third-party invites"))
}

async fn no_members(State(state): State<Arc<Homeserver>>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    Err(MatrixError::unrecognized())
}

/// `query/{queryType}`: `profile` and `directory` have their own routes; anything else is unknown.
async fn custom_query(State(state): State<Arc<Homeserver>>, Path(_t): Path<String>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    Err(MatrixError::unrecognized())
}

/// `GET event/{eventId}`: one event of a room this server is in, wrapped in a transaction.
async fn event(State(state): State<Arc<Homeserver>>, OriginalUri(uri): OriginalUri, headers: HeaderMap, Path(event_id): Path<String>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let origin = authenticate(&state, "GET", &uri, &headers, &[]).await?;
    let local = crate::store::matrix_server_name().to_string();
    with_conn_pub(&state, move |c| {
        let room = event_room(c, &event_id).ok_or_else(|| MatrixError::not_found("unknown event"))?;
        if !server_in_room(c, &room, &origin) {
            return Err(MatrixError::forbidden("your server is not in that room"));
        }
        let pdu = event_pdu(c, &event_id, &local)?;
        Ok(Json(json!({ "origin": local, "origin_server_ts": fed::now_ms(), "pdus": [pdu] })))
    })
    .await
}

fn event_room(c: &rusqlite::Connection, event_id: &str) -> Option<String> {
    #[cfg(feature = "f3-hash-ids")]
    if let Some(r) = crate::f3::room_of_event(c, event_id) {
        return Some(r);
    }
    crate::store::get_event(c, event_id).ok().flatten().map(|e| e.room_id)
}

fn event_pdu(c: &rusqlite::Connection, event_id: &str, local: &str) -> Result<Value, MatrixError> {
    #[cfg(feature = "f3-hash-ids")]
    if let Some(p) = crate::f3::pdu_json(c, event_id) {
        return Ok(p);
    }
    let ev = crate::store::get_event(c, event_id)?.ok_or_else(|| MatrixError::not_found("unknown event"))?;
    fr::pdu_for_event(c, &ev, local, fed::now_ms()).map_err(|_| MatrixError::internal())
}

/// Does a user of `server` have any membership row in the room (so the server may read it)?
fn server_in_room(c: &rusqlite::Connection, room: &str, server: &str) -> bool {
    fr::remote_domains(c, room).map(|d| d.contains(server)).unwrap_or(false)
        || crate::store::get_room(c, room).ok().flatten().is_some_and(|r| r.join_rule == crate::store::JoinRule::Public)
}

async fn make_leave(State(state): State<Arc<Homeserver>>, OriginalUri(uri): OriginalUri, headers: HeaderMap, Path((room_id, user_id)): Path<(String, String)>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let origin = authenticate(&state, "GET", &uri, &headers, &[]).await?;
    if fr::domain_of(&user_id) != Some(origin.as_str()) {
        return Err(MatrixError::forbidden("user does not belong to the requesting server"));
    }
    with_conn_pub(&state, move |c| {
        let room = crate::store::get_room(c, &room_id)?.ok_or_else(|| MatrixError::not_found("unknown room"))?;
        let member = match crate::store::user_id_of(c, &user_id)? {
            Some(u) => crate::store::room_member(c, &room_id, u)?.map(|m| m.membership),
            None => None,
        };
        if !matches!(member, Some(crate::store::Membership::Join | crate::store::Membership::Invite)) {
            return Err(MatrixError::forbidden("that user is neither in nor invited to the room"));
        }
        #[cfg(feature = "f3-hash-ids")]
        if crate::f3::is_f3_room(c, &room_id) {
            let event = crate::f3::leave_template(c, &room_id, &user_id, fed::now_ms())?;
            return Ok(Json(json!({ "room_version": room.room_version, "event": event, "m4a_f3": true })));
        }
        Ok(Json(json!({ "room_version": room.room_version, "event": {
            "type": "m.room.member", "state_key": user_id, "sender": user_id, "room_id": room_id,
            "origin_server_ts": fed::now_ms(), "content": { "membership": "leave" } } })))
    })
    .await
}

async fn send_leave(State(state): State<Arc<Homeserver>>, OriginalUri(uri): OriginalUri, headers: HeaderMap, Path((room_id, event_id)): Path<(String, String)>, body: Bytes) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let origin = authenticate(&state, "PUT", &uri, &headers, &body).await?;
    let pdu = parse_body(&body)?;
    let sender = pdu.get("sender").and_then(Value::as_str).unwrap_or_default().to_string();
    let leaves = pdu.get("type").and_then(Value::as_str) == Some("m.room.member")
        && pdu.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("leave")
        && pdu.get("state_key").and_then(Value::as_str) == Some(sender.as_str());
    if !leaves || fr::domain_of(&sender) != Some(origin.as_str()) || pdu.get("room_id").and_then(Value::as_str) != Some(room_id.as_str()) {
        return Err(MatrixError::bad_json("not a valid leave event for this request"));
    }
    #[cfg(feature = "f3-hash-ids")]
    if crate::f3::is_f3_wire(&pdu) {
        if crate::f3::wire_id(&pdu)? != event_id {
            return Err(MatrixError::bad_json("event id does not match"));
        }
        let got = super::fed_net::f3_receive_live(&state, &origin, &pdu).await?;
        after_ingest(&state, got.wake);
        return Ok(Json(json!({})));
    }
    if pdu.get("event_id").and_then(Value::as_str) != Some(event_id.as_str()) {
        return Err(MatrixError::bad_json("event id does not match"));
    }
    let content_ok = super::fed_net::verify_pdu(&state, &pdu).await?;
    let p = pdu.clone();
    let wake = with_conn_pub(&state, move |c| {
        let ing = fr::ingest_pdu(c, &p, content_ok, fr::Mode::Live, &chrono::Utc::now().to_rfc3339())?;
        Ok(ing.wake)
    })
    .await?;
    after_ingest(&state, wake);
    Ok(Json(json!({})))
}

#[derive(serde::Deserialize)]
struct HierQuery {
    #[serde(default)]
    suggested_only: bool,
}

/// `GET hierarchy/{roomId}`: this server's part of a space tree, as a remote server sees it
/// (only rooms anyone may join). The room itself, then its children found here.
async fn hierarchy(State(state): State<Arc<Homeserver>>, OriginalUri(uri): OriginalUri, headers: HeaderMap, Path(room_id): Path<String>, Query(q): Query<HierQuery>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    authenticate(&state, "GET", &uri, &headers, &[]).await?;
    with_conn_pub(&state, move |c| {
        let v = crate::spaces::hierarchy(c, 0, &room_id, q.suggested_only, 200, Some(1), 0)?.ok_or_else(|| MatrixError::not_found("room not found or not visible"))?;
        let mut rooms = v.get("rooms").and_then(Value::as_array).cloned().unwrap_or_default();
        if rooms.is_empty() {
            return Err(MatrixError::not_found("room not found or not visible"));
        }
        let root = rooms.remove(0);
        Ok(Json(json!({ "room": root, "children": rooms, "inaccessible_children": [] })))
    })
    .await
}

async fn timestamp_to_event(State(state): State<Arc<Homeserver>>, OriginalUri(uri): OriginalUri, headers: HeaderMap, Path(room_id): Path<String>, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let origin = authenticate(&state, "GET", &uri, &headers, &[]).await?;
    let ts = q.get("ts").and_then(|t| t.parse::<i64>().ok()).ok_or_else(|| MatrixError::invalid_param("ts"))?;
    let forward = match q.get("dir").map(String::as_str) {
        Some("f") => true,
        Some("b") => false,
        _ => return Err(MatrixError::invalid_param("dir must be f or b")),
    };
    with_conn_pub(&state, move |c| {
        crate::store::get_room(c, &room_id)?.ok_or_else(|| MatrixError::not_found("unknown room"))?;
        if !server_in_room(c, &room_id, &origin) {
            return Err(MatrixError::forbidden("your server is not in that room"));
        }
        let (event_id, origin_server_ts) = super::spec_rest::nearest_event(c, &room_id, ts, forward).ok_or_else(|| MatrixError::not_found("no event near that time"))?;
        Ok(Json(json!({ "event_id": event_id, "origin_server_ts": origin_server_ts })))
    })
    .await
}
