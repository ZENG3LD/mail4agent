//! Federation F0 routes: this server's signing keys, a version probe, one
//! signed-request-protected query (profile existence), and the `X-Matrix`
//! authentication helper later federation routes call. Everything is off
//! (`M_UNRECOGNIZED`) unless federation is enabled in config.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{OriginalUri, Path, Query, State};
use axum::http::{header, HeaderMap, Uri};
use axum::body::Bytes;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde_json::{json, Value};

use super::{with_conn_pub, Homeserver};
use crate::error::MatrixError;
use crate::fed_rooms as fr;
use crate::federation as fed;

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new()
        .route("/key/v2/server", get(own_keys))
        .route("/key/v2/server/{key_id}", get(own_keys_by_id))
        .route("/federation/v1/version", get(version))
        .merge(super::fed_rest::routes())
        .route("/federation/v1/media/download/{media_id}", get(fed_media_download))
        .route("/federation/v1/media/thumbnail/{media_id}", get(fed_media_thumbnail))
        .route("/federation/v1/query/profile", get(profile))
        .route("/federation/v1/send/{txn_id}", put(send_txn))
        .route("/federation/v1/make_join/{room_id}/{user_id}", get(make_join))
        .route("/federation/v2/send_join/{room_id}/{event_id}", put(send_join))
        .route("/federation/v2/invite/{room_id}/{event_id}", put(invite))
        .route("/federation/v1/backfill/{room_id}", get(backfill))
        .route("/federation/v1/get_missing_events/{room_id}", post(get_missing_events))
        .route("/federation/v1/query/directory", get(query_directory))
        .route("/federation/v1/event_auth/{room_id}/{event_id}", get(event_auth))
        .route("/federation/v1/state_ids/{room_id}", get(state_ids))
        .route("/federation/v1/state/{room_id}", get(state_events))
        .route("/federation/v1/publicRooms", get(fed_public_rooms).post(fed_public_rooms_post))
        .route("/key/v2/query/{server_name}", get(notary_get))
        .route("/key/v2/query/{server_name}/{key_id}", get(notary_get_key))
        .route("/key/v2/query", post(notary_post))
        .route("/federation/v1/openid/userinfo", get(openid_userinfo))
        .route("/federation/v1/user/keys/query", post(keys_query))
        .route("/federation/v1/user/keys/claim", post(keys_claim))
        .route("/federation/v1/user/devices/{user_id}", get(user_devices))
}

pub(super) fn require_enabled(state: &Homeserver) -> Result<(), MatrixError> {
    state.federation_enabled.get().map(|_| ()).ok_or_else(MatrixError::unrecognized)
}

async fn own_keys(State(state): State<Arc<Homeserver>>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let server = crate::store::matrix_server_name().to_string();
    let doc = with_conn_pub(&state, move |c| fed::server_keys_response(c, &server, fed::now_ms()).map_err(|_| MatrixError::internal())).await?;
    Ok(Json(doc))
}

async fn own_keys_by_id(State(state): State<Arc<Homeserver>>, Path(_key_id): Path<String>) -> Result<Json<Value>, MatrixError> {
    // The full document is returned whatever id is asked for (spec-permitted).
    own_keys(State(state)).await
}

async fn version(State(state): State<Arc<Homeserver>>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    Ok(Json(json!({ "server": { "name": "mail4agent", "version": env!("CARGO_PKG_VERSION") } })))
}

async fn profile(
    State(state): State<Arc<Homeserver>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    authenticate(&state, "GET", &uri, &headers, &[]).await?;
    let user_id = q.get("user_id").cloned().ok_or_else(|| MatrixError::invalid_param("user_id required"))?;
    let user_id2 = user_id.clone();
    let known = with_conn_pub(&state, move |c| {
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM matrix_users WHERE mxid = ?1", [&user_id], |r| r.get(0))
            .map_err(|_| MatrixError::internal())?;
        Ok(n > 0)
    })
    .await?;
    if known {
        let m = user_id2.clone();
        let p = with_conn_pub(&state, move |c| super::extras::local_profile(c, &m)).await?;
        Ok(Json(p.unwrap_or_else(|| json!({}))))
    } else {
        Err(MatrixError::not_found("user not found"))
    }
}

fn internal<E>(_: E) -> MatrixError {
    MatrixError::internal()
}

fn rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub(super) fn parse_body(body: &Bytes) -> Result<Value, MatrixError> {
    serde_json::from_slice(body).map_err(|_| MatrixError::bad_json("body is not JSON"))
}

/// Wake local users and poke the outbox (events ingested may need relaying).
pub(super) fn after_ingest(state: &Arc<Homeserver>, wake: impl IntoIterator<Item = i64>) {
    super::wake_users(state, wake.into_iter().filter(|id| *id > 0));
    state.fed_notify.notify_one();
}

async fn send_txn(
    State(state): State<Arc<Homeserver>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(_txn): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let origin = authenticate(&state, "PUT", &uri, &headers, &body).await?;
    let v = parse_body(&body)?;
    if v.get("origin").and_then(Value::as_str) != Some(origin.as_str()) {
        return Err(MatrixError::forbidden("origin in body does not match the signing server"));
    }
    let pdus = v.get("pdus").and_then(Value::as_array).cloned().unwrap_or_default();
    let edus = v.get("edus").and_then(Value::as_array).cloned().unwrap_or_default();
    if pdus.len() > 50 || edus.len() > 100 {
        return Err(MatrixError::invalid_param("too many pdus or edus"));
    }
    let mut results = serde_json::Map::new();
    let mut wake_all: Vec<i64> = Vec::new();
    for pdu in pdus {
        #[cfg(feature = "f3-hash-ids")]
        if crate::f3::is_f3_wire(&pdu) {
            let id = crate::f3::wire_id(&pdu).unwrap_or_else(|_| "?".to_string());
            let res = super::fed_net::f3_receive_live(&state, &origin, &pdu).await;
            match res {
                Ok(r) => {
                    wake_all.extend(r.wake);
                    results.insert(id, json!({}));
                }
                Err(e) => {
                    results.insert(id, json!({ "error": e.error }));
                }
            }
            continue;
        }
        let id = pdu.get("event_id").and_then(Value::as_str).unwrap_or("?").to_string();
        let outcome = match super::fed_net::verify_pdu(&state, &pdu).await {
            Ok(content_ok) => {
                let p = pdu.clone();
                with_conn_pub(&state, move |c| fr::ingest_pdu(c, &p, content_ok, fr::Mode::Live, &rfc3339())).await
            }
            Err(e) => Err(e),
        };
        match outcome {
            Ok(i) => {
                wake_all.extend(i.wake);
                results.insert(id, json!({}));
            }
            Err(e) => {
                results.insert(id, json!({ "error": e.error }));
            }
        }
    }
    for edu in edus {
        if matches!(edu.get("edu_type").and_then(Value::as_str), Some("m.typing" | "m.receipt" | "m.device_list_update" | "m.presence")) {
            let (o, e, st) = (origin.clone(), edu.clone(), Arc::clone(&state));
            if let Ok(ids) = with_conn_pub(&state, move |c| Ok(crate::fed_edus::apply_inbound(c, &st.typing, &o, &e))).await {
                wake_all.extend(ids);
            }
            continue;
        }
        if edu.get("edu_type").and_then(Value::as_str) == Some("m.direct_to_device") {
            let content = edu.get("content").cloned().unwrap_or(Value::Null);
            let origin2 = origin.clone();
            if let Ok(ids) = with_conn_pub(&state, move |c| apply_direct_to_device(c, &origin2, &content)).await {
                wake_all.extend(ids);
            }
        }
    }
    after_ingest(&state, wake_all);
    Ok(Json(json!({ "pdus": results })))
}

fn apply_direct_to_device(conn: &mut rusqlite::Connection, origin: &str, content: &Value) -> Result<Vec<i64>, MatrixError> {
    let sender = content.get("sender").and_then(Value::as_str).unwrap_or_default();
    if fr::domain_of(sender) != Some(origin) {
        return Err(MatrixError::forbidden("to-device sender is not on the origin server"));
    }
    let sender_uid = fr::ensure_remote_user(conn, sender, &rfc3339()).map_err(|_| MatrixError::bad_json("sender"))?;
    let ty = content.get("type").and_then(Value::as_str).unwrap_or_default().to_string();
    let message_id = content.get("message_id").and_then(Value::as_str).unwrap_or_default().to_string();
    let messages: std::collections::BTreeMap<String, std::collections::BTreeMap<String, Value>> =
        serde_json::from_value(content.get("messages").cloned().unwrap_or(Value::Null)).map_err(|_| MatrixError::bad_json("messages"))?;
    if ty.is_empty() || message_id.is_empty() {
        return Err(MatrixError::bad_json("type/message_id"));
    }
    match crate::key_ops::apply_send_to_device(conn, sender_uid, &format!("fed:{origin}"), &ty, &message_id, &messages, &rfc3339())? {
        crate::key_ops::SendToDeviceOutcome::New(ids) => Ok(ids.into_iter().collect()),
        crate::key_ops::SendToDeviceOutcome::AlreadySent => Ok(Vec::new()),
    }
}

async fn make_join(
    State(state): State<Arc<Homeserver>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path((room_id, user_id)): Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let origin = authenticate(&state, "GET", &uri, &headers, &[]).await?;
    if fr::domain_of(&user_id) != Some(origin.as_str()) {
        return Err(MatrixError::forbidden("user does not belong to the requesting server"));
    }
    with_conn_pub(&state, move |c| {
        let room = crate::store::get_room(c, &room_id)?.ok_or_else(|| MatrixError::not_found("unknown room"))?;
        let current = match crate::store::user_id_of(c, &user_id)? {
            Some(u) => crate::store::room_member(c, &room_id, u)?.map(|m| m.membership),
            None => None,
        };
        match current {
            Some(crate::store::Membership::Ban) => return Err(MatrixError::forbidden("banned")),
            Some(crate::store::Membership::Invite) | Some(crate::store::Membership::Join) => {}
            _ if room.join_rule == crate::store::JoinRule::Public => {}
            #[cfg(feature = "f3-hash-ids")]
            _ if crate::f3::is_f3_room(c, &room_id) && crate::f3::state_join_rule_is_public(c, &room_id) => {}
            _ => return Err(MatrixError::forbidden("room is not open to this user")),
        }
        #[cfg(feature = "f3-hash-ids")]
        if crate::f3::is_f3_room(c, &room_id) {
            let event = crate::f3::join_template(c, &room_id, &user_id, fed::now_ms())?;
            return Ok(Json(json!({ "room_version": room.room_version, "event": event, "m4a_f3": true })));
        }
        Ok(Json(json!({
            "room_version": room.room_version,
            "event": {
                "type": "m.room.member", "state_key": user_id, "sender": user_id, "room_id": room_id,
                "origin_server_ts": fed::now_ms(), "content": { "membership": "join" }
            }
        })))
    })
    .await
}

async fn send_join(
    State(state): State<Arc<Homeserver>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path((room_id, event_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let origin = authenticate(&state, "PUT", &uri, &headers, &body).await?;
    let pdu = parse_body(&body)?;
    #[cfg(feature = "f3-hash-ids")]
    if crate::f3::is_f3_wire(&pdu) {
        return send_join_f3(&state, &origin, &room_id, &event_id, pdu).await;
    }
    let sender = pdu.get("sender").and_then(Value::as_str).unwrap_or_default().to_string();
    let is_join = pdu.get("type").and_then(Value::as_str) == Some("m.room.member")
        && pdu.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("join")
        && pdu.get("state_key").and_then(Value::as_str) == Some(sender.as_str());
    if !is_join
        || fr::domain_of(&sender) != Some(origin.as_str())
        || pdu.get("event_id").and_then(Value::as_str) != Some(event_id.as_str())
        || pdu.get("room_id").and_then(Value::as_str) != Some(room_id.as_str())
    {
        return Err(MatrixError::bad_json("not a valid join event for this request"));
    }
    let content_ok = super::fed_net::verify_pdu(&state, &pdu).await?;
    let local = crate::store::matrix_server_name().to_string();
    let (p, origin2) = (pdu.clone(), origin.clone());
    let resp = with_conn_pub(&state, move |c| {
        let ing = fr::ingest_pdu(c, &p, content_ok, fr::Mode::Live, &rfc3339())?;
        let now = fed::now_ms();
        if !ing.duplicate {
            fr::relay_pdu(c, &room_id, &p, &[origin2.as_str()], now).map_err(internal)?;
        }
        let mut state_pdus = Vec::new();
        for ev in crate::store::current_state_all(c, &room_id)? {
            if let Ok(x) = fr::pdu_for_event(c, &ev, &local, now) {
                state_pdus.push(x);
            }
        }
        let mut timeline = Vec::new();
        for ev in crate::store::events_in_room_before(c, &room_id, i64::MAX, 50)? {
            if ev.state_key.is_none() {
                if let Ok(x) = fr::pdu_for_event(c, &ev, &local, now) {
                    timeline.push(x);
                }
            }
        }
        timeline.reverse();
        let info = fr::room_info(c, &room_id).map_err(internal)?;
        Ok((ing.wake, json!({ "origin": local, "state": state_pdus, "auth_chain": [], "members_omitted": false, "m4a_room": info, "m4a_timeline": timeline })))
    })
    .await?;
    after_ingest(&state, resp.0);
    Ok(Json(resp.1))
}

/// A peer's signed join of a DAG room: checked and accepted like any event (so a join that raced
/// another event forks the DAG and is merged by state resolution), answered with the room as it
/// stood right after the join.
#[cfg(feature = "f3-hash-ids")]
async fn send_join_f3(state: &Arc<Homeserver>, origin: &str, room_id: &str, event_id: &str, pdu: Value) -> Result<Json<Value>, MatrixError> {
    let sender = pdu.get("sender").and_then(Value::as_str).unwrap_or_default().to_string();
    let is_join = pdu.get("type").and_then(Value::as_str) == Some("m.room.member")
        && pdu.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("join")
        && pdu.get("state_key").and_then(Value::as_str) == Some(sender.as_str());
    if !is_join || pdu.get("room_id").and_then(Value::as_str) != Some(room_id) || crate::f3::wire_id(&pdu)? != event_id {
        return Err(MatrixError::bad_json("not a valid join event for this request"));
    }
    let got = super::fed_net::f3_receive_live(state, origin, &pdu).await?;
    let room = room_id.to_string();
    let eid = event_id.to_string();
    let local = crate::store::matrix_server_name().to_string();
    let (snap, info) = with_conn_pub(state, move |c| {
        let snap = crate::f3::snapshot_json(c, &room, &eid)?;
        let info = fr::room_info(c, &room).map_err(internal)?;
        Ok((snap, info))
    })
    .await?;
    let wake = got.wake;
    after_ingest(state, wake);
    let chain = snap.get("auth_chain").cloned().unwrap_or_else(|| json!([]));
    Ok(Json(json!({ "origin": local, "state": snap["state"], "auth_chain": chain, "m4a_room": info, "m4a_f3": snap })))
}

async fn invite(
    State(state): State<Arc<Homeserver>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path((room_id, event_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let origin = authenticate(&state, "PUT", &uri, &headers, &body).await?;
    let v = parse_body(&body)?;
    let event = v.get("event").cloned().ok_or_else(|| MatrixError::bad_json("event"))?;
    #[cfg(feature = "f3-hash-ids")]
    if v.get("room_info").is_none() && v.get("room_version").and_then(Value::as_str) == Some("11") && event.get("event_id").is_none() {
        // A spec server's invite: signed event plus stripped state, no snapshot.
        let invitee = event.get("state_key").and_then(Value::as_str).unwrap_or_default().to_string();
        let ok = event.get("type").and_then(Value::as_str) == Some("m.room.member")
            && event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("invite")
            && fr::domain_of(event.get("sender").and_then(Value::as_str).unwrap_or_default()) == Some(origin.as_str())
            && event.get("room_id").and_then(Value::as_str) == Some(room_id.as_str())
            && !fr::is_remote_mxid(&invitee)
            && crate::f3::wire_id(&event)? == event_id;
        if !ok {
            return Err(MatrixError::bad_json("not a valid invite for this request"));
        }
        let stripped = v.get("invite_room_state").and_then(Value::as_array).cloned().unwrap_or_default();
        let keys = super::fed_net::f3_keys(&state, std::slice::from_ref(&event)).await?;
        let (room, ev) = (room_id.clone(), event.clone());
        let (signed, wake) = with_conn_pub(&state, move |c| {
            if crate::store::user_id_of(c, &invitee)?.is_none() {
                return Err(MatrixError::not_found("unknown local user"));
            }
            let (_, signed) = crate::f3::sign_own(c, &ev, fed::now_ms())?;
            let mut keys = keys;
            let refs = [&signed];
            for (server, key_id) in crate::f3::missing_keys(c, &refs, &mut keys) {
                let _ = (server, key_id);
            }
            crate::f3::import_spec_invite(c, &room, &signed, &stripped, &keys, &rfc3339())?;
            Ok((signed, crate::rooms::member_and_invited_ids(c, &room).map_err(internal)?))
        })
        .await?;
        after_ingest(&state, wake);
        return Ok(Json(json!({ "event": signed })));
    }
    let info = v.get("room_info").cloned().ok_or_else(|| MatrixError::bad_json("room_info"))?;
    let state_pdus = v.get("invite_room_state").and_then(Value::as_array).cloned().unwrap_or_default();
    let sender = event.get("sender").and_then(Value::as_str).unwrap_or_default();
    let invitee = event.get("state_key").and_then(Value::as_str).unwrap_or_default().to_string();
    #[cfg(feature = "f3-hash-ids")]
    if let Some(snap) = v.get("f3").cloned() {
        let is_invite = event.get("type").and_then(Value::as_str) == Some("m.room.member")
            && event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("invite")
            && fr::domain_of(sender) == Some(origin.as_str())
            && event.get("room_id").and_then(Value::as_str) == Some(room_id.as_str())
            && !fr::is_remote_mxid(&invitee)
            && crate::f3::wire_id(&event)? == event_id;
        if !is_invite {
            return Err(MatrixError::bad_json("not a valid invite for this request"));
        }
        let all = crate::f3::snapshot_events(&snap);
        if !all.iter().any(|p| p == &event) {
            return Err(MatrixError::bad_json("the snapshot does not contain the invite"));
        }
        let keys = super::fed_net::f3_keys(&state, &all).await?;
        let room = room_id.clone();
        let wake = with_conn_pub(&state, move |c| {
            crate::f3::import_snapshot(c, &room, &info, &snap, &keys, &rfc3339())?;
            Ok(crate::rooms::member_and_invited_ids(c, &room).map_err(internal)?)
        })
        .await?;
        after_ingest(&state, wake);
        return Ok(Json(json!({ "event": event })));
    }
    let is_invite = event.get("type").and_then(Value::as_str) == Some("m.room.member")
        && event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("invite");
    if !is_invite
        || fr::domain_of(sender) != Some(origin.as_str())
        || event.get("event_id").and_then(Value::as_str) != Some(event_id.as_str())
        || event.get("room_id").and_then(Value::as_str) != Some(room_id.as_str())
        || fr::is_remote_mxid(&invitee)
    {
        return Err(MatrixError::bad_json("not a valid invite for this request"));
    }
    let mut checked: Vec<(Value, bool)> = Vec::new();
    for p in &state_pdus {
        if p.get("room_id").and_then(Value::as_str) != Some(room_id.as_str()) {
            return Err(MatrixError::bad_json("state event of another room"));
        }
        checked.push((p.clone(), super::fed_net::verify_pdu(&state, p).await?));
    }
    let ev_ok = super::fed_net::verify_pdu(&state, &event).await?;
    let (ev2, invitee2) = (event.clone(), invitee.clone());
    let wake = with_conn_pub(&state, move |c| {
        if crate::store::user_id_of(c, &invitee2)?.is_none() {
            return Err(MatrixError::not_found("unknown local user"));
        }
        let now = rfc3339();
        fr::create_replica_room(c, &room_id, &info, &now)?;
        for (p, ok) in &checked {
            fr::ingest_pdu(c, p, *ok, fr::Mode::Trusted, &now)?;
        }
        Ok(fr::ingest_pdu(c, &ev2, ev_ok, fr::Mode::Live, &now)?.wake)
    })
    .await?;
    after_ingest(&state, wake);
    Ok(Json(json!({ "event": event })))
}

#[derive(serde::Deserialize)]
struct BackfillQuery {
    v: Option<String>,
    limit: Option<i64>,
}

async fn backfill(
    State(state): State<Arc<Homeserver>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Query(q): Query<BackfillQuery>,
) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let origin = authenticate(&state, "GET", &uri, &headers, &[]).await?;
    let local = crate::store::matrix_server_name().to_string();
    let limit = q.limit.unwrap_or(50).clamp(1, 100);
    with_conn_pub(&state, move |c| {
        #[cfg(feature = "f3-hash-ids")]
        if crate::f3::is_f3_room(c, &room_id) {
            if !crate::f3::origin_in_room(c, &room_id, &origin) {
                return Err(MatrixError::forbidden("server has no member in this room"));
            }
            let v: Vec<String> = q.v.clone().into_iter().collect();
            let pdus = crate::f3::backfill_json(c, &room_id, &origin, &v, q.limit.unwrap_or(50).clamp(1, 100) as usize);
            return Ok(Json(json!({ "origin": local, "origin_server_ts": fed::now_ms(), "pdus": pdus })));
        }
        if !fr::remote_domains(c, &room_id)?.contains(&origin) {
            return Err(MatrixError::forbidden("server has no member in this room"));
        }
        let before = match q.v.as_deref() {
            Some(id) => crate::store::get_event(c, id)?.map(|e| e.stream_id).ok_or_else(|| MatrixError::not_found("unknown event"))?,
            None => i64::MAX,
        };
        let mut pdus = Vec::new();
        for ev in crate::store::events_in_room_before(c, &room_id, before, limit)? {
            if let Ok(p) = fr::pdu_for_event(c, &ev, &local, fed::now_ms()) {
                pdus.push(p);
            }
        }
        Ok(Json(json!({ "origin": local, "origin_server_ts": fed::now_ms(), "pdus": pdus })))
    })
    .await
}

/// `POST get_missing_events`: the ancestors of `latest_events` that are not at or behind
/// `earliest_events`, oldest first. Only DAG rooms, only to a server with a user in the room.
async fn get_missing_events(
    State(state): State<Arc<Homeserver>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let origin = authenticate(&state, "POST", &uri, &headers, &body).await?;
    let v = parse_body(&body)?;
    #[cfg(feature = "f3-hash-ids")]
    {
        let ids = |k: &str| -> Vec<String> { v.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default() };
        let (earliest, latest) = (ids("earliest_events"), ids("latest_events"));
        let limit = v.get("limit").and_then(Value::as_u64).unwrap_or(10) as usize;
        return with_conn_pub(&state, move |c| {
            if !crate::f3::is_f3_room(c, &room_id) {
                return Err(MatrixError::not_found("unknown room"));
            }
            if !crate::f3::origin_in_room(c, &room_id, &origin) {
                return Err(MatrixError::forbidden("server has no member in this room"));
            }
            Ok(Json(json!({ "events": crate::f3::missing_events_json(c, &room_id, &origin, &earliest, &latest, limit) })))
        })
        .await;
    }
    #[cfg(not(feature = "f3-hash-ids"))]
    {
        let _ = (v, room_id, origin);
        Err(MatrixError::unrecognized())
    }
}

/// `GET query/directory`: the room behind a local alias.
async fn query_directory(State(state): State<Arc<Homeserver>>, OriginalUri(uri): OriginalUri, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    authenticate(&state, "GET", &uri, &headers, &[]).await?;
    let alias = q.get("room_alias").cloned().ok_or_else(|| MatrixError::invalid_param("room_alias required"))?;
    let local = crate::store::matrix_server_name().to_string();
    with_conn_pub(&state, move |c| {
        let room = super::extras::resolve_local_alias(c, &alias).ok_or_else(|| MatrixError::not_found("no such alias"))?;
        Ok(Json(json!({ "room_id": room, "servers": [local] })))
    })
    .await
}

/// `GET openid/userinfo`: who an OpenID token (issued here) belongs to. Unauthenticated by design.
async fn openid_userinfo(State(state): State<Arc<Homeserver>>, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let token = q.get("access_token").cloned().unwrap_or_default();
    with_conn_pub(&state, move |c| match super::extras::openid_subject(c, &token) {
        Some(sub) => Ok(Json(json!({ "sub": sub }))),
        None => Err(MatrixError::new(401, "M_UNKNOWN_TOKEN", "unknown or expired token")),
    })
    .await
}

#[derive(serde::Deserialize)]
#[cfg(feature = "f3-hash-ids")]
struct AtQuery {
    event_id: Option<String>,
}

/// A DAG room's history may be read by servers that have a member in it.
#[cfg(feature = "f3-hash-ids")]
async fn dag_room_access(state: &Arc<Homeserver>, origin: String, room_id: String) -> Result<(), MatrixError> {
    with_conn_pub(state, move |c| {
        if !crate::f3::is_f3_room(c, &room_id) {
            return Err(MatrixError::new(404, "M_UNRECOGNIZED", "only hash-id rooms offer this"));
        }
        if !crate::f3::origin_in_room(c, &room_id, &origin) {
            return Err(MatrixError::forbidden("server has no member in this room"));
        }
        Ok(())
    })
    .await
}

#[cfg(feature = "f3-hash-ids")]
async fn event_auth(State(state): State<Arc<Homeserver>>, OriginalUri(uri): OriginalUri, headers: HeaderMap, Path((room_id, event_id)): Path<(String, String)>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let origin = authenticate(&state, "GET", &uri, &headers, &[]).await?;
    dag_room_access(&state, origin, room_id.clone()).await?;
    with_conn_pub(&state, move |c| crate::f3::event_auth_json(c, &room_id, &event_id).map(Json)).await
}

#[cfg(feature = "f3-hash-ids")]
async fn state_at(state: Arc<Homeserver>, uri: Uri, headers: HeaderMap, room_id: String, q: AtQuery, ids_only: bool) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let origin = authenticate(&state, "GET", &uri, &headers, &[]).await?;
    dag_room_access(&state, origin, room_id.clone()).await?;
    let at = q.event_id.ok_or_else(|| MatrixError::invalid_param("event_id required"))?;
    with_conn_pub(&state, move |c| crate::f3::state_at_json(c, &room_id, &at, ids_only).map(Json)).await
}

#[cfg(feature = "f3-hash-ids")]
async fn state_ids(State(state): State<Arc<Homeserver>>, OriginalUri(uri): OriginalUri, headers: HeaderMap, Path(room_id): Path<String>, Query(q): Query<AtQuery>) -> Result<Json<Value>, MatrixError> {
    state_at(state, uri, headers, room_id, q, true).await
}

#[cfg(feature = "f3-hash-ids")]
async fn state_events(State(state): State<Arc<Homeserver>>, OriginalUri(uri): OriginalUri, headers: HeaderMap, Path(room_id): Path<String>, Query(q): Query<AtQuery>) -> Result<Json<Value>, MatrixError> {
    state_at(state, uri, headers, room_id, q, false).await
}

#[cfg(not(feature = "f3-hash-ids"))]
async fn event_auth() -> Result<Json<Value>, MatrixError> {
    Err(MatrixError::new(404, "M_UNRECOGNIZED", "hash-id rooms are not enabled"))
}
#[cfg(not(feature = "f3-hash-ids"))]
async fn state_ids() -> Result<Json<Value>, MatrixError> {
    Err(MatrixError::new(404, "M_UNRECOGNIZED", "hash-id rooms are not enabled"))
}
#[cfg(not(feature = "f3-hash-ids"))]
async fn state_events() -> Result<Json<Value>, MatrixError> {
    Err(MatrixError::new(404, "M_UNRECOGNIZED", "hash-id rooms are not enabled"))
}

/// `GET media/download`: one of our local files for another server (multipart: `{}`, then bytes).
async fn fed_media_download(State(state): State<Arc<Homeserver>>, OriginalUri(uri): OriginalUri, headers: HeaderMap, Path(media_id): Path<String>) -> Result<axum::response::Response, MatrixError> {
    fed_media(state, uri, headers, media_id, None).await
}

async fn fed_media_thumbnail(State(state): State<Arc<Homeserver>>, OriginalUri(uri): OriginalUri, headers: HeaderMap, Path(media_id): Path<String>, Query(q): Query<HashMap<String, String>>) -> Result<axum::response::Response, MatrixError> {
    let num = |k: &str| q.get(k).and_then(|v| v.parse::<u32>().ok()).filter(|n| (1..=2048).contains(n));
    let (Some(w), Some(h)) = (num("width"), num("height")) else { return Err(MatrixError::invalid_param("width and height are required")) };
    fed_media(state, uri, headers, media_id, Some((w, h, q.get("method").map(String::as_str) == Some("crop")))).await
}

async fn fed_media(state: Arc<Homeserver>, uri: axum::http::Uri, headers: HeaderMap, media_id: String, thumb: Option<(u32, u32, bool)>) -> Result<axum::response::Response, MatrixError> {
    use axum::response::IntoResponse;
    require_enabled(&state)?;
    authenticate(&state, "GET", &uri, &headers, &[]).await?;
    if !crate::media::federation_enabled() {
        return Err(MatrixError::not_found("media federation is off on this server"));
    }
    let blob = with_conn_pub(&state, move |c| Ok(crate::media::get(c, &media_id)?)).await?.ok_or_else(|| MatrixError::not_found("no such media"))?;
    let blob = match thumb {
        Some((w, h, crop)) => {
            let data = blob.data.clone();
            match tokio::task::spawn_blocking(move || crate::media::thumbnail(&data, w, h, crop)).await.ok().flatten() {
                Some((bytes, mime)) => crate::media::Blob { content_type: mime.into(), filename: blob.filename, data: bytes },
                None => blob,
            }
        }
        None => blob,
    };
    let (ct, body) = crate::media::multipart_body(&blob);
    Ok(([(axum::http::header::CONTENT_TYPE, ct)], body).into_response())
}

/// `GET publicRooms`: the public channels of this server, for another server's room directory.
async fn fed_public_rooms(State(state): State<Arc<Homeserver>>, OriginalUri(uri): OriginalUri, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    authenticate(&state, "GET", &uri, &headers, &[]).await?;
    let (limit, since) = (q.get("limit").and_then(|l| l.parse().ok()), q.get("since").cloned());
    with_conn_pub(&state, move |c| crate::account::list_public_rooms(c, since.as_deref(), limit, None).map(Json)).await
}

async fn fed_public_rooms_post(State(state): State<Arc<Homeserver>>, OriginalUri(uri): OriginalUri, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    authenticate(&state, "POST", &uri, &headers, &body).await?;
    let v = parse_body(&body)?;
    let limit = v.get("limit").and_then(Value::as_i64);
    let since = v.get("since").and_then(Value::as_str).map(str::to_string);
    let term = v.pointer("/filter/generic_search_term").and_then(Value::as_str).map(str::to_string);
    with_conn_pub(&state, move |c| crate::account::list_public_rooms(c, since.as_deref(), limit, term.as_deref()).map(Json)).await
}

/// One server's key document, as a notary: our own, or a peer's fetched, checked, and counter-signed.
async fn notary_doc(state: &Arc<Homeserver>, server: &str) -> Result<Value, MatrixError> {
    let local = crate::store::matrix_server_name().to_string();
    if server == local {
        return with_conn_pub(state, move |c| fed::server_keys_response(c, &local, fed::now_ms()).map_err(|_| MatrixError::internal())).await;
    }
    let (status, doc) = super::fed_net::fed_request(state, server, "GET", "/key/v2/server", None).await?;
    if status != 200 {
        return Err(MatrixError::unknown("could not fetch that server's keys"));
    }
    fed::parse_server_keys(&doc, server, fed::now_ms()).map_err(|_| MatrixError::unknown("that server's keys do not check out"))?;
    let mut obj = doc.as_object().cloned().ok_or_else(MatrixError::internal)?;
    with_conn_pub(state, move |c| {
        let (key_id, key) = fed::active_signing_key(c, fed::now_ms()).map_err(|_| MatrixError::internal())?;
        fed::sign_json(&mut obj, &local, &key_id, &key);
        Ok(Value::Object(obj))
    })
    .await
}

async fn notary_get(State(state): State<Arc<Homeserver>>, Path(server): Path<String>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    Ok(Json(json!({ "server_keys": [notary_doc(&state, &server).await?] })))
}

/// The older form with a key id in the path: the same document (all of the server's keys).
async fn notary_get_key(State(state): State<Arc<Homeserver>>, Path((server, _key_id)): Path<(String, String)>) -> Result<Json<Value>, MatrixError> {
    notary_get(State(state), Path(server)).await
}

async fn notary_post(State(state): State<Arc<Homeserver>>, Json(body): Json<Value>) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let mut out = Vec::new();
    for server in body.get("server_keys").and_then(Value::as_object).map(|m| m.keys().cloned().collect::<Vec<_>>()).unwrap_or_default().into_iter().take(20) {
        if let Ok(d) = notary_doc(&state, &server).await {
            out.push(d);
        }
    }
    Ok(Json(json!({ "server_keys": out })))
}

async fn keys_query(State(state): State<Arc<Homeserver>>, OriginalUri(uri): OriginalUri, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let origin = authenticate(&state, "POST", &uri, &headers, &body).await?;
    let req: crate::key_ops::KeysQueryRequest = serde_json::from_slice(&body).map_err(|_| MatrixError::bad_json("keys query"))?;
    with_conn_pub(&state, move |c| {
        let visible = fr::users_visible_to_origin(c, &origin)?;
        let local_only: std::collections::BTreeMap<String, Vec<String>> = req.device_keys.into_iter().filter(|(m, _)| !fr::is_remote_mxid(m)).collect();
        crate::key_ops::build_keys_query_visible(c, &visible, None, &local_only).map(Json)
    })
    .await
}

async fn keys_claim(State(state): State<Arc<Homeserver>>, OriginalUri(uri): OriginalUri, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let origin = authenticate(&state, "POST", &uri, &headers, &body).await?;
    let req: crate::key_ops::KeysClaimRequest = serde_json::from_slice(&body).map_err(|_| MatrixError::bad_json("keys claim"))?;
    with_conn_pub(&state, move |c| {
        let visible = fr::users_visible_to_origin(c, &origin)?;
        let local_only: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>> =
            req.one_time_keys.into_iter().filter(|(m, _)| !fr::is_remote_mxid(m)).collect();
        crate::key_ops::build_keys_claim_visible(c, &visible, &local_only).map(Json)
    })
    .await
}

async fn user_devices(
    State(state): State<Arc<Homeserver>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    require_enabled(&state)?;
    let origin = authenticate(&state, "GET", &uri, &headers, &[]).await?;
    with_conn_pub(&state, move |c| {
        let uid = crate::store::user_id_of(c, &user_id)?.filter(|u| *u > 0).ok_or_else(|| MatrixError::not_found("unknown user"))?;
        if !fr::users_visible_to_origin(c, &origin)?.contains(&uid) {
            return Err(MatrixError::not_found("unknown user"));
        }
        let one: std::collections::BTreeMap<String, Vec<String>> = [(user_id.clone(), Vec::new())].into();
        let visible: std::collections::HashSet<i64> = [uid].into();
        let q = crate::key_ops::build_keys_query_visible(c, &visible, None, &one)?;
        let devices: Vec<Value> = q["device_keys"][&user_id].as_object().map(|m| m.iter().map(|(id, keys)| json!({ "device_id": id, "keys": keys })).collect()).unwrap_or_default();
        Ok(Json(json!({
            "user_id": user_id, "stream_id": crate::fed_edus::device_list_stream(c, uid), "devices": devices,
            "master_key": q["master_keys"].get(&user_id).cloned().unwrap_or(Value::Null),
            "self_signing_key": q["self_signing_keys"].get(&user_id).cloned().unwrap_or(Value::Null),
        })))
    })
    .await
}

/// Path+query as the sender signed it: always with the `/_matrix` prefix,
/// which an edge in front of the core may have stripped.
fn signed_uri(uri: &Uri) -> String {
    let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    if pq.starts_with("/_matrix/") {
        pq.to_string()
    } else {
        format!("/_matrix{pq}")
    }
}

/// Authenticate a federation request from its `X-Matrix` header and return
/// the verified origin server name. `body` is the raw request body (empty for GET).
pub(crate) async fn authenticate(
    state: &Arc<Homeserver>,
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<String, MatrixError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| MatrixError::unauthorized("missing X-Matrix authorization"))?;
    let xm = fed::parse_x_matrix(value).map_err(|e| MatrixError::unauthorized(e.to_string()))?;
    let local = crate::store::matrix_server_name();
    if let Some(dest) = &xm.destination {
        if !crate::store::is_local_server_name(dest) {
            return Err(MatrixError::unauthorized("request is addressed to another server"));
        }
    }
    if fed::parse_server_name(&xm.origin).is_none() || crate::store::is_local_server_name(&xm.origin) {
        return Err(MatrixError::unauthorized("invalid origin"));
    }
    if let Some(allow) = state.federation_allow.get() {
        if !allow.iter().any(|a| a.eq_ignore_ascii_case(&xm.origin)) {
            return Err(MatrixError::forbidden("origin is not on the federation allowlist"));
        }
    }
    let content: Option<Value> = if body.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(body).map_err(|_| MatrixError::bad_json("body is not JSON"))?)
    };
    let public_key = remote_key(state, &xm.origin, &xm.key).await?;
    fed::verify_request_signature(&xm, method, &signed_uri(uri), local, content.as_ref(), &public_key)
        .map_err(|_| MatrixError::unauthorized("bad request signature"))?;
    Ok(xm.origin)
}

/// Public key of `server` for `key_id`: cache first, then one resolved fetch
/// (rate-limited per server), validated before it is stored.
pub(crate) async fn remote_key(state: &Arc<Homeserver>, server: &str, key_id: &str) -> Result<String, MatrixError> {
    let now = fed::now_ms();
    let (s, k) = (server.to_string(), key_id.to_string());
    let cached = with_conn_pub(state, move |c| fed::cached_remote_key(c, &s, &k, now).map_err(|_| MatrixError::internal())).await?;
    if let Some(pk) = cached {
        return Ok(pk);
    }
    let s = server.to_string();
    if !with_conn_pub(state, move |c| fed::may_refetch(c, &s, now).map_err(|_| MatrixError::internal())).await? {
        return Err(MatrixError::unauthorized("unknown signing key"));
    }
    let fetcher = state.key_fetcher.get().cloned().ok_or_else(|| MatrixError::unauthorized("remote key fetching is not configured"))?;
    let resp = fetcher.fetch_server_keys(server).await.map_err(|e| MatrixError::unauthorized(format!("cannot fetch keys: {e}")))?;
    let parsed = fed::parse_server_keys(&resp, server, now).map_err(|e| MatrixError::unauthorized(format!("invalid keys: {e}")))?;
    let found = parsed.keys.iter().find(|(id, _)| id == key_id).map(|(_, pk)| pk.clone());
    let (s, p) = (server.to_string(), parsed);
    with_conn_pub(state, move |c| fed::store_remote_keys(c, &s, &p, now).map_err(|_| MatrixError::internal())).await?;
    found.ok_or_else(|| MatrixError::unauthorized("unknown signing key"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::{FetchFuture, RemoteKeys};
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use rusqlite::Connection;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tower::ServiceExt;

    struct Mock {
        docs: Mutex<HashMap<String, Value>>,
        calls: AtomicUsize,
    }
    impl RemoteKeys for Mock {
        fn fetch_server_keys<'a>(&'a self, server: &'a str) -> FetchFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.docs.lock().unwrap().get(server).cloned().ok_or(fed::FedError::Network("unreachable".into()))
            })
        }
    }

    fn mem() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        crate::store::create_matrix_schema(&c).unwrap();
        crate::keys::create_matrix_keys_schema(&c).unwrap();
        c
    }

    /// A "receiving" homeserver plus a remote sender `a.example` whose key document the mock serves.
    fn setup() -> (Arc<Homeserver>, Arc<Mock>, rusqlite::Connection, String, ed25519_dalek::SigningKey) {
        let c = mem();
        crate::store::ensure_matrix_user(&c, 1, "alice000000000000000000000000a1", "2026-10-09T00:00:00+00:00").unwrap();
        let hs = Arc::new(Homeserver::new(c));
        hs.federation_enabled.set(()).unwrap();
        let sender = mem();
        let (kid, key) = fed::active_signing_key(&sender, 0).unwrap();
        let doc = fed::server_keys_response(&sender, "a.example", fed::now_ms()).unwrap();
        let mock = Arc::new(Mock { docs: Mutex::new(HashMap::from([("a.example".to_string(), doc)])), calls: AtomicUsize::new(0) });
        let _ = hs.key_fetcher.set(mock.clone());
        (hs, mock, sender, kid, key)
    }

    async fn call(hs: &Arc<Homeserver>, req: Request<Body>) -> (StatusCode, Value) {
        let resp = crate::http::router(Arc::clone(hs)).oneshot(req).await.unwrap();
        let st = resp.status();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (st, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    fn signed_get(uri: &str, origin: &str, dest: &str, kid: &str, key: &ed25519_dalek::SigningKey, signed_uri: &str) -> Request<Body> {
        let h = fed::build_x_matrix_header(origin, dest, kid, key, "GET", signed_uri, None);
        Request::get(uri).header(header::AUTHORIZATION, h).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn federation_is_off_until_enabled() {
        let hs = Arc::new(Homeserver::new(mem()));
        assert_eq!(call(&hs, Request::get("/key/v2/server").body(Body::empty()).unwrap()).await.0, StatusCode::NOT_FOUND);
        assert_eq!(call(&hs, Request::get("/federation/v1/version").body(Body::empty()).unwrap()).await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn own_key_document_is_served_and_valid() {
        let (hs, _, _, _, _) = setup();
        let (st, doc) = call(&hs, Request::get("/key/v2/server").body(Body::empty()).unwrap()).await;
        assert_eq!(st, StatusCode::OK);
        let me = crate::store::matrix_server_name();
        assert_eq!(doc["server_name"], me);
        assert!(fed::parse_server_keys(&doc, me, fed::now_ms()).is_ok());
        let (st2, doc2) = call(&hs, Request::get("/key/v2/server/ed25519:whatever").body(Body::empty()).unwrap()).await;
        assert_eq!((st2, doc2["verify_keys"].clone()), (StatusCode::OK, doc["verify_keys"].clone()), "stable key");
        assert_eq!(call(&hs, Request::get("/federation/v1/version").body(Body::empty()).unwrap()).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn signed_request_is_verified_with_fetched_then_cached_keys() {
        let (hs, mock, _, kid, key) = setup();
        let me = crate::store::matrix_server_name();
        let uri = "/federation/v1/query/profile?user_id=%40alice000000000000000000000000a1%3Aexample.org";
        let signed = format!("/_matrix{uri}");
        let (st, _) = call(&hs, signed_get(uri, "a.example", me, &kid, &key, &signed)).await;
        assert_eq!(st, StatusCode::OK);
        let (st, _) = call(&hs, signed_get(uri, "a.example", me, &kid, &key, &signed)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1, "second request served from the key cache");
        // The prefix is added once, whether or not an edge stripped it.
        assert_eq!(signed_uri(&"/federation/v1/x?a=1".parse().unwrap()), "/_matrix/federation/v1/x?a=1");
        assert_eq!(signed_uri(&"/_matrix/federation/v1/x?a=1".parse().unwrap()), "/_matrix/federation/v1/x?a=1");
    }

    #[tokio::test]
    async fn bad_requests_are_rejected() {
        let (hs, mock, _, kid, key) = setup();
        let me = crate::store::matrix_server_name();
        let uri = "/federation/v1/query/profile?user_id=%40alice000000000000000000000000a1%3Aexample.org";
        let signed = format!("/_matrix{uri}");
        // no header
        assert_eq!(call(&hs, Request::get(uri).body(Body::empty()).unwrap()).await.0, StatusCode::UNAUTHORIZED);
        // signature over another uri
        assert_eq!(call(&hs, signed_get(uri, "a.example", me, &kid, &key, "/_matrix/federation/v1/query/profile")).await.0, StatusCode::UNAUTHORIZED);
        // wrong destination
        assert_eq!(call(&hs, signed_get(uri, "a.example", "other.example", &kid, &key, &signed)).await.0, StatusCode::UNAUTHORIZED);
        // signed by a different key than the origin published
        let evil = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        assert_eq!(call(&hs, signed_get(uri, "a.example", me, &kid, &evil, &signed)).await.0, StatusCode::UNAUTHORIZED);
        // unknown key id
        assert_eq!(call(&hs, signed_get(uri, "a.example", me, "ed25519:nope", &key, &signed)).await.0, StatusCode::UNAUTHORIZED);
        // origin that cannot be reached
        assert_eq!(call(&hs, signed_get(uri, "ghost.example", me, &kid, &key, &signed)).await.0, StatusCode::UNAUTHORIZED);
        // claiming to be ourselves
        assert_eq!(call(&hs, signed_get(uri, me, me, &kid, &key, &signed)).await.0, StatusCode::UNAUTHORIZED);
        assert!(mock.calls.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn allowlist_and_unknown_user() {
        let (hs, _, _, kid, key) = setup();
        let me = crate::store::matrix_server_name();
        let uri = "/federation/v1/query/profile?user_id=%40nobody%3Aexample.org";
        let signed = format!("/_matrix{uri}");
        assert_eq!(call(&hs, signed_get(uri, "a.example", me, &kid, &key, &signed)).await.0, StatusCode::NOT_FOUND, "authenticated, user unknown");
        let (hs2, _, _, kid2, key2) = setup();
        hs2.federation_allow.set(vec!["b.example".into()]).unwrap();
        assert_eq!(call(&hs2, signed_get(uri, "a.example", me, &kid2, &key2, &signed)).await.0, StatusCode::FORBIDDEN);
    }
}
