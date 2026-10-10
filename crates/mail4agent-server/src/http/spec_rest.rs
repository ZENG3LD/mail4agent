//! The rest of the client-server API a homeserver is expected to answer: the support well-known,
//! third-party lookups (this server bridges nothing), custom profile fields, room directory
//! visibility, knocking (refused: no room here allows it), timestamp lookup, room summaries, user
//! reports, admin lookups (refused), and the account routes that the product server owns.
//!
//! Where the messenger deliberately does not offer something, the answer is the spec's own error
//! (`M_FORBIDDEN`, `M_NOT_FOUND`, `M_THREEPID_DENIED`, `M_UNRECOGNIZED`), never a missing route.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{any, get, post, put};
use axum::{Json, Router};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use super::{resolve_caller, with_conn_pub, with_read_pub, Homeserver};
use crate::error::MatrixError;
use crate::store;

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new()
        .route("/.well-known/matrix/support", get(support))
        .route("/client/v3/thirdparty/protocol/{protocol}", get(unknown_protocol))
        .route("/client/v3/thirdparty/location/{protocol}", get(empty_list))
        .route("/client/v3/thirdparty/user/{protocol}", get(empty_list))
        .route("/client/v3/thirdparty/location", get(empty_list))
        .route("/client/v3/thirdparty/user", get(empty_list))
        .route("/client/v3/profile/{user_id}/{key}", get(get_field).put(put_field).delete(delete_field))
        .route("/client/v3/directory/list/room/{room_id}", get(get_visibility).put(put_visibility))
        .route("/client/v3/directory/list/appservice/{network_id}/{room_id}", put(appservice_only))
        .route("/client/v3/knock/{room}", post(knock))
        .route("/client/v1/rooms/{room_id}/timestamp_to_event", get(timestamp_to_event))
        .route("/client/v1/room_summary/{room}", get(room_summary))
        .route("/client/v1/rooms/{room_id}/summary", get(room_summary))
        .route("/client/v3/users/{user_id}/report", post(report_user))
        .route("/client/v3/admin/whois/{user_id}", get(admin_only))
        // Owned by the product server in front of this one (see the product kit).
        .route("/client/v1/login/get_token", post(product_owns))
        .route("/client/v3/refresh", post(product_owns))
        .route("/client/v3/register/email/requestToken", post(product_owns))
        .route("/client/v3/register/msisdn/requestToken", post(product_owns))
        .route("/client/v1/register/m.login.registration_token/validity", get(registration_token_validity))
        .route("/client/v3/account/password/email/requestToken", post(product_owns))
        .route("/client/v3/account/password/msisdn/requestToken", post(product_owns))
        .route("/client/v3/account/3pid/email/requestToken", post(threepid_denied))
        .route("/client/v3/account/3pid/msisdn/requestToken", post(threepid_denied))
        // Single sign-on and OIDC discovery are not offered: the spec's own "not here".
        .route("/client/v3/login/sso/redirect", any(not_offered))
        .route("/client/v3/login/sso/redirect/{idp}", any(not_offered))
        .route("/client/v1/auth_metadata", any(not_offered))
}

pub fn create_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS profile_fields (
            user_id INTEGER NOT NULL,
            field TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY (user_id, field)
        );",
    )
}

/// Custom profile fields of a local user (spec v1.16), as a JSON object.
pub fn profile_fields(conn: &Connection, user_id: i64) -> Vec<(String, Value)> {
    let Ok(mut st) = conn.prepare("SELECT field, value FROM profile_fields WHERE user_id = ?1 ORDER BY field") else { return vec![] };
    st.query_map([user_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map(|rows| rows.flatten().filter_map(|(k, v)| Some((k, serde_json::from_str(&v).ok()?))).collect())
        .unwrap_or_default()
}

async fn not_offered() -> MatrixError {
    MatrixError::unrecognized()
}

async fn product_owns() -> Result<Json<Value>, MatrixError> {
    Err(MatrixError::forbidden("this is handled by the product server in front of this one"))
}

async fn threepid_denied() -> MatrixError {
    MatrixError::new(403, "M_THREEPID_DENIED", "this server does not use third-party identifiers")
}

async fn registration_token_validity() -> Json<Value> {
    // Registration (and its tokens) belong to the product server; none are valid here.
    Json(json!({ "valid": false }))
}

async fn admin_only() -> MatrixError {
    MatrixError::forbidden("the admin API is not offered")
}

async fn appservice_only() -> MatrixError {
    MatrixError::forbidden("only an application service may change that, and none is registered")
}

async fn knock() -> MatrixError {
    MatrixError::forbidden("no room on this server allows knocking")
}

/// `/.well-known/matrix/support`: whatever `M4A_WELLKNOWN_SUPPORT` holds (a JSON document), else 404.
async fn support() -> Result<Json<Value>, MatrixError> {
    let doc = std::env::var("M4A_WELLKNOWN_SUPPORT").ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()).filter(Value::is_object);
    doc.map(Json).ok_or_else(|| MatrixError::not_found("no support information is configured"))
}

async fn unknown_protocol(State(state): State<Arc<Homeserver>>, headers: HeaderMap) -> Result<Json<Value>, MatrixError> {
    resolve_caller(&state, &headers, None).await?;
    Err(MatrixError::not_found("no such protocol: this server bridges none"))
}

async fn empty_list(State(state): State<Arc<Homeserver>>, headers: HeaderMap) -> Result<Json<Value>, MatrixError> {
    resolve_caller(&state, &headers, None).await?;
    Ok(Json(json!([])))
}

// ------------------------------------------------------------ custom profile fields

fn field_ok(key: &str) -> bool {
    !key.is_empty() && key.len() <= 255 && key.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':'))
}

async fn get_field(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path((user_id, key)): Path<(String, String)>) -> Result<Json<Value>, MatrixError> {
    resolve_caller(&state, &headers, None).await?;
    let p = super::extras::profile_of(&state, &user_id).await?;
    p.get(&key).map(|v| Json(json!({ key.clone(): v }))).ok_or_else(|| MatrixError::not_found("no such profile field"))
}

async fn put_field(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path((user_id, key)): Path<(String, String)>, Json(body): Json<Value>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    crate::account::check_caller_owns_user_id(&user_id, &caller.mxid)?;
    if !field_ok(&key) {
        return Err(MatrixError::invalid_param("not a valid profile field name"));
    }
    let value = body.get(&key).cloned().ok_or_else(|| MatrixError::bad_json("the body must hold the field"))?;
    let text = serde_json::to_string(&value).map_err(|_| MatrixError::bad_json("value"))?;
    with_conn_pub(&state, move |c| {
        let total: i64 = c.query_row("SELECT COALESCE(SUM(LENGTH(field) + LENGTH(value)), 0) FROM profile_fields WHERE user_id = ?1 AND field <> ?2", params![caller.user_id, key], |r| r.get(0)).map_err(|_| MatrixError::internal())?;
        if total + (text.len() + key.len()) as i64 > 65_536 {
            return Err(MatrixError::new(400, "M_PROFILE_TOO_LARGE", "the profile would exceed 64 KiB"));
        }
        c.execute("INSERT INTO profile_fields (user_id, field, value) VALUES (?1,?2,?3) ON CONFLICT(user_id, field) DO UPDATE SET value = excluded.value", params![caller.user_id, key, text]).map_err(|_| MatrixError::internal())?;
        Ok(Json(json!({})))
    })
    .await
}

async fn delete_field(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path((user_id, key)): Path<(String, String)>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    crate::account::check_caller_owns_user_id(&user_id, &caller.mxid)?;
    with_conn_pub(&state, move |c| {
        c.execute("DELETE FROM profile_fields WHERE user_id = ?1 AND field = ?2", params![caller.user_id, key]).map_err(|_| MatrixError::internal())?;
        Ok(Json(json!({})))
    })
    .await
}

// ------------------------------------------------------------ room directory visibility

async fn get_visibility(State(state): State<Arc<Homeserver>>, Path(room_id): Path<String>) -> Result<Json<Value>, MatrixError> {
    with_read_pub(&state, move |c| {
        store::get_room(c, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let public = crate::public_channels::is_public_room(c, &room_id).unwrap_or(false);
        Ok(Json(json!({ "visibility": if public { "public" } else { "private" } })))
    })
    .await
}

/// Visibility is fixed when a room is created (public channels are published, everything else is
/// private); setting the value it already has succeeds, changing it is refused.
async fn put_visibility(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(room_id): Path<String>, Json(body): Json<Value>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let want = body.get("visibility").and_then(Value::as_str).unwrap_or("public").to_string();
    if want != "public" && want != "private" {
        return Err(MatrixError::invalid_param("visibility must be public or private"));
    }
    with_read_pub(&state, move |c| {
        let room = store::get_room(c, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        if !store::room_member(c, &room.id, caller.user_id)?.is_some_and(|m| m.membership == store::Membership::Join) {
            return Err(MatrixError::forbidden("you are not in that room"));
        }
        let public = crate::public_channels::is_public_room(c, &room_id).unwrap_or(false);
        if (want == "public") != public {
            return Err(MatrixError::forbidden("a room's directory visibility is fixed when it is created"));
        }
        Ok(Json(json!({})))
    })
    .await
}

// ------------------------------------------------------------ timestamp_to_event

#[derive(serde::Deserialize)]
struct TsQuery {
    ts: i64,
    dir: String,
}

/// The event of a room closest to a timestamp, going forward (`f`) or backward (`b`) from it.
pub(crate) fn nearest_event(c: &Connection, room_id: &str, ts: i64, forward: bool) -> Option<(String, i64)> {
    let public = crate::public_channels::is_public_room(c, room_id).unwrap_or(false);
    let table = if public { "pub_events" } else { "events" };
    let sql = if forward {
        format!("SELECT event_id, origin_server_ts FROM {table} WHERE room_id = ?1 AND origin_server_ts >= ?2 ORDER BY origin_server_ts ASC, stream_id ASC LIMIT 1")
    } else {
        format!("SELECT event_id, origin_server_ts FROM {table} WHERE room_id = ?1 AND origin_server_ts <= ?2 ORDER BY origin_server_ts DESC, stream_id DESC LIMIT 1")
    };
    c.query_row(&sql, params![room_id, ts], |r| Ok((r.get(0)?, r.get(1)?))).optional().ok().flatten()
}

async fn timestamp_to_event(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(room_id): Path<String>, Query(q): Query<TsQuery>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let forward = match q.dir.as_str() {
        "f" => true,
        "b" => false,
        _ => return Err(MatrixError::invalid_param("dir must be f or b")),
    };
    with_read_pub(&state, move |c| {
        let room = store::get_room(c, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        if !crate::spaces::caller_may_see(c, &room, caller.user_id)? {
            return Err(MatrixError::forbidden("you cannot see that room"));
        }
        let (event_id, origin_server_ts) = nearest_event(c, &room_id, q.ts, forward).ok_or_else(|| MatrixError::not_found("no event near that time"))?;
        Ok(Json(json!({ "event_id": event_id, "origin_server_ts": origin_server_ts })))
    })
    .await
}

// ------------------------------------------------------------ room summary

async fn room_summary(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(room): Path<String>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let room_id = if room.starts_with('#') { super::extras::resolve_alias(&state, &room).await?.0 } else { room };
    with_read_pub(&state, move |c| {
        let r = store::get_room(c, &room_id)?.ok_or_else(|| MatrixError::not_found("room not found or not visible"))?;
        if !crate::spaces::caller_may_see(c, &r, caller.user_id)? {
            return Err(MatrixError::not_found("room not found or not visible"));
        }
        let content = |t: &str| crate::spaces::state_content(c, &room_id, t, "").ok().flatten();
        let mut out = json!({
            "room_id": room_id,
            "num_joined_members": crate::spaces::joined_count(c, &room_id)?,
            "world_readable": r.history_visibility == store::HistoryVisibility::WorldReadable,
            "guest_can_join": false,
            "join_rule": crate::spaces::join_rule_wire(c, &r)?,
            "room_version": r.room_version,
        });
        let o = out.as_object_mut().expect("object");
        if let Some(n) = content("m.room.name").and_then(|v| v.get("name").cloned()) {
            o.insert("name".into(), n);
        }
        if let Some(t) = content("m.room.topic").and_then(|v| v.get("topic").cloned()) {
            o.insert("topic".into(), t);
        }
        if let Some(a) = content("m.room.avatar").and_then(|v| v.get("url").cloned()) {
            o.insert("avatar_url".into(), a);
        }
        if let Some(a) = content("m.room.canonical_alias").and_then(|v| v.get("alias").cloned()) {
            o.insert("canonical_alias".into(), a);
        }
        if let Some(t) = crate::spaces::room_type(c, &room_id)? {
            o.insert("room_type".into(), json!(t));
        }
        if let Some(e) = content("m.room.encryption").and_then(|v| v.get("algorithm").cloned()) {
            o.insert("encryption".into(), e);
        }
        if let Some(m) = store::room_member(c, &room_id, caller.user_id)? {
            o.insert("membership".into(), json!(m.membership.as_str()));
        }
        Ok(Json(out))
    })
    .await
}

// ------------------------------------------------------------ user reports

async fn report_user(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(user_id): Path<String>, Json(body): Json<Value>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let reason = body.get("reason").and_then(Value::as_str).map(|s| s.chars().take(2048).collect::<String>());
    with_conn_pub(&state, move |c| {
        store::user_id_of(c, &user_id)?.ok_or_else(|| MatrixError::not_found("unknown user"))?;
        // A user report is a report with no room: the reported user id is stored as the event id.
        c.execute("INSERT INTO event_reports (room_id, event_id, reporter_user_id, reason, score, created_at) VALUES ('', ?1, ?2, ?3, NULL, ?4)", params![user_id, caller.user_id, reason, chrono::Utc::now().to_rfc3339()]).map_err(|_| MatrixError::internal())?;
        Ok(Json(json!({})))
    })
    .await
}
