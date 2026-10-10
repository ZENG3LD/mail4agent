//! Presence: `PUT/GET /presence/{userId}/status`, the sync `presence` section, and `m.presence`
//! EDUs between servers.
//!
//! Optional: the `presence` cargo feature (default on) and the environment switch
//! `M4A_PRESENCE=off`. Off, a PUT is accepted and forgotten, a GET says `offline`, sync carries no
//! presence and no EDU is sent or applied.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use super::{resolve_caller, with_conn_pub, wake_users, Homeserver};
use crate::error::MatrixError;
use crate::store;

/// A user who has been silent this long while "online" is reported "unavailable".
const IDLE_MS: i64 = 5 * 60 * 1000;

pub fn enabled() -> bool {
    cfg!(feature = "presence") && std::env::var("M4A_PRESENCE").map(|v| v != "off").unwrap_or(true)
}

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new().route("/client/v3/presence/{user_id}/status", get(get_status).put(put_status))
}

pub fn create_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS presence (
            user_id INTEGER PRIMARY KEY,
            state TEXT NOT NULL,
            status_msg TEXT,
            last_active_ms INTEGER NOT NULL,
            stream_id INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_presence_stream ON presence(stream_id);",
    )
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// The content of one user's presence (as in `m.presence` events), if any is known.
pub fn content_of(conn: &Connection, user_id: i64) -> Option<Value> {
    let (state, msg, last): (String, Option<String>, i64) = conn
        .query_row("SELECT state, status_msg, last_active_ms FROM presence WHERE user_id = ?1", [user_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .optional()
        .ok()??;
    let ago = (now_ms() - last).max(0);
    let shown = if state == "online" && ago > IDLE_MS { "unavailable".to_string() } else { state };
    let mut v = json!({ "presence": shown, "last_active_ago": ago, "currently_active": shown == "online" });
    if let Some(m) = msg {
        v["status_msg"] = json!(m);
    }
    Some(v)
}

/// Record a presence change (own user or a remote one learned by EDU); returns the users to wake.
pub fn set(conn: &mut Connection, user_id: i64, state: &str, msg: Option<&str>, last_active_ms: i64) -> rusqlite::Result<std::collections::HashSet<i64>> {
    let tx = conn.transaction()?;
    let stream = store::next_stream_id(&tx)?;
    tx.execute(
        "INSERT INTO presence (user_id, state, status_msg, last_active_ms, stream_id) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(user_id) DO UPDATE SET state = excluded.state, status_msg = excluded.status_msg, last_active_ms = excluded.last_active_ms, stream_id = excluded.stream_id",
        params![user_id, state, msg, last_active_ms, stream],
    )?;
    tx.commit()?;
    let mut ids = crate::key_ops::peers_sharing_a_room_with(conn, user_id)?;
    ids.retain(|u| *u > 0);
    Ok(ids)
}

/// Sync's `presence.events` for `caller`: peers whose presence changed after `since_stream`.
pub fn sync_events(conn: &Connection, caller: i64, since_stream: i64, upto: i64) -> rusqlite::Result<Vec<Value>> {
    if !enabled() {
        return Ok(vec![]);
    }
    let peers = crate::key_ops::peers_sharing_a_room_with(conn, caller)?;
    let mut st = conn.prepare("SELECT user_id FROM presence WHERE stream_id > ?1 AND stream_id <= ?2")?;
    let changed: Vec<i64> = st.query_map(params![since_stream, upto], |r| r.get(0))?.flatten().collect();
    let mut out = Vec::new();
    for u in changed.into_iter().filter(|u| peers.contains(u) && *u != caller) {
        if let (Some(mxid), Some(content)) = (store::mxid_of(conn, u)?, content_of(conn, u)) {
            out.push(json!({ "type": "m.presence", "sender": mxid, "content": content }));
        }
    }
    Ok(out)
}

async fn put_status(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(user_id): Path<String>, Json(body): Json<Value>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    crate::account::check_caller_owns_user_id(&user_id, &caller.mxid)?;
    let st = body.get("presence").and_then(Value::as_str).ok_or_else(|| MatrixError::bad_json("presence"))?.to_string();
    if !["online", "offline", "unavailable"].contains(&st.as_str()) {
        return Err(MatrixError::invalid_param("presence must be online, offline or unavailable"));
    }
    let msg = body.get("status_msg").and_then(Value::as_str).map(|s| s.chars().take(256).collect::<String>());
    if !enabled() {
        return Ok(Json(json!({})));
    }
    let uid = caller.user_id;
    let ids = with_conn_pub(&state, move |c| {
        let ids = set(c, uid, &st, msg.as_deref(), now_ms()).map_err(|_| MatrixError::internal())?;
        crate::fed_edus::enqueue_presence(c, uid);
        Ok(ids)
    })
    .await?;
    wake_users(&state, ids);
    Ok(Json(json!({})))
}

async fn get_status(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(user_id): Path<String>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    if !enabled() {
        return Ok(Json(json!({ "presence": "offline" })));
    }
    let me = caller.user_id;
    with_conn_pub(&state, move |c| {
        let target = store::user_id_of(c, &user_id)?.ok_or_else(|| MatrixError::not_found("unknown user"))?;
        if target != me && !crate::key_ops::peers_sharing_a_room_with(c, me)?.contains(&target) {
            return Err(MatrixError::forbidden("you share no room with that user"));
        }
        Ok(Json(content_of(c, target).unwrap_or_else(|| json!({ "presence": "offline" }))))
    })
    .await
}
