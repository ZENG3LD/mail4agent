//! Send, redact, and history reads. Paths have no `/_matrix` prefix.
//! Each write locks `Homeserver::conn` only inside `spawn_blocking`, then
//! wakes with the ids the apply function returned.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::{Json, Router};

use crate::error::MatrixError;
use crate::events::client_event_json;
use crate::messaging::{
    clamp_limit, format_stream_token, lazy_load_member_state, paginate_messages, parse_filter, parse_stream_token,
    resolve_messages_start, Direction, MessagesQuery, RedactBody, RelationsQuery,
};
use crate::store::{self, HistoryWindow};

use super::{resolve_caller, wake_users, Homeserver};

fn lock_conn(state: &Homeserver) -> std::sync::MutexGuard<'_, rusqlite::Connection> {
    state.conn.lock().unwrap_or_else(|e| e.into_inner())
}

async fn send_event(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((room_id, event_type, txn_id)): Path<(String, String, String)>,
    Json(content): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    state.check_policy(&caller, crate::policy::Action::SendEvent, None)?;
    let content_str = content.to_string();
    if content_str.len() > store::MATRIX_EVENT_CONTENT_MAX_BYTES {
        return Err(MatrixError::bad_json("event content too large"));
    }

    let user_id = caller.user_id;
    let mxid = caller.mxid;
    let device_id = caller.device_id;
    let state_db = Arc::clone(&state);
    let (event_id, wake_ids, room_text) = tokio::task::spawn_blocking(move || -> Result<(String, HashSet<i64>, Option<crate::push::RoomTextPush>), MatrixError> {
        let mut conn = lock_conn(&state_db);
        let room = store::get_room(&conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let now = chrono::Utc::now().to_rfc3339();
        let origin_ts = chrono::Utc::now().timestamp_millis();
        let event_id = store::new_event_id();
        let outcome = crate::messaging::apply_send(
            &mut conn,
            &room,
            user_id,
            &mxid,
            &device_id,
            &txn_id,
            &event_id,
            &event_type,
            &content_str,
            &now,
            origin_ts,
        )?;
        let room_text = if outcome.is_new {
            crate::push::recipients_for_room_text(
                &conn,
                &event_type,
                &content_str,
                &room_id,
                user_id,
                &mxid,
                &outcome.event.event_id,
                &outcome.wake_ids,
            )?
        } else {
            None
        };
        Ok((outcome.event.event_id, outcome.wake_ids, room_text))
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    wake_users(&state, wake_ids);
    if let Some(room_text) = room_text {
        state.push.publish_room_text(&room_text);
    }
    Ok(Json(serde_json::json!({ "event_id": event_id })))
}

async fn redact_event_handler(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((room_id, target_event_id, txn_id)): Path<(String, String, String)>,
    Json(body): Json<RedactBody>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let mxid = caller.mxid;
    let device_id = caller.device_id;
    let state_db = Arc::clone(&state);
    let (event_id, wake_ids) = tokio::task::spawn_blocking(move || -> Result<(String, HashSet<i64>), MatrixError> {
        let mut conn = lock_conn(&state_db);
        store::get_room(&conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let now = chrono::Utc::now().to_rfc3339();
        let origin_ts = chrono::Utc::now().timestamp_millis();
        let redaction_event_id = store::new_event_id();
        let outcome = crate::messaging::apply_redact(
            &mut conn,
            &room_id,
            user_id,
            &mxid,
            &device_id,
            &txn_id,
            &target_event_id,
            &redaction_event_id,
            body.reason.as_deref(),
            &now,
            origin_ts,
        )?;
        Ok((outcome.event.event_id, outcome.wake_ids))
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    wake_users(&state, wake_ids);
    Ok(Json(serde_json::json!({ "event_id": event_id })))
}

async fn get_messages(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Query(query): Query<MessagesQuery>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let dir = Direction::from_query(query.dir.as_deref())?;
    let from_token = query.from.as_deref().map(parse_stream_token).transpose()?;
    let to_stream = query.to.as_deref().map(parse_stream_token).transpose()?.map(|token| token.to_bound(dir));
    let limit = clamp_limit(query.limit);
    let filter = parse_filter(query.filter.as_deref())?;
    let user_id = caller.user_id;
    let device_id = caller.device_id;

    let body = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let conn = lock_conn(&state);
        let room = store::get_room(&conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let window = store::visible_upper_bound(&conn, &room, user_id)?;
        if window == HistoryWindow::Nothing {
            return Err(MatrixError::forbidden("no read access to this room"));
        }

        let from_stream = resolve_messages_start(&conn, from_token, dir)?;
        let page = paginate_messages(&conn, &room_id, window, from_stream, to_stream, dir, limit, &filter)?;
        let mut chunk_json = Vec::with_capacity(page.chunk.len());
        for event in &page.chunk {
            let own_txn_id = store::txn_id_for_event(&conn, user_id, &device_id, &event.event_id)?;
            chunk_json.push(client_event_json(&conn, event, own_txn_id.as_deref())?);
        }

        let mut body = serde_json::json!({ "chunk": chunk_json, "start": page.start });
        if let Some(end) = page.end {
            body["end"] = serde_json::Value::String(end);
        }
        if filter.lazy_load_members {
            body["state"] = serde_json::Value::Array(lazy_load_member_state(&conn, &room_id, &page.chunk)?);
        }
        Ok(body)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(body))
}

async fn get_event(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((room_id, event_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let device_id = caller.device_id;

    let body = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let conn = lock_conn(&state);
        let room = store::get_room(&conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let window = store::visible_upper_bound(&conn, &room, user_id)?;
        if window == HistoryWindow::Nothing {
            return Err(MatrixError::forbidden("no read access to this room"));
        }
        let event = store::get_event(&conn, &event_id)?
            .filter(|event| event.room_id == room_id)
            .ok_or_else(|| MatrixError::not_found("no such event"))?;
        if !window.contains(event.stream_id) {
            return Err(MatrixError::forbidden("event is outside your visible history"));
        }
        let own_txn_id = store::txn_id_for_event(&conn, user_id, &device_id, &event.event_id)?;
        client_event_json(&conn, &event, own_txn_id.as_deref())
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(body))
}

async fn get_relations_inner(
    state: Arc<Homeserver>,
    headers: HeaderMap,
    room_id: String,
    event_id: String,
    rel_type: Option<String>,
    event_type: Option<String>,
    query: RelationsQuery,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let before_stream = match &query.from {
        Some(raw) => parse_stream_token(raw)?.backward_bound(),
        None => i64::MAX,
    };
    let limit = clamp_limit(query.limit);
    let user_id = caller.user_id;

    let body = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let conn = lock_conn(&state);
        let room = store::get_room(&conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let window = store::visible_upper_bound(&conn, &room, user_id)?;
        if window == HistoryWindow::Nothing {
            return Err(MatrixError::forbidden("no read access to this room"));
        }
        let target = store::get_event(&conn, &event_id)?
            .filter(|event| event.room_id == room_id)
            .ok_or_else(|| MatrixError::not_found("no such event"))?;
        if !window.contains(target.stream_id) {
            return Err(MatrixError::forbidden("event is outside your visible history"));
        }

        let raw_page = store::relations_of(&conn, &event_id, rel_type.as_deref(), event_type.as_deref(), before_stream, limit)?;
        let raw_len = raw_page.len();
        let any_window_truncated = raw_page.iter().any(|event| !window.contains(event.stream_id));
        let mut chunk_json = Vec::new();
        for event in raw_page.iter().filter(|event| window.contains(event.stream_id)) {
            chunk_json.push(client_event_json(&conn, event, None)?);
        }

        let mut body = serde_json::json!({ "chunk": chunk_json });
        if raw_len == limit as usize && !any_window_truncated {
            if let Some(last) = raw_page.last() {
                body["next_batch"] = serde_json::Value::String(format_stream_token(last.stream_id));
            }
        }
        Ok(body)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(body))
}

async fn get_relations_all(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((room_id, event_id)): Path<(String, String)>,
    Query(query): Query<RelationsQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    get_relations_inner(state, headers, room_id, event_id, None, None, query).await
}

async fn get_relations_by_rel_type(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((room_id, event_id, rel_type)): Path<(String, String, String)>,
    Query(query): Query<RelationsQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    get_relations_inner(state, headers, room_id, event_id, Some(rel_type), None, query).await
}

async fn get_relations_by_rel_type_and_event_type(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((room_id, event_id, rel_type, event_type)): Path<(String, String, String, String)>,
    Query(query): Query<RelationsQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    get_relations_inner(state, headers, room_id, event_id, Some(rel_type), Some(event_type), query).await
}

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new()
        .route("/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}", put(send_event))
        .route("/client/v3/rooms/{room_id}/redact/{event_id}/{txn_id}", put(redact_event_handler))
        .route("/client/v3/rooms/{room_id}/messages", get(get_messages))
        .route("/client/v3/rooms/{room_id}/event/{event_id}", get(get_event))
        .route("/client/v3/rooms/{room_id}/relations/{event_id}", get(get_relations_all))
        .route("/client/v3/rooms/{room_id}/relations/{event_id}/{rel_type}", get(get_relations_by_rel_type))
        .route(
            "/client/v3/rooms/{room_id}/relations/{event_id}/{rel_type}/{event_type}",
            get(get_relations_by_rel_type_and_event_type),
        )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
    use tower::ServiceExt;

    use crate::http::{hash_token, Homeserver};
    use crate::keys::{create_device, create_matrix_keys_schema, CredentialKind};
    use crate::nick::set_nick;
    use crate::store::{self, HistoryVisibility, JoinRule, RoomKind};

    use super::routes;

    const T0: &str = "2026-10-05T00:00:00+00:00";
    const ROOM: &str = "!pub:example.org";
    const RAW: &str = "send-token";

    #[tokio::test]
    /// Legacy path: a pre-model unencrypted public room still accepts
    /// plaintext `m.room.message`. New channels are created encrypted.
    async fn joined_member_sends_message_in_unencrypted_public_room() {
        let mut conn = rusqlite::Connection::open_in_memory().expect("in-memory sqlite");
        store::create_matrix_schema(&conn).expect("matrix schema");
        create_matrix_keys_schema(&conn).expect("keys schema");
        let mxid = store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000060", T0).expect("matrix user");
        set_nick(&conn, 1, "alice_nick").expect("nick");
        create_device(&conn, 1, CredentialKind::Bearer, &hash_token(RAW), T0).expect("device");
        store::create_room(&conn, ROOM, RoomKind::Channel, 1, T0, false, JoinRule::Public, HistoryVisibility::WorldReadable, None, None)
            .expect("room");
        store::apply_state_event(
            &mut conn,
            &store::StateEventWrite {
                event_id: "$join",
                room_id: ROOM,
                sender_user_id: 1,
                event_type: "m.room.member",
                state_key: &mxid,
                content: r#"{"membership":"join"}"#,
                origin_server_ts: 1_000,
                now: T0,
            },
        )
        .expect("join");

        let app = routes().with_state(Arc::new(Homeserver::new(conn)));
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/client/v3/rooms/{ROOM}/send/m.room.message/txn-1"))
                    .header(header::AUTHORIZATION, format!("Bearer {RAW}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"msgtype":"m.text","body":"hi"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("body");
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&bytes));
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert!(value.get("event_id").and_then(|id| id.as_str()).is_some_and(|id| !id.is_empty()));
    }
}
