//! Typing, receipts, and read markers.
//!
//! Each handler resolves the bearer, then runs the matching
//! [`crate::ephemeral`] decision inside `spawn_blocking` while `state.conn`
//! is locked. A wake runs only after that lock is released, and only for the
//! ids the decision returns (`None`, or an empty set, wakes nobody).

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{post, put};
use axum::{Json, Router};

use crate::ephemeral::{self, ReadMarkersBody, TypingBody};
use crate::error::MatrixError;
use crate::store::ReceiptType;

use super::Homeserver;

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new()
        .route("/client/v3/rooms/{room_id}/typing/{user_id}", put(put_typing))
        .route("/client/v3/rooms/{room_id}/receipt/{receipt_type}/{event_id}", post(post_receipt))
        .route("/client/v3/rooms/{room_id}/read_markers", post(post_read_markers))
}

async fn put_typing(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((room_id, target_mxid)): Path<(String, String)>,
    Json(body): Json<TypingBody>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    ephemeral::check_typing_target(&target_mxid, &caller.mxid)?;

    let timeout_ms = body.timeout.unwrap_or(ephemeral::DEFAULT_TYPING_TIMEOUT_MS);
    let typing = body.typing;
    let user_id = caller.user_id;
    let state_for_blocking = Arc::clone(&state);

    let wake_ids = tokio::task::spawn_blocking(move || {
        state_for_blocking.conn_scope(|conn: &mut rusqlite::Connection| {
        ephemeral::apply_typing(&conn, &state_for_blocking.typing, &room_id, user_id, typing, timeout_ms, Instant::now())
        })
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    if let Some(ids) = wake_ids {
        super::wake_users(&state, ids);
    }
    Ok(Json(serde_json::json!({})))
}

async fn post_receipt(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((room_id, receipt_type_raw, event_id)): Path<(String, String, String)>,
    // `thread_id` and any other field are accepted and ignored.
    Json(_body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let receipt_type = ReceiptType::from_wire_name(&receipt_type_raw)
        .ok_or_else(|| MatrixError::invalid_param("receiptType must be m.read or m.read.private"))?;
    let user_id = caller.user_id;
    let state_for_blocking = Arc::clone(&state);

    let wake_ids = tokio::task::spawn_blocking(move || {
        state_for_blocking.conn_scope(|conn: &mut rusqlite::Connection| {
        let room = crate::store::get_room(&conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        ephemeral::apply_receipt(&mut *conn, &room, user_id, receipt_type, &event_id, now_ms)
        })
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    if let Some(ids) = wake_ids {
        super::wake_users(&state, ids);
    }
    Ok(Json(serde_json::json!({})))
}

async fn post_read_markers(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Json(body): Json<ReadMarkersBody>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let state_for_blocking = Arc::clone(&state);

    let wake_ids = tokio::task::spawn_blocking(move || {
        state_for_blocking.conn_scope(|conn: &mut rusqlite::Connection| {
        let room = crate::store::get_room(&conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        ephemeral::apply_read_markers(
            &mut *conn,
            &room,
            user_id,
            body.fully_read.as_deref(),
            body.read.as_deref(),
            body.read_private.as_deref(),
            now_ms,
        )
        })
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    if !wake_ids.is_empty() {
        super::wake_users(&state, wake_ids);
    }
    Ok(Json(serde_json::json!({})))
}

#[cfg(test)]
mod tests {
    use super::routes;
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
    use tower::ServiceExt;

    const T0: &str = "2026-09-24T00:00:00+00:00";
    const ROOM: &str = "!testroom:example.org";

    #[tokio::test]
    async fn typing_as_another_user_returns_403() {
        let mut conn = rusqlite::Connection::open_in_memory().expect("in-memory sqlite");
        crate::store::create_matrix_schema(&conn).expect("matrix schema");
        crate::keys::create_matrix_keys_schema(&conn).expect("keys schema");
        crate::store::create_room(
            &conn,
            ROOM,
            crate::store::RoomKind::Group,
            1,
            T0,
            false,
            crate::store::JoinRule::Invite,
            crate::store::HistoryVisibility::Shared,
            None,
            None,
        )
        .expect("create room");
        let alice = crate::store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000001", T0).expect("alice");
        crate::store::apply_state_event(
            &mut conn,
            &crate::store::StateEventWrite {
                event_id: "$m1",
                room_id: ROOM,
                sender_user_id: 1,
                event_type: "m.room.member",
                state_key: &alice,
                content: r#"{"membership":"join"}"#,
                origin_server_ts: 900,
                now: T0,
            },
        )
        .expect("alice joins");
        let raw = "alice-token";
        let hash = crate::http::hash_token(raw);
        crate::keys::create_device(&conn, 1, crate::keys::CredentialKind::Bearer, &hash, T0).expect("device");

        let app = routes().with_state(Arc::new(crate::http::Homeserver::new(conn)));
        let other = "@bob000000000000000000000000002:example.org";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/client/v3/rooms/{ROOM}/typing/{other}"))
                    .header(header::AUTHORIZATION, format!("Bearer {raw}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"typing":true}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(value["errcode"], "M_FORBIDDEN");
        assert_eq!(value["error"], "userId must be the caller's own mxid");
    }
}
