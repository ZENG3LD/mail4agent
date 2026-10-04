//! Client-Server key routes. Paths have no `/_matrix` prefix.
//! Protocol decisions stay in [`crate::key_ops`] and [`crate::keys`].

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};

use crate::error::MatrixError;

use super::Homeserver;

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new()
        .route("/client/v3/keys/upload", post(keys_upload))
        .route("/client/v3/keys/query", post(keys_query))
        .route("/client/v3/keys/claim", post(keys_claim))
        .route("/client/v3/keys/changes", get(keys_changes))
        .route("/client/v3/keys/device_signing/upload", post(device_signing_upload))
        .route("/client/v3/keys/signatures/upload", post(signatures_upload))
        .route("/client/v3/sendToDevice/{event_type}/{txn_id}", put(send_to_device))
        .route("/client/v3/devices", get(list_devices_route))
        .route(
            "/client/v3/devices/{device_id}",
            get(get_device_route).put(put_device_route).delete(delete_device_route),
        )
        .route("/client/v3/delete_devices", post(bulk_delete_devices))
        .route(
            "/client/v3/room_keys/version",
            post(post_backup_version).get(get_current_backup_version),
        )
        .route(
            "/client/v3/room_keys/version/{version}",
            get(get_backup_version_route).put(put_backup_version_route).delete(delete_backup_version_route),
        )
        .route(
            "/client/v3/room_keys/keys",
            get(get_backup_keys_all).put(put_backup_keys_all).delete(delete_backup_keys_all),
        )
        .route(
            "/client/v3/room_keys/keys/{room_id}",
            get(get_backup_keys_room).put(put_backup_keys_room).delete(delete_backup_keys_room),
        )
        .route(
            "/client/v3/room_keys/keys/{room_id}/{session_id}",
            get(get_backup_keys_session).put(put_backup_keys_session).delete(delete_backup_keys_session),
        )
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Database work only. The connection mutex is taken on the blocking thread
/// and dropped before this future resolves.
async fn on_conn<T, F>(state: &Arc<Homeserver>, f: F) -> Result<T, MatrixError>
where
    T: Send + 'static,
    F: FnOnce(&mut rusqlite::Connection) -> Result<T, MatrixError> + Send + 'static,
{
    let state = Arc::clone(state);
    tokio::task::spawn_blocking(move || {
        let mut conn = state.conn.lock().unwrap_or_else(|poison| poison.into_inner());
        f(&mut conn)
    })
    .await
    .map_err(|_| MatrixError::internal())?
}

async fn keys_upload(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Json(request): Json<crate::key_ops::KeysUploadRequest>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let mxid = caller.mxid;
    let device_id = caller.device_id;
    let (otk_counts, wake_ids) = on_conn(&state, move |conn| {
        let now = now_rfc3339();
        let outcome = crate::key_ops::apply_keys_upload(conn, user_id, &mxid, &device_id, &request, &now)?;
        let wake_ids = if outcome.device_keys_changed {
            Some(crate::key_ops::peers_sharing_a_room_with(conn, user_id)?)
        } else {
            None
        };
        Ok((outcome.otk_counts, wake_ids))
    })
    .await?;
    if let Some(wake_ids) = wake_ids {
        super::wake_users(&state, wake_ids);
    }
    Ok(Json(serde_json::json!({ "one_time_key_counts": otk_counts })))
}

async fn keys_query(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Json(request): Json<crate::key_ops::KeysQueryRequest>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let mxid = caller.mxid;
    on_conn(&state, move |conn| {
        crate::key_ops::build_keys_query_response(conn, user_id, &mxid, &request.device_keys)
    })
    .await
    .map(Json)
}

async fn keys_claim(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Json(request): Json<crate::key_ops::KeysClaimRequest>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let cost = crate::key_ops::count_claim_targets(&request.one_time_keys) as f64;
    if !state.claim_rate.try_consume(caller.user_id, cost, Instant::now()) {
        return Err(MatrixError::limit_exceeded(60_000));
    }
    let user_id = caller.user_id;
    on_conn(&state, move |conn| {
        crate::key_ops::build_keys_claim_response(conn, user_id, &request.one_time_keys)
    })
    .await
    .map(Json)
}

async fn keys_changes(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Query(query): Query<crate::key_ops::KeysChangesQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let from = crate::sync_token::parse(query.from.as_deref().ok_or_else(|| MatrixError::invalid_param("from is required"))?)?
        .stream_id;
    let to = crate::sync_token::parse(query.to.as_deref().ok_or_else(|| MatrixError::invalid_param("to is required"))?)?.stream_id;
    on_conn(&state, move |conn| crate::key_ops::build_keys_changes_response(conn, user_id, from, to)).await.map(Json)
}

async fn device_signing_upload(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Json(request): Json<crate::key_ops::DeviceSigningUploadRequest>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let mxid = caller.mxid;
    let wake_ids = on_conn(&state, move |conn| {
        let now = now_rfc3339();
        let wrote = crate::key_ops::apply_device_signing_upload(conn, user_id, &mxid, &request, &now)?;
        if wrote {
            Ok(Some(crate::key_ops::peers_sharing_a_room_with(conn, user_id)?))
        } else {
            Ok(None)
        }
    })
    .await?;
    if let Some(wake_ids) = wake_ids {
        super::wake_users(&state, wake_ids);
    }
    Ok(Json(serde_json::json!({})))
}

async fn signatures_upload(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let mxid = caller.mxid;
    let body = body.as_object().cloned().ok_or_else(|| MatrixError::invalid_param("body must be an object"))?;
    let failures = on_conn(&state, move |conn| {
        let now = now_rfc3339();
        crate::key_ops::apply_signatures_upload(conn, user_id, &mxid, &body, &now)
    })
    .await?;
    Ok(Json(serde_json::json!({ "failures": failures })))
}

async fn send_to_device(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((event_type, txn_id)): Path<(String, String)>,
    Json(body): Json<crate::key_ops::SendToDeviceRequest>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let device_id = caller.device_id;
    let messages = body.messages;
    let wake_ids = on_conn(&state, move |conn| {
        let now = now_rfc3339();
        match crate::key_ops::apply_send_to_device(conn, user_id, &device_id, &event_type, &txn_id, &messages, &now)? {
            crate::key_ops::SendToDeviceOutcome::New(wake_ids) => Ok(wake_ids),
            crate::key_ops::SendToDeviceOutcome::AlreadySent => Ok(std::collections::HashSet::new()),
        }
    })
    .await?;
    if !wake_ids.is_empty() {
        super::wake_users(&state, wake_ids);
    }
    Ok(Json(serde_json::json!({})))
}

async fn list_devices_route(State(state): State<Arc<Homeserver>>, headers: HeaderMap) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    on_conn(&state, move |conn| {
        let devices = crate::keys::list_devices(conn, user_id)?;
        let devices: Vec<_> = devices.iter().map(crate::key_ops::device_to_json).collect();
        Ok(serde_json::json!({ "devices": devices }))
    })
    .await
    .map(Json)
}

async fn get_device_route(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    on_conn(&state, move |conn| {
        let device = crate::keys::get_device(conn, user_id, &device_id)?.ok_or_else(|| MatrixError::not_found("no such device"))?;
        Ok(crate::key_ops::device_to_json(&device))
    })
    .await
    .map(Json)
}

async fn put_device_route(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(body): Json<crate::key_ops::PutDeviceRequest>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let display_name = body.display_name;
    on_conn(&state, move |conn| {
        let updated = crate::keys::set_device_display_name(conn, user_id, &device_id, display_name.as_deref())?;
        if !updated {
            return Err(MatrixError::not_found("no such device"));
        }
        Ok(serde_json::json!({}))
    })
    .await
    .map(Json)
}

async fn delete_device_route(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let deleted = on_conn(&state, move |conn| {
        let now = now_rfc3339();
        Ok(crate::keys::delete_device(conn, user_id, &device_id, &now)?)
    })
    .await?;
    if !deleted {
        return Err(MatrixError::not_found("no such device"));
    }
    // `delete_device` returns no wake set and there is no identity credential to revoke.
    super::wake_users(&state, [user_id]);
    Ok(Json(serde_json::json!({})))
}

async fn bulk_delete_devices(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Json(body): Json<crate::key_ops::DeleteDevicesRequest>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let device_ids = body.devices;
    let deleted_any = on_conn(&state, move |conn| {
        let now = now_rfc3339();
        let mut deleted_any = false;
        for device_id in &device_ids {
            if crate::keys::delete_device(conn, user_id, device_id, &now)? {
                deleted_any = true;
            }
        }
        Ok(deleted_any)
    })
    .await?;
    if deleted_any {
        super::wake_users(&state, [user_id]);
    }
    Ok(Json(serde_json::json!({})))
}

async fn post_backup_version(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Json(body): Json<crate::key_ops::BackupVersionCreateRequest>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    crate::key_ops::validate_backup_algorithm(&body.algorithm)?;
    let algorithm = body.algorithm;
    let auth_data = body.auth_data.to_string();
    let version = on_conn(&state, move |conn| {
        let now = now_rfc3339();
        Ok(crate::keys::create_backup_version(conn, user_id, &algorithm, &auth_data, &now)?)
    })
    .await?;
    Ok(Json(serde_json::json!({ "version": version.to_string() })))
}

async fn get_current_backup_version(State(state): State<Arc<Homeserver>>, headers: HeaderMap) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    on_conn(&state, move |conn| {
        let row = crate::keys::current_backup_version(conn, user_id)?.ok_or_else(|| MatrixError::not_found("no key backup exists"))?;
        let (count, _) = crate::keys::backup_count_and_etag(conn, user_id, row.version)?;
        crate::key_ops::backup_version_to_response(&row, count)
    })
    .await
    .map(Json)
}

async fn get_backup_version_route(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(version): Path<String>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let version = version.parse::<i64>().map_err(|_| MatrixError::invalid_param("version must be an integer"))?;
    on_conn(&state, move |conn| {
        let row = crate::keys::get_backup_version(conn, user_id, version)?
            .filter(|row| !row.is_deleted)
            .ok_or_else(|| MatrixError::not_found("no such backup version"))?;
        let (count, _) = crate::keys::backup_count_and_etag(conn, user_id, version)?;
        crate::key_ops::backup_version_to_response(&row, count)
    })
    .await
    .map(Json)
}

async fn put_backup_version_route(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(version): Path<String>,
    Json(body): Json<crate::key_ops::BackupVersionUpdateRequest>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let version = version.parse::<i64>().map_err(|_| MatrixError::invalid_param("version must be an integer"))?;
    let algorithm = body.algorithm;
    let auth_data = body.auth_data.to_string();
    on_conn(&state, move |conn| {
        let existing = crate::keys::get_backup_version(conn, user_id, version)?
            .filter(|row| !row.is_deleted)
            .ok_or_else(|| MatrixError::not_found("no such backup version"))?;
        if let Some(algorithm) = &algorithm {
            if algorithm != &existing.algorithm {
                return Err(MatrixError::invalid_param("a backup version's algorithm cannot change"));
            }
        }
        crate::keys::update_backup_version_auth_data(conn, user_id, version, &auth_data)?;
        Ok(serde_json::json!({}))
    })
    .await
    .map(Json)
}

async fn delete_backup_version_route(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(version): Path<String>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let version = version.parse::<i64>().map_err(|_| MatrixError::invalid_param("version must be an integer"))?;
    let deleted = on_conn(&state, move |conn| Ok(crate::keys::delete_backup_version(conn, user_id, version)?)).await?;
    if !deleted {
        return Err(MatrixError::not_found("no such backup version"));
    }
    Ok(Json(serde_json::json!({})))
}

async fn get_backup_keys_inner(
    state: Arc<Homeserver>,
    headers: HeaderMap,
    room_id: Option<String>,
    session_id: Option<String>,
    version_query: crate::key_ops::VersionQuery,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let version = crate::key_ops::parse_required_version(version_query.version.as_deref())?;
    on_conn(&state, move |conn| {
        crate::key_ops::require_current_backup_version(conn, user_id, version)?;
        let sessions = crate::keys::get_backup_sessions(conn, user_id, version, room_id.as_deref(), session_id.as_deref())?;
        crate::key_ops::backup_sessions_to_response(room_id.as_deref(), session_id.as_deref(), sessions)
    })
    .await
    .map(Json)
}

async fn get_backup_keys_all(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Query(query): Query<crate::key_ops::VersionQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    get_backup_keys_inner(state, headers, None, None, query).await
}

async fn get_backup_keys_room(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Query(query): Query<crate::key_ops::VersionQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    get_backup_keys_inner(state, headers, Some(room_id), None, query).await
}

async fn get_backup_keys_session(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(query): Query<crate::key_ops::VersionQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    get_backup_keys_inner(state, headers, Some(room_id), Some(session_id), query).await
}

async fn put_backup_keys_inner(
    state: Arc<Homeserver>,
    headers: HeaderMap,
    room_id: Option<String>,
    session_id: Option<String>,
    version_query: crate::key_ops::VersionQuery,
    body: serde_json::Value,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let version = crate::key_ops::parse_required_version(version_query.version.as_deref())?;
    let sessions = crate::key_ops::normalize_put_backup_body(room_id.as_deref(), session_id.as_deref(), &body)?;
    on_conn(&state, move |conn| {
        let now = now_rfc3339();
        match crate::keys::put_backup_sessions(conn, user_id, version, &sessions, &now) {
            Ok(()) => {}
            Err(crate::keys::MatrixKeysStoreError::WrongBackupVersion) => {
                let current = crate::keys::current_backup_version(conn, user_id)?;
                return Err(MatrixError::wrong_room_keys_version(current.map(|row| row.version)));
            }
            Err(err) => return Err(err.into()),
        }
        let (count, etag) = crate::keys::backup_count_and_etag(conn, user_id, version)?;
        Ok(serde_json::json!({ "etag": etag.to_string(), "count": count }))
    })
    .await
    .map(Json)
}

async fn put_backup_keys_all(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Query(query): Query<crate::key_ops::VersionQuery>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, MatrixError> {
    put_backup_keys_inner(state, headers, None, None, query, body).await
}

async fn put_backup_keys_room(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Query(query): Query<crate::key_ops::VersionQuery>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, MatrixError> {
    put_backup_keys_inner(state, headers, Some(room_id), None, query, body).await
}

async fn put_backup_keys_session(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(query): Query<crate::key_ops::VersionQuery>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, MatrixError> {
    put_backup_keys_inner(state, headers, Some(room_id), Some(session_id), query, body).await
}

async fn delete_backup_keys_inner(
    state: Arc<Homeserver>,
    headers: HeaderMap,
    room_id: Option<String>,
    session_id: Option<String>,
    version_query: crate::key_ops::VersionQuery,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    let user_id = caller.user_id;
    let version = crate::key_ops::parse_required_version(version_query.version.as_deref())?;
    on_conn(&state, move |conn| {
        crate::key_ops::require_current_backup_version(conn, user_id, version)?;
        crate::keys::delete_backup_sessions(conn, user_id, version, room_id.as_deref(), session_id.as_deref())?;
        let (count, etag) = crate::keys::backup_count_and_etag(conn, user_id, version)?;
        Ok(serde_json::json!({ "etag": etag.to_string(), "count": count }))
    })
    .await
    .map(Json)
}

async fn delete_backup_keys_all(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Query(query): Query<crate::key_ops::VersionQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    delete_backup_keys_inner(state, headers, None, None, query).await
}

async fn delete_backup_keys_room(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Query(query): Query<crate::key_ops::VersionQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    delete_backup_keys_inner(state, headers, Some(room_id), None, query).await
}

async fn delete_backup_keys_session(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(query): Query<crate::key_ops::VersionQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    delete_backup_keys_inner(state, headers, Some(room_id), Some(session_id), query).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use rusqlite::Connection;
    use tower::ServiceExt;

    #[tokio::test]
    async fn get_devices_includes_the_bearer_device() {
        const RAW: &str = "test-bearer-token";
        const NOW: &str = "2026-10-05T00:00:00+00:00";

        let conn = Connection::open_in_memory().expect("memory");
        crate::store::create_matrix_schema(&conn).expect("schema");
        crate::keys::create_matrix_keys_schema(&conn).expect("keys schema");
        crate::store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000001", NOW).expect("user");
        let device_id = crate::keys::create_device(
            &conn,
            1,
            crate::keys::CredentialKind::Bearer,
            &crate::http::hash_token(RAW),
            NOW,
        )
        .expect("device");
        let app = crate::http::router(Arc::new(crate::http::Homeserver::new(conn)));
        let response = app
            .oneshot(
                Request::get("/client/v3/devices")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {RAW}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.expect("body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let devices = value["devices"].as_array().expect("devices");
        assert!(devices.iter().any(|device| device["device_id"].as_str() == Some(device_id.as_str())));
    }
}
