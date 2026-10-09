//! Account data, tags, filters, profile, directory search, public rooms, and whoami.
//! Paths have no `/_matrix` prefix. Display names come from nicks.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use axum::{Json, Router};

use crate::account;
use crate::error::MatrixError;

use super::Homeserver;

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new()
        .route(
            "/client/v3/user/{user_id}/account_data/{event_type}",
            get(get_account_data_global).put(put_account_data_global),
        )
        .route(
            "/client/v3/user/{user_id}/rooms/{room_id}/account_data/{event_type}",
            get(get_account_data_room).put(put_account_data_room),
        )
        .route("/client/v3/user/{user_id}/rooms/{room_id}/tags", get(get_tags))
        .route(
            "/client/v3/user/{user_id}/rooms/{room_id}/tags/{tag}",
            put(put_tag).delete(delete_tag),
        )
        .route("/client/v3/user/{user_id}/filter", post(post_filter))
        .route("/client/v3/user/{user_id}/filter/{filter_id}", get(get_filter))
        .route("/client/v3/profile/{user_id}", get(get_profile))
        .route(
            "/client/v3/profile/{user_id}/displayname",
            get(get_profile_displayname).put(put_displayname),
        )
        .route("/client/v3/user_directory/search", post(user_directory_search))
        .route("/client/v3/publicRooms", get(get_public_rooms).post(post_public_rooms))
        .route("/client/v3/account/whoami", get(whoami))
}

async fn whoami(State(state): State<Arc<Homeserver>>, headers: HeaderMap) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    Ok(Json(account::whoami_response(&caller.mxid, &caller.device_id)))
}

async fn get_account_data_global(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((user_id, event_type)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    account::check_caller_owns_user_id(&user_id, &caller.mxid)?;
    let owner = caller.user_id;
    let content = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let conn = state.conn.lock().unwrap_or_else(|e| e.into_inner());
        let row = crate::store::get_account_data(&conn, owner, crate::store::GLOBAL_ACCOUNT_DATA_ROOM, &event_type)?
            .ok_or_else(|| MatrixError::not_found("no account data of this type"))?;
        Ok(serde_json::from_str(&row.content)?)
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    Ok(Json(content))
}

async fn put_account_data_global(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((user_id, event_type)): Path<(String, String)>,
    Json(content): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    account::check_caller_owns_user_id(&user_id, &caller.mxid)?;
    account::check_account_data_type_allowed(&event_type)?;
    let content_str = account::validate_account_data_content(&content)?;
    let state_db = Arc::clone(&state);
    let owner = caller.user_id;
    tokio::task::spawn_blocking(move || -> Result<(), MatrixError> {
        let mut conn = state_db.conn.lock().unwrap_or_else(|e| e.into_inner());
        crate::store::upsert_account_data(&mut conn, owner, crate::store::GLOBAL_ACCOUNT_DATA_ROOM, &event_type, &content_str)?;
        Ok(())
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    super::wake_users(&state, [caller.user_id]);
    Ok(Json(serde_json::json!({})))
}

async fn get_account_data_room(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((user_id, room_id, event_type)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    account::check_caller_owns_user_id(&user_id, &caller.mxid)?;
    let owner = caller.user_id;
    let content = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let conn = state.conn.lock().unwrap_or_else(|e| e.into_inner());
        require_room(&conn, &room_id, owner, false)?;
        let row = crate::store::get_account_data(&conn, owner, &room_id, &event_type)?
            .ok_or_else(|| MatrixError::not_found("no account data of this type"))?;
        Ok(serde_json::from_str(&row.content)?)
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    Ok(Json(content))
}

async fn put_account_data_room(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((user_id, room_id, event_type)): Path<(String, String, String)>,
    Json(content): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    account::check_caller_owns_user_id(&user_id, &caller.mxid)?;
    account::check_account_data_type_allowed(&event_type)?;
    let content_str = account::validate_account_data_content(&content)?;
    let state_db = Arc::clone(&state);
    let owner = caller.user_id;
    tokio::task::spawn_blocking(move || -> Result<(), MatrixError> {
        let mut conn = state_db.conn.lock().unwrap_or_else(|e| e.into_inner());
        require_room(&conn, &room_id, owner, false)?;
        crate::store::upsert_account_data(&mut conn, owner, &room_id, &event_type, &content_str)?;
        Ok(())
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    super::wake_users(&state, [caller.user_id]);
    Ok(Json(serde_json::json!({})))
}

async fn get_tags(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((user_id, room_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    account::check_caller_owns_user_id(&user_id, &caller.mxid)?;
    let owner = caller.user_id;
    let tags = tokio::task::spawn_blocking(move || -> Result<serde_json::Map<String, serde_json::Value>, MatrixError> {
        let conn = state.conn.lock().unwrap_or_else(|e| e.into_inner());
        require_room(&conn, &room_id, owner, true)?;
        account::read_tags(&conn, owner, &room_id)
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    Ok(Json(serde_json::json!({ "tags": tags })))
}

async fn put_tag(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((user_id, room_id, tag)): Path<(String, String, String)>,
    Json(body): Json<account::TagBody>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    account::check_caller_owns_user_id(&user_id, &caller.mxid)?;
    let state_db = Arc::clone(&state);
    let owner = caller.user_id;
    let order = body.order;
    tokio::task::spawn_blocking(move || -> Result<(), MatrixError> {
        let mut conn = state_db.conn.lock().unwrap_or_else(|e| e.into_inner());
        require_room(&conn, &room_id, owner, true)?;
        account::apply_tag_put(&mut conn, owner, &room_id, &tag, order)
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    super::wake_users(&state, [caller.user_id]);
    Ok(Json(serde_json::json!({})))
}

async fn delete_tag(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((user_id, room_id, tag)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    account::check_caller_owns_user_id(&user_id, &caller.mxid)?;
    let state_db = Arc::clone(&state);
    let owner = caller.user_id;
    tokio::task::spawn_blocking(move || -> Result<(), MatrixError> {
        let mut conn = state_db.conn.lock().unwrap_or_else(|e| e.into_inner());
        require_room(&conn, &room_id, owner, true)?;
        account::apply_tag_delete(&mut conn, owner, &room_id, &tag)
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    super::wake_users(&state, [caller.user_id]);
    Ok(Json(serde_json::json!({})))
}

async fn post_filter(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    account::check_caller_owns_user_id(&user_id, &caller.mxid)?;
    let definition = account::validate_filter_definition(&body)?;
    let owner = caller.user_id;
    let filter_id = tokio::task::spawn_blocking(move || -> Result<i64, MatrixError> {
        let conn = state.conn.lock().unwrap_or_else(|e| e.into_inner());
        Ok(crate::store::create_filter(&conn, owner, &definition)?)
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    Ok(Json(serde_json::json!({ "filter_id": filter_id.to_string() })))
}

async fn get_filter(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path((user_id, filter_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    account::check_caller_owns_user_id(&user_id, &caller.mxid)?;
    let filter_id: i64 = filter_id.parse().map_err(|_| MatrixError::invalid_param("filterId must be numeric"))?;
    let owner = caller.user_id;
    let content = tokio::task::spawn_blocking(move || -> Result<String, MatrixError> {
        let conn = state.conn.lock().unwrap_or_else(|e| e.into_inner());
        crate::store::get_filter(&conn, owner, filter_id)?.ok_or_else(|| MatrixError::not_found("no such filter"))
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    Ok(Json(serde_json::from_str(&content)?))
}

async fn get_profile(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    profile_response(state, headers, user_id).await
}

async fn get_profile_displayname(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    profile_response(state, headers, user_id).await
}

async fn profile_response(
    state: Arc<Homeserver>,
    headers: HeaderMap,
    mxid: String,
) -> Result<Json<serde_json::Value>, MatrixError> {
    super::resolve_caller(&state, &headers, None).await?;
    let displayname = tokio::task::spawn_blocking(move || -> Result<String, MatrixError> {
        let conn = state.conn.lock().unwrap_or_else(|e| e.into_inner());
        let user_id = crate::store::user_id_of(&conn, &mxid)?.ok_or_else(|| MatrixError::not_found("unknown user"))?;
        Ok(crate::nick::effective_label(&conn, user_id)?)
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    Ok(Json(serde_json::json!({ "displayname": displayname })))
}

async fn put_displayname(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let caller = super::resolve_caller(&state, &headers, None).await?;
    // Account-backed callers change their nick through the display name; others keep the refusal.
    if user_id == caller.mxid {
        if let Some(name) = body.get("displayname").and_then(|v| v.as_str()) {
            state.check_policy(&caller, crate::policy::Action::SetNick, None)?;
            if super::identity::set_display_name(&state, caller.user_id, name.to_string()).await?.is_some() {
                return Ok(Json(serde_json::json!({})));
            }
        }
    }
    Err(MatrixError::forbidden("displayname follows your nick — change it in account settings, not here"))
}

async fn user_directory_search(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Json(req): Json<account::UserDirectorySearchRequest>,
) -> Result<Json<account::UserDirectorySearchResponse>, MatrixError> {
    super::resolve_caller(&state, &headers, None).await?;
    let term = req.search_term.trim().to_string();
    if term.is_empty() {
        return Err(MatrixError::invalid_param("search_term must not be empty"));
    }
    let limit = match req.limit {
        Some(limit) => limit.clamp(1, account::MAX_DIRECTORY_RESULTS as i64) as usize,
        None => account::DEFAULT_DIRECTORY_RESULTS,
    };
    let response = tokio::task::spawn_blocking(move || -> Result<account::UserDirectorySearchResponse, MatrixError> {
        let conn = state.conn.lock().unwrap_or_else(|e| e.into_inner());
        let (hits, limited) = crate::nick::search_nicks(&conn, &term, limit)?;
        let results = hits
            .into_iter()
            .map(|hit| account::UserDirectoryResult { user_id: hit.mxid, display_name: hit.nick })
            .collect();
        Ok(account::UserDirectorySearchResponse { results, limited })
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    Ok(Json(response))
}

async fn get_public_rooms(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Query(query): Query<account::PublicRoomsQuery>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    public_rooms(state, headers, query.since, query.limit, None).await
}

async fn post_public_rooms(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Json(body): Json<account::PublicRoomsRequestBody>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    public_rooms(state, headers, body.since, body.limit, body.filter.generic_search_term).await
}

async fn public_rooms(
    state: Arc<Homeserver>,
    headers: HeaderMap,
    since: Option<String>,
    limit: Option<i64>,
    search_term: Option<String>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    super::resolve_caller(&state, &headers, None).await?;
    let response = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let conn = state.conn.lock().unwrap_or_else(|e| e.into_inner());
        account::list_public_rooms(&conn, since.as_deref(), limit, search_term.as_deref())
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    Ok(Json(response))
}

/// Joined members for per-room account data. Tags also allow an invite.
fn require_room(conn: &rusqlite::Connection, room_id: &str, user_id: i64, allow_invite: bool) -> Result<(), MatrixError> {
    crate::store::get_room(conn, room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
    let membership = crate::store::room_member(conn, room_id, user_id)?.map(|member| member.membership);
    if allow_invite {
        account::require_member_or_invited(membership)
    } else {
        account::require_member(membership)
    }
}

#[cfg(test)]
mod tests {
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn whoami_with_bearer_returns_mxid_and_device_id() {
        let conn = rusqlite::Connection::open_in_memory().expect("memory");
        crate::store::create_matrix_schema(&conn).expect("schema");
        crate::keys::create_matrix_keys_schema(&conn).expect("keys schema");
        let mxid = crate::store::ensure_matrix_user(&conn, 1, "alice000000000000000000000000a1", "2026-10-05T00:00:00+00:00")
            .expect("user");
        let raw = "whoami-bearer";
        let device_id = crate::keys::create_device(
            &conn,
            1,
            crate::keys::CredentialKind::Bearer,
            &crate::http::hash_token(raw),
            "2026-10-05T00:00:00+00:00",
        )
        .expect("device");
        let app = crate::http::router(std::sync::Arc::new(crate::http::Homeserver::new(conn)));
        let response = app
            .oneshot(
                Request::get("/client/v3/account/whoami")
                    .header(header::AUTHORIZATION, format!("Bearer {raw}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.expect("body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(value, serde_json::json!({ "user_id": mxid, "device_id": device_id, "is_guest": false }));
    }
}
