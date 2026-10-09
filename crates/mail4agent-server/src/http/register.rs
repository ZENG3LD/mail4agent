//! `POST /client/v3/register`. One route, no `/_matrix` prefix.
//!
//! The client sends a public id (mxid localpart), a session nick, and a
//! session id it chose. The server creates the matrix user if needed, creates
//! one device if that user has none, and inserts the session row. The raw
//! device bearer is minted here, returned in this response only when this
//! call created the device, and stored only as [`super::hash_token`]. A
//! repeat of the same session id returns the existing ids and no secret.
//! A later session on a user who already has a device also gets no secret:
//! one bearer per device, and the raw value is not kept.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::error::MatrixError;
use crate::keys::CredentialKind;
use crate::nick;

use super::Homeserver;

#[derive(Deserialize)]
struct RegisterRequest {
    public_id: String,
    nick: String,
    session_id: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    user_id: String,
    device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
}

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new().route("/client/v3/register", post(register))
}

async fn register(
    State(state): State<Arc<Homeserver>>,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, MatrixError> {
    if state.self_register_disabled.get().is_some() {
        return Err(MatrixError::forbidden("self-registration is disabled on this server"));
    }
    let state = Arc::clone(&state);
    let response = tokio::task::spawn_blocking(move || {
        let mut conn = state.conn.lock().unwrap_or_else(|err| err.into_inner());
        register_on(&mut conn, body)
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    Ok(Json(response))
}

fn register_on(
    conn: &mut Connection,
    body: RegisterRequest,
) -> Result<RegisterResponse, MatrixError> {
    validate_session_id(&body.session_id)?;
    if let Some(existing) = nick::session_by_id(conn, &body.session_id)? {
        return registered_without_secret(conn, &existing);
    }
    let public_id = body.public_id.trim();
    validate_public_id(public_id)?;
    let nick_value = nick::normalize_nick(&body.nick)?;
    let now = chrono::Utc::now().to_rfc3339();

    let tx = conn.transaction()?;
    let (user_id, mxid) = ensure_user(&tx, public_id, &now)?;
    let legacy = nick::legacy_session_id(user_id);
    let replace_legacy = nick::session_by_id(&tx, &legacy)?
        .is_some_and(|session| session.user_id == user_id && session.device_id.is_empty());
    let except = if replace_legacy {
        Some(legacy.as_str())
    } else {
        None
    };
    if nick::nick_taken(&tx, &nick_value, except)? {
        return Err(MatrixError::invalid_param("nick is taken"));
    }
    let (device_id, raw) = device_for_user(&tx, user_id, &now)?;
    nick::save_session(
        &tx,
        &body.session_id,
        user_id,
        &device_id,
        &nick_value,
        replace_legacy,
    )?;
    tx.commit()?;
    Ok(RegisterResponse {
        user_id: mxid,
        device_id,
        access_token: raw,
    })
}

fn registered_without_secret(
    conn: &Connection,
    existing: &nick::MessengerSession,
) -> Result<RegisterResponse, MatrixError> {
    if existing.device_id.is_empty() {
        return Err(MatrixError::internal());
    }
    let mxid = crate::store::mxid_of(conn, existing.user_id)?.ok_or_else(MatrixError::internal)?;
    Ok(RegisterResponse {
        user_id: mxid,
        device_id: existing.device_id.clone(),
        access_token: None,
    })
}

fn ensure_user(
    conn: &Connection,
    public_id: &str,
    now: &str,
) -> Result<(i64, String), MatrixError> {
    let mxid = crate::store::mxid_for_public_id(public_id);
    if let Some(user_id) = crate::store::user_id_of(conn, &mxid)? {
        return Ok((user_id, mxid));
    }
    let user_id: i64 = conn.query_row(
        "SELECT COALESCE(MAX(user_id), 0) + 1 FROM matrix_users",
        [],
        |row| row.get(0),
    )?;
    let mxid = crate::store::ensure_matrix_user(conn, user_id, public_id, now)?;
    Ok((user_id, mxid))
}

/// The user's existing device, or one new device and its raw bearer.
/// The raw bearer leaves this function only as the `Option` the HTTP
/// response serializes. Callers must not log it or write it down.
fn device_for_user(
    conn: &Connection,
    user_id: i64,
    now: &str,
) -> Result<(String, Option<String>), MatrixError> {
    let existing: Option<String> = conn
        .query_row(
            "SELECT device_id FROM devices WHERE user_id = ?1 ORDER BY created_at, device_id LIMIT 1",
            params![user_id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(device_id) = existing {
        return Ok((device_id, None));
    }
    let raw = mint_bearer();
    let hash = super::hash_token(&raw);
    let device_id = crate::keys::create_device(conn, user_id, CredentialKind::Bearer, &hash, now)?;
    Ok((device_id, Some(raw)))
}

fn mint_bearer() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn validate_public_id(public_id: &str) -> Result<(), MatrixError> {
    if public_id.is_empty()
        || public_id.len() > 255
        || public_id
            .chars()
            .any(|c| c.is_whitespace() || c == ':' || c == '@' || c == '/')
    {
        return Err(MatrixError::invalid_param(
            "public_id must be one localpart",
        ));
    }
    Ok(())
}

fn validate_session_id(session_id: &str) -> Result<(), MatrixError> {
    if session_id.is_empty()
        || session_id.len() > 128
        || session_id.starts_with("legacy-user-")
        || session_id
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(MatrixError::invalid_param(
            "session_id must be 1..=128 without whitespace",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
    use tower::ServiceExt;

    use crate::http::{hash_token, router, Homeserver};
    use crate::keys::{create_device, create_matrix_keys_schema, CredentialKind};
    use crate::store::{create_matrix_schema, ensure_matrix_user, mxid_for_public_id};

    const NOW: &str = "2026-10-05T00:00:00+00:00";

    fn homeserver() -> Arc<Homeserver> {
        let conn = rusqlite::Connection::open_in_memory().expect("memory");
        create_matrix_schema(&conn).expect("schema");
        create_matrix_keys_schema(&conn).expect("keys");
        Arc::new(Homeserver::new(conn))
    }

    async fn post_json(
        state: &Arc<Homeserver>,
        path: &str,
        body: serde_json::Value,
        bearer: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::post(path).header(header::CONTENT_TYPE, "application/json");
        if let Some(bearer) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        let response = router(Arc::clone(state))
            .oneshot(
                builder
                    .body(Body::from(serde_json::to_vec(&body).expect("json")))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    fn take_token(value: &mut serde_json::Value) -> Option<String> {
        value
            .as_object_mut()
            .and_then(|object| object.remove("access_token"))
            .and_then(|token| match token {
                serde_json::Value::String(token) => Some(token),
                _ => None,
            })
    }

    #[tokio::test]
    async fn register_mints_a_bearer_once_and_stores_only_its_hash() {
        let state = homeserver();
        let (status, mut body) = post_json(
            &state,
            "/client/v3/register",
            serde_json::json!({
                "public_id": "alicepub",
                "nick": "alice_nick",
                "session_id": "session-alice-1",
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let token = take_token(&mut body).expect("first response has a bearer");
        let token_len = token.len();
        let token_is_url_safe = token
            .bytes()
            .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'));
        assert!(token_len >= 43, "bearer must be at least 32 url-safe bytes");
        assert!(token_is_url_safe);
        let mxid = mxid_for_public_id("alicepub");
        assert_eq!(body["user_id"], mxid);
        let device_id = body["device_id"].as_str().expect("device").to_string();
        assert!(!device_id.is_empty());

        {
            let conn = state.conn.lock().unwrap_or_else(|err| err.into_inner());
            let stored: String = conn
                .query_row(
                    "SELECT credential_ref FROM devices WHERE device_id = ?1",
                    [device_id.as_str()],
                    |row| row.get(0),
                )
                .expect("hash");
            assert_eq!(stored.len(), 64);
            assert!(stored.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(stored, hash_token(&token));
            let session_nick: String = conn
                .query_row(
                    "SELECT nick FROM messenger_sessions WHERE session_id = 'session-alice-1'",
                    [],
                    |row| row.get(0),
                )
                .expect("nick");
            assert_eq!(session_nick, "alice_nick");
            let column: Option<String> = conn
                .query_row(
                    "SELECT nick FROM matrix_users WHERE mxid = ?1",
                    [mxid.as_str()],
                    |row| row.get(0),
                )
                .expect("column");
            assert!(column.is_none());
            let devices: i64 = conn
                .query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))
                .expect("count");
            assert_eq!(devices, 1);
        }

        let (status, mut replay) = post_json(
            &state,
            "/client/v3/register",
            serde_json::json!({
                "public_id": "alicepub",
                "nick": "other_nick",
                "session_id": "session-alice-1",
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let replay_leaked = take_token(&mut replay).is_some();
        assert!(!replay_leaked);
        assert_eq!(replay["user_id"], mxid);
        assert_eq!(replay["device_id"], device_id);
        {
            let conn = state.conn.lock().unwrap_or_else(|err| err.into_inner());
            let session_nick: String = conn
                .query_row(
                    "SELECT nick FROM messenger_sessions WHERE session_id = 'session-alice-1'",
                    [],
                    |row| row.get(0),
                )
                .expect("nick");
            assert_eq!(session_nick, "alice_nick");
        }

        let (status, mut second) = post_json(
            &state,
            "/client/v3/register",
            serde_json::json!({
                "public_id": "alicepub",
                "nick": "alice_two",
                "session_id": "session-alice-2",
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let second_leaked = take_token(&mut second).is_some();
        assert!(!second_leaked);
        assert_eq!(second["device_id"], device_id);
        {
            let conn = state.conn.lock().unwrap_or_else(|err| err.into_inner());
            let devices: i64 = conn
                .query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))
                .expect("count");
            assert_eq!(devices, 1);
            let sessions: i64 = conn
                .query_row("SELECT COUNT(*) FROM messenger_sessions", [], |row| {
                    row.get(0)
                })
                .expect("sessions");
            assert_eq!(sessions, 2);
        }

        let response = router(Arc::clone(&state))
            .oneshot(
                Request::get("/client/v3/account/whoami")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("whoami");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let who: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(who["user_id"], mxid);
        assert_eq!(who["device_id"], device_id);
        assert_eq!(who["is_guest"], false);
    }

    #[tokio::test]
    async fn register_reuses_an_existing_device_without_a_bearer() {
        let state = homeserver();
        let mxid = {
            let conn = state.conn.lock().unwrap_or_else(|err| err.into_inner());
            let mxid = ensure_matrix_user(&conn, 7, "bobpub", NOW).expect("user");
            let device_id = create_device(
                &conn,
                7,
                CredentialKind::Bearer,
                &hash_token("already-issued"),
                NOW,
            )
            .expect("device");
            (mxid, device_id)
        };
        let (status, mut body) = post_json(
            &state,
            "/client/v3/register",
            serde_json::json!({
                "public_id": "bobpub",
                "nick": "bob_nick",
                "session_id": "session-bob",
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let leaked = take_token(&mut body).is_some();
        assert!(!leaked);
        assert_eq!(body["user_id"], mxid.0);
        assert_eq!(body["device_id"], mxid.1);
        let conn = state.conn.lock().unwrap_or_else(|err| err.into_inner());
        let devices: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM devices WHERE user_id = 7",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(devices, 1);
        let nick: String = conn
            .query_row(
                "SELECT nick FROM messenger_sessions WHERE session_id = 'session-bob'",
                [],
                |row| row.get(0),
            )
            .expect("nick");
        assert_eq!(nick, "bob_nick");
    }

    #[tokio::test]
    async fn self_registration_can_be_switched_off() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        create_matrix_schema(&conn).unwrap();
        create_matrix_keys_schema(&conn).unwrap();
        let hs = Arc::new(Homeserver::new(conn));
        let _ = hs.self_register_disabled.set(());
        let req = Request::post("/client/v3/register").header("content-type", "application/json")
            .body(Body::from(r#"{"public_id":"abcdefgh","nick":"abcdefgh","session_id":"s1"}"#)).unwrap();
        let resp = crate::http::router(hs).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
