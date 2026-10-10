use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};

use crate::error::MatrixError;
use crate::live::WaitOutcome;

use super::{Caller, Homeserver};

#[derive(serde::Deserialize, Default)]
struct SyncQuery {
    #[serde(default)]
    set_presence: Option<String>,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    timeout: Option<u64>,
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    full_state: Option<bool>,
    #[serde(default)]
    access_token: Option<String>,
}

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new().route("/client/v3/sync", get(sync_handler))
}

async fn sync_handler(
    State(state): State<Arc<Homeserver>>,
    headers: HeaderMap,
    Query(query): Query<SyncQuery>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    let Caller { user_id, mxid, device_id, .. } = super::resolve_caller(&state, &headers, query.access_token.as_deref()).await?;
    if super::presence::enabled() && query.set_presence.as_deref().is_none_or(|p| p == "online") {
        // A client that is syncing is active: keep an "online" user from going idle.
        let now = chrono::Utc::now().timestamp_millis();
        let _ = super::with_conn_pub(&state, move |c| {
            let _ = c.execute("UPDATE presence SET last_active_ms = ?2 WHERE user_id = ?1 AND state = 'online' AND last_active_ms < ?2 - 60000", rusqlite::params![user_id, now]);
            Ok(())
        })
        .await;
    }
    let since = query.since.as_deref().map(crate::sync_token::parse).transpose()?;
    let timeout = Duration::from_millis(query.timeout.unwrap_or(0).min(crate::sync::SYNC_MAX_TIMEOUT_MS));
    let full_state = query.full_state.unwrap_or(false);

    let filter = {
        let state = Arc::clone(&state);
        let filter_raw = query.filter.clone();
        tokio::task::spawn_blocking(move || -> Result<crate::sync::SyncFilter, MatrixError> {
            state.conn_scope(|conn: &mut rusqlite::Connection| {
            crate::sync::parse_filter_param(&conn, user_id, filter_raw.as_deref())
            })
        })
        .await
        .map_err(|_| MatrixError::internal())??
    };

    let deadline = Instant::now() + timeout;
    loop {
        // Register before the rebuild. The connection guard lives only
        // inside spawn_blocking, so wait never holds it.
        let registration = state.live.register(&format!("user:{user_id}"));
        let response = {
            // The only write of a sync is the device's retention ack: it goes through the writer,
            // the (long) read of the response goes through the parallel readers.
            let since = {
                let device_id = device_id.clone();
                super::with_conn_pub(&state, move |conn| {
                    // A `since` above the server's own stream counter cannot come from this
                    // store (fresh instance, restored backup): answer with an initial sync.
                    let since = match since {
                        Some(t) if t.stream_id > crate::store::max_stream_id(conn)? => None,
                        other => other,
                    };
                    if let Some(token) = since {
                        // `since` proves this device holds everything up to it (retention ack).
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or(0);
                        let _ = crate::retention::record_device_ack(conn, user_id, &device_id, token.stream_id, now_ms);
                    }
                    Ok(since)
                })
                .await?
            };
            let st = Arc::clone(&state);
            let mxid = mxid.clone();
            let device_id = device_id.clone();
            let filter = filter.clone();
            super::with_read_pub(&state, move |conn| {
                crate::sync::build_sync_response(
                    conn,
                    &st.typing,
                    user_id,
                    &mxid,
                    &device_id,
                    since,
                    &filter,
                    full_state,
                    std::time::Instant::now(),
                )
            })
            .await?
        };
        if !crate::sync::sync_response_is_empty(&response) {
            return Ok(Json(response));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(Json(response));
        }
        if registration.wait(remaining).await == WaitOutcome::TimedOut {
            return Ok(Json(response));
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use rusqlite::Connection;
    use tower::ServiceExt;

    const NOW: &str = "2026-10-05T00:00:00+00:00";

    #[tokio::test]
    async fn get_sync_timeout_zero_returns_next_batch() {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        crate::store::create_matrix_schema(&conn).expect("matrix schema");
        crate::keys::create_matrix_keys_schema(&conn).expect("matrix keys schema");
        crate::store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000001", NOW).expect("user");
        let raw = "sync-bearer";
        crate::keys::create_device(&conn, 1, crate::keys::CredentialKind::Bearer, &crate::http::hash_token(raw), NOW).expect("device");

        let app = crate::http::router(std::sync::Arc::new(crate::http::Homeserver::new(conn)));
        let request = Request::get("/client/v3/sync?timeout=0")
            .header(axum::http::header::AUTHORIZATION, format!("Bearer {raw}"))
            .body(Body::empty())
            .expect("request");
        let resp = tokio::time::timeout(std::time::Duration::from_secs(2), app.oneshot(request))
            .await
            .expect("GET /sync hung")
            .expect("response");

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert!(value.get("next_batch").and_then(|v| v.as_str()).is_some(), "missing next_batch: {value}");
    }

    #[tokio::test]
    async fn since_above_the_stream_counter_gives_an_initial_sync() {
        let conn = Connection::open_in_memory().expect("db");
        crate::store::create_matrix_schema(&conn).unwrap();
        crate::keys::create_matrix_keys_schema(&conn).unwrap();
        crate::store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000001", NOW).unwrap();
        crate::keys::create_device(&conn, 1, crate::keys::CredentialKind::Bearer, &crate::http::hash_token("t"), NOW).unwrap();
        crate::nick::set_nick(&conn, 1, "alice").unwrap();
        let app = crate::http::router(std::sync::Arc::new(crate::http::Homeserver::new(conn)));
        let go = |method: &str, uri: String, body: &str| {
            let app = app.clone();
            let req = Request::builder().method(method).uri(uri).header("authorization", "Bearer t").header("content-type", "application/json").body(Body::from(body.to_string())).unwrap();
            async move {
                let r = app.oneshot(req).await.unwrap();
                serde_json::from_slice::<serde_json::Value>(&to_bytes(r.into_body(), usize::MAX).await.unwrap()).unwrap()
            }
        };
        let room = go("POST", "/client/v3/createRoom".into(), r#"{"name":"r","visibility":"public"}"#).await;
        let room_id = room["room_id"].as_str().unwrap().to_string();
        let first = go("GET", "/client/v3/sync?timeout=0".into(), "").await;
        let next = first["next_batch"].as_str().unwrap().to_string();
        assert!(first["rooms"]["join"].get(&room_id).is_some());
        let stream: i64 = next.trim_start_matches('s').split('_').next().unwrap().parse().unwrap();
        let again = go("GET", format!("/client/v3/sync?timeout=0&since={next}"), "").await;
        assert!(again["rooms"]["join"].get(&room_id).is_none(), "incremental at the counter is empty: {again}");
        let above = go("GET", format!("/client/v3/sync?timeout=0&since=s{}_0", stream + 1000), "").await;
        assert!(above["rooms"]["join"].get(&room_id).is_some(), "initial sync expected: {above}");
        assert_eq!(above["next_batch"], first["next_batch"]);
    }
}
