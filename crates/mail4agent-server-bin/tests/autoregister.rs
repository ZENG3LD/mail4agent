//! Register on the in-process router, then open the client store with the
//! bearer that response returned. The bearer is not printed.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use mail4agent_messenger_shell::{DeviceId, OpenedStore};
use mail4agent_server::http::{hash_token, router, Homeserver};
use mail4agent_server::keys::create_matrix_keys_schema;
use mail4agent_server::store::{self, create_matrix_schema};
use tower::ServiceExt;

fn take_token(value: &mut serde_json::Value) -> Option<String> {
    value
        .as_object_mut()
        .and_then(|object| object.remove("access_token"))
        .and_then(|token| match token {
            serde_json::Value::String(token) => Some(token),
            _ => None,
        })
}

fn open_store(
    dir: &std::path::Path,
    session_id: &str,
    device_id: &str,
    user_id: &str,
    token: &str,
) -> OpenedStore {
    let device = DeviceId::parse(device_id).expect("device id");
    OpenedStore::open(
        dir,
        session_id,
        device,
        user_id,
        "localhost",
        "http://127.0.0.1:9",
        token,
    )
    .expect("open store")
}

#[test]
fn register_against_the_router_opens_the_store_and_whoami() {
    store::set_matrix_server_name("localhost").expect("server name once");
    let conn = rusqlite::Connection::open_in_memory().expect("memory");
    create_matrix_schema(&conn).expect("schema");
    create_matrix_keys_schema(&conn).expect("keys");
    let state = Arc::new(Homeserver::new(conn));

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let (token, user_id, device_id) = runtime.block_on(async {
        let response = router(Arc::clone(&state))
            .oneshot(
                Request::post("/client/v3/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "public_id": "carolpub",
                            "nick": "carol_nick",
                            "session_id": "session-carol",
                        }))
                        .expect("json"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("register");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let mut body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let token = take_token(&mut body).expect("bearer is returned once");
        let user_id = body["user_id"].as_str().expect("user").to_string();
        let device_id = body["device_id"].as_str().expect("device").to_string();
        (token, user_id, device_id)
    });
    // The shell's blocking HTTP client builds its own runtime.
    drop(runtime);

    assert!(token.len() >= 43);
    assert!(token
        .bytes()
        .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')));
    assert_eq!(user_id, "@carolpub:localhost");

    let dir = PathBuf::from(format!(
        "/tmp/m4a-autoregister-{}-{}",
        std::process::id(),
        "carol"
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let _store = open_store(&dir, "session-carol", &device_id, &user_id, &token);
    let _ = std::fs::remove_dir_all(&dir);

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let who = router(Arc::clone(&state))
            .oneshot(
                Request::get("/client/v3/account/whoami")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("whoami");
        assert_eq!(who.status(), StatusCode::OK);
        let bytes = to_bytes(who.into_body(), usize::MAX).await.expect("body");
        let who: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(who["user_id"], user_id);
        assert_eq!(who["device_id"], device_id);
    });

    let conn = state.conn.lock().unwrap_or_else(|err| err.into_inner());
    let nick: String = conn
        .query_row(
            "SELECT nick FROM messenger_sessions WHERE session_id = 'session-carol'",
            [],
            |row| row.get(0),
        )
        .expect("session nick");
    assert_eq!(nick, "carol_nick");
    let stored: String = conn
        .query_row(
            "SELECT credential_ref FROM devices WHERE device_id = ?1",
            [device_id.as_str()],
            |row| row.get(0),
        )
        .expect("hash");
    assert_eq!(stored, hash_token(&token));
    assert_ne!(stored.len(), token.len());
}
