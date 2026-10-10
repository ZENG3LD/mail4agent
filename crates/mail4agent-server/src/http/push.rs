//! `GET /client/v3/push`. The machine client opens this socket. The
//! server does not call out. The first text frame registers every device
//! bearer this connection speaks for. Later frames are acks. A new room
//! text, or a new encrypted event with no plaintext body, is pushed after
//! that, one envelope per recipient.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};

use crate::keys::CredentialKind;

use super::{hash_token, Homeserver};

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new().route("/client/v3/push", get(push_socket))
}

async fn push_socket(
    ws: WebSocketUpgrade,
    State(state): State<Arc<Homeserver>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    // A handshake vouched for by a signed assertion registers by the verified
    // identity: no token frame is needed or read.
    let verified = super::identity::read_resolved(&headers).map(|(uid, _, _)| uid).filter(|uid| *uid > 0);
    if super::identity::read_resolved(&headers).is_some() && verified.is_none() {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }
    ws.max_message_size(64 * 1024)
        .max_frame_size(64 * 1024)
        .on_upgrade(move |socket| run_push(socket, state, verified))
}

fn parse_register(text: &str) -> Option<Vec<String>> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    if value.get("type")?.as_str()? != "register" {
        return None;
    }
    let tokens = value.get("tokens")?.as_array()?;
    if tokens.is_empty() || tokens.len() > 64 {
        return None;
    }
    let mut out = Vec::with_capacity(tokens.len());
    for token in tokens {
        let token = token.as_str()?;
        if token.is_empty()
            || token.len() > 512
            || token
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || !byte.is_ascii())
        {
            return None;
        }
        out.push(token.to_string());
    }
    Some(out)
}

async fn resolve_users(state: Arc<Homeserver>, tokens: Vec<String>) -> Result<Vec<i64>, ()> {
    tokio::task::spawn_blocking(move || -> Result<Vec<i64>, ()> {
        state.conn_scope(|conn: &mut rusqlite::Connection| {
        let mut users = Vec::new();
        for token in &tokens {
            let hash = hash_token(token);
            let device = crate::keys::device_for_credential(&conn, CredentialKind::Bearer, &hash)
                .map_err(|_| ())?
                .ok_or(())?;
            if !users.contains(&device.user_id) {
                users.push(device.user_id);
            }
        }
        if users.is_empty() {
            return Err(());
        }
        Ok(users)
        })
    })
    .await
    .map_err(|_| ())?
}

struct Unsubscribe {
    state: Arc<Homeserver>,
    id: u64,
}

impl Drop for Unsubscribe {
    fn drop(&mut self) {
        self.state.push.unsubscribe(self.id);
    }
}

async fn run_push(mut socket: WebSocket, state: Arc<Homeserver>, verified: Option<i64>) {
    let users = match verified {
        Some(uid) => vec![uid],
        None => {
            let text = match socket.recv().await {
                Some(Ok(Message::Text(text))) => text.to_string(),
                _ => return,
            };
            let Some(tokens) = parse_register(&text) else {
                return;
            };
            drop(text);
            let Ok(users) = resolve_users(Arc::clone(&state), tokens).await else {
                return;
            };
            users
        }
    };
    let (id, mut rx) = state.push.subscribe(users);
    let _unsub = Unsubscribe {
        state: Arc::clone(&state),
        id,
    };
    let (mut sink, mut stream) = socket.split();
    if sink
        .send(Message::text(r#"{"type":"registered"}"#))
        .await
        .is_err()
    {
        return;
    }
    loop {
        tokio::select! {
            incoming = stream.next() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(_)) => {}
                }
            }
            outgoing = rx.recv() => {
                match outgoing {
                    Some(line) => {
                        if sink.send(Message::text(line)).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
}
