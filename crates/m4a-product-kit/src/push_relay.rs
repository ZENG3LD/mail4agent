//! Push WebSocket through the product. The product authenticates the client's
//! handshake, signs an assertion for it, opens the upstream socket to the edge
//! with that assertion, and relays frames both ways. The messenger registers
//! the connection by the verified identity; the client's token never leaves
//! the product.

use axum::extract::ws::{Message as AMsg, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as TMsg;

use crate::edge_link::EdgeLink;
use crate::service::AuthUser;

const PUSH_PATH: &str = "/client/v3/push";

impl EdgeLink {
    /// Upgrade the client's socket and relay it to the messenger as `who`.
    pub fn relay_push(&self, who: AuthUser, ws: WebSocketUpgrade) -> Response {
        let link = self.clone();
        ws.max_message_size(64 * 1024).on_upgrade(move |client| async move { link.run_push_relay(who, client).await })
    }

    async fn run_push_relay(&self, who: AuthUser, mut client: WebSocket) {
        let url = format!("{}/_matrix{PUSH_PATH}", self.base.replacen("http", "ws", 1));
        let Ok(mut req) = url.into_client_request() else { return };
        let Ok(v) = HeaderValue::from_str(&self.assertion_for(&who, "GET", PUSH_PATH)) else { return };
        let Ok(name) = axum::http::HeaderName::from_bytes(self.assertion_header.as_bytes()) else { return };
        req.headers_mut().insert(name, v);
        if let Some(t) = &self.link_token {
            if let Ok(tv) = HeaderValue::from_str(t) {
                req.headers_mut().insert(axum::http::HeaderName::from_static(m4a_seam::LINK_TOKEN_HEADER), tv);
            }
        }
        let Ok((upstream, _)) = tokio_tungstenite::connect_async(req).await else {
            let _ = client.send(AMsg::Close(None)).await;
            return;
        };
        let (mut c_tx, mut c_rx) = client.split();
        let (mut u_tx, mut u_rx) = upstream.split();
        let up = async {
            while let Some(Ok(m)) = c_rx.next().await {
                let t = match m {
                    AMsg::Text(t) => TMsg::text(t.to_string()),
                    AMsg::Binary(b) => TMsg::binary(b.to_vec()),
                    AMsg::Ping(_) | AMsg::Pong(_) => continue,
                    AMsg::Close(_) => break,
                };
                if u_tx.send(t).await.is_err() {
                    break;
                }
            }
            let _ = u_tx.close().await;
        };
        let down = async {
            while let Some(Ok(m)) = u_rx.next().await {
                let t = match m {
                    TMsg::Text(t) => AMsg::text(t.to_string()),
                    TMsg::Binary(b) => AMsg::Binary(b.to_vec().into()),
                    TMsg::Close(_) => break,
                    _ => continue,
                };
                if c_tx.send(t).await.is_err() {
                    break;
                }
            }
            let _ = c_tx.close().await;
        };
        tokio::select! { _ = up => {}, _ = down => {} }
    }
}

/// 401 body for a refused handshake.
pub fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({ "errcode": "M_UNKNOWN_TOKEN", "error": "login required for push" }))).into_response()
}
