//! Edge role. Rules:
//! - Client-facing contracts are unchanged: the edge forwards the CS API, the
//!   push v1 WebSocket and `GET /rooms/{id}/messages` byte for byte (minus the
//!   `/_matrix` prefix, which the core's routes do not carry).
//! - Minimal state: the only state here is the per-client rate limiter, held in
//!   memory and rebuilt from nothing after a restart. No database, no keys, no
//!   sessions, no message bodies at rest. Everything durable is in the core.
//! - The edge authenticates itself to the core with a shared secret header; any
//!   such header sent by a client is dropped.
//! - Push: the client's WebSocket is terminated here and relayed to the core's
//!   push hub, so the core notifies through the edge. Edge-side fan-out cache is
//!   a later step; today it is a relay.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::ws::{CloseFrame, Message as AMsg, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as TMsg;

/// Header the core checks.
pub const EDGE_SECRET_HEADER: &str = "x-m4a-edge-secret";
const MAX_BODY: usize = 26 * 1024 * 1024;

/// Edge settings.
#[derive(Clone)]
pub struct EdgeConfig {
    /// Core base URL over the tunnel, no trailing slash.
    pub core_url: String,
    /// Shared secret (>= 32 chars).
    pub secret: String,
    /// Barrier token for the product -> edge link (`M4A_LINK_TOKEN`). When set, every
    /// request except the public protocol surfaces must carry it in `x-m4a-link-token`.
    pub link_token: Option<String>,
}

struct Limiter {
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

impl Limiter {
    /// Token bucket: `burst` tokens, refilled at `per_sec`. true = allowed.
    fn allow(&self, key: &str, burst: f64, per_sec: f64) -> bool {
        let mut m = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if m.len() > 50_000 {
            m.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(300));
        }
        let e = m.entry(key.to_string()).or_insert((burst, now));
        let refill = now.duration_since(e.1).as_secs_f64() * per_sec;
        e.0 = (e.0 + refill).min(burst);
        e.1 = now;
        if e.0 >= 1.0 {
            e.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

struct Edge {
    cfg: EdgeConfig,
    http: reqwest::Client,
    limiter: Limiter,
}

/// Host used in URLs when the core is reached over a unix socket (`unix:/path`).
const UNIX_HOST: &str = "http://m4a-core.local";

impl Edge {
    /// URL prefix for core requests.
    fn core_base(&self) -> &str {
        if self.cfg.core_url.starts_with("unix:") {
            UNIX_HOST
        } else {
            &self.cfg.core_url
        }
    }
    fn core_socket(&self) -> Option<&str> {
        self.cfg.core_url.strip_prefix("unix:")
    }
}

/// Builds the edge router.
pub fn edge_router(cfg: EdgeConfig) -> Router {
    let mut hb = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).no_proxy().timeout(Duration::from_secs(120));
    if let Some(path) = cfg.core_url.strip_prefix("unix:") {
        hb = hb.unix_socket(path.to_string());
    }
    let http = hb.build().expect("http client");
    let state = Arc::new(Edge { cfg, http, limiter: Limiter { buckets: Mutex::new(HashMap::new()) } });
    Router::new()
        .route("/edge/healthz", get(healthz))
        .route("/client/v3/push", get(push_relay))
        .route("/_matrix/client/v3/push", get(push_relay))
        .fallback(forward)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(axum::middleware::from_fn_with_state(state.clone(), link_gate))
        .with_state(state)
}

/// Barrier token check; the header never travels past the edge.
async fn link_gate(State(e): State<Arc<Edge>>, mut req: Request<Body>, next: axum::middleware::Next) -> Response {
    if let Some(expected) = e.cfg.link_token.as_deref() {
        let presented = req.headers().get(m4a_seam::LINK_TOKEN_HEADER).and_then(|v| v.to_str().ok());
        if !m4a_seam::link_path_is_open(req.uri().path()) && !m4a_seam::link_token_ok(presented, expected) {
            return err(StatusCode::UNAUTHORIZED, "M4A_LINK_TOKEN_REQUIRED", "link token required");
        }
    }
    req.headers_mut().remove(m4a_seam::LINK_TOKEN_HEADER);
    next.run(req).await
}

async fn healthz(State(e): State<Arc<Edge>>) -> impl IntoResponse {
    let ok = e.http.get(format!("{}/client/versions", e.core_base())).header(EDGE_SECRET_HEADER, &e.cfg.secret).send().await.map(|r| r.status().is_success()).unwrap_or(false);
    (if ok { StatusCode::OK } else { StatusCode::BAD_GATEWAY }, Json(json!({ "edge": true, "core": ok })))
}

fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    // The proxy in front is on loopback; trust its X-Forwarded-For only then.
    let from_loopback = peer.is_none_or(|p| p.ip().is_loopback());
    if from_loopback {
        if let Some(x) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = x.split(',').next() {
                let first = first.trim();
                if !first.is_empty() && first.len() < 64 {
                    return first.to_string();
                }
            }
        }
    }
    peer.map(|p| p.ip().to_string()).unwrap_or_else(|| "local".into())
}

fn core_path(uri: &Uri) -> String {
    let p = uri.path();
    let p = p.strip_prefix("/_matrix").filter(|r| r.starts_with('/')).unwrap_or(p);
    match uri.query() {
        Some(q) => format!("{p}?{q}"),
        None => p.to_string(),
    }
}

fn err(status: StatusCode, code: &str, msg: &str) -> Response {
    (status, Json(json!({ "errcode": code, "error": msg }))).into_response()
}

const HOP: [&str; 9] = ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "host"];

async fn forward(State(e): State<Arc<Edge>>, peer: Option<axum::Extension<ConnectInfo<SocketAddr>>>, req: Request<Body>) -> Response {
    let ip = client_ip(req.headers(), peer.map(|p| p.0 .0));
    let path = req.uri().path().to_string();
    let (burst, rate) = if path.ends_with("/register") { (10.0, 0.2) } else { (200.0, 50.0) };
    if !e.limiter.allow(&format!("{ip}|{}", path.ends_with("/register")), burst, rate) {
        return err(StatusCode::TOO_MANY_REQUESTS, "M_LIMIT_EXCEEDED", "slow down");
    }
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return err(StatusCode::PAYLOAD_TOO_LARGE, "M_TOO_LARGE", "body too large"),
    };
    let url = format!("{}{}", e.core_base(), core_path(&parts.uri));
    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut rb = e.http.request(method, url);
    for (name, value) in &parts.headers {
        let n = name.as_str();
        if HOP.contains(&n) || n == EDGE_SECRET_HEADER || n == "content-length" || n == "x-forwarded-for" {
            continue;
        }
        rb = rb.header(n, value.as_bytes());
    }
    rb = rb.header(EDGE_SECRET_HEADER, &e.cfg.secret).header("x-forwarded-for", &ip);
    if parts.method != Method::GET && parts.method != Method::HEAD {
        rb = rb.body(bytes);
    }
    let resp = match rb.send().await {
        Ok(r) => r,
        Err(_) => return err(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "core unreachable"),
    };
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut out_headers = HeaderMap::new();
    for (name, value) in resp.headers() {
        if HOP.contains(&name.as_str()) || name == reqwest::header::CONTENT_LENGTH {
            continue;
        }
        if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(name.as_str().as_bytes()), HeaderValue::from_bytes(value.as_bytes())) {
            out_headers.append(n, v);
        }
    }
    let body = match resp.bytes().await {
        Ok(b) => b,
        Err(_) => return err(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "core body read failed"),
    };
    let mut r = (status, body).into_response();
    r.headers_mut().extend(out_headers);
    r
}

async fn push_relay(State(e): State<Arc<Edge>>, headers: HeaderMap, ws: WebSocketUpgrade) -> Response {
    ws.max_message_size(64 * 1024).on_upgrade(move |sock| relay(sock, e, headers))
}

/// Handshake headers that may cross to the core: everything but hop-by-hop,
/// websocket negotiation, the edge secret (set by the edge itself) and the
/// internal hand-over header (never trusted from a client).
fn handshake_passes(name: &str) -> bool {
    !(HOP.contains(&name) || name.starts_with("sec-websocket-") || name == EDGE_SECRET_HEADER || name == m4a_seam::LINK_TOKEN_HEADER || name == "x-m4a-resolved" || name == "content-length" || name == "x-forwarded-for")
}

async fn relay(client: WebSocket, e: Arc<Edge>, handshake: HeaderMap) {
    let url = format!("{}/client/v3/push", e.core_base().replacen("http", "ws", 1));
    let Ok(mut req) = url.into_client_request() else { return };
    let Ok(v) = HeaderValue::from_str(&e.cfg.secret) else { return };
    for (name, value) in &handshake {
        if handshake_passes(name.as_str()) {
            if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(name.as_str().as_bytes()), HeaderValue::from_bytes(value.as_bytes())) {
                req.headers_mut().insert(n, v);
            }
        }
    }
    req.headers_mut().insert(EDGE_SECRET_HEADER, v);
    let mut client = client;
    if let Some(path) = e.core_socket() {
        if let Ok(stream) = tokio::net::UnixStream::connect(path).await {
            if let Ok((core, _)) = tokio_tungstenite::client_async(req, stream).await {
                return pump(client, core).await;
            }
        }
    } else if let Ok((core, _)) = tokio_tungstenite::connect_async(req).await {
        return pump(client, core).await;
    }
    let _ = client.send(AMsg::Close(Some(CloseFrame { code: 1011, reason: "core unreachable".into() }))).await;
}

async fn pump<S>(client: WebSocket, core: tokio_tungstenite::WebSocketStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut c_tx, mut c_rx) = client.split();
    let (mut k_tx, mut k_rx) = core.split();
    let up = async {
        while let Some(Ok(m)) = c_rx.next().await {
            let t = match m {
                AMsg::Text(t) => TMsg::text(t.to_string()),
                AMsg::Binary(b) => TMsg::binary(b.to_vec()),
                AMsg::Ping(_) | AMsg::Pong(_) => continue,
                AMsg::Close(_) => break,
            };
            if k_tx.send(t).await.is_err() {
                break;
            }
        }
        let _ = k_tx.close().await;
    };
    let down = async {
        while let Some(Ok(m)) = k_rx.next().await {
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
