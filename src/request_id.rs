//! `X-Request-Id` middleware: mints one when absent, echoes the caller's
//! own value when present, and inserts it into request extensions so a
//! handler can read it via `axum::Extension<RequestId>` -- the same job an
//! internal build framework's own request-id layer did before this
//! crate's open-sourcing dropped it.
//!
//! Mints an id from a monotonic per-process counter plus the wall clock,
//! hashed through SHA-256 -- both already dependencies of this crate for
//! [`crate::identity::derive_session_id`] -- rather than adding a `uuid`
//! dependency for one correlation string. A counter makes a collision
//! impossible within one process's lifetime, which a random id only makes
//! merely improbable.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use sha2::{Digest, Sha256};

const HEADER: &str = "x-request-id";
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// The id attached to every request that passes this middleware. A handler
/// reads it via `axum::Extension<RequestId>` and its own `Display` impl,
/// the same way it would read any other correlation id -- no other
/// accessor is needed.
#[derive(Debug, Clone)]
pub struct RequestId(Arc<str>);

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn mint() -> String {
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(counter.to_le_bytes());
    hasher.update(nanos.to_le_bytes());
    hex::encode(hasher.finalize())
}

/// `from_fn` middleware. Wire via `.layer(middleware::from_fn(request_id_layer))`.
pub async fn request_id_layer(mut req: Request, next: Next) -> Response {
    let id = req.headers().get(HEADER).and_then(|h| h.to_str().ok()).map(str::to_owned).unwrap_or_else(mint);

    let id_arc: Arc<str> = Arc::from(id.as_str());
    req.extensions_mut().insert(RequestId(id_arc.clone()));

    let mut resp = next.run(req).await;
    if let Ok(hv) = HeaderValue::from_str(&id_arc) {
        resp.headers_mut().insert(HEADER, hv);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use axum::{middleware, Extension, Router};
    use tower::ServiceExt;

    async fn echo(Extension(id): Extension<RequestId>) -> String {
        id.to_string()
    }

    fn app() -> Router {
        Router::new().route("/", get(echo)).layer(middleware::from_fn(request_id_layer))
    }

    #[tokio::test]
    async fn mints_id_when_absent() {
        let resp = app().oneshot(HttpRequest::builder().uri("/").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let hdr = resp.headers().get(HEADER).cloned();
        assert!(hdr.is_some());
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(body, hdr.unwrap().to_str().unwrap());
    }

    #[tokio::test]
    async fn propagates_inbound_id() {
        let resp = app()
            .oneshot(HttpRequest::builder().uri("/").header(HEADER, "lm-tr-1-abc").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let hdr = resp.headers().get(HEADER).unwrap();
        assert_eq!(hdr.to_str().unwrap(), "lm-tr-1-abc");
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(String::from_utf8(body.to_vec()).unwrap(), "lm-tr-1-abc");
    }

    #[test]
    fn mint_never_repeats_across_many_calls() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(mint()), "mint() produced a duplicate id");
        }
    }
}
