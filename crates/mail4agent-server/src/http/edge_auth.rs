//! Core-side gate for the edge/core split. When the server runs with
//! `--role core`, every request must carry the shared secret the edge adds
//! (`X-M4A-Edge-Secret`). The tunnel and a firewall allowlist are the first
//! line; this header is the second, so a stray process on the tunnel network
//! cannot talk to the core. The secret comes from the environment and is never
//! logged.

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{from_fn, Next};
use axum::response::IntoResponse;
use axum::Router;

/// Header name carrying the shared secret edge -> core.
pub const EDGE_SECRET_HEADER: &str = "x-m4a-edge-secret";

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Wraps `router` so requests without the right secret get a Matrix-shaped 401.
pub fn require_edge_secret(router: Router, secret: String) -> Router {
    let secret: std::sync::Arc<str> = secret.into();
    router.layer(from_fn(move |req: Request, next: Next| {
        let secret = std::sync::Arc::clone(&secret);
        async move {
            let ok = req
                .headers()
                .get(EDGE_SECRET_HEADER)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|got| ct_eq(got.as_bytes(), secret.as_bytes()));
            if ok {
                next.run(req).await
            } else {
                (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"errcode": "M_UNKNOWN_TOKEN", "error": "edge secret required"}))).into_response()
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn constant_time_compare() {
        assert!(super::ct_eq(b"abc", b"abc"));
        assert!(!super::ct_eq(b"abc", b"abd"));
        assert!(!super::ct_eq(b"abc", b"ab"));
    }
}
