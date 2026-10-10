//! The signing link from the product server to the messenger edge. It is the
//! only path by which a person's request reaches the messenger: the product
//! authenticates the caller, signs an assertion over the path as the core will
//! see it, and forwards.

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use m4a_seam::{sign_assertion, Assertion, ASSERTION_TTL_S};
use rand::RngCore;

use crate::service::AuthUser;

const MAX_BODY: usize = 64 * 1024 * 1024;
/// Prefix the edge strips before the core sees the path.
const MATRIX_PREFIX: &str = "/_matrix";

/// Link configuration. `base` is the edge URL on the private link
/// (`M4A_PRODUCT_EDGE_URL`); `secret` the assertion secret.
#[derive(Clone)]
pub struct EdgeLink {
    pub base: String,
    pub secret: Vec<u8>,
    pub assertion_header: String,
    client: reqwest::Client,
}

impl EdgeLink {
    pub fn new(base: &str, secret: Vec<u8>, assertion_header: Option<String>) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            secret,
            assertion_header: assertion_header.unwrap_or_else(|| m4a_seam::DEFAULT_ASSERTION_HEADER.into()).to_ascii_lowercase(),
            client: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().expect("client"),
        }
    }

    /// Assertion value for one request (`path` as the core sees it).
    pub fn assertion_for(&self, who: &AuthUser, method: &str, core_path: &str) -> String {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let mut n = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut n);
        let a = Assertion { nick: who.nick.clone(), cred_ref: who.cred_ref.clone(), authenticated: 1, paid: who.flag, iat: now, exp: now + ASSERTION_TTL_S, nonce: hex::encode(n) };
        sign_assertion(&self.secret, method, core_path, &a)
    }

    /// Forward `req` to the edge, asserting `who` when given. Any client-supplied
    /// `authorization`, assertion or hand-over header is dropped first.
    pub async fn forward(&self, who: Option<&AuthUser>, req: Request) -> Response {
        let (parts, body) = req.into_parts();
        let Ok(bytes) = to_bytes(body, MAX_BODY).await else { return plain(StatusCode::PAYLOAD_TOO_LARGE, "body too large") };
        let pq = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/").to_string();
        let core_path = pq.strip_prefix(MATRIX_PREFIX).unwrap_or(&pq).to_string();
        let mut rb = self.client.request(parts.method.clone(), format!("{}{}", self.base, pq));
        for (k, v) in forwardable(&parts.headers, &self.assertion_header) {
            rb = rb.header(k, v);
        }
        if let Some(w) = who {
            rb = rb.header(self.assertion_header.as_str(), self.assertion_for(w, parts.method.as_str(), &core_path));
        }
        match rb.body(bytes).send().await {
            Ok(r) => {
                let status = r.status();
                let mut out = Response::builder().status(status);
                for (k, v) in r.headers() {
                    if !matches!(k.as_str(), "transfer-encoding" | "connection" | "content-length" | "keep-alive") {
                        out = out.header(k, v);
                    }
                }
                let b = r.bytes().await.unwrap_or_else(|_| Bytes::new());
                out.body(Body::from(b)).unwrap_or_else(|_| plain(StatusCode::BAD_GATEWAY, "bad upstream response"))
            }
            Err(e) => {
                tracing::warn!("edge link: {e}");
                plain(StatusCode::BAD_GATEWAY, "messenger unavailable")
            }
        }
    }

    /// POST raw bytes to a path on the edge with extra headers (used by the publisher).
    pub(crate) async fn post(&self, path: &str, headers: &[(&str, String)], body: Vec<u8>) -> Result<u16, String> {
        let mut rb = self.client.post(format!("{}{}", self.base, path)).header("content-type", "application/json");
        for (k, v) in headers {
            rb = rb.header(*k, v);
        }
        rb.body(body).send().await.map(|r| r.status().as_u16()).map_err(|e| e.to_string())
    }
}

fn plain(status: StatusCode, msg: &str) -> Response {
    Response::builder().status(status).header("content-type", "application/json").body(Body::from(format!("{{\"errcode\":\"M_UNKNOWN\",\"error\":\"{msg}\"}}"))).unwrap()
}

fn forwardable(h: &HeaderMap, assertion_header: &str) -> Vec<(HeaderName, HeaderValue)> {
    h.iter()
        .filter(|(k, _)| {
            let k = k.as_str();
            !matches!(k, "host" | "content-length" | "connection" | "transfer-encoding" | "upgrade" | "authorization" | "x-m4a-resolved" | "keep-alive") && k != assertion_header
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_credentials_and_forged_headers_never_cross() {
        let mut h = HeaderMap::new();
        for k in ["authorization", "x-m4a-assertion", "x-m4a-resolved", "host", "x-keep"] {
            h.insert(HeaderName::from_static(k), HeaderValue::from_static("v"));
        }
        let names: Vec<String> = forwardable(&h, "x-m4a-assertion").into_iter().map(|(k, _)| k.to_string()).collect();
        assert_eq!(names, vec!["x-keep"]);
    }

    #[test]
    fn assertion_verifies_against_the_core_path() {
        let l = EdgeLink::new("http://edge.invalid", b"0123456789abcdef0123".to_vec(), None);
        let who = AuthUser { nick: "zed".into(), cred_ref: "c".into(), flag: 1 };
        let v = l.assertion_for(&who, "POST", "/client/v3/createRoom");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
        let a = m4a_seam::verify_assertion(&[l.secret.clone()], &v, "POST", "/client/v3/createRoom", now, 5_000).unwrap();
        assert_eq!((a.nick.as_str(), a.paid), ("zed", 1));
    }
}
