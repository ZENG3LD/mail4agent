//! The seam between a product server and the messenger server.
//!
//! One small crate used by BOTH sides so the wire cannot drift: the product
//! server signs, the messenger core verifies. No I/O, no database.
//!
//! # Assertion v1
//!
//! Header value: `v1.<base64url(json)>.<hex hmac-sha256>`. The JSON carries
//! `nick`, `cred_ref`, `authenticated` (1), `paid` (0 or 1), `iat`, `exp`
//! (unix seconds) and `nonce`. The HMAC key is the raw UTF-8 of the shared
//! secret. The HMAC input is this UTF-8 text, every line ending in a newline:
//!
//! ```text
//! v1
//! <METHOD>
//! <path and query as the receiver sees it>
//! <nick>
//! 1
//! <0 or 1>
//! <cred_ref>
//! <iat>
//! <exp>
//! <nonce>
//! ```
//!
//! The verifier rebuilds the text from the parsed JSON, so the JSON values are
//! exactly what was signed.
//!
//! # Events
//!
//! JSON bodies with `id` and `type` (`credential.revoked`, `account.deleted`,
//! `nick.changed`); the signature header carries the hex HMAC-SHA256 of the
//! raw body bytes under the same secret.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Default header carrying the assertion. Products may configure another name.
pub const DEFAULT_ASSERTION_HEADER: &str = "x-m4a-assertion";
/// Default header carrying the event body signature.
pub const DEFAULT_EVENT_SIG_HEADER: &str = "x-m4a-event-sig";
/// Lifetime of an assertion the signer makes, in seconds.
pub const ASSERTION_TTL_S: i64 = 60;

/// Header carrying the barrier token on private links (product -> edge, product -> core).
/// Every receiver of a link checks it inside, on top of the transport (WireGuard or a
/// unix socket) that already protects the link.
pub const LINK_TOKEN_HEADER: &str = "x-m4a-link-token";

/// Paths that stay reachable without the barrier token because they are public
/// protocol surfaces (federation peers, key documents, discovery, health).
pub fn link_path_is_open(path: &str) -> bool {
    path == "/edge/healthz"
        || path.starts_with("/_matrix/federation/")
        || path.starts_with("/_matrix/key/")
        || path.starts_with("/.well-known/")
        || path == "/_matrix/client/versions"
        || path == "/client/versions"
}

/// Constant-time comparison of a presented barrier token with the expected one.
pub fn link_token_ok(presented: Option<&str>, expected: &str) -> bool {
    match presented {
        Some(p) if p.len() == expected.len() => p.bytes().zip(expected.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0,
        _ => false,
    }
}

/// Shared accept/reject vectors for assertion v1 (JSON; see the file).
pub const VECTORS: &str = include_str!("../vectors/assertion_v1.json");

/// What an assertion states about the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assertion {
    pub nick: String,
    pub cred_ref: String,
    /// Always 1 on the wire; an unauthenticated person is not asserted.
    pub authenticated: u8,
    /// Opaque flag (0 or 1) that the receiving policy hook may read.
    pub paid: u8,
    pub iat: i64,
    pub exp: i64,
    pub nonce: String,
}

/// Why verification failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeamError {
    Malformed(&'static str),
    BadSignature,
    Expired,
    Replay,
}

fn mac(secret: &[u8], parts: &[&[u8]]) -> HmacSha256 {
    let mut m = HmacSha256::new_from_slice(secret).expect("hmac takes any key length");
    for p in parts {
        m.update(p);
    }
    m
}

fn signing_text(method: &str, path: &str, a: &Assertion) -> String {
    format!(
        "v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        method.to_ascii_uppercase(),
        path,
        a.nick,
        a.authenticated,
        a.paid,
        a.cred_ref,
        a.iat,
        a.exp,
        a.nonce
    )
}

/// Make the header value for one request. `path` is the path and query as the
/// receiver will see it.
pub fn sign_assertion(secret: &[u8], method: &str, path: &str, a: &Assertion) -> String {
    let json = serde_json::to_vec(a).expect("assertion serializes");
    let sig = hex::encode(mac(secret, &[signing_text(method, path, a).as_bytes()]).finalize().into_bytes());
    format!("v1.{}.{}", URL_SAFE_NO_PAD.encode(json), sig)
}

/// Verify a header value against any of `secrets` (current first). `now_ms` and
/// `skew_ms` bound `[iat, exp]`. Replay is the caller's concern ([`NonceCache`]).
pub fn verify_assertion(secrets: &[Vec<u8>], value: &str, method: &str, path: &str, now_ms: i64, skew_ms: i64) -> Result<Assertion, SeamError> {
    let mut it = value.splitn(3, '.');
    let (v, b64, sig) = (it.next().unwrap_or(""), it.next().ok_or(SeamError::Malformed("parts"))?, it.next().ok_or(SeamError::Malformed("parts"))?);
    if v != "v1" {
        return Err(SeamError::Malformed("version"));
    }
    let raw = URL_SAFE_NO_PAD.decode(b64).map_err(|_| SeamError::Malformed("base64"))?;
    let a: Assertion = serde_json::from_slice(&raw).map_err(|_| SeamError::Malformed("json"))?;
    if a.authenticated != 1 || a.paid > 1 {
        return Err(SeamError::Malformed("flags"));
    }
    if a.nick.is_empty() || a.cred_ref.is_empty() || a.nonce.is_empty() || a.nick.contains('\n') || a.cred_ref.contains('\n') || a.nonce.contains('\n') {
        return Err(SeamError::Malformed("fields"));
    }
    let sig = hex::decode(sig).map_err(|_| SeamError::Malformed("hex"))?;
    let text = signing_text(method, path, &a);
    if !secrets.iter().any(|s| mac(s, &[text.as_bytes()]).verify_slice(&sig).is_ok()) {
        return Err(SeamError::BadSignature);
    }
    if a.exp * 1000 < now_ms - skew_ms || a.iat * 1000 > now_ms + skew_ms {
        return Err(SeamError::Expired);
    }
    Ok(a)
}

/// Remembers nonces until their assertion expires.
#[derive(Default)]
pub struct NonceCache {
    seen: Mutex<HashMap<String, i64>>,
}

impl NonceCache {
    pub fn new() -> Self {
        Self::default()
    }
    /// Record `a`'s nonce; `Err(Replay)` when it was already used.
    pub fn check_and_insert(&self, a: &Assertion, now_ms: i64, skew_ms: i64) -> Result<(), SeamError> {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.retain(|_, exp| *exp >= now_ms - skew_ms);
        if seen.insert(a.nonce.clone(), a.exp * 1000).is_some() {
            return Err(SeamError::Replay);
        }
        Ok(())
    }
}

/// Lifecycle events, product -> messenger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EventKind {
    #[serde(rename = "credential.revoked")]
    CredentialRevoked { cred_ref: String },
    #[serde(rename = "account.deleted")]
    AccountDeleted { nick: String },
    #[serde(rename = "nick.changed")]
    NickChanged { old: String, new: String },
}

/// One event with its idempotency id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    #[serde(flatten)]
    pub kind: EventKind,
}

/// Hex HMAC-SHA256 of a raw event body.
pub fn sign_body(secret: &[u8], body: &[u8]) -> String {
    hex::encode(mac(secret, &[body]).finalize().into_bytes())
}

/// True when `sig_hex` is valid for `body` under any of `secrets`.
pub fn verify_body(secrets: &[Vec<u8>], body: &[u8], sig_hex: &str) -> bool {
    match hex::decode(sig_hex) {
        Ok(sig) => secrets.iter().any(|s| mac(s, &[body]).verify_slice(&sig).is_ok()),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn sample(nonce: &str) -> Assertion {
        Assertion { nick: "carol".into(), cred_ref: "c1".into(), authenticated: 1, paid: 1, iat: 1_800_000_000, exp: 1_800_000_060, nonce: nonce.into() }
    }
    const NOW: i64 = 1_800_000_010_000;

    #[test]
    fn round_trip_and_binding_to_method_and_path() {
        let s = b"0123456789abcdef0123".to_vec();
        let v = sign_assertion(&s, "post", "/client/v3/x?q=1", &sample("n1"));
        assert_eq!(verify_assertion(&[s.clone()], &v, "POST", "/client/v3/x?q=1", NOW, 30_000).unwrap(), sample("n1"));
        assert_eq!(verify_assertion(&[s.clone()], &v, "GET", "/client/v3/x?q=1", NOW, 30_000), Err(SeamError::BadSignature));
        assert_eq!(verify_assertion(&[s], &v, "POST", "/client/v3/y", NOW, 30_000), Err(SeamError::BadSignature));
    }

    #[test]
    fn link_token_is_constant_length_checked_and_public_paths_stay_open() {
        assert!(link_token_ok(Some("abcdefgh"), "abcdefgh"));
        assert!(!link_token_ok(Some("abcdefgX"), "abcdefgh") && !link_token_ok(Some("abc"), "abcdefgh") && !link_token_ok(None, "abcdefgh"));
        assert!(link_path_is_open("/_matrix/federation/v1/send/1") && link_path_is_open("/.well-known/matrix/server") && link_path_is_open("/edge/healthz"));
        assert!(!link_path_is_open("/_matrix/client/v3/sync") && !link_path_is_open("/client/v3/push"));
    }

    #[test]
    fn replay_cache_refuses_second_use() {
        let c = NonceCache::new();
        c.check_and_insert(&sample("n"), NOW, 30_000).unwrap();
        assert_eq!(c.check_and_insert(&sample("n"), NOW, 30_000), Err(SeamError::Replay));
        c.check_and_insert(&sample("m"), NOW, 30_000).unwrap();
    }

    #[test]
    fn event_bodies_round_trip_and_sign() {
        let e = Event { id: "a".repeat(32), kind: EventKind::NickChanged { old: "a1b".into(), new: "c2d".into() } };
        let body = serde_json::to_vec(&e).unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["type"], "nick.changed");
        assert_eq!(serde_json::from_slice::<Event>(&body).unwrap(), e);
        let s = b"0123456789abcdef0123".to_vec();
        let sig = sign_body(&s, &body);
        assert!(verify_body(&[s.clone()], &body, &sig));
        assert!(!verify_body(&[s], b"{}", &sig));
    }

    /// The shared vector file: every party runs this same table.
    #[test]
    fn shared_vectors() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        let secret = v["secret"].as_str().unwrap().as_bytes().to_vec();
        let prev = v["secret_prev"].as_str().unwrap().as_bytes().to_vec();
        let now_ms = v["now_ms"].as_i64().unwrap();
        let skew = v["skew_ms"].as_i64().unwrap();
        for case in v["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let a: Assertion = serde_json::from_value(case["assertion"].clone()).unwrap();
            let (method, path) = (case["method"].as_str().unwrap(), case["path"].as_str().unwrap());
            let signer = if case["signed_with"] == "prev" { &prev } else { &secret };
            let mut value = sign_assertion(signer, case["sign_method"].as_str().unwrap_or(method), case["sign_path"].as_str().unwrap_or(path), &a);
            if let Some(t) = case["tamper_nick_to"].as_str() {
                let json = serde_json::to_vec(&Assertion { nick: t.into(), ..a.clone() }).unwrap();
                let sig = value.rsplit('.').next().unwrap().to_string();
                value = format!("v1.{}.{}", URL_SAFE_NO_PAD.encode(json), sig);
            }
            if case["expected_value"].is_string() {
                assert_eq!(value, case["expected_value"].as_str().unwrap(), "{name}: pinned wire value");
            }
            let accept = [secret.clone(), prev.clone()];
            let secrets: &[Vec<u8>] = if case["accept_prev"] == true { &accept } else { &accept[..1] };
            let got = verify_assertion(secrets, &value, method, path, now_ms, skew);
            match case["expect"].as_str().unwrap() {
                "ok" => assert!(got.is_ok(), "{name}: {got:?}"),
                "bad_signature" => assert_eq!(got, Err(SeamError::BadSignature), "{name}"),
                "expired" => assert_eq!(got, Err(SeamError::Expired), "{name}"),
                "malformed" => assert!(matches!(got, Err(SeamError::Malformed(_))), "{name}: {got:?}"),
                other => panic!("{name}: unknown expectation {other}"),
            }
        }
    }
}
