//! Account sources: where an authenticated identity comes from.
//!
//! A source turns request parts into an [`Asserted`] identity. The messenger
//! then maps it to an account with [`crate::accounts::resolve_account`]. Two
//! sources ship: [`LocalSource`] (the existing device bearer, no behaviour
//! change) and [`SignedHeaderSource`] (HMAC-signed assertion from a trusted
//! proxy that owns the user accounting). Concrete secrets and source ids come
//! only from the environment.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::error::MatrixError;

type HmacSha256 = Hmac<Sha256>;

/// Header carrying `base64url(json)` of the assertion.
pub const ASSERTION_HEADER: &str = "x-m4a-assertion";
/// Header carrying hex `HMAC-SHA256(secret, value "\n" METHOD "\n" path)`.
pub const ASSERTION_SIG_HEADER: &str = "x-m4a-assertion-sig";
/// Header carrying hex `HMAC-SHA256(secret, raw body)` on lifecycle event posts.
pub const EVENT_SIG_HEADER: &str = "x-m4a-event-sig";

/// Source id of the built-in local source.
pub const LOCAL_SOURCE: &str = "local";

/// An identity asserted by a source for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asserted {
    /// Which source or door (`local`, `issuer:<name>`, `matrix`, `oauth:<p>`, `mail`).
    pub source: String,
    /// Login key part two. For an issuer without subjects: the nick at first contact.
    pub subject: String,
    /// The issuer's current nick. Doors leave this `None`.
    pub nick: Option<String>,
    /// Issuer says the nick is still a generated placeholder.
    pub placeholder: bool,
    pub authenticated: bool,
    /// Opaque flag for the policy hook; this crate attaches no meaning.
    pub paid: bool,
    /// Stable reference of the credential (device continuity, revoke).
    pub cred_ref: String,
    pub expires_ms: i64,
}

impl Asserted {
    /// True when the source owns nicks (issuer sources), so we do not.
    pub fn is_issuer(&self) -> bool {
        self.nick.is_some()
    }
}

/// What the policy hook may know about the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountFacts {
    pub source: String,
    pub authenticated: bool,
    pub paid: bool,
}

impl AccountFacts {
    /// Facts for a caller that came in through the local device bearer.
    pub fn local() -> Self {
        Self { source: LOCAL_SOURCE.to_string(), authenticated: true, paid: false }
    }
}

/// Why a source refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
    /// Signature, encoding or field problem.
    Invalid(&'static str),
    Expired,
    Replay,
}

impl From<SourceError> for MatrixError {
    fn from(e: SourceError) -> Self {
        match e {
            SourceError::Invalid(m) => MatrixError::unauthorized(format!("assertion rejected: {m}")),
            SourceError::Expired => MatrixError::unauthorized("assertion expired"),
            SourceError::Replay => MatrixError::unauthorized("assertion replayed"),
        }
    }
}

/// Request data a source may inspect.
pub struct RequestParts<'a> {
    pub method: &'a str,
    /// Path (and query) exactly as the signer saw it.
    pub path: &'a str,
    pub headers: &'a axum::http::HeaderMap,
    pub now_ms: i64,
}

/// A pluggable provider of asserted identities.
pub trait AccountSource: Send + Sync {
    fn id(&self) -> &str;
    /// `Ok(None)` means "not mine, try the next source".
    fn authenticate(&self, req: &RequestParts<'_>) -> Result<Option<Asserted>, SourceError>;
}

/// The existing device-bearer path. It asserts nothing by itself: bearer
/// resolution stays in `http::resolve_caller`; this type exists so the local
/// source is listed and uniform.
pub struct LocalSource;

impl AccountSource for LocalSource {
    fn id(&self) -> &str {
        LOCAL_SOURCE
    }
    fn authenticate(&self, _req: &RequestParts<'_>) -> Result<Option<Asserted>, SourceError> {
        Ok(None)
    }
}

#[derive(Deserialize)]
struct WireAssertion {
    v: u32,
    nick: String,
    #[serde(default = "yes")]
    placeholder: bool,
    #[serde(default)]
    authenticated: bool,
    #[serde(default)]
    paid: bool,
    cred_ref: String,
    iat: i64,
    exp: i64,
    nonce: String,
}

fn yes() -> bool {
    true
}

/// Verifies assertions signed with a shared secret by a trusted proxy.
pub struct SignedHeaderSource {
    id: String,
    secrets: Vec<Vec<u8>>,
    skew_ms: i64,
    seen: Mutex<HashMap<String, i64>>,
}

impl SignedHeaderSource {
    /// `source_id` is stored as the account source (`issuer:<name>`).
    /// `secrets[0]` is current; further entries are accepted while rotating.
    pub fn new(source_id: &str, secrets: Vec<Vec<u8>>, skew_ms: i64) -> Self {
        Self { id: source_id.to_string(), secrets, skew_ms, seen: Mutex::new(HashMap::new()) }
    }

    /// From `M4A_ASSERTION_SECRET` (+ optional `M4A_ASSERTION_SECRET_PREV`),
    /// `M4A_ASSERTION_SOURCE` (default `issuer:default`), `M4A_ASSERTION_SKEW_S` (default 30).
    /// `Ok(None)` when no secret is configured.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Ok(secret) = std::env::var("M4A_ASSERTION_SECRET") else { return Ok(None) };
        if secret.len() < 16 {
            return Err("M4A_ASSERTION_SECRET must be at least 16 characters".into());
        }
        let mut secrets = vec![secret.into_bytes()];
        if let Ok(prev) = std::env::var("M4A_ASSERTION_SECRET_PREV") {
            if !prev.is_empty() {
                secrets.push(prev.into_bytes());
            }
        }
        let id = std::env::var("M4A_ASSERTION_SOURCE").unwrap_or_else(|_| "issuer:default".into());
        if !id.starts_with("issuer:") {
            return Err("M4A_ASSERTION_SOURCE must start with `issuer:`".into());
        }
        let skew_s: i64 = std::env::var("M4A_ASSERTION_SKEW_S").ok().and_then(|v| v.parse().ok()).unwrap_or(30);
        Ok(Some(Self::new(&id, secrets, skew_s * 1000)))
    }

    /// Signature of `value` for `method` and `path` under the current secret.
    pub fn sign(&self, value: &str, method: &str, path: &str) -> String {
        sign_with(&self.secrets[0], &[value.as_bytes(), b"\n", method.as_bytes(), b"\n", path.as_bytes()])
    }

    /// True when `sig` is a valid HMAC of `body` under any accepted secret.
    pub fn verify_body(&self, body: &[u8], sig_hex: &str) -> bool {
        self.secrets.iter().any(|s| verify_with(s, &[body], sig_hex))
    }

    fn verify_request(&self, value: &str, method: &str, path: &str, sig: &str) -> bool {
        self.secrets
            .iter()
            .any(|s| verify_with(s, &[value.as_bytes(), b"\n", method.as_bytes(), b"\n", path.as_bytes()], sig))
    }
}

fn mac_of(secret: &[u8], parts: &[&[u8]]) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    for p in parts {
        mac.update(p);
    }
    mac
}

fn sign_with(secret: &[u8], parts: &[&[u8]]) -> String {
    hex::encode(mac_of(secret, parts).finalize().into_bytes())
}

fn verify_with(secret: &[u8], parts: &[&[u8]], sig_hex: &str) -> bool {
    match hex::decode(sig_hex) {
        Ok(sig) => mac_of(secret, parts).verify_slice(&sig).is_ok(),
        Err(_) => false,
    }
}

impl AccountSource for SignedHeaderSource {
    fn id(&self) -> &str {
        &self.id
    }

    fn authenticate(&self, req: &RequestParts<'_>) -> Result<Option<Asserted>, SourceError> {
        // Client-supplied copies never reach here: the trusted proxy overwrites
        // both headers, and without a valid signature the request is rejected.
        let Some(value) = req.headers.get(ASSERTION_HEADER) else { return Ok(None) };
        let value = value.to_str().map_err(|_| SourceError::Invalid("header encoding"))?;
        let sig = req
            .headers
            .get(ASSERTION_SIG_HEADER)
            .and_then(|v| v.to_str().ok())
            .ok_or(SourceError::Invalid("missing signature"))?;
        if !self.verify_request(value, req.method, req.path, sig) {
            return Err(SourceError::Invalid("bad signature"));
        }
        let raw = URL_SAFE_NO_PAD.decode(value).map_err(|_| SourceError::Invalid("base64"))?;
        let w: WireAssertion = serde_json::from_slice(&raw).map_err(|_| SourceError::Invalid("json"))?;
        if w.v != 1 {
            return Err(SourceError::Invalid("version"));
        }
        if w.cred_ref.is_empty() || w.nonce.is_empty() || w.nick.is_empty() {
            return Err(SourceError::Invalid("missing field"));
        }
        let now = req.now_ms;
        if w.exp * 1000 < now - self.skew_ms || w.iat * 1000 > now + self.skew_ms {
            return Err(SourceError::Expired);
        }
        {
            let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
            seen.retain(|_, exp| *exp >= now - self.skew_ms);
            // A nonce is single-use only for requests that are not idempotent reads.
            if req.method != "GET" && req.method != "HEAD" && seen.insert(w.nonce.clone(), w.exp * 1000).is_some() {
                return Err(SourceError::Replay);
            }
        }
        Ok(Some(Asserted {
            source: self.id.clone(),
            subject: w.nick.clone(),
            nick: Some(w.nick),
            placeholder: w.placeholder,
            authenticated: w.authenticated,
            paid: w.paid,
            cred_ref: w.cred_ref,
            expires_ms: w.exp * 1000,
        }))
    }
}

/// Builds a signed assertion for tests and for proxies written in Rust.
pub fn build_assertion(
    src: &SignedHeaderSource,
    method: &str,
    path: &str,
    json: &serde_json::Value,
) -> (String, String) {
    let value = URL_SAFE_NO_PAD.encode(json.to_string());
    let sig = src.sign(&value, method, path);
    (value, sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use serde_json::json;

    const NOW: i64 = 1_800_000_000_000;

    fn src() -> SignedHeaderSource {
        SignedHeaderSource::new("issuer:test", vec![b"0123456789abcdef0123".to_vec()], 30_000)
    }
    fn body(nonce: &str) -> serde_json::Value {
        json!({"v":1,"nick":"carol","placeholder":false,"authenticated":true,"paid":true,
               "cred_ref":"c1","iat":NOW/1000,"exp":NOW/1000+60,"nonce":nonce})
    }
    fn headers(v: &str, s: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(ASSERTION_HEADER, HeaderValue::from_str(v).unwrap());
        h.insert(ASSERTION_SIG_HEADER, HeaderValue::from_str(s).unwrap());
        h
    }
    fn parts<'a>(h: &'a HeaderMap, method: &'a str, path: &'a str, now: i64) -> RequestParts<'a> {
        RequestParts { method, path, headers: h, now_ms: now }
    }

    #[test]
    fn valid_assertion_is_accepted_and_replay_refused() {
        let s = src();
        let (v, sig) = build_assertion(&s, "POST", "/client/v3/createRoom", &body("n1"));
        let h = headers(&v, &sig);
        let a = s.authenticate(&parts(&h, "POST", "/client/v3/createRoom", NOW)).unwrap().unwrap();
        assert_eq!((a.source.as_str(), a.subject.as_str(), a.paid, a.placeholder), ("issuer:test", "carol", true, false));
        assert_eq!(s.authenticate(&parts(&h, "POST", "/client/v3/createRoom", NOW)), Err(SourceError::Replay));
    }

    #[test]
    fn tamper_wrong_path_method_and_missing_signature_are_refused() {
        let s = src();
        let (v, sig) = build_assertion(&s, "POST", "/p", &body("n2"));
        let h = headers(&v, &sig);
        assert_eq!(s.authenticate(&parts(&h, "POST", "/other", NOW)), Err(SourceError::Invalid("bad signature")));
        assert_eq!(s.authenticate(&parts(&h, "PUT", "/p", NOW)), Err(SourceError::Invalid("bad signature")));
        let forged = URL_SAFE_NO_PAD.encode(body("n2").to_string().replace("carol", "admin"));
        let h2 = headers(&forged, &sig);
        assert_eq!(s.authenticate(&parts(&h2, "POST", "/p", NOW)), Err(SourceError::Invalid("bad signature")));
        let mut h3 = HeaderMap::new();
        h3.insert(ASSERTION_HEADER, HeaderValue::from_str(&v).unwrap());
        assert_eq!(s.authenticate(&parts(&h3, "POST", "/p", NOW)), Err(SourceError::Invalid("missing signature")));
        assert_eq!(s.authenticate(&parts(&HeaderMap::new(), "POST", "/p", NOW)), Ok(None));
    }

    #[test]
    fn expiry_skew_and_wrong_secret() {
        let s = src();
        let (v, sig) = build_assertion(&s, "GET", "/p", &body("n3"));
        let h = headers(&v, &sig);
        assert!(s.authenticate(&parts(&h, "GET", "/p", NOW + 60_000 + 29_000)).unwrap().is_some());
        assert_eq!(s.authenticate(&parts(&h, "GET", "/p", NOW + 60_000 + 31_000)), Err(SourceError::Expired));
        assert_eq!(s.authenticate(&parts(&h, "GET", "/p", NOW - 31_000)), Err(SourceError::Expired));
        let other = SignedHeaderSource::new("issuer:test", vec![b"zzzzzzzzzzzzzzzzzzzz".to_vec()], 30_000);
        assert_eq!(other.authenticate(&parts(&h, "GET", "/p", NOW)), Err(SourceError::Invalid("bad signature")));
    }

    #[test]
    fn reads_may_repeat_and_previous_secret_is_accepted() {
        let old = SignedHeaderSource::new("issuer:test", vec![b"oldoldoldoldoldold1".to_vec()], 30_000);
        let (v, sig) = build_assertion(&old, "GET", "/p", &body("n4"));
        let h = headers(&v, &sig);
        let rotating = SignedHeaderSource::new("issuer:test", vec![b"newnewnewnewnewnew1".to_vec(), b"oldoldoldoldoldold1".to_vec()], 30_000);
        assert!(rotating.authenticate(&parts(&h, "GET", "/p", NOW)).unwrap().is_some());
        assert!(rotating.authenticate(&parts(&h, "GET", "/p", NOW)).unwrap().is_some());
    }

    #[test]
    fn event_body_signature() {
        let s = src();
        let sig = sign_with(&s.secrets[0], &[b"{\"a\":1}"]);
        assert!(s.verify_body(b"{\"a\":1}", &sig));
        assert!(!s.verify_body(b"{\"a\":2}", &sig));
        assert!(!s.verify_body(b"{\"a\":1}", "zz"));
    }
}
