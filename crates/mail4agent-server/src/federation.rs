//! Federation stage F0: this server's signing keys, canonical-JSON signing,
//! `X-Matrix` request authentication, and remote key resolution/cache.
//!
//! Nothing here sends events or joins rooms (that is F1+). The server name is
//! always a parameter, so the module is testable without the process-wide
//! name. Remote key fetching is behind [`RemoteKeys`] so tests (and staged
//! deployments) can substitute the network.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};

/// Validity of a published key response (a week, within the spec's limit).
pub const KEY_VALIDITY_MS: i64 = 7 * 24 * 3600 * 1000;
/// Largest remote key/well-known body we read.
const MAX_REMOTE_BODY: usize = 64 * 1024;
/// A server whose keys were fetched this recently is not re-fetched for an unknown key id.
const REFETCH_FLOOR_MS: i64 = 30_000;

/// Federation-layer failure. Mapped to `M_UNAUTHORIZED` at the HTTP edge.
#[derive(Debug, Clone, PartialEq)]
pub enum FedError {
    /// Malformed header, key response, or signature material.
    Malformed(String),
    /// Signature did not verify.
    BadSignature,
    /// Remote could not be resolved or reached.
    Network(String),
    /// Storage failure.
    Db(String),
}

impl std::fmt::Display for FedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FedError::Malformed(m) => write!(f, "malformed: {m}"),
            FedError::BadSignature => write!(f, "signature verification failed"),
            FedError::Network(m) => write!(f, "network: {m}"),
            FedError::Db(m) => write!(f, "db: {m}"),
        }
    }
}

impl From<rusqlite::Error> for FedError {
    fn from(e: rusqlite::Error) -> Self {
        FedError::Db(e.to_string())
    }
}

/// Current time in milliseconds since the epoch.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Matrix canonical JSON: keys sorted, no whitespace. `serde_json` keeps
/// object keys in a sorted map (the `preserve_order` feature is not enabled),
/// and the output is compact UTF-8, which is what the signing rules need for
/// the integer/string/array/object values used here.
pub fn canonical_json(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

fn b64(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>, FedError> {
    STANDARD_NO_PAD.decode(s.trim_end_matches('=')).map_err(|_| FedError::Malformed("bad base64".into()))
}

fn random_key_id() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut raw = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut raw);
    let tail: String = raw.iter().map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char).collect();
    format!("ed25519:{tail}")
}

/// The active signing key, generated and stored on first use.
pub fn active_signing_key(conn: &Connection, now_ms: i64) -> Result<(String, SigningKey), FedError> {
    let row: Option<(String, Vec<u8>)> = conn
        .query_row(
            "SELECT key_id, secret FROM fed_signing_keys WHERE retired_ms IS NULL ORDER BY created_ms DESC, key_id LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((id, secret)) = row {
        let bytes: [u8; 32] = secret.try_into().map_err(|_| FedError::Malformed("stored key length".into()))?;
        return Ok((id, SigningKey::from_bytes(&bytes)));
    }
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let id = random_key_id();
    conn.execute(
        "INSERT INTO fed_signing_keys (key_id, secret, created_ms) VALUES (?1, ?2, ?3)",
        params![id, seed.to_vec(), now_ms],
    )?;
    Ok((id, SigningKey::from_bytes(&seed)))
}

/// Retire the active key (rotation). The next call to [`active_signing_key`] mints a new one.
pub fn retire_active_key(conn: &Connection, now_ms: i64) -> Result<(), FedError> {
    conn.execute("UPDATE fed_signing_keys SET retired_ms = ?1 WHERE retired_ms IS NULL", params![now_ms])?;
    Ok(())
}

/// Sign `object` in place: adds `signatures[server][key_id]` over the
/// canonical form without `signatures` and `unsigned`.
pub fn sign_json(object: &mut Map<String, Value>, server: &str, key_id: &str, key: &SigningKey) {
    let mut bare = object.clone();
    bare.remove("signatures");
    bare.remove("unsigned");
    let sig = key.sign(&canonical_json(&Value::Object(bare)));
    let sigs = object.entry("signatures").or_insert_with(|| json!({}));
    if let Some(map) = sigs.as_object_mut() {
        let per = map.entry(server.to_string()).or_insert_with(|| json!({}));
        if let Some(per) = per.as_object_mut() {
            per.insert(key_id.to_string(), Value::String(b64(&sig.to_bytes())));
        }
    }
}

/// Verify `object.signatures[server][key_id]` with a base64 public key.
pub fn verify_json(object: &Value, server: &str, key_id: &str, public_key_b64: &str) -> Result<(), FedError> {
    let obj = object.as_object().ok_or_else(|| FedError::Malformed("not an object".into()))?;
    let sig_b64 = obj
        .get("signatures")
        .and_then(|s| s.get(server))
        .and_then(|s| s.get(key_id))
        .and_then(Value::as_str)
        .ok_or(FedError::BadSignature)?;
    let mut bare = obj.clone();
    bare.remove("signatures");
    bare.remove("unsigned");
    verify_bytes(&canonical_json(&Value::Object(bare)), sig_b64, public_key_b64)
}

fn verify_bytes(message: &[u8], sig_b64: &str, public_key_b64: &str) -> Result<(), FedError> {
    let pk: [u8; 32] = unb64(public_key_b64)?.try_into().map_err(|_| FedError::Malformed("public key length".into()))?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| FedError::Malformed("public key".into()))?;
    let sig: [u8; 64] = unb64(sig_b64)?.try_into().map_err(|_| FedError::BadSignature)?;
    vk.verify(message, &Signature::from_bytes(&sig)).map_err(|_| FedError::BadSignature)
}

/// Body of `GET /_matrix/key/v2/server`, self-signed.
pub fn server_keys_response(conn: &Connection, server: &str, now_ms: i64) -> Result<Value, FedError> {
    let (key_id, key) = active_signing_key(conn, now_ms)?;
    let mut old = Map::new();
    let mut stmt = conn.prepare("SELECT key_id, secret, retired_ms FROM fed_signing_keys WHERE retired_ms IS NOT NULL")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, i64>(2)?)))?;
    for row in rows {
        let (id, secret, retired) = row?;
        if let Ok(bytes) = <[u8; 32]>::try_from(secret) {
            let pk = SigningKey::from_bytes(&bytes).verifying_key();
            old.insert(id, json!({ "key": b64(pk.as_bytes()), "expired_ts": retired }));
        }
    }
    let mut obj = Map::new();
    obj.insert("server_name".into(), json!(server));
    obj.insert("verify_keys".into(), json!({ key_id.clone(): { "key": b64(key.verifying_key().as_bytes()) } }));
    obj.insert("old_verify_keys".into(), Value::Object(old));
    obj.insert("valid_until_ts".into(), json!(now_ms + KEY_VALIDITY_MS));
    sign_json(&mut obj, server, &key_id, &key);
    Ok(Value::Object(obj))
}

// ---------------------------------------------------------------- X-Matrix

/// Parsed `Authorization: X-Matrix ...` header.
#[derive(Debug, Clone, PartialEq)]
pub struct XMatrix {
    /// Sending server.
    pub origin: String,
    /// Receiving server (absent from pre-1.3 senders).
    pub destination: Option<String>,
    /// Key id the signature was made with.
    pub key: String,
    /// Unpadded base64 signature.
    pub sig: String,
}

/// Parse an `X-Matrix` Authorization value (quoted or bare parameters).
pub fn parse_x_matrix(value: &str) -> Result<XMatrix, FedError> {
    let rest = value.trim().strip_prefix("X-Matrix ").ok_or_else(|| FedError::Malformed("not X-Matrix".into()))?;
    let mut map: HashMap<String, String> = HashMap::new();
    for part in split_params(rest) {
        let (k, v) = part.split_once('=').ok_or_else(|| FedError::Malformed("parameter".into()))?;
        let v = v.trim();
        let v = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(v);
        map.insert(k.trim().to_ascii_lowercase(), v.replace("\\\"", "\"").replace("\\\\", "\\"));
    }
    let get = |k: &str| map.get(k).cloned().filter(|s| !s.is_empty());
    Ok(XMatrix {
        origin: get("origin").ok_or_else(|| FedError::Malformed("origin".into()))?,
        destination: get("destination"),
        key: get("key").ok_or_else(|| FedError::Malformed("key".into()))?,
        sig: get("sig").ok_or_else(|| FedError::Malformed("sig".into()))?,
    })
}

fn split_params(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut quoted, mut esc) = (Vec::new(), String::new(), false, false);
    for c in s.chars() {
        match c {
            _ if esc => {
                cur.push(c);
                esc = false;
            }
            '\\' if quoted => {
                cur.push(c);
                esc = true;
            }
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// The object a sender signs for an authenticated federation request.
/// `uri` is the full path and query as the receiver sees it, including `/_matrix`.
pub fn request_signing_object(method: &str, uri: &str, origin: &str, destination: &str, content: Option<&Value>) -> Value {
    let mut o = BTreeMap::new();
    o.insert("method", json!(method.to_ascii_uppercase()));
    o.insert("uri", json!(uri));
    o.insert("origin", json!(origin));
    o.insert("destination", json!(destination));
    if let Some(c) = content {
        o.insert("content", c.clone());
    }
    json!(o)
}

/// Build the `Authorization` header value for an outgoing signed request.
pub fn build_x_matrix_header(
    origin: &str,
    destination: &str,
    key_id: &str,
    key: &SigningKey,
    method: &str,
    uri: &str,
    content: Option<&Value>,
) -> String {
    let obj = request_signing_object(method, uri, origin, destination, content);
    let sig = b64(&key.sign(&canonical_json(&obj)).to_bytes());
    format!("X-Matrix origin=\"{origin}\",destination=\"{destination}\",key=\"{key_id}\",sig=\"{sig}\"")
}

/// Verify a signed request given the sender's public key.
pub fn verify_request_signature(
    header: &XMatrix,
    method: &str,
    uri: &str,
    local_server: &str,
    content: Option<&Value>,
    public_key_b64: &str,
) -> Result<(), FedError> {
    let obj = request_signing_object(method, uri, &header.origin, header.destination.as_deref().unwrap_or(local_server), content);
    verify_bytes(&canonical_json(&obj), &header.sig, public_key_b64)
}

// ------------------------------------------------------- remote key cache

/// Verify keys parsed from a remote `key/v2/server` response.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedKeys {
    /// `(key_id, base64 public key)`.
    pub keys: Vec<(String, String)>,
    /// Expiry, already capped to one validity window from now.
    pub valid_until_ms: i64,
}

/// Validate a remote key response: right server name, not expired, and
/// self-signed by every listed key that carries a signature (at least one).
pub fn parse_server_keys(resp: &Value, expect_server: &str, now_ms: i64) -> Result<ParsedKeys, FedError> {
    if resp.get("server_name").and_then(Value::as_str) != Some(expect_server) {
        return Err(FedError::Malformed("server_name mismatch".into()));
    }
    let valid_until = resp.get("valid_until_ts").and_then(Value::as_i64).ok_or_else(|| FedError::Malformed("valid_until_ts".into()))?;
    if valid_until <= now_ms {
        return Err(FedError::Malformed("keys expired".into()));
    }
    let vk = resp.get("verify_keys").and_then(Value::as_object).ok_or_else(|| FedError::Malformed("verify_keys".into()))?;
    let (mut keys, mut verified) = (Vec::new(), 0);
    for (id, v) in vk {
        let pk = v.get("key").and_then(Value::as_str).ok_or_else(|| FedError::Malformed("key".into()))?;
        let signed = resp.get("signatures").and_then(|s| s.get(expect_server)).and_then(|s| s.get(id)).is_some();
        if signed {
            verify_json(resp, expect_server, id, pk)?;
            verified += 1;
        }
        keys.push((id.clone(), pk.to_string()));
    }
    if verified == 0 {
        return Err(FedError::BadSignature);
    }
    Ok(ParsedKeys { keys, valid_until_ms: valid_until.min(now_ms + KEY_VALIDITY_MS) })
}

/// Cached public key for `(server, key_id)` that is still valid.
pub fn cached_remote_key(conn: &Connection, server: &str, key_id: &str, now_ms: i64) -> Result<Option<String>, FedError> {
    Ok(conn
        .query_row(
            "SELECT public_key FROM fed_remote_keys WHERE server_name=?1 AND key_id=?2 AND valid_until_ms > ?3",
            params![server, key_id, now_ms],
            |r| r.get(0),
        )
        .optional()?)
}

/// Last time any key of `server` was fetched, if ever.
pub fn last_fetch_ms(conn: &Connection, server: &str) -> Result<Option<i64>, FedError> {
    Ok(conn.query_row("SELECT MAX(fetched_ms) FROM fed_remote_keys WHERE server_name=?1", params![server], |r| r.get(0))?)
}

/// Store the keys of a validated response.
pub fn store_remote_keys(conn: &Connection, server: &str, parsed: &ParsedKeys, now_ms: i64) -> Result<(), FedError> {
    for (id, pk) in &parsed.keys {
        conn.execute(
            "INSERT INTO fed_remote_keys (server_name, key_id, public_key, valid_until_ms, fetched_ms) VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(server_name, key_id) DO UPDATE SET public_key=excluded.public_key, valid_until_ms=excluded.valid_until_ms, fetched_ms=excluded.fetched_ms",
            params![server, id, pk, parsed.valid_until_ms, now_ms],
        )?;
    }
    Ok(())
}

/// Whether a refetch for an unknown key is allowed right now.
pub fn may_refetch(conn: &Connection, server: &str, now_ms: i64) -> Result<bool, FedError> {
    Ok(last_fetch_ms(conn, server)?.map_or(true, |t| now_ms - t >= REFETCH_FLOOR_MS))
}

// ------------------------------------------------------------ resolution

/// Boxed future returned by [`RemoteKeys::fetch_server_keys`].
pub type FetchFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, FedError>> + Send + 'a>>;

/// Fetches a remote server's `key/v2/server` document.
pub trait RemoteKeys: Send + Sync {
    /// Resolve `server` and return its raw key response (unvalidated).
    fn fetch_server_keys<'a>(&'a self, server: &'a str) -> FetchFuture<'a>;
}

/// Where a server name points after delegation.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    /// Host (or IP literal) to connect to.
    pub host: String,
    /// Port; `None` means the default federation port 8448.
    pub port: Option<u16>,
}

impl Target {
    fn authority(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{}", self.host, p),
            None => format!("{}:8448", self.host),
        }
    }
}

/// Split `host[:port]`, handling bracketed IPv6. Returns `(host, port, is_ip_literal)`.
pub fn parse_server_name(name: &str) -> Option<(String, Option<u16>, bool)> {
    if name.is_empty() || name.contains('/') || name.contains(' ') {
        return None;
    }
    if let Some(rest) = name.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(p.parse().ok()?),
            None if tail.is_empty() => None,
            None => return None,
        };
        return Some((format!("[{host}]"), port, true));
    }
    let (host, port) = match name.rsplit_once(':') {
        Some((h, p)) => (h, Some(p.parse::<u16>().ok()?)),
        None => (name, None),
    };
    let is_ip = host.parse::<std::net::Ipv4Addr>().is_ok();
    Some((host.to_string(), port, is_ip))
}

/// Resolve a server name to a connection target. `well_known` is the
/// delegated `m.server` value, when the name served one. SRV records are not
/// consulted (F0); a name that needs SRV must publish `.well-known`.
pub fn resolve_target(name: &str, well_known: Option<&str>) -> Option<Target> {
    let (host, port, is_ip) = parse_server_name(name)?;
    if is_ip || port.is_some() {
        return Some(Target { host, port });
    }
    if let Some(delegate) = well_known {
        let (dh, dp, _) = parse_server_name(delegate)?;
        return Some(Target { host: dh, port: dp });
    }
    Some(Target { host, port: None })
}

/// Production fetcher: `.well-known` delegation, then HTTPS GET of the key document.
pub struct HttpKeyFetcher {
    client: reqwest::Client,
    overrides: HashMap<String, String>,
}

impl HttpKeyFetcher {
    /// New fetcher with a 10 s timeout and no redirects.
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self { client, overrides: HashMap::new() }
    }

    /// Staging aid: talk to `server_name` at `base_url` (e.g. `http://127.0.0.1:9000`) instead of resolving it.
    pub fn with_override(mut self, server_name: &str, base_url: &str) -> Self {
        self.overrides.insert(server_name.to_string(), base_url.trim_end_matches('/').to_string());
        self
    }

    /// Parse `name=base_url,name2=base_url2`.
    pub fn with_overrides_from(mut self, spec: &str) -> Self {
        for pair in spec.split(',').filter(|s| !s.trim().is_empty()) {
            if let Some((n, u)) = pair.split_once('=') {
                self = self.with_override(n.trim(), u.trim());
            }
        }
        self
    }

    async fn get_limited(&self, url: &str) -> Result<Vec<u8>, FedError> {
        let resp = self.client.get(url).send().await.map_err(|e| FedError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(FedError::Network(format!("status {}", resp.status().as_u16())));
        }
        let bytes = resp.bytes().await.map_err(|e| FedError::Network(e.to_string()))?;
        if bytes.len() > MAX_REMOTE_BODY {
            return Err(FedError::Network("body too large".into()));
        }
        Ok(bytes.to_vec())
    }
}

impl Default for HttpKeyFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpKeyFetcher {
    /// Unauthenticated GET of `uri` (full path and query) on `server`; `(status, json)`.
    pub async fn get_unsigned(&self, server: &str, uri: &str) -> Result<(u16, Value), FedError> {
        let base = self.base_url(server).await?;
        let resp = self.client.get(format!("{base}{uri}")).send().await.map_err(|e| FedError::Network(e.to_string()))?;
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await.map_err(|e| FedError::Network(e.to_string()))?;
        if bytes.len() > 64 * 1024 {
            return Err(FedError::Network("body too large".into()));
        }
        Ok((status, serde_json::from_slice(&bytes).unwrap_or(Value::Null)))
    }

    /// Base URL (`scheme://authority`) for a server name: staging override,
    /// else `.well-known` delegation, else `name:8448`.
    pub async fn base_url(&self, server: &str) -> Result<String, FedError> {
        if let Some(base) = self.overrides.get(server) {
            return Ok(base.clone());
        }
        let (host, port, is_ip) = parse_server_name(server).ok_or_else(|| FedError::Malformed("server name".into()))?;
        let well_known = if is_ip || port.is_some() {
            None
        } else {
            match self.get_limited(&format!("https://{host}/.well-known/matrix/server")).await {
                Ok(b) => serde_json::from_slice::<Value>(&b).ok().and_then(|v| v.get("m.server").and_then(Value::as_str).map(str::to_string)),
                Err(_) => None,
            }
        };
        let target = resolve_target(server, well_known.as_deref()).ok_or_else(|| FedError::Malformed("delegate".into()))?;
        Ok(format!("https://{}", target.authority()))
    }
}

impl RemoteKeys for HttpKeyFetcher {
    fn fetch_server_keys<'a>(&'a self, server: &'a str) -> FetchFuture<'a> {
        Box::pin(async move {
            let base = self.base_url(server).await?;
            let body = self.get_limited(&format!("{base}/_matrix/key/v2/server")).await?;
            serde_json::from_slice(&body).map_err(|_| FedError::Malformed("key json".into()))
        })
    }
}

/// Boxed future returned by [`FedTransport::request`].
pub type ReqFuture<'a> = Pin<Box<dyn Future<Output = Result<(u16, Value), FedError>> + Send + 'a>>;

/// Sends one signed federation request and returns `(status, json body)`.
/// `uri` is the full path and query including `/_matrix`.
pub trait FedTransport: Send + Sync {
    /// Deliver to `destination`; `authorization` is the complete `X-Matrix` header value.
    fn request<'a>(&'a self, destination: &'a str, method: &'a str, uri: &'a str, authorization: &'a str, body: Option<&'a Value>) -> ReqFuture<'a>;
}

impl FedTransport for HttpKeyFetcher {
    fn request<'a>(&'a self, destination: &'a str, method: &'a str, uri: &'a str, authorization: &'a str, body: Option<&'a Value>) -> ReqFuture<'a> {
        Box::pin(async move {
            let base = self.base_url(destination).await?;
            let m = reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| FedError::Malformed("method".into()))?;
            let mut req = self.client.request(m, format!("{base}{uri}")).header("Authorization", authorization);
            if let Some(b) = body {
                req = req.header("Content-Type", "application/json").body(canonical_json(b));
            }
            let resp = req.send().await.map_err(|e| FedError::Network(e.to_string()))?;
            let status = resp.status().as_u16();
            let bytes = resp.bytes().await.map_err(|e| FedError::Network(e.to_string()))?;
            if bytes.len() > 8 * 1024 * 1024 {
                return Err(FedError::Network("body too large".into()));
            }
            Ok((status, serde_json::from_slice(&bytes).unwrap_or(Value::Null)))
        })
    }
}

/// Percent-encode one path segment (RFC 3986 unreserved characters pass through).
pub fn enc(segment: &str) -> String {
    let mut out = String::new();
    for b in segment.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        crate::store::create_matrix_schema(&c).unwrap();
        c
    }

    #[test]
    fn canonical_json_sorts_keys_and_is_compact() {
        let v = json!({"b": 1, "a": {"d": [1, 2], "c": "x"}});
        assert_eq!(String::from_utf8(canonical_json(&v)).unwrap(), r#"{"a":{"c":"x","d":[1,2]},"b":1}"#);
    }

    #[test]
    fn signing_key_is_stable_until_retired() {
        let c = db();
        let (id1, k1) = active_signing_key(&c, 1000).unwrap();
        let (id2, k2) = active_signing_key(&c, 2000).unwrap();
        assert_eq!((id1.clone(), k1.to_bytes()), (id2, k2.to_bytes()));
        assert!(id1.starts_with("ed25519:"));
        retire_active_key(&c, 3000).unwrap();
        let (id3, _) = active_signing_key(&c, 4000).unwrap();
        assert_ne!(id1, id3);
        let resp = server_keys_response(&c, "a.example", 5000).unwrap();
        assert!(resp["old_verify_keys"][&id1]["expired_ts"].as_i64() == Some(3000));
    }

    #[test]
    fn sign_and_verify_json_ignores_signatures_and_unsigned() {
        let c = db();
        let (id, key) = active_signing_key(&c, 0).unwrap();
        let pk = b64(key.verifying_key().as_bytes());
        let mut o = Map::new();
        o.insert("x".into(), json!(1));
        sign_json(&mut o, "a.example", &id, &key);
        let mut v = Value::Object(o);
        verify_json(&v, "a.example", &id, &pk).unwrap();
        v["unsigned"] = json!({"age": 5});
        verify_json(&v, "a.example", &id, &pk).unwrap();
        v["x"] = json!(2);
        assert_eq!(verify_json(&v, "a.example", &id, &pk), Err(FedError::BadSignature));
        assert_eq!(verify_json(&v, "b.example", &id, &pk), Err(FedError::BadSignature));
    }

    #[test]
    fn published_keys_validate_and_reject_tampering() {
        let c = db();
        let resp = server_keys_response(&c, "a.example", 1000).unwrap();
        let parsed = parse_server_keys(&resp, "a.example", 2000).unwrap();
        assert_eq!(parsed.keys.len(), 1);
        assert_eq!(parse_server_keys(&resp, "other.example", 2000), Err(FedError::Malformed("server_name mismatch".into())));
        assert!(parse_server_keys(&resp, "a.example", 1000 + KEY_VALIDITY_MS + 1).is_err(), "expired");
        let mut bad = resp.clone();
        bad["valid_until_ts"] = json!(i64::MAX / 2);
        assert_eq!(parse_server_keys(&bad, "a.example", 2000), Err(FedError::BadSignature));
        let mut unsigned = resp.clone();
        unsigned.as_object_mut().unwrap().remove("signatures");
        assert_eq!(parse_server_keys(&unsigned, "a.example", 2000), Err(FedError::BadSignature));
    }

    #[test]
    fn x_matrix_header_parses_quoted_bare_and_old_forms() {
        let h = parse_x_matrix(r#"X-Matrix origin="a.example",destination="b.example",key="ed25519:k1",sig="AbC""#).unwrap();
        assert_eq!((h.origin.as_str(), h.destination.as_deref(), h.key.as_str(), h.sig.as_str()), ("a.example", Some("b.example"), "ed25519:k1", "AbC"));
        let old = parse_x_matrix("X-Matrix origin=a.example,key=ed25519:k1,sig=AbC").unwrap();
        assert_eq!(old.destination, None);
        assert!(parse_x_matrix("Bearer x").is_err());
        assert!(parse_x_matrix(r#"X-Matrix origin="a",key="k""#).is_err());
    }

    #[test]
    fn request_signature_roundtrip_and_binding() {
        let c = db();
        let (id, key) = active_signing_key(&c, 0).unwrap();
        let pk = b64(key.verifying_key().as_bytes());
        let body = json!({"k": "v"});
        let hdr = build_x_matrix_header("a.example", "b.example", &id, &key, "PUT", "/_matrix/federation/v1/send/1", Some(&body));
        let parsed = parse_x_matrix(&hdr).unwrap();
        verify_request_signature(&parsed, "PUT", "/_matrix/federation/v1/send/1", "b.example", Some(&body), &pk).unwrap();
        assert!(verify_request_signature(&parsed, "PUT", "/_matrix/federation/v1/send/2", "b.example", Some(&body), &pk).is_err(), "uri bound");
        assert!(verify_request_signature(&parsed, "GET", "/_matrix/federation/v1/send/1", "b.example", Some(&body), &pk).is_err(), "method bound");
        assert!(verify_request_signature(&parsed, "PUT", "/_matrix/federation/v1/send/1", "b.example", Some(&json!({"k":"w"})), &pk).is_err(), "body bound");
        let mut other = parsed.clone();
        other.destination = Some("c.example".into());
        assert!(verify_request_signature(&other, "PUT", "/_matrix/federation/v1/send/1", "b.example", Some(&body), &pk).is_err(), "destination bound");
    }

    #[test]
    fn remote_key_cache_respects_expiry_and_refetch_floor() {
        let c = db();
        let parsed = ParsedKeys { keys: vec![("ed25519:k".into(), "AAAA".into())], valid_until_ms: 10_000 };
        assert_eq!(cached_remote_key(&c, "a.example", "ed25519:k", 100).unwrap(), None);
        store_remote_keys(&c, "a.example", &parsed, 100).unwrap();
        assert_eq!(cached_remote_key(&c, "a.example", "ed25519:k", 5000).unwrap().as_deref(), Some("AAAA"));
        assert_eq!(cached_remote_key(&c, "a.example", "ed25519:k", 10_000).unwrap(), None, "expired");
        assert!(!may_refetch(&c, "a.example", 100 + REFETCH_FLOOR_MS - 1).unwrap());
        assert!(may_refetch(&c, "a.example", 100 + REFETCH_FLOOR_MS).unwrap());
        assert!(may_refetch(&c, "never.example", 0).unwrap());
    }

    #[test]
    fn server_name_resolution_rules() {
        assert_eq!(parse_server_name("a.example"), Some(("a.example".into(), None, false)));
        assert_eq!(parse_server_name("a.example:8449"), Some(("a.example".into(), Some(8449), false)));
        assert_eq!(parse_server_name("192.0.2.1"), Some(("192.0.2.1".into(), None, true)));
        assert_eq!(parse_server_name("[2001:db8::1]:9"), Some(("[2001:db8::1]".into(), Some(9), true)));
        assert_eq!(parse_server_name("a/b"), None);
        assert_eq!(resolve_target("a.example", None), Some(Target { host: "a.example".into(), port: None }));
        assert_eq!(resolve_target("a.example", Some("edge.example:443")), Some(Target { host: "edge.example".into(), port: Some(443) }));
        assert_eq!(resolve_target("a.example:8449", Some("edge.example")), Some(Target { host: "a.example".into(), port: Some(8449) }), "explicit port wins, no well-known");
        assert_eq!(Target { host: "h".into(), port: None }.authority(), "h:8448");
    }
}
