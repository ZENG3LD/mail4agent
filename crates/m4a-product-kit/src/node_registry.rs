//! Accounts registered by trusted nodes.
//!
//! A node (a machine that runs agent sessions for one owner) is registered here by an admin with
//! its ed25519 public key and owner. A registered, non-revoked node may then register accounts
//! for its own sessions without an operator invite: it signs each request with its node key
//! ([`request_message`]); the product answers with a one-time invite that the session's own
//! client spends in the normal key enroll, so each account still has its own key.
//!
//! Guards: unknown or revoked node -> refused; timestamp window; nonce replay book; per-node rate
//! limit; every decision is appended to an audit log (no secrets). Revoking a node returns the
//! nicks it registered so the caller can remove those accounts too.
//!
//! State is a small owner-only JSON file next to the product's state, not the user database.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Accepted clock skew of a signed request.
pub const MAX_SKEW_MS: i64 = 5 * 60 * 1000;
/// Default accounts a node may register per hour.
pub const DEFAULT_RATE_PER_HOUR: usize = 60;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRecord {
    /// ed25519 public key, URL-safe base64 without padding (normalized on register).
    pub public_key: String,
    pub owner: String,
    pub revoked: bool,
    pub created_ms: i64,
    #[serde(default)]
    pub nicks: Vec<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    nodes: BTreeMap<String, NodeRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeError {
    UnknownNode,
    Revoked,
    BadSignature,
    Stale,
    Replay,
    RateLimited,
    Invalid(&'static str),
    Io(String),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            NodeError::UnknownNode => "node is not registered",
            NodeError::Revoked => "node is revoked",
            NodeError::BadSignature => "bad node signature",
            NodeError::Stale => "request timestamp out of window",
            NodeError::Replay => "nonce already used",
            NodeError::RateLimited => "node rate limit reached",
            NodeError::Invalid(m) => m,
            NodeError::Io(_) => "registry storage failed",
        })
    }
}

/// One signed account request from a node.
#[derive(Clone, Debug, Deserialize)]
pub struct NodeAccountRequest {
    pub node_id: String,
    #[serde(default)]
    pub nick: Option<String>,
    pub ts_ms: i64,
    pub nonce: String,
    pub signature: String,
}

/// Exact bytes a node signs.
pub fn request_message(audience: &str, node_id: &str, nick: Option<&str>, ts_ms: i64, nonce: &str) -> Vec<u8> {
    format!("m4a-node-account-v1\n{audience}\n{node_id}\n{}\n{ts_ms}\n{nonce}\n", nick.unwrap_or("")).into_bytes()
}

/// Decodes standard or URL-safe base64 (padded or not).
pub fn decode_any(text: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD].iter().find_map(|e| e.decode(text.trim()).ok())
}

fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}

pub struct NodeRegistry {
    path: PathBuf,
    audit: PathBuf,
    rate_per_hour: usize,
    state: Mutex<State>,
    nonces: Mutex<HashMap<String, i64>>,
    recent: Mutex<HashMap<String, VecDeque<i64>>>,
}

impl NodeRegistry {
    /// Opens (or starts) the registry file `path`; the audit log is `path` + `.audit.jsonl`.
    pub fn open(path: impl Into<PathBuf>, rate_per_hour: usize) -> Result<Self, NodeError> {
        let path = path.into();
        let state = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|_| NodeError::Io("registry is not json".into()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(NodeError::Io(e.kind().to_string())),
        };
        let mut audit = path.clone().into_os_string();
        audit.push(".audit.jsonl");
        Ok(Self { path, audit: audit.into(), rate_per_hour: rate_per_hour.max(1), state: Mutex::new(state), nonces: Mutex::default(), recent: Mutex::default() })
    }

    fn save(&self, state: &State) -> Result<(), NodeError> {
        let tmp = self.path.with_extension("tmp");
        write_private(&tmp, &serde_json::to_vec_pretty(state).unwrap_or_default())?;
        std::fs::rename(&tmp, &self.path).map_err(|e| NodeError::Io(e.kind().to_string()))
    }

    fn audit(&self, now_ms: i64, event: &str, node_id: &str, detail: &str) {
        use std::io::Write;
        let line = serde_json::json!({"ts_ms": now_ms, "event": event, "node_id": node_id, "detail": detail}).to_string();
        tracing::info!(event, node_id, detail, "node registry");
        let mut o = std::fs::OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        if let Ok(mut f) = o.open(&self.audit) {
            let _ = writeln!(f, "{line}");
        }
    }

    pub fn register(&self, node_id: &str, public_key: &str, owner: &str, now_ms: i64) -> Result<NodeRecord, NodeError> {
        if !valid_id(node_id) || owner.trim().is_empty() {
            return Err(NodeError::Invalid("node_id and owner are required"));
        }
        let pk = decode_any(public_key).filter(|k| k.len() == 32).ok_or(NodeError::Invalid("public_key must be a 32-byte ed25519 key"))?;
        let pk = m4a_seam::keyproof::encode(&pk);
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if st.nodes.get(node_id).is_some_and(|n| n.revoked) {
            return Err(NodeError::Revoked);
        }
        let nicks = st.nodes.get(node_id).map(|n| n.nicks.clone()).unwrap_or_default();
        let rec = NodeRecord { public_key: pk, owner: owner.to_owned(), revoked: false, created_ms: now_ms, nicks };
        st.nodes.insert(node_id.to_owned(), rec.clone());
        self.save(&st)?;
        drop(st);
        self.audit(now_ms, "register", node_id, owner);
        Ok(rec)
    }

    /// Marks the node revoked (final) and returns the nicks it registered.
    pub fn revoke(&self, node_id: &str, now_ms: i64) -> Result<Vec<String>, NodeError> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let rec = st.nodes.get_mut(node_id).ok_or(NodeError::UnknownNode)?;
        rec.revoked = true;
        let nicks = rec.nicks.clone();
        self.save(&st)?;
        drop(st);
        self.audit(now_ms, "revoke", node_id, &format!("{} accounts", nicks.len()));
        Ok(nicks)
    }

    pub fn list(&self) -> BTreeMap<String, NodeRecord> {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).nodes.clone()
    }

    /// Checks a node's signed request. On success the nonce is spent and the rate slot taken.
    pub fn authorize(&self, audience: &str, req: &NodeAccountRequest, now_ms: i64) -> Result<NodeRecord, NodeError> {
        let result = self.authorize_inner(audience, req, now_ms);
        if let Err(e) = &result {
            self.audit(now_ms, "refused", &req.node_id, &e.to_string());
        }
        result
    }

    fn authorize_inner(&self, audience: &str, req: &NodeAccountRequest, now_ms: i64) -> Result<NodeRecord, NodeError> {
        if !valid_id(&req.node_id) || req.nonce.len() < 8 || req.nonce.len() > 128 {
            return Err(NodeError::Invalid("malformed request"));
        }
        let rec = self.state.lock().unwrap_or_else(|p| p.into_inner()).nodes.get(&req.node_id).cloned().ok_or(NodeError::UnknownNode)?;
        if rec.revoked {
            return Err(NodeError::Revoked);
        }
        if (now_ms - req.ts_ms).abs() > MAX_SKEW_MS {
            return Err(NodeError::Stale);
        }
        let sig = decode_any(&req.signature).map(|s| m4a_seam::keyproof::encode(&s)).ok_or(NodeError::BadSignature)?;
        let msg = request_message(audience, &req.node_id, req.nick.as_deref(), req.ts_ms, &req.nonce);
        if !m4a_seam::keyproof::verify(&rec.public_key, &msg, &sig) {
            return Err(NodeError::BadSignature);
        }
        {
            let mut n = self.nonces.lock().unwrap_or_else(|p| p.into_inner());
            n.retain(|_, t| now_ms - *t <= 2 * MAX_SKEW_MS);
            let key = format!("{}\n{}", req.node_id, req.nonce);
            if n.contains_key(&key) {
                return Err(NodeError::Replay);
            }
            n.insert(key, now_ms);
        }
        let mut r = self.recent.lock().unwrap_or_else(|p| p.into_inner());
        let q = r.entry(req.node_id.clone()).or_default();
        while q.front().is_some_and(|t| now_ms - *t > 3_600_000) {
            q.pop_front();
        }
        if q.len() >= self.rate_per_hour {
            return Err(NodeError::RateLimited);
        }
        q.push_back(now_ms);
        Ok(rec)
    }

    /// Records an account the node registered (scope: that node and its owner).
    pub fn record_account(&self, node_id: &str, nick: &str, now_ms: i64) -> Result<(), NodeError> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let rec = st.nodes.get_mut(node_id).ok_or(NodeError::UnknownNode)?;
        if !rec.nicks.iter().any(|n| n == nick) {
            rec.nicks.push(nick.to_owned());
        }
        self.save(&st)?;
        drop(st);
        self.audit(now_ms, "account", node_id, nick);
        Ok(())
    }
}

fn write_private(p: &Path, b: &[u8]) -> Result<(), NodeError> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(p).and_then(|mut f| f.write_all(b)).map_err(|e| NodeError::Io(e.kind().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn reg(tag: &str, rate: usize) -> (NodeRegistry, PathBuf) {
        let dir = std::env::temp_dir().join(format!("m4a-node-reg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (NodeRegistry::open(dir.join("nodes.json"), rate).unwrap(), dir)
    }

    fn signed(key: &SigningKey, node: &str, nick: Option<&str>, ts: i64, nonce: &str) -> NodeAccountRequest {
        let sig = key.sign(&request_message("aud", node, nick, ts, nonce));
        NodeAccountRequest {
            node_id: node.into(),
            nick: nick.map(Into::into),
            ts_ms: ts,
            nonce: nonce.into(),
            signature: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        }
    }

    #[test]
    fn only_registered_unrevoked_nodes_with_valid_signatures_pass() {
        let (r, dir) = reg("a", 10);
        let k = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[8u8; 32]);
        assert_eq!(r.authorize("aud", &signed(&k, "n1", None, 1000, "nonce-0001"), 1000), Err(NodeError::UnknownNode));
        let pk = base64::engine::general_purpose::STANDARD.encode(k.verifying_key().to_bytes());
        r.register("n1", &pk, "owner-a", 1000).unwrap();
        assert!(r.authorize("aud", &signed(&k, "n1", Some("x-1"), 1000, "nonce-0002"), 1000).is_ok());
        assert_eq!(r.authorize("aud", &signed(&k, "n1", None, 1000, "nonce-0002"), 1000), Err(NodeError::Replay));
        assert_eq!(r.authorize("aud", &signed(&other, "n1", None, 1000, "nonce-0003"), 1000), Err(NodeError::BadSignature));
        assert_eq!(r.authorize("other-aud", &signed(&k, "n1", None, 1000, "nonce-0004"), 1000), Err(NodeError::BadSignature));
        assert_eq!(r.authorize("aud", &signed(&k, "n1", None, 1000, "nonce-0005"), 1000 + MAX_SKEW_MS + 1), Err(NodeError::Stale));
        r.record_account("n1", "x-1", 1000).unwrap();
        assert_eq!(r.revoke("n1", 2000).unwrap(), vec!["x-1".to_owned()]);
        assert_eq!(r.authorize("aud", &signed(&k, "n1", None, 2000, "nonce-0006"), 2000), Err(NodeError::Revoked));
        assert_eq!(r.register("n1", &pk, "owner-a", 3000), Err(NodeError::Revoked));
        // persisted
        let again = NodeRegistry::open(dir.join("nodes.json"), 10).unwrap();
        assert!(again.list()["n1"].revoked);
        assert!(std::fs::read_to_string(dir.join("nodes.json.audit.jsonl")).unwrap().contains("\"revoke\""));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rate_limit_per_node() {
        let (r, dir) = reg("b", 2);
        let k = SigningKey::from_bytes(&[9u8; 32]);
        r.register("n2", &m4a_seam::keyproof::encode(&k.verifying_key().to_bytes()), "o", 0).unwrap();
        assert!(r.authorize("aud", &signed(&k, "n2", None, 10, "nonce-a001"), 10).is_ok());
        assert!(r.authorize("aud", &signed(&k, "n2", None, 10, "nonce-a002"), 10).is_ok());
        assert_eq!(r.authorize("aud", &signed(&k, "n2", None, 10, "nonce-a003"), 10), Err(NodeError::RateLimited));
        let _ = std::fs::remove_dir_all(dir);
    }
}
