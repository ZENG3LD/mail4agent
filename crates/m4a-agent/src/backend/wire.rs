//! The smallest HTTP shape the login needs, so the protocol code is the same over any transport
//! (and testable without a network).

use serde_json::Value;

use crate::error::{AgentError, Result};

pub trait Wire: Send {
    /// POST JSON; the status and the JSON answer (`Null` when the body is not JSON).
    fn post(&self, path: &str, body: &Value, bearer: Option<&str>) -> Result<(u16, Value)>;
    fn get(&self, path: &str, bearer: Option<&str>) -> Result<(u16, Value)>;
}

#[cfg(any(feature = "tier-server", feature = "tier-matrix"))]
pub struct HttpWire {
    base: String,
    http: reqwest::blocking::Client,
}

#[cfg(any(feature = "tier-server", feature = "tier-matrix"))]
impl HttpWire {
    pub fn new(base: &str) -> Result<Self> {
        let http = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(30)).build().map_err(|e| AgentError::Transport(e.to_string()))?;
        Ok(Self { base: base.trim_end_matches('/').to_string(), http })
    }
    fn finish(r: reqwest::Result<reqwest::blocking::Response>) -> Result<(u16, Value)> {
        let r = r.map_err(|e| AgentError::Transport(e.to_string()))?;
        let status = r.status().as_u16();
        Ok((status, r.json::<Value>().unwrap_or(Value::Null)))
    }
}

#[cfg(any(feature = "tier-server", feature = "tier-matrix"))]
impl Wire for HttpWire {
    fn post(&self, path: &str, body: &Value, bearer: Option<&str>) -> Result<(u16, Value)> {
        let mut r = self.http.post(format!("{}{path}", self.base)).json(body);
        if let Some(b) = bearer {
            r = r.bearer_auth(b);
        }
        Self::finish(r.send())
    }
    fn get(&self, path: &str, bearer: Option<&str>) -> Result<(u16, Value)> {
        let mut r = self.http.get(format!("{}{path}", self.base));
        if let Some(b) = bearer {
            r = r.bearer_auth(b);
        }
        Self::finish(r.send())
    }
}

/// Reads a string field, or fails as a protocol error.
pub fn field(v: &Value, key: &str) -> Result<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string).ok_or_else(|| AgentError::Protocol(format!("answer without {key}")))
}
