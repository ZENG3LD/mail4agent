//! HTTP execution of the engine's requests against one server: URL building (the spec prefix is
//! kept only when the server was found to serve it), discovery, and the bearer.

use std::time::Duration;

use mail4agent_messenger::{HttpResponseDescriptor, OutgoingRequest};
use reqwest::Url;

use crate::error::{AgentError, Result};

/// Same clipping the shell uses for text that may reach logs: no long opaque tokens.
pub fn clip_public(text: String) -> String {
    let mut out = String::new();
    for token in text.split_whitespace() {
        if token.len() > 80 {
            out.push_str("[omitted]");
        } else {
            out.push_str(token);
        }
        out.push(' ');
        if out.len() > 240 {
            break;
        }
    }
    out
}

pub fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// A server origin plus the decision whether it serves the Matrix paths under `/_matrix`.
#[derive(Clone)]
pub struct HttpExec {
    client: reqwest::blocking::Client,
    base: Url,
    keep_prefix: bool,
}

pub(crate) fn parse_origin(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).map_err(|_| AgentError::Protocol("not a valid server URL".into()))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() || url.query().is_some() || !url.username().is_empty() || url.password().is_some() {
        return Err(AgentError::Protocol("not a valid server URL".into()));
    }
    let mut url = url;
    url.set_fragment(None);
    Ok(url)
}

impl HttpExec {
    pub fn new(base: &str) -> Result<Self> {
        let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(60)).http1_only().build().map_err(|e| AgentError::Transport(clip_public(e.to_string())))?;
        Ok(Self { client, base: parse_origin(base)?, keep_prefix: false })
    }

    /// Our own mounts serve `/client/v3` without the spec prefix. Anything else is asked, never
    /// assumed: `GET /_matrix/client/versions` answering 2xx means the prefix is served.
    pub fn probe_prefix(&mut self) -> bool {
        self.keep_prefix = self.get_status("/_matrix/client/versions").is_some_and(|s| (200..300).contains(&s));
        self.keep_prefix
    }

    pub fn set_keep_prefix(&mut self, keep: bool) {
        self.keep_prefix = keep;
    }

    pub fn keep_prefix(&self) -> bool {
        self.keep_prefix
    }

    pub fn base(&self) -> &Url {
        &self.base
    }

    pub fn client(&self) -> &reqwest::blocking::Client {
        &self.client
    }

    /// Replaces the origin (`.well-known` told us the real one).
    pub fn rebase(&mut self, origin: &str) -> Result<()> {
        self.base = parse_origin(origin)?;
        Ok(())
    }

    fn get_status(&self, path: &str) -> Option<u16> {
        let url = self.url(path, &[]).ok()?;
        self.client.get(url).send().ok().map(|r| r.status().as_u16())
    }

    /// `GET path` as JSON (no bearer): `(status, json)`.
    pub fn get_json(&self, path: &str) -> Result<(u16, serde_json::Value)> {
        let url = self.url(path, &[])?;
        let r = self.client.get(url).send().map_err(|e| AgentError::Transport(clip_public(e.to_string())))?;
        let st = r.status().as_u16();
        Ok((st, r.json().unwrap_or(serde_json::Value::Null)))
    }

    /// `GET path` as JSON with a bearer: `(status, json)`.
    pub fn get_json_as(&self, bearer: &str, path: &str) -> Result<(u16, serde_json::Value)> {
        let url = self.url(path, &[])?;
        let r = self.client.get(url).bearer_auth(bearer).send().map_err(|e| AgentError::Transport(clip_public(e.to_string())))?;
        let st = r.status().as_u16();
        Ok((st, r.json().unwrap_or(serde_json::Value::Null)))
    }

    /// `/_matrix/client/v3/x` becomes `/client/v3/x` unless the server serves the prefix. A path
    /// already without it is left alone.
    pub fn url(&self, path: &str, query: &[(String, String)]) -> Result<Url> {
        let path = if self.keep_prefix { path } else { path.strip_prefix("/_matrix").unwrap_or(path) };
        if !path.starts_with('/') {
            return Err(AgentError::Protocol("path must start with a slash".into()));
        }
        let mut raw = self.base.as_str().trim_end_matches('/').to_string();
        raw.push_str(path);
        if !query.is_empty() {
            raw.push('?');
            for (i, (n, v)) in query.iter().enumerate() {
                if i > 0 {
                    raw.push('&');
                }
                raw.push_str(&percent_encode(n));
                raw.push('=');
                raw.push_str(&percent_encode(v));
            }
        }
        Url::parse(&raw).map_err(|_| AgentError::Protocol("not a valid request URL".into()))
    }

    /// One engine request with `bearer`.
    pub fn perform(&self, bearer: &str, request: &OutgoingRequest) -> Result<HttpResponseDescriptor> {
        let url = self.url(&request.path, &request.query)?;
        let method = reqwest::Method::from_bytes(request.method.as_str().as_bytes()).map_err(|_| AgentError::Protocol("unsupported method".into()))?;
        let mut header = reqwest::header::HeaderValue::from_str(&format!("Bearer {bearer}")).map_err(|_| AgentError::Protocol("token is not a header value".into()))?;
        header.set_sensitive(true);
        let mut builder = self.client.request(method, url).header(reqwest::header::AUTHORIZATION, header);
        if let Some(body) = &request.body {
            let bytes = serde_json::to_vec(body).map_err(|e| AgentError::Protocol(e.to_string()))?;
            builder = builder.header(reqwest::header::CONTENT_TYPE, "application/json").body(bytes);
        }
        let response = builder.send().map_err(|e| AgentError::Transport(clip_public(e.to_string())))?;
        let status = response.status().as_u16();
        let body = response.bytes().map_err(|e| AgentError::Transport(clip_public(e.to_string())))?.to_vec();
        Ok(HttpResponseDescriptor { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_spec_prefix_is_kept_only_when_asked() {
        let mut h = HttpExec::new("http://127.0.0.1:9").expect("base");
        let q = [("timeout".to_string(), "5".to_string())];
        assert_eq!(h.url("/_matrix/client/v3/sync", &q).unwrap().as_str(), "http://127.0.0.1:9/client/v3/sync?timeout=5");
        assert_eq!(h.url("/client/v3/sync", &[]).unwrap().path(), "/client/v3/sync");
        h.set_keep_prefix(true);
        assert_eq!(h.url("/_matrix/client/v3/sync", &q).unwrap().as_str(), "http://127.0.0.1:9/_matrix/client/v3/sync?timeout=5");
        assert!(HttpExec::new("ftp://x").is_err());
        assert!(HttpExec::new("http://u:p@x").is_err());
    }
}
