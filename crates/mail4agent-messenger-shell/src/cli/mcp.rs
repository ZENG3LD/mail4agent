//! `m4a-agent mcp`: stdio MCP server (newline-delimited JSON-RPC 2.0) giving a provider session
//! its own mailbox tools: `whoami`, `send`, `inbox`.
//!
//! Identity, first match wins:
//! 1. the environment (`M4A_NICK`, `M4A_SESSION_ID`, `M4A_SESSION_CAP`), also filled by
//!    `m4a-agent --session-file <path> mcp`;
//! 2. on-demand attach: the local node's ops listener (`M4A_NODE_OPS`, `host:port`) is asked
//!    `POST /m4a/attach` with the owner-only control token (its file path comes from the node's
//!    `/health`; only the same OS user can read it). The node verifies this process descends
//!    from a live provider process, applies its adoption policy and issues a per-session account.
//!
//! The capability stays in this process's memory; it reaches only the short-lived `m4a-agent`
//! child that performs a send, through that child's environment. It is never written to stdout,
//! a file, or a log.

use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

const PROTOCOL_VERSION: &str = "2025-06-18";
pub const NODE_OPS_ENV: &str = "M4A_NODE_OPS";
pub const PROVIDER_ENV: &str = "M4A_PROVIDER";
pub const PROVIDER_SESSION_ENV: &str = "M4A_PROVIDER_SESSION";

#[derive(Clone, Default)]
pub struct Identity {
    pub nick: String,
    pub session_id: String,
    cap: String,
    /// The account's own store root and the messenger URL, when the node told them (attach) or
    /// the environment has them. Directories and URLs only, no secret.
    pub store_root: String,
    pub product_url: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity").field("nick", &self.nick).finish_non_exhaustive()
    }
}

impl Identity {
    pub fn from_env() -> Option<Self> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Some(Self {
            nick: get("M4A_NICK")?,
            session_id: get("M4A_SESSION_ID").unwrap_or_default(),
            cap: get(crate::session_account::SESSION_CAP_ENV).unwrap_or_default(),
            store_root: get("M4A_STORE_ROOT").unwrap_or_default(),
            product_url: get("M4A_PRODUCT_URL").unwrap_or_default(),
        })
    }

    fn child_env(&self, cmd: &mut Command) {
        cmd.env("M4A_NICK", &self.nick);
        if !self.store_root.is_empty() {
            cmd.env("M4A_STORE_ROOT", &self.store_root);
        }
        if !self.product_url.is_empty() {
            cmd.env("M4A_PRODUCT_URL", &self.product_url);
            if std::env::var_os("M4A_HOMESERVER_URL").is_none_or(|v| v.is_empty()) {
                cmd.env("M4A_HOMESERVER_URL", &self.product_url);
            }
        }
        if !self.session_id.is_empty() {
            cmd.env("M4A_SESSION_ID", &self.session_id);
        }
        if self.cap.is_empty() {
            cmd.env_remove(crate::session_account::SESSION_CAP_ENV);
        } else {
            cmd.env(crate::session_account::SESSION_CAP_ENV, &self.cap);
        }
    }
}

struct Server {
    identity: Option<Identity>,
    provider: Option<String>,
    provider_session: Option<String>,
    node_ops: String,
}

pub fn run(args: Vec<String>) {
    let mut provider = std::env::var(PROVIDER_ENV).ok().filter(|v| !v.is_empty());
    let mut provider_session = std::env::var(PROVIDER_SESSION_ENV).ok().filter(|v| !v.is_empty());
    let mut node_ops = std::env::var(NODE_OPS_ENV).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| "127.0.0.1:18330".into());
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--provider" => provider = it.next(),
            "--provider-session" => provider_session = it.next(),
            "--node-ops" => node_ops = it.next().unwrap_or(node_ops),
            "-h" | "--help" => {
                println!("usage: m4a-agent [--session-file <path>] mcp [--provider <id>] [--provider-session <id>] [--node-ops <host:port>]");
                return;
            }
            _ => {}
        }
    }
    let mut server = Server { identity: Identity::from_env(), provider, provider_session, node_ops };
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        if let Some(reply) = server.handle_line(&line) {
            let _ = writeln!(out, "{reply}");
            let _ = out.flush();
        }
    }
}

impl Server {
    fn handle_line(&mut self, line: &str) -> Option<Value> {
        let Ok(msg) = serde_json::from_str::<Value>(line) else {
            return Some(json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}));
        };
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or_default();
        let id = id?; // notifications get no reply
        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": msg.pointer("/params/protocolVersion").and_then(Value::as_str).unwrap_or(PROTOCOL_VERSION),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "m4a", "version": env!("CARGO_PKG_VERSION")},
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => {
                let name = msg.pointer("/params/name").and_then(Value::as_str).unwrap_or_default().to_owned();
                let args = msg.pointer("/params/arguments").cloned().unwrap_or(json!({}));
                Ok(match self.call(&name, &args) {
                    Ok(text) => json!({"content":[{"type":"text","text":text}]}),
                    Err(text) => json!({"content":[{"type":"text","text":text}],"isError":true}),
                })
            }
            _ => Err(json!({"code":-32601,"message":"method not found"})),
        };
        Some(match result {
            Ok(r) => json!({"jsonrpc":"2.0","id":id,"result":r}),
            Err(e) => json!({"jsonrpc":"2.0","id":id,"error":e}),
        })
    }

    fn identity(&mut self) -> Result<Identity, String> {
        if let Some(i) = &self.identity {
            return Ok(i.clone());
        }
        let provider = self.provider.clone().ok_or("not attached: no identity in the environment and no provider (--provider / M4A_PROVIDER) to attach with")?;
        let i = attach(&self.node_ops, &provider, self.provider_session.as_deref(), std::process::id())?;
        self.identity = Some(i.clone());
        Ok(i)
    }

    fn call(&mut self, name: &str, args: &Value) -> Result<String, String> {
        match name {
            "whoami" => {
                let i = self.identity()?;
                Ok(json!({"nick": i.nick, "session_id": i.session_id, "has_capability": !i.cap.is_empty()}).to_string())
            }
            "send" => {
                let to = args.get("to").and_then(Value::as_str).filter(|s| !s.trim().is_empty()).ok_or("`to` is required")?;
                let text = args.get("text").and_then(Value::as_str).filter(|s| !s.trim().is_empty()).ok_or("`text` is required")?;
                let i = self.identity()?;
                let mut a = vec!["send", "--as", i.nick.as_str(), "--to", to];
                if !i.session_id.is_empty() {
                    a.extend(["--session", i.session_id.as_str()]);
                }
                a.push("-");
                run_self(&i, &a, Some(text))
            }
            "inbox" => {
                let i = self.identity()?;
                let mut a = vec!["inbox", "drain", "--format", "text"];
                let provider = self.provider.clone();
                if let Some(p) = provider.as_deref() {
                    a.extend(["--provider", p]);
                }
                if !i.session_id.is_empty() {
                    a.extend(["--session", i.session_id.as_str()]);
                }
                run_self(&i, &a, None)
            }
            other => Err(format!("unknown tool {other:?}")),
        }
    }
}

pub fn tools() -> Value {
    json!([
        {"name":"whoami","description":"This session's own mailbox nick and session id (never the key).",
         "inputSchema":{"type":"object","properties":{}}},
        {"name":"send","description":"Send an encrypted direct message from this session's own mailbox to a nick (or a room alias the client accepts as `to`).",
         "inputSchema":{"type":"object","properties":{"to":{"type":"string"},"text":{"type":"string"}},"required":["to","text"]}},
        {"name":"inbox","description":"Read (drain) the letters waiting for this session.",
         "inputSchema":{"type":"object","properties":{}}}
    ])
}

fn run_self(identity: &Identity, args: &[&str], stdin: Option<&str>) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("self path: {}", e.kind()))?;
    let mut cmd = Command::new(exe);
    cmd.args(args).stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    identity.child_env(&mut cmd);
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {}", e.kind()))?;
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let _ = pipe.write_all(text.as_bytes());
    }
    let out = child.wait_with_output().map_err(|e| format!("wait: {}", e.kind()))?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)).trim().to_owned();
    if out.status.success() { Ok(if text.is_empty() { "ok".into() } else { text }) } else { Err(text) }
}

/// Minimal HTTP/1.1 to the loopback ops listener: `(status, body)`.
fn http(addr: &str, method: &str, path: &str, bearer: Option<&str>) -> Result<(u16, String), String> {
    let mut s = TcpStream::connect(addr).map_err(|e| format!("node unreachable: {}", e.kind()))?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
    let auth = bearer.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
    let req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Content-Length: 0\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).map_err(|e| e.kind().to_string())?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).map_err(|e| e.kind().to_string())?;
    let status = buf.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or("bad http reply")?;
    let body = buf.split_once("\r\n\r\n").map(|(_, b)| b.to_owned()).unwrap_or_default();
    Ok((status, body))
}

fn query_escape(v: &str) -> String {
    v.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

pub fn attach(node_ops: &str, provider: &str, provider_session: Option<&str>, pid: u32) -> Result<Identity, String> {
    let (_, health) = http(node_ops, "GET", "/health", None)?;
    let health: Value = serde_json::from_str(&health).map_err(|_| "node health is not json")?;
    let file = health.get("control_token_file").and_then(Value::as_str).ok_or("node has no owner control token (attach unavailable)")?;
    let token = std::fs::read_to_string(file).map_err(|e| format!("owner token not readable by this user: {}", e.kind()))?;
    let mut path = format!("/m4a/attach?provider={}&pid={pid}", query_escape(provider));
    if let Some(s) = provider_session {
        path.push_str(&format!("&session={}", query_escape(s)));
    }
    let (status, body) = http(node_ops, "POST", &path, Some(token.trim()))?;
    let v: Value = serde_json::from_str(&body).unwrap_or(json!({}));
    if status != 200 {
        return Err(format!("attach refused ({status}): {}", v.get("error").and_then(Value::as_str).unwrap_or("no reason")));
    }
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default().to_owned();
    let identity = Identity { nick: s("nick"), session_id: s("session_id"), cap: s("cap"), store_root: s("store_root"), product_url: s("product_url") };
    if identity.nick.is_empty() {
        return Err("attach reply has no nick".into());
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(identity: Option<Identity>) -> Server {
        Server { identity, provider: None, provider_session: None, node_ops: "127.0.0.1:1".into() }
    }

    #[test]
    fn initialize_and_list_tools() {
        let mut s = server(None);
        let r = s.handle_line(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#).unwrap();
        assert_eq!(r["result"]["protocolVersion"], "2025-03-26");
        assert!(s.handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
        let r = s.handle_line(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).unwrap();
        let names: Vec<_> = r["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_owned()).collect();
        assert_eq!(names, ["whoami", "send", "inbox"]);
    }

    #[test]
    fn whoami_never_reveals_the_capability() {
        let mut s = server(Some(Identity { nick: "a-1".into(), session_id: "s".into(), cap: "secret-cap-value".into(), ..Default::default() }));
        let r = s.handle_line(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"whoami","arguments":{}}}"#).unwrap();
        let text = r.to_string();
        assert!(text.contains("a-1") && text.contains("has_capability"));
        assert!(!text.contains("secret-cap-value"));
        assert!(!format!("{:?}", s.identity).contains("secret-cap-value"));
    }

    #[test]
    fn unattached_without_provider_is_a_tool_error_not_a_crash() {
        let mut s = server(None);
        let r = s.handle_line(r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send","arguments":{"to":"b","text":"hi"}}}"#).unwrap();
        assert_eq!(r["result"]["isError"], true);
    }

    #[test]
    fn attach_reads_token_from_health_and_returns_identity() {
        use std::net::TcpListener;
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let dir = std::env::temp_dir().join(format!("m4a-mcp-attach-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let tok = dir.join("token");
        std::fs::write(&tok, "tkn\n").unwrap();
        let tok_s = tok.to_string_lossy().replace('\\', "\\\\");
        let h = std::thread::spawn(move || {
            for (i, conn) in l.incoming().take(2).enumerate() {
                let mut c = conn.unwrap();
                let mut buf = [0u8; 2048];
                let n = c.read(&mut buf).unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = if i == 0 {
                    format!(r#"{{"control_token_file":"{tok_s}"}}"#)
                } else {
                    assert!(req.starts_with("POST /m4a/attach?provider=grok&pid=7&session=x%2Fy"));
                    assert!(req.contains("Authorization: Bearer tkn\r\n"));
                    r#"{"nick":"grok-9","session_id":"k","cap":"c"}"#.to_owned()
                };
                write!(c, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let i = attach(&addr, "grok", Some("x/y"), 7).unwrap();
        h.join().unwrap();
        assert_eq!(i.nick, "grok-9");
        let _ = std::fs::remove_dir_all(dir);
    }
}
