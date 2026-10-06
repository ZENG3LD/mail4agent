//! Headless-only fallback: host the session through an ACP adapter that
//! SPAWNS its own agent process (it does not join a client that already has
//! the session open):
//!
//! | Kind | Adapter (default program) | Resume |
//! |---|---|---|
//! | claude_code | `claude-agent-acp` (ex zed `claude-code-acp`, `@agentclientprotocol/claude-agent-acp`) | `session/load` |
//! | cursor | `agent acp` (official, hidden) | `session/load` |
//! | cursor | `cursor-agent-acp` (community `@blowmage/cursor-agent-acp`) | `session/load` |
//!
//! One wake = spawn → `initialize` → `session/load {sessionId}` →
//! `session/prompt`. The prompt runs to completion in a background thread;
//! permission requests are answered `cancelled` (nobody is watching a
//! headless session), client fs/terminal calls get an error. `session/new`
//! is never used: a fresh session would lose the conversation.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{json, Value};

use super::{
    wake_prompt, ProviderKind, ProviderSession, SessionKind, WakeAdapter, WakeError, WakeLetter,
    WakeOutcome,
};

/// Which ACP adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpHost {
    /// `claude-agent-acp`.
    ClaudeAgentAcp,
    /// `agent acp`.
    CursorAgentAcp,
    /// `cursor-agent-acp` (community).
    CursorCommunityAcp,
}

impl AcpHost {
    /// Chain link id.
    pub fn id(self) -> &'static str {
        match self {
            AcpHost::ClaudeAgentAcp => "claude-agent-acp-host",
            AcpHost::CursorAgentAcp => "cursor-agent-acp-host",
            AcpHost::CursorCommunityAcp => "cursor-community-acp-host",
        }
    }

    /// Provider.
    pub fn provider(self) -> ProviderKind {
        match self {
            AcpHost::ClaudeAgentAcp => ProviderKind::ClaudeCode,
            _ => ProviderKind::Cursor,
        }
    }

    /// Env override of the program.
    pub fn bin_env(self) -> &'static str {
        match self {
            AcpHost::ClaudeAgentAcp => "M4A_CLAUDE_ACP_BIN",
            AcpHost::CursorAgentAcp => "M4A_CURSOR_AGENT_BIN",
            AcpHost::CursorCommunityAcp => "M4A_CURSOR_COMMUNITY_ACP_BIN",
        }
    }

    /// Default `(program, args)`.
    pub fn default_command(self) -> (&'static str, &'static [&'static str]) {
        match self {
            AcpHost::ClaudeAgentAcp => ("claude-agent-acp", &[]),
            AcpHost::CursorAgentAcp => ("agent", &["acp"]),
            AcpHost::CursorCommunityAcp => ("cursor-agent-acp", &[]),
        }
    }
}

/// Spawns an ACP adapter for a headless session.
pub struct AcpHostAdapter {
    host: AcpHost,
    program: PathBuf,
    args: Vec<String>,
    timeout: Duration,
}

impl AcpHostAdapter {
    /// Adapter with an explicit program (`None`: env override or default).
    pub fn new(host: AcpHost, program: Option<PathBuf>) -> Self {
        let (default, args) = host.default_command();
        let program = program
            .or_else(|| {
                std::env::var_os(host.bin_env())
                    .filter(|v| !v.is_empty())
                    .map(PathBuf::from)
            })
            .unwrap_or_else(|| PathBuf::from(default));
        Self {
            host,
            program,
            args: args.iter().map(|a| a.to_string()).collect(),
            timeout: Duration::from_secs(60),
        }
    }

    /// The host.
    pub fn host(&self) -> AcpHost {
        self.host
    }
}

fn send(stdin: &mut ChildStdin, value: &Value) -> std::io::Result<()> {
    stdin.write_all(value.to_string().as_bytes())?;
    stdin.write_all(b"\n")?;
    stdin.flush()
}

/// Reply for an agent → client request on a headless host.
pub fn headless_reply(request: &Value) -> Option<Value> {
    let id = request.get("id")?;
    let method = request.get("method")?.as_str()?;
    Some(match method {
        "session/request_permission" => {
            json!({"jsonrpc": "2.0", "id": id, "result": {"outcome": {"outcome": "cancelled"}}})
        }
        _ => {
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "not supported by a headless host"}})
        }
    })
}

struct Running {
    child: Child,
    stdin: ChildStdin,
    rx: mpsc::Receiver<Value>,
}

impl Running {
    fn call(
        &mut self,
        id: i64,
        method: &str,
        params: Value,
        wait: Duration,
    ) -> Result<Value, WakeError> {
        send(
            &mut self.stdin,
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        )
        .map_err(|err| WakeError::Transport(format!("acp write: {}", err.kind())))?;
        let deadline = std::time::Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let message = self
                .rx
                .recv_timeout(left)
                .map_err(|_| WakeError::Transport(format!("acp {method}: no answer")))?;
            if message.get("method").is_some() {
                if let Some(reply) = headless_reply(&message) {
                    let _ = send(&mut self.stdin, &reply);
                }
                continue;
            }
            if message["id"] == json!(id) {
                if let Some(err) = message.get("error") {
                    let text = err["message"].as_str().unwrap_or("error");
                    return Err(WakeError::Transport(format!("acp {method}: {text}")));
                }
                return Ok(message["result"].clone());
            }
        }
    }
}

impl WakeAdapter for AcpHostAdapter {
    fn kind(&self) -> SessionKind {
        SessionKind::local(self.host.provider())
    }

    fn probe(&self, session: &ProviderSession) -> Result<(), WakeError> {
        if !session.headless {
            return Err(WakeError::Unavailable(
                "session has a live client; ACP host spawns its own agent (headless-only)".into(),
            ));
        }
        Ok(())
    }

    fn wake(
        &mut self,
        session: &ProviderSession,
        letter: &WakeLetter<'_>,
    ) -> Result<WakeOutcome, WakeError> {
        self.probe(session)?;
        let cwd = super::session_cwd(session)?;
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .current_dir(&cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|err| WakeError::Unavailable(format!("acp spawn: {}", err.kind())))?;
        let stdin = child.stdin.take().expect("piped");
        let stdout = child.stdout.take().expect("piped");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(value) = serde_json::from_str::<Value>(&line) {
                    if tx.send(value).is_err() {
                        break;
                    }
                }
            }
        });
        let mut running = Running { child, stdin, rx };
        let setup = (|| {
            running.call(
                0,
                "initialize",
                json!({"protocolVersion": 1, "clientInfo": {"name": "mail4agent", "version": env!("CARGO_PKG_VERSION")},
                       "clientCapabilities": {"fs": {"readTextFile": false, "writeTextFile": false}, "terminal": false}}),
                self.timeout,
            )?;
            running.call(
                1,
                "session/load",
                json!({"sessionId": session.session_id, "cwd": cwd, "mcpServers": []}),
                self.timeout,
            )?;
            send(
                &mut running.stdin,
                &json!({"jsonrpc": "2.0", "id": 2, "method": "session/prompt",
                        "params": {"sessionId": session.session_id, "prompt": [{"type": "text", "text": wake_prompt(session, letter)}]}}),
            )
            .map_err(|err| WakeError::Transport(format!("acp write: {}", err.kind())))
        })();
        if let Err(err) = setup {
            let _ = running.child.kill();
            let _ = running.child.wait();
            return Err(err);
        }
        // The turn finishes on its own; answer permission requests until the
        // prompt result arrives, then let the adapter exit.
        std::thread::spawn(move || {
            let limit = std::time::Instant::now() + Duration::from_secs(3600);
            while std::time::Instant::now() < limit {
                match running.rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(message) => {
                        if message.get("method").is_some() {
                            if let Some(reply) = headless_reply(&message) {
                                let _ = send(&mut running.stdin, &reply);
                            }
                        } else if message["id"] == json!(2) {
                            break;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            let _ = running.child.kill();
            let _ = running.child.wait();
        });
        Ok(WakeOutcome::Delivered)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::provider::tests::{letter, session};

    #[test]
    fn refuses_open_sessions_and_answers_permission_cancelled() {
        let kind = SessionKind::local(ProviderKind::ClaudeCode);
        let mut adapter = AcpHostAdapter::new(AcpHost::ClaudeAgentAcp, Some("/bin/false".into()));
        let err = adapter
            .wake(&session(kind), &letter("x"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("headless-only"), "{err}");
        let reply = headless_reply(
            &json!({"jsonrpc":"2.0","id":7,"method":"session/request_permission","params":{}}),
        )
        .unwrap();
        assert_eq!(reply["result"]["outcome"]["outcome"], "cancelled");
        assert!(headless_reply(&json!({"jsonrpc":"2.0","method":"session/update"})).is_none());
    }

    #[test]
    fn headless_wake_loads_the_session_then_prompts() {
        let dir = std::env::temp_dir().join(format!("m4a-acp-host-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let log = dir.join("calls");
        let script = dir.join("fake-acp");
        // Answers initialize (0) and session/load (1); records every method.
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nwhile read -r line; do\n  printf %s\\\\n \"$line\" >> {log}\n  case \"$line\" in\n    *'\"id\":0'*) echo '{{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{{\"protocolVersion\":1}}}}';;\n    *'\"id\":1'*) echo '{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{}}}}';;\n    *'\"id\":2'*) echo '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"stopReason\":\"end_turn\"}}}}';;\n  esac\ndone\n",
                log = log.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let kind = SessionKind::local(ProviderKind::ClaudeCode);
        let mut s = session(kind);
        s.headless = true;
        let mut adapter = AcpHostAdapter::new(AcpHost::ClaudeAgentAcp, Some(script));
        assert_eq!(
            adapter.wake(&s, &letter("ping")).unwrap(),
            WakeOutcome::Delivered
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut text = String::new();
        while std::time::Instant::now() < deadline {
            text = std::fs::read_to_string(&log).unwrap_or_default();
            if text.contains("session/prompt") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let methods: Vec<String> = text
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter_map(|v| v["method"].as_str().map(str::to_string))
            .collect();
        assert_eq!(methods, ["initialize", "session/load", "session/prompt"]);
        assert!(!text.contains("session/new"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Live: `M4A_LIVE_ACP_BIN` (e.g. claude-agent-acp), `M4A_LIVE_ACP_SESSION`
    /// (an existing session id), `M4A_LIVE_ACP_CWD`.
    #[test]
    #[ignore]
    fn live_acp_host_loads_and_prompts() {
        let kind = SessionKind::local(ProviderKind::ClaudeCode);
        let mut s = session(kind);
        s.session_id = std::env::var("M4A_LIVE_ACP_SESSION").expect("session");
        s.cwd = Some(std::env::var("M4A_LIVE_ACP_CWD").expect("cwd").into());
        s.headless = true;
        let program = std::env::var("M4A_LIVE_ACP_BIN").expect("bin");
        let mut adapter = AcpHostAdapter::new(AcpHost::ClaudeAgentAcp, Some(program.into()));
        assert_eq!(
            adapter.wake(&s, &letter("PING-LIVE-ACP-HOST")).unwrap(),
            WakeOutcome::Delivered
        );
        std::thread::sleep(Duration::from_secs(10));
    }
}
