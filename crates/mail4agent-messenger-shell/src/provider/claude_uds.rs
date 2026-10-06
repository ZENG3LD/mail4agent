//! Claude Code "uds-messaging": a running Claude Code (interactive TUI or
//! `-p`) listens on a per-process Unix socket and routes
//! `{"type":"user","message":{"role":"user","content":...}}` lines into its
//! prompt queue (`priority=next`): a turn in the OPEN session, idle or busy.
//!
//! Discovery: `<claude config dir>/sessions/<pid>.json` (written by Claude
//! Code 2.1.290) carries `sessionId`, `cwd`, `name`, `kind`, `status` and
//! `messagingSocketPath`; `<pid>.<hash>.key` holds `{"peerToken": ...}`,
//! sent first as `{"type":"auth","token":...}`. Verified on the box
//! 2026-10-06 against an interactive TUI on a stub model endpoint. The
//! feature sits behind Claude's own cross-session messaging gate; when the
//! gate is off no socket is published and this link reports unavailable.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{
    wake_prompt, ProviderKind, ProviderSession, SessionKind, Surface, WakeAdapter, WakeError,
    WakeLetter, WakeOutcome,
};

/// Claude config dir: `CLAUDE_CONFIG_DIR`, else `~/.claude`.
pub fn config_dir() -> Option<PathBuf> {
    std::env::var_os("CLAUDE_CONFIG_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
                .map(|home| PathBuf::from(home).join(".claude"))
        })
}

/// One running Claude Code process that published a messaging socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveClaude {
    /// Process id.
    pub pid: u32,
    /// Claude session id.
    pub session_id: String,
    /// Working directory.
    pub cwd: Option<PathBuf>,
    /// Session display name (`name`), e.g. `proj-1d`.
    pub name: Option<String>,
    /// `interactive`, `sdk`, ...
    pub kind: Option<String>,
    /// Messaging socket.
    pub socket: PathBuf,
    /// Peer token, when the key file is readable.
    pub token: Option<String>,
}

fn pid_alive(pid: u32) -> bool {
    if cfg!(target_os = "linux") {
        Path::new(&format!("/proc/{pid}")).exists()
    } else {
        true
    }
}

/// Every live Claude Code process under `dir/sessions`.
pub fn live_sessions(dir: &Path) -> Vec<LiveClaude> {
    let sessions = dir.join("sessions");
    let Ok(read) = std::fs::read_dir(&sessions) else {
        return Vec::new();
    };
    let names: Vec<String> = read
        .filter_map(Result::ok)
        .map(|item| item.file_name().to_string_lossy().into_owned())
        .collect();
    let mut out = Vec::new();
    for name in names.iter().filter(|n| n.ends_with(".json")) {
        let Some(meta) = std::fs::read(sessions.join(name))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        else {
            continue;
        };
        let Some(pid) = meta["pid"].as_u64().map(|p| p as u32) else {
            continue;
        };
        let (Some(session_id), Some(socket)) = (
            meta["sessionId"].as_str(),
            meta["messagingSocketPath"].as_str(),
        ) else {
            continue;
        };
        let socket = PathBuf::from(socket);
        if !pid_alive(pid) || !socket.exists() {
            continue;
        }
        let prefix = format!("{pid}.");
        let token = names
            .iter()
            .find(|n| n.starts_with(&prefix) && n.ends_with(".key"))
            .and_then(|key| std::fs::read(sessions.join(key)).ok())
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|v| v["peerToken"].as_str().map(str::to_string));
        out.push(LiveClaude {
            pid,
            session_id: session_id.to_string(),
            cwd: meta["cwd"].as_str().map(PathBuf::from),
            name: meta["name"].as_str().map(str::to_string),
            kind: meta["kind"].as_str().map(str::to_string),
            socket,
            token,
        });
    }
    out.sort_by_key(|s| s.pid);
    out
}

/// The two lines written to the socket (auth first when a token is known).
pub fn inject_lines(token: Option<&str>, text: &str) -> String {
    let mut lines = String::new();
    if let Some(token) = token {
        lines.push_str(&serde_json::json!({"type": "auth", "token": token}).to_string());
        lines.push('\n');
    }
    lines.push_str(
        &serde_json::json!({"type": "user", "message": {"role": "user", "content": text}})
            .to_string(),
    );
    lines.push('\n');
    lines
}

/// Writes one user message into a running Claude Code.
#[cfg(unix)]
pub fn inject(socket: &Path, token: Option<&str>, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut stream = std::os::unix::net::UnixStream::connect(socket)?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.write_all(inject_lines(token, text).as_bytes())?;
    stream.flush()?;
    // Let the receiver read the complete lines before the socket closes.
    std::thread::sleep(std::time::Duration::from_millis(300));
    Ok(())
}

/// Non-unix: Claude publishes no Unix socket there.
#[cfg(not(unix))]
pub fn inject(_socket: &Path, _token: Option<&str>, _text: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "claude messaging socket is unix-only",
    ))
}

/// In-session wake through the messaging socket of the process that has
/// this session open.
pub struct ClaudeUdsAdapter {
    surface: Surface,
    config_dir: Option<PathBuf>,
}

impl ClaudeUdsAdapter {
    /// Adapter reading `config_dir` (default [`config_dir`]).
    pub fn new(surface: Surface, config_dir: Option<PathBuf>) -> Self {
        Self {
            surface,
            config_dir: config_dir.or_else(self::config_dir),
        }
    }

    fn find(&self, session: &ProviderSession) -> Result<LiveClaude, WakeError> {
        let dir = self
            .config_dir
            .as_deref()
            .ok_or_else(|| WakeError::Unavailable("claude config dir unknown".into()))?;
        live_sessions(dir)
            .into_iter()
            .find(|live| live.session_id == session.session_id)
            .ok_or_else(|| {
                WakeError::Unavailable(
                    "no running claude publishes a socket for this session".into(),
                )
            })
    }
}

impl WakeAdapter for ClaudeUdsAdapter {
    fn kind(&self) -> SessionKind {
        SessionKind {
            provider: ProviderKind::ClaudeCode,
            surface: self.surface,
        }
    }

    fn probe(&self, session: &ProviderSession) -> Result<(), WakeError> {
        self.find(session).map(|_| ())
    }

    fn wake(
        &mut self,
        session: &ProviderSession,
        letter: &WakeLetter<'_>,
    ) -> Result<WakeOutcome, WakeError> {
        let live = self.find(session)?;
        inject(
            &live.socket,
            live.token.as_deref(),
            &wake_prompt(session, letter),
        )
        .map(|()| WakeOutcome::Delivered)
        .map_err(|err| WakeError::Transport(format!("claude socket: {}", err.kind())))
    }
}

/// Running Claude sessions as provider sessions for the local client
/// (nick from the session `name`, else the cwd folder).
pub fn discover(dir: &Path) -> Vec<ProviderSession> {
    live_sessions(dir)
        .into_iter()
        .filter_map(|live| {
            let label = live.name.clone().or_else(|| {
                live.cwd
                    .as_deref()
                    .and_then(Path::file_name)
                    .map(|n| n.to_string_lossy().into_owned())
            })?;
            let nick = crate::nick_from_display_name(&label).ok()?;
            Some(ProviderSession {
                kind: SessionKind::local(ProviderKind::ClaudeCode),
                session_id: live.session_id,
                nick,
                cwd: live.cwd,
                headless: false,
            })
        })
        .collect()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::provider::tests::{letter, session};
    use std::io::{BufRead, BufReader};

    #[test]
    fn finds_the_published_socket_and_injects_auth_then_user_line() {
        let dir = std::env::temp_dir().join(format!("m4a-claude-uds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let sessions = dir.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let sock = dir.join("peer.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let pid = std::process::id();
        std::fs::write(
            sessions.join(format!("{pid}.json")),
            serde_json::json!({"pid": pid, "sessionId": "s-1", "cwd": "/tmp/proj", "name": "proj-1d",
                "kind": "interactive", "messagingSocketPath": sock}).to_string(),
        )
        .unwrap();
        std::fs::write(
            sessions.join(format!("{pid}.abc.key")),
            r#"{"peerToken":"tok"}"#,
        )
        .unwrap();
        let reader = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            BufReader::new(stream)
                .lines()
                .map_while(Result::ok)
                .collect::<Vec<_>>()
        });
        let kind = SessionKind::local(ProviderKind::ClaudeCode);
        let mut adapter = ClaudeUdsAdapter::new(Surface::Local, Some(dir.clone()));
        let mut other = session(kind);
        other.session_id = "nope".into();
        assert!(adapter.probe(&other).is_err());
        let s = session(kind);
        assert_eq!(
            adapter.wake(&s, &letter("ping")).unwrap(),
            WakeOutcome::Delivered
        );
        let lines = reader.join().unwrap();
        assert_eq!(lines.len(), 2);
        let auth: Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(
            (auth["type"].as_str(), auth["token"].as_str()),
            (Some("auth"), Some("tok"))
        );
        let user: Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(user["type"], "user");
        assert!(user["message"]["content"]
            .as_str()
            .unwrap()
            .ends_with("ping"));
        let found = discover(&dir);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].nick, "proj-1d");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Live: a running Claude Code whose `sessions/<pid>.json` names
    /// `M4A_LIVE_CLAUDE_SESSION` (config dir from `CLAUDE_CONFIG_DIR` / HOME).
    #[test]
    #[ignore]
    fn live_inject_into_running_claude() {
        let kind = SessionKind::local(ProviderKind::ClaudeCode);
        let mut s = session(kind);
        s.session_id = std::env::var("M4A_LIVE_CLAUDE_SESSION").expect("session");
        let mut adapter = ClaudeUdsAdapter::new(Surface::Local, None);
        assert_eq!(
            adapter.wake(&s, &letter("PING-LIVE-UDS")).unwrap(),
            WakeOutcome::Delivered
        );
    }
}
