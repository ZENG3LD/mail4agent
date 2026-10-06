//! Provider wake adapters for the one-per-machine local client.
//!
//! The local client (push link, decrypt, sealed store, `m4a-send` socket) is
//! provider-agnostic. The only provider-specific step is *wake*: putting one
//! decrypted room text in front of an already-running agent session. That
//! step is the [`WakeAdapter`] trait. Replies never go through the adapter:
//! every provider answers with the shell command
//! `m4a-send --as <own-nick> --to <peer-nick> '<text>'`, which reaches the
//! client's send socket.
//!
//! Status on branch `provider-clients`:
//!
//! | Adapter | Channel | State |
//! | --- | --- | --- |
//! | [`GrokLeaderAdapter`] | ACP `session/prompt` on Grok `leader.sock` | live (delegates to `mail4agent_grok`) |
//! | [`KimiCodeAdapter`] | ACP host (`kimi acp`), or hook doorbell | stub |
//! | [`ClaudeCodeAdapter`] | hook doorbell (`Stop` / `UserPromptSubmit`) + inbox, or ACP host | stub |
//! | [`CodexAdapter`] | `codex app-server` (`turn/start` / `turn/steer`), or ACP host | stub |
//! | [`CursorAgentAdapter`] | hook doorbell + inbox, or headless resume | stub, optional, Linux-only, verify on the box |
//!
//! Core four: Grok, Kimi Code, Claude Code, Codex. Cursor CLI is optional.
//! Design: `project-docs/docs/mail4agent/provider-clients-design.md`.
//! No adapter spawns a provider process on its own initiative, answers a
//! permission modal, or logs the plaintext.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::{reply_hint, SEND_COMMAND};

/// Environment variable naming the provider of a local session.
pub const PROVIDER_ENV: &str = "M4A_PROVIDER";

/// Environment variable for a per-session inbox directory used by
/// doorbell-style adapters (a provider hook drains it at a turn boundary).
pub const INBOX_DIR_ENV: &str = "M4A_INBOX_DIR";

/// Agent CLIs the stack drives. Ids match the gate4agent catalog / adapter
/// ids (`grok`, `kimi`, `claude`, `codex`, `cursor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderKind {
    /// xAI Grok CLI.
    Grok,
    /// Kimi Code CLI.
    KimiCode,
    /// Claude Code.
    ClaudeCode,
    /// OpenAI Codex CLI.
    Codex,
    /// Cursor CLI (`cursor-agent`). Optional; Linux-only; not in the
    /// gate4agent catalog.
    Cursor,
}

impl ProviderKind {
    /// The core four, Grok first.
    pub const CORE: [ProviderKind; 4] = [
        ProviderKind::Grok,
        ProviderKind::KimiCode,
        ProviderKind::ClaudeCode,
        ProviderKind::Codex,
    ];

    /// Every provider, including the optional Cursor CLI.
    pub const ALL: [ProviderKind; 5] = [
        ProviderKind::Grok,
        ProviderKind::KimiCode,
        ProviderKind::ClaudeCode,
        ProviderKind::Codex,
        ProviderKind::Cursor,
    ];

    /// Stable id (gate4agent catalog spelling).
    pub fn id(self) -> &'static str {
        match self {
            ProviderKind::Grok => "grok",
            ProviderKind::KimiCode => "kimi",
            ProviderKind::ClaudeCode => "claude",
            ProviderKind::Codex => "codex",
            ProviderKind::Cursor => "cursor",
        }
    }

    /// `true` for the optional fifth provider.
    pub fn is_optional(self) -> bool {
        matches!(self, ProviderKind::Cursor)
    }

    /// Parses an id or a common alias. Case-insensitive.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "grok" => Some(ProviderKind::Grok),
            "kimi" | "kimi-code" | "kimicode" => Some(ProviderKind::KimiCode),
            "claude" | "claude-code" | "claudecode" => Some(ProviderKind::ClaudeCode),
            "codex" => Some(ProviderKind::Codex),
            "cursor" | "cursor-agent" => Some(ProviderKind::Cursor),
            _ => None,
        }
    }

    /// Reads [`PROVIDER_ENV`]. Unset means Grok (the only live adapter today).
    pub fn from_env() -> Result<Self, WakeError> {
        match std::env::var(PROVIDER_ENV) {
            Ok(value) if !value.trim().is_empty() => {
                Self::parse(&value).ok_or(WakeError::UnknownProvider)
            }
            _ => Ok(ProviderKind::Grok),
        }
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// One local session the client wakes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSession {
    /// Which CLI runs the session.
    pub kind: ProviderKind,
    /// Provider-native session / thread / chat id.
    pub session_id: String,
    /// mail4agent nick of this session (slug of the display name).
    pub nick: String,
    /// Working directory the provider session was started in.
    pub cwd: Option<PathBuf>,
}

/// One decrypted room text to put in front of the session.
#[derive(Debug, Clone, Copy)]
pub struct WakeLetter<'a> {
    /// Plaintext body.
    pub body: &'a str,
    /// Sender nick.
    pub from_nick: &'a str,
    /// Matrix event id (dedupe key).
    pub event_id: &'a str,
    /// Room id, if known.
    pub room: Option<&'a str>,
}

/// What a wake did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeOutcome {
    /// The session received the prompt now (e.g. ACP prompt accepted).
    Delivered,
    /// Stored for the session to pick up at its next turn boundary
    /// (doorbell adapters). The path is the inbox entry written.
    Queued(PathBuf),
}

/// Why a wake did not happen. Never carries the plaintext or a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeError {
    /// [`PROVIDER_ENV`] named something unknown.
    UnknownProvider,
    /// The adapter is a skeleton on this branch.
    NotImplemented(ProviderKind),
    /// The provider endpoint (socket, app-server, hook inbox) is absent.
    Unavailable(String),
    /// The endpoint answered but the wake failed.
    Transport(String),
}

impl fmt::Display for WakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WakeError::UnknownProvider => write!(f, "unknown provider in {PROVIDER_ENV}"),
            WakeError::NotImplemented(kind) => {
                write!(f, "wake adapter for {kind} is not implemented")
            }
            WakeError::Unavailable(why) => write!(f, "wake endpoint unavailable: {why}"),
            WakeError::Transport(why) => write!(f, "wake failed: {why}"),
        }
    }
}

impl std::error::Error for WakeError {}

/// Provider-specific wake. One instance per local session.
///
/// The caller keeps the per-`event_id` sent set. Implementations must not
/// spawn a provider unless the adapter is explicitly a host adapter, must
/// not answer permission prompts, and must not log `letter.body`.
pub trait WakeAdapter: Send {
    /// Provider this adapter wakes.
    fn kind(&self) -> ProviderKind;

    /// Cheap readiness check (socket exists, app-server reachable, hook
    /// installed). Called before register and on every full drive.
    fn probe(&self, session: &ProviderSession) -> Result<(), WakeError>;

    /// Puts one letter in front of the session.
    fn wake(
        &mut self,
        session: &ProviderSession,
        letter: &WakeLetter<'_>,
    ) -> Result<WakeOutcome, WakeError>;
}

/// The prompt text every adapter injects. Same shape for all providers so
/// agents learn one protocol (`docs/mail4agent/agent-mail-protocol.md`).
pub fn wake_prompt(session: &ProviderSession, letter: &WakeLetter<'_>) -> String {
    let reply = reply_hint(&session.nick, letter.from_nick);
    format!(
        "[mail4agent] Letter from {from} to {to} (event {event}).\n\
         Answer every direct letter with {cmd}; at minimum \"принято\" plus what you will do and when.\n\
         Reply: {reply}\n\
         ---\n\
         {body}",
        from = letter.from_nick,
        to = session.nick,
        event = letter.event_id,
        cmd = SEND_COMMAND,
        reply = reply,
        body = letter.body,
    )
}

/// Builds the adapter for `kind`. `leader_sock` is used by Grok only;
/// `inbox_dir` by doorbell adapters.
pub fn adapter_for(
    kind: ProviderKind,
    leader_sock: Option<PathBuf>,
    inbox_dir: Option<PathBuf>,
) -> Box<dyn WakeAdapter> {
    match kind {
        ProviderKind::Grok => Box::new(GrokLeaderAdapter { leader_sock }),
        ProviderKind::KimiCode => Box::new(KimiCodeAdapter { inbox_dir }),
        ProviderKind::ClaudeCode => Box::new(ClaudeCodeAdapter { inbox_dir }),
        ProviderKind::Codex => Box::new(CodexAdapter { app_server: None }),
        ProviderKind::Cursor => Box::new(CursorAgentAdapter { inbox_dir }),
    }
}

/// Grok: ACP `session/prompt` on an already-running `leader.sock`.
pub struct GrokLeaderAdapter {
    /// `M4A_LEADER_SOCK`.
    pub leader_sock: Option<PathBuf>,
}

impl WakeAdapter for GrokLeaderAdapter {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Grok
    }

    fn probe(&self, _session: &ProviderSession) -> Result<(), WakeError> {
        match self.leader_sock.as_deref() {
            Some(path) if path.exists() => Ok(()),
            Some(_) => Err(WakeError::Unavailable("leader socket missing".into())),
            None => Err(WakeError::Unavailable("leader socket unset".into())),
        }
    }

    fn wake(
        &mut self,
        session: &ProviderSession,
        letter: &WakeLetter<'_>,
    ) -> Result<WakeOutcome, WakeError> {
        self.probe(session)?;
        let Some(sock) = self.leader_sock.as_deref() else {
            return Err(WakeError::Unavailable("leader socket unset".into()));
        };
        let cwd = session_cwd(session)?;
        mail4agent_grok::wake_decrypted_room_blocking(
            sock,
            &session.session_id,
            &cwd,
            &wake_prompt(session, letter),
        )
        .map(|()| WakeOutcome::Delivered)
        .map_err(|err| WakeError::Transport(err.to_string()))
    }
}

/// Kimi Code (stub). Planned channel: ACP `session/prompt` when the session
/// is hosted over `kimi acp`; otherwise inbox + hook doorbell.
pub struct KimiCodeAdapter {
    /// `M4A_INBOX_DIR`.
    pub inbox_dir: Option<PathBuf>,
}

/// Claude Code (stub). Planned channel: inbox + `Stop` hook that returns
/// `decision: block` with the letter as `reason` (the session continues),
/// and `UserPromptSubmit` / `SessionStart` hooks adding it as context. ACP
/// host (`claude-agent-acp`) only when gate4agent owns the session.
pub struct ClaudeCodeAdapter {
    /// `M4A_INBOX_DIR`.
    pub inbox_dir: Option<PathBuf>,
}

/// Codex (stub). Planned channel: `codex app-server` on a unix socket shared
/// with the operator's TUI (`codex --remote unix://…`): `thread/resume` then
/// `turn/start`, or `turn/steer` on an active turn.
pub struct CodexAdapter {
    /// `unix://` path of the app-server, when configured.
    pub app_server: Option<PathBuf>,
}

/// Cursor CLI (stub). Optional, Linux-only, verify on the box. Planned
/// channel: inbox + `cursor-agent` hooks, or headless resume when no TUI
/// holds the chat.
pub struct CursorAgentAdapter {
    /// `M4A_INBOX_DIR`.
    pub inbox_dir: Option<PathBuf>,
}

macro_rules! stub_adapter {
    ($ty:ty, $kind:expr) => {
        impl WakeAdapter for $ty {
            fn kind(&self) -> ProviderKind {
                $kind
            }

            fn probe(&self, _session: &ProviderSession) -> Result<(), WakeError> {
                Err(WakeError::NotImplemented($kind))
            }

            fn wake(
                &mut self,
                _session: &ProviderSession,
                _letter: &WakeLetter<'_>,
            ) -> Result<WakeOutcome, WakeError> {
                Err(WakeError::NotImplemented($kind))
            }
        }
    };
}

stub_adapter!(KimiCodeAdapter, ProviderKind::KimiCode);
stub_adapter!(ClaudeCodeAdapter, ProviderKind::ClaudeCode);
stub_adapter!(CodexAdapter, ProviderKind::Codex);
stub_adapter!(CursorAgentAdapter, ProviderKind::Cursor);

fn session_cwd(session: &ProviderSession) -> Result<String, WakeError> {
    session
        .cwd
        .as_deref()
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok())
        .map(|path| path.display().to_string())
        .filter(|cwd| !cwd.is_empty())
        .ok_or_else(|| WakeError::Unavailable("session cwd is empty".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(kind: ProviderKind) -> ProviderSession {
        ProviderSession {
            kind,
            session_id: "s-1".into(),
            nick: "hostbot".into(),
            cwd: Some(PathBuf::from("/tmp")),
        }
    }

    #[test]
    fn ids_round_trip() {
        for kind in ProviderKind::ALL {
            assert_eq!(ProviderKind::parse(kind.id()), Some(kind));
        }
        assert_eq!(
            ProviderKind::parse("Claude-Code"),
            Some(ProviderKind::ClaudeCode)
        );
        assert_eq!(ProviderKind::parse("gemini"), None);
        assert!(ProviderKind::CORE.iter().all(|kind| !kind.is_optional()));
        assert!(ProviderKind::Cursor.is_optional());
    }

    #[test]
    fn stubs_refuse_without_side_effects() {
        let letter = WakeLetter {
            body: "x",
            from_nick: "peer",
            event_id: "$e",
            room: None,
        };
        for kind in [
            ProviderKind::KimiCode,
            ProviderKind::ClaudeCode,
            ProviderKind::Codex,
            ProviderKind::Cursor,
        ] {
            let mut adapter = adapter_for(kind, None, None);
            assert_eq!(adapter.kind(), kind);
            let s = session(kind);
            assert_eq!(adapter.probe(&s), Err(WakeError::NotImplemented(kind)));
            assert_eq!(
                adapter.wake(&s, &letter),
                Err(WakeError::NotImplemented(kind))
            );
        }
    }

    #[test]
    fn grok_without_socket_is_unavailable() {
        let adapter = adapter_for(ProviderKind::Grok, None, None);
        assert!(matches!(
            adapter.probe(&session(ProviderKind::Grok)),
            Err(WakeError::Unavailable(_))
        ));
    }

    #[test]
    fn prompt_carries_reply_command_and_body() {
        let letter = WakeLetter {
            body: "ping",
            from_nick: "carol",
            event_id: "$e",
            room: None,
        };
        let text = wake_prompt(&session(ProviderKind::Codex), &letter);
        assert!(text.contains("m4a-send --as hostbot --to carol"));
        assert!(text.ends_with("ping"));
    }
}
