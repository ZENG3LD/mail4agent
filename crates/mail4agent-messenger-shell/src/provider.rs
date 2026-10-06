//! Provider wake adapters for the one-per-machine mail4agent clients.
//!
//! The clients (push link, decrypt, sealed store, `m4a-send` socket) are
//! provider-agnostic. The only provider-specific step is *wake*: putting one
//! decrypted room text in front of an agent session so it takes a turn.
//! That step is the [`WakeAdapter`] trait. A session is addressed by a
//! [`SessionKind`]: the vendor ([`ProviderKind`]) and the [`Surface`] it runs
//! on (vendor-hosted web/cloud, or a CLI on the user's machine). Replies
//! never go through the adapter: every agent answers with the shell command
//! `m4a-send --as <own-nick> --to <peer-nick> '<text>'`.
//!
//! | Kind | Adapter | Channel | State |
//! | --- | --- | --- | --- |
//! | Cursor / Grok Bot web | [`RoutineWebhookAdapter`] | the bot's own webhook routine | live |
//! | Claude Code web | [`ClaudeRoutineFireAdapter`] | routine `/fire` (starts a NEW session) | stub, vendor-side fix |
//! | Codex cloud | [`CodexCloudAdapter`] | none into an existing task | stub, vendor-side fix |
//! | Kimi web, Grok web | [`NoInboundAdapter`] | none documented | stub |
//! | Grok CLI | [`GrokLeaderAdapter`] | ACP `session/prompt` on `leader.sock` | live |
//! | Codex CLI | [`codex::CodexAppServerAdapter`] | app-server `turn/start` (unix:// or ws://) | live, verified on the box |
//! | Kimi Code CLI | [`kimi::KimiServerAdapter`] | `kimi web` server `POST /api/v1/sessions/{id}/prompts` | live, verified on the box |
//! | Claude Code CLI | [`ClaudeChannelAdapter`] + `m4a-claude-channel` | channel MCP `notifications/claude/channel` | implemented; live turn unverified (needs login) |
//! | Cursor CLI | [`CursorAgentAdapter`] | `agent acp` / hooks | stub, optional, Linux-only, verify on the box |
//!
//! Core four: Grok, Kimi Code, Claude Code, Codex. Cursor CLI is optional.
//! Design: `project-docs/docs/mail4agent/client-architecture.md`.
//! No adapter spawns a provider process, answers a permission modal, or
//! logs the plaintext or a credential.

pub mod claude_channel;
pub mod codex;
pub mod inbox;
pub mod kimi;

use std::fmt;
use std::path::{Path, PathBuf};

use crate::{post_decrypted_with_bearer, reply_hint, DecryptedWake, SEND_COMMAND};

pub use claude_channel::ClaudeChannelAdapter;
pub use codex::{CodexAppServerAdapter, CodexEndpoint};
pub use inbox::{InboxEntry, InboxLetter};
pub use kimi::KimiServerAdapter;

/// Environment variable naming the provider of a local session.
pub const PROVIDER_ENV: &str = "M4A_PROVIDER";

/// Environment variable for a per-session inbox directory used by
/// queue-style adapters (Claude channel server, hook doorbells).
pub const INBOX_DIR_ENV: &str = "M4A_INBOX_DIR";

/// Agent vendors the stack drives. Ids match the gate4agent catalog /
/// adapter ids (`grok`, `kimi`, `claude`, `codex`, `cursor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderKind {
    /// xAI Grok.
    Grok,
    /// Kimi Code.
    KimiCode,
    /// Claude Code.
    ClaudeCode,
    /// OpenAI Codex.
    Codex,
    /// Cursor: the vendor-hosted web agents (Grok Bot boxes) and the
    /// optional Linux-only `cursor-agent` CLI.
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

    /// `true` for the optional fifth CLI provider.
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

    /// Reads [`PROVIDER_ENV`]. Unset means Grok.
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

/// Where a session runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Surface {
    /// Vendor-hosted web / cloud session (`m4a-web-client`).
    Web,
    /// CLI session on the user's machine (local client).
    Local,
}

/// Vendor + surface: what picks the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKind {
    /// Vendor.
    pub provider: ProviderKind,
    /// Web or local.
    pub surface: Surface,
}

impl SessionKind {
    /// Local CLI session of `provider`.
    pub fn local(provider: ProviderKind) -> Self {
        Self {
            provider,
            surface: Surface::Local,
        }
    }

    /// Vendor-hosted web session of `provider`.
    pub fn web(provider: ProviderKind) -> Self {
        Self {
            provider,
            surface: Surface::Web,
        }
    }
}

impl fmt::Display for SessionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let surface = match self.surface {
            Surface::Web => "web",
            Surface::Local => "local",
        };
        write!(f, "{}/{}", self.provider, surface)
    }
}

/// One session a client wakes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSession {
    /// Vendor + surface.
    pub kind: SessionKind,
    /// Vendor-native session / thread / chat id. Never logged or committed.
    pub session_id: String,
    /// mail4agent nick of this session (slug of the display name).
    pub nick: String,
    /// Working directory the session was started in (local only).
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
    /// The session accepted the prompt now (a turn started or was queued
    /// by the vendor runtime).
    Delivered,
    /// Stored for the session to pick up (channel server / hook). The path
    /// is the inbox entry written.
    Queued(PathBuf),
}

/// Why a wake did not happen. Never carries the plaintext or a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeError {
    /// [`PROVIDER_ENV`] named something unknown.
    UnknownProvider,
    /// The adapter is a skeleton on this branch.
    NotImplemented(SessionKind),
    /// The vendor exposes no inbound trigger into an existing session.
    NoInboundTrigger(SessionKind),
    /// The endpoint (socket, server, inbox, routine) is absent or unset.
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
            WakeError::NoInboundTrigger(kind) => {
                write!(
                    f,
                    "{kind} exposes no inbound trigger into a running session"
                )
            }
            WakeError::Unavailable(why) => write!(f, "wake endpoint unavailable: {why}"),
            WakeError::Transport(why) => write!(f, "wake failed: {why}"),
        }
    }
}

impl std::error::Error for WakeError {}

/// Vendor/surface-specific wake. One instance per session.
///
/// The caller keeps the per-`event_id` sent set. Implementations must not
/// spawn a provider, must not answer permission prompts, and must not log
/// `letter.body` or a credential.
pub trait WakeAdapter: Send {
    /// Session kind this adapter wakes.
    fn kind(&self) -> SessionKind;

    /// Cheap readiness check (socket exists, server configured, routine
    /// key present). Called before register and on every full drive.
    fn probe(&self, session: &ProviderSession) -> Result<(), WakeError>;

    /// Puts one letter in front of the session.
    fn wake(
        &mut self,
        session: &ProviderSession,
        letter: &WakeLetter<'_>,
    ) -> Result<WakeOutcome, WakeError>;
}

/// The prompt text every local adapter injects. Same shape for all
/// providers so agents learn one protocol
/// (`docs/mail4agent/agent-mail-protocol.md`). Web routines get the JSON
/// object instead, whose `reply` field carries the same command.
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

/// Endpoints the host hands to [`adapter_for`]. Every field is optional;
/// an adapter whose endpoint is missing reports [`WakeError::Unavailable`].
/// Credentials come from the host keychain / environment, never a literal.
#[derive(Default, Clone)]
pub struct AdapterConfig {
    /// Grok `leader.sock` (`M4A_LEADER_SOCK`).
    pub leader_sock: Option<PathBuf>,
    /// Inbox directory for queue-style adapters (`M4A_INBOX_DIR`).
    pub inbox_dir: Option<PathBuf>,
    /// Codex app-server endpoint (`M4A_CODEX_APP_SERVER`).
    pub codex: Option<CodexEndpoint>,
    /// Kimi local server origin (`M4A_KIMI_SERVER_URL`).
    pub kimi_url: Option<String>,
    /// Kimi local server bearer (`M4A_KIMI_SERVER_TOKEN`), in memory only.
    pub kimi_bearer: Option<String>,
    /// Web routine URL of the bot (`M4A_ROUTINE_URL`), in memory only.
    pub routine_url: Option<String>,
    /// Web routine key (`M4A_ROUTINE_BEARER`), in memory only.
    pub routine_bearer: Option<String>,
}

impl fmt::Debug for AdapterConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print endpoints that may embed keys, or bearers.
        f.debug_struct("AdapterConfig")
            .field("leader_sock", &self.leader_sock.is_some())
            .field("inbox_dir", &self.inbox_dir.is_some())
            .field("codex", &self.codex.is_some())
            .field("kimi_url", &self.kimi_url.is_some())
            .field("routine_url", &self.routine_url.is_some())
            .finish()
    }
}

/// Builds the adapter for `kind` from `config`.
pub fn adapter_for(kind: SessionKind, config: &AdapterConfig) -> Box<dyn WakeAdapter> {
    match (kind.surface, kind.provider) {
        (Surface::Local, ProviderKind::Grok) => Box::new(GrokLeaderAdapter {
            leader_sock: config.leader_sock.clone(),
        }),
        (Surface::Local, ProviderKind::Codex) => {
            Box::new(CodexAppServerAdapter::new(config.codex.clone()))
        }
        (Surface::Local, ProviderKind::KimiCode) => Box::new(KimiServerAdapter::new(
            config.kimi_url.clone(),
            config.kimi_bearer.clone(),
        )),
        (Surface::Local, ProviderKind::ClaudeCode) => {
            Box::new(ClaudeChannelAdapter::new(config.inbox_dir.clone()))
        }
        (Surface::Local, ProviderKind::Cursor) => Box::new(CursorAgentAdapter {
            inbox_dir: config.inbox_dir.clone(),
        }),
        (Surface::Web, ProviderKind::Cursor) => Box::new(RoutineWebhookAdapter {
            provider: ProviderKind::Cursor,
            url: config.routine_url.clone(),
            bearer: config.routine_bearer.clone(),
        }),
        (Surface::Web, ProviderKind::ClaudeCode) => Box::new(ClaudeRoutineFireAdapter),
        (Surface::Web, ProviderKind::Codex) => Box::new(CodexCloudAdapter),
        (Surface::Web, provider @ (ProviderKind::KimiCode | ProviderKind::Grok)) => {
            Box::new(NoInboundAdapter { provider })
        }
    }
}

// ---------------------------------------------------------------- local --

/// Grok CLI: ACP `session/prompt` on an already-running `leader.sock`.
pub struct GrokLeaderAdapter {
    /// `M4A_LEADER_SOCK`.
    pub leader_sock: Option<PathBuf>,
}

impl WakeAdapter for GrokLeaderAdapter {
    fn kind(&self) -> SessionKind {
        SessionKind::local(ProviderKind::Grok)
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

/// Cursor CLI (stub). Optional, Linux-only, verify on the box.
///
/// TODO(cursor): `agent acp` (hidden subcommand, 2026.10.01) is an ACP
/// stdio server, and `agent persist attach` keeps a session alive. Neither
/// is a documented way into an interactive chat another process owns.
/// Candidate: ACP host for persist sessions, or hook doorbell via the inbox.
pub struct CursorAgentAdapter {
    /// `M4A_INBOX_DIR`.
    pub inbox_dir: Option<PathBuf>,
}

impl WakeAdapter for CursorAgentAdapter {
    fn kind(&self) -> SessionKind {
        SessionKind::local(ProviderKind::Cursor)
    }

    fn probe(&self, _session: &ProviderSession) -> Result<(), WakeError> {
        Err(WakeError::NotImplemented(self.kind()))
    }

    fn wake(
        &mut self,
        _session: &ProviderSession,
        _letter: &WakeLetter<'_>,
    ) -> Result<WakeOutcome, WakeError> {
        Err(WakeError::NotImplemented(self.kind()))
    }
}

// ------------------------------------------------------------------ web --

/// Vendor-hosted web session woken by its own webhook routine (Cursor /
/// Grok Bot boxes). Same JSON object `m4a-web-client` posts today
/// (`body`, `from`, `from_nick`, `to`, `event_id`, `room`, `reply`).
pub struct RoutineWebhookAdapter {
    /// Vendor of the web session.
    pub provider: ProviderKind,
    /// Routine URL. In memory only.
    pub url: Option<String>,
    /// Routine key. In memory only.
    pub bearer: Option<String>,
}

impl WakeAdapter for RoutineWebhookAdapter {
    fn kind(&self) -> SessionKind {
        SessionKind::web(self.provider)
    }

    fn probe(&self, _session: &ProviderSession) -> Result<(), WakeError> {
        match self.url.as_deref() {
            Some(url) if !url.is_empty() => Ok(()),
            _ => Err(WakeError::Unavailable("routine url unset".into())),
        }
    }

    fn wake(
        &mut self,
        session: &ProviderSession,
        letter: &WakeLetter<'_>,
    ) -> Result<WakeOutcome, WakeError> {
        self.probe(session)?;
        let url = self.url.as_deref().unwrap_or_default();
        let reply = reply_hint(&session.nick, letter.from_nick);
        let wake = DecryptedWake {
            body: letter.body,
            from: letter.from_nick,
            nick: None,
            event_id: letter.event_id,
            room: letter.room,
            from_nick: Some(letter.from_nick),
            to: Some(&session.nick),
            reply: Some(&reply),
        };
        post_decrypted_with_bearer(url, &wake, self.bearer.as_deref())
            .map(|()| WakeOutcome::Delivered)
            .map_err(|err| WakeError::Transport(err.to_string()))
    }
}

/// Claude Code on the web (stub, vendor-side fix).
///
/// TODO(claude-web): routines expose `POST /v1/claude_code/routines/{id}/fire`
/// with a per-routine bearer and optional `text`, but every fire starts a
/// NEW cloud session (rate-limited per routine and per account). There is
/// no documented API to post into an existing cloud session. The Claude web
/// session itself decides how it wants to be reached.
pub struct ClaudeRoutineFireAdapter;

/// Codex cloud (stub, vendor-side fix).
///
/// TODO(codex-cloud): `codex cloud exec --env <ENV_ID> <prompt>` creates a
/// NEW task; no documented follow-up into an existing cloud task.
pub struct CodexCloudAdapter;

/// Vendor web surface with no documented inbound trigger (Kimi web, Grok web).
pub struct NoInboundAdapter {
    /// Vendor.
    pub provider: ProviderKind,
}

macro_rules! refuse_adapter {
    ($ty:ty, $kind:expr, $err:ident) => {
        impl WakeAdapter for $ty {
            fn kind(&self) -> SessionKind {
                $kind(self)
            }

            fn probe(&self, _session: &ProviderSession) -> Result<(), WakeError> {
                Err(WakeError::$err(self.kind()))
            }

            fn wake(
                &mut self,
                _session: &ProviderSession,
                _letter: &WakeLetter<'_>,
            ) -> Result<WakeOutcome, WakeError> {
                Err(WakeError::$err(self.kind()))
            }
        }
    };
}

refuse_adapter!(
    ClaudeRoutineFireAdapter,
    |_: &ClaudeRoutineFireAdapter| SessionKind::web(ProviderKind::ClaudeCode),
    NotImplemented
);
refuse_adapter!(
    CodexCloudAdapter,
    |_: &CodexCloudAdapter| SessionKind::web(ProviderKind::Codex),
    NotImplemented
);
refuse_adapter!(
    NoInboundAdapter,
    |adapter: &NoInboundAdapter| SessionKind::web(adapter.provider),
    NoInboundTrigger
);

pub(crate) fn session_cwd(session: &ProviderSession) -> Result<String, WakeError> {
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
pub(crate) mod tests {
    use super::*;

    pub(crate) fn session(kind: SessionKind) -> ProviderSession {
        ProviderSession {
            kind,
            session_id: "s-1".into(),
            nick: "hostbot".into(),
            cwd: Some(PathBuf::from("/tmp")),
        }
    }

    pub(crate) fn letter<'a>(body: &'a str) -> WakeLetter<'a> {
        WakeLetter {
            body,
            from_nick: "carol",
            event_id: "$ev1",
            room: None,
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
        assert_eq!(
            SessionKind::web(ProviderKind::Codex).to_string(),
            "codex/web"
        );
    }

    #[test]
    fn every_kind_gets_an_adapter_of_that_kind() {
        let config = AdapterConfig::default();
        for provider in ProviderKind::ALL {
            for kind in [SessionKind::local(provider), SessionKind::web(provider)] {
                assert_eq!(adapter_for(kind, &config).kind(), kind);
            }
        }
    }

    #[test]
    fn stubs_and_unconfigured_adapters_refuse_without_side_effects() {
        let config = AdapterConfig::default();
        let cases = [
            (SessionKind::local(ProviderKind::Cursor), "not implemented"),
            (
                SessionKind::web(ProviderKind::ClaudeCode),
                "not implemented",
            ),
            (SessionKind::web(ProviderKind::Codex), "not implemented"),
            (SessionKind::web(ProviderKind::KimiCode), "no inbound"),
            (SessionKind::web(ProviderKind::Grok), "no inbound"),
            (SessionKind::web(ProviderKind::Cursor), "unavailable"),
            (SessionKind::local(ProviderKind::Grok), "unavailable"),
            (SessionKind::local(ProviderKind::Codex), "unavailable"),
            (SessionKind::local(ProviderKind::KimiCode), "unavailable"),
            (SessionKind::local(ProviderKind::ClaudeCode), "unavailable"),
        ];
        for (kind, expect) in cases {
            let mut adapter = adapter_for(kind, &config);
            let s = session(kind);
            let err = adapter.wake(&s, &letter("x")).unwrap_err().to_string();
            assert!(err.contains(expect), "{kind}: {err}");
        }
    }

    #[test]
    fn prompt_carries_reply_command_and_body() {
        let text = wake_prompt(
            &session(SessionKind::local(ProviderKind::Codex)),
            &letter("ping"),
        );
        assert!(text.contains("m4a-send --as hostbot --to carol"));
        assert!(text.ends_with("ping"));
    }

    #[test]
    fn config_debug_hides_values() {
        let config = AdapterConfig {
            kimi_bearer: Some("k-secret".into()),
            routine_url: Some("https://example.invalid/hook".into()),
            ..AdapterConfig::default()
        };
        let shown = format!("{config:?}");
        assert!(!shown.contains("secret") && !shown.contains("example"));
    }
}
