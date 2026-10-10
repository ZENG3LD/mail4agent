//! Web machine client: one process for every bot session on this machine.
//!
//! This is not the homeserver, and it is not the node CLI
//! ([`crate::OpenedStore::connect_node_from_env`]). Discovery prefers the
//! live agents directory ([`AGENTS_DIR_ENV`], or
//! [`DEFAULT_AGENTS_DIR`] when that folder exists): each child folder is a
//! Grok Bot agent id and `profile.json` carries the display name. The mail
//! session id is that agent id, unless [`SESSION_IDS_ENV`] maps the agent
//! to an existing session id. The host may still pass a list, or this
//! process may read [`SESSIONS_DIR_ENV`] when no agents directory is
//! present. A session record is the bot display name, the mail session id,
//! and the Grok Bot agent id when this session has one. A routine URL or a
//! bearer in the file is refused.
//!
//! Wake routines. Every bot here is server-hosted, so only the bot itself
//! can put a routine on the backend, with its own `UpdateRoutine`. The
//! bot's nick, the routine's name, and its folder id are one string
//! (`privet-mir`): the nick already follows the host slug rule, so
//! [`crate::routine_folder_id`] leaves it unchanged. A homeserver that
//! still enforces the older `[A-Za-z0-9_]` nick rule refuses such a nick
//! at register (400) until it is redeployed; users already registered under
//! underscore nicks are left as they are. Its backend id is
//! `stableAutomationId(agentId, folderId)`. The local gateway hands out a
//! webhook key only for a routine it finds locally, and mints it for that
//! same id, so [`MachineClient::from_env`] keeps a disabled local mirror
//! (webhook trigger, same folder) per bot through `createAgentAutomation`
//! and then calls `getAutomationWebhookCredential`. A null key means the
//! bot has not created its routine yet: logged, retried by
//! [`MachineClient::poll_agent_directory`], and never answered with another
//! routine. A mirror that lands in any other folder is deleted again.
//! [`SKIP_NICKS_ENV`] lists bots to leave alone. A ready URL and key stay
//! in memory and in the session's keychain file ([`WAKE_KEYCHAIN_FILE`],
//! mode 0600, under the sealed store root); they are never logged. When a
//! bot first becomes ready, this client POSTs `kind=peer_joined` once to
//! every other ready bot's webhook ([`crate::post_routine_json`]); URLs
//! and keys stay out of the log. A record with no agent id gets no wake.
//! One URL is not shared across sessions.
//! [`ensure_agent_webhook_routines`] is the same path without opening
//! sealed stores. [`crate::LEADER_SOCK_ENV`] is not this path. The node
//! CLI does not create a routine.
//!
//! Each session still seals under [`crate::session_store_dir`]. Olm pickles
//! are not shared. While [`MachineClient::set_local_delivery`] is set, the
//! existing drive performs requests against an in-process bus instead of
//! the homeserver. Turn it off to reach a session that is not in the list.
//! The bus is called from that drive. It is not a second sync loop.
//! Room text from the homeserver is not a second sync loop either.
//! [`MachineClient::open`] opens one socket for every session it
//! registered. The homeserver pushes an event down that socket. This
//! process delivers it to that session. A routine POST is the later
//! drive, and only for a session that has its own webhook.
//! [`MachineClient::tick`] is that loop step; the `m4a-web-client` binary
//! runs it.
//!
//! Session bearers. Each session logs in by signature with its own vaulted identity; the
//! bearer lives in memory only and is never stored or handed in.

//! the device. With [`KEYCHAIN_DIR_ENV`] set, [`MachineClient::from_env`]

use std::fs::File;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::ipc::{SendListener, SendStream};
pub(crate) use crate::local_bus::{ensure_server_name, LocalBus};
use crate::{
    clip_public, register_session, DeviceId, OpenedStore,
    SessionConfig, SessionWake, ShellError, HOMESERVER_URL_ENV, STORE_ROOT_ENV,
};

/// Directory of session records. Each `*.json` file is `bot_name`,
/// `session_id`, and an optional `agent_id`. Used when no agents directory
/// is available. Unset means the host passed the list to
/// [`MachineClient::open`] instead.
pub const SESSIONS_DIR_ENV: &str = "M4A_SESSIONS_DIR";

/// Live Grok Bot agents on this machine. Each child folder name is an
/// agent id; `profile.json` has the display `name`. [`MachineClient::from_env`]
/// prefers this over [`SESSIONS_DIR_ENV`] when the directory exists.
pub const AGENTS_DIR_ENV: &str = "M4A_AGENTS_DIR";

/// Default agents directory, relative to the user's home (`$HOME` or
/// `%USERPROFILE%`). Used when [`AGENTS_DIR_ENV`] is unset and the resolved path
/// is a directory.
pub const DEFAULT_AGENTS_DIR: &str = "agent-data/agents";

/// `<home>/<rel>`, with the home taken from the environment; a bare relative path when none is set.
pub(crate) fn under_home(rel: &str) -> PathBuf {
    match std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        Ok(h) if !h.is_empty() => PathBuf::from(h).join(rel),
        _ => PathBuf::from(rel),
    }
}

/// Optional rescan period in seconds for [`MachineClient::poll_agent_directory`].
/// Unset or `0` means the caller decides when to poll; open still scans once.
pub const AGENT_RESCAN_SECS_ENV: &str = "M4A_AGENT_RESCAN_SECS";

/// One bot session the host says lives on this machine.
///
/// `routine_url` and `routine_bearer` are optional and stay in memory.
/// They are not part of a session record on disk.
pub struct HostSession {
    /// Display name the host already shows (`Alice`, `Привет мир`).
    pub bot_name: String,
    /// Session id the host already assigned. This is the mail session, not
    /// the Grok Bot agent id.
    pub session_id: String,
    /// Grok Bot agent id for [`createAgentAutomation`]. Absent means this
    /// session does not get a webhook routine.
    pub agent_id: Option<String>,
    /// Routine URL for this session, if the host has one. Not a file.
    pub routine_url: Option<String>,
    /// Bearer for that routine POST. Memory only.
    pub routine_bearer: Option<String>,
    /// The operator's one-time invite code, needed only until this session's identity is
    /// enrolled. Read by the client, never given to the agent.
    pub invite: Option<String>,
    /// `server` tier (default) or `matrix`.
    pub tier: m4a_agent::BackendKind,
}

impl HostSession {
    /// A session with no routine and no stored device bearer.
    pub fn new(bot_name: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            bot_name: bot_name.into(),
            session_id: session_id.into(),
            agent_id: None,
            routine_url: None,
            routine_bearer: None,
            invite: None,
            tier: m4a_agent::BackendKind::Server,
        }
    }

    pub(crate) fn config(&self, url: &str, store_root: &Path) -> Result<SessionConfig, ShellError> {
        SessionConfig::new_identity(url, self.tier, &self.session_id, store_root, self.invite.clone())
    }

    /// The operator's invite for this session's first login.
    pub fn with_invite(mut self, invite: impl Into<String>) -> Self {
        self.invite = Some(invite.into());
        self
    }

    /// Which tier this session logs in on.
    pub fn with_tier(mut self, tier: m4a_agent::BackendKind) -> Self {
        self.tier = tier;
        self
    }

    /// Attaches a routine target. The bearer is kept only as this value.
    pub fn with_routine(mut self, url: impl Into<String>, bearer: Option<String>) -> Self {
        self.routine_url = Some(url.into());
        self.routine_bearer = bearer.filter(|token| !token.is_empty());
        self
    }

}

impl std::fmt::Debug for HostSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostSession")
            .field("bot_name", &self.bot_name)
            .field("session_id", &self.session_id)
            .field("agent_id", &self.agent_id)
            .field("routine_url", &self.routine_url.as_ref().map(|_| "[set]"))
            .field(
                "routine_bearer",
                &self.routine_bearer.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionFile {
    bot_name: String,
    session_id: String,
    /// Grok Bot agent id. Missing or blank skips routine creation.
    #[serde(default)]
    agent_id: Option<String>,
}

/// Reads `*.json` session records from `dir`. A file that carries anything
/// besides `bot_name`, `session_id`, and `agent_id` is refused, so a
/// webhook URL or a bearer cannot ride along in a world-readable record.
pub fn load_session_records(dir: &Path) -> Result<Vec<HostSession>, ShellError> {
    if !dir.is_dir() {
        return Err(ShellError::SessionList(
            "session directory is missing".to_string(),
        ));
    }
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        paths.push(path);
    }
    paths.sort();
    if paths.is_empty() {
        return Err(ShellError::SessionList(
            "session directory has no records".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let text = std::fs::read_to_string(&path)
            .map_err(|err| ShellError::SessionList(clip_public(err.to_string())))?;
        let file: SessionFile = serde_json::from_str(&text)
            .map_err(|err| ShellError::SessionList(clip_public(err.to_string())))?;
        let mut session = HostSession::new(file.bot_name, file.session_id);
        session.agent_id = file
            .agent_id
            .map(|id| id.trim().to_string())
            .filter(|id| !id.is_empty());
        out.push(session);
    }
    Ok(out)
}

#[derive(serde::Deserialize)]
struct AgentProfileFile {
    name: String,
}

/// Reads each agent folder under `dir`. Folder name is the agent id and the
/// mail session id. `profile.json` supplies the display name. Folders
/// without a usable profile are skipped. This does not hardcode agent ids.
pub fn load_agents_dir(dir: &Path) -> Result<Vec<HostSession>, ShellError> {
    if !dir.is_dir() {
        return Err(ShellError::SessionList(
            "agents directory is missing".to_string(),
        ));
    }
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(id) = name.to_str() else {
            continue;
        };
        if id.is_empty() || id.starts_with('.') {
            continue;
        }
        ids.push(id.to_string());
    }
    ids.sort();
    if ids.is_empty() {
        return Err(ShellError::SessionList(
            "agents directory has no agents".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let profile_path = dir.join(&id).join("profile.json");
        if !profile_path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&profile_path)
            .map_err(|err| ShellError::SessionList(clip_public(err.to_string())))?;
        let profile: AgentProfileFile = serde_json::from_str(&text)
            .map_err(|err| ShellError::SessionList(clip_public(err.to_string())))?;
        let bot_name = profile.name.trim().to_string();
        if bot_name.is_empty() {
            continue;
        }
        let mut session = HostSession::new(bot_name, id.clone());
        session.agent_id = Some(id);
        out.push(session);
    }
    if out.is_empty() {
        return Err(ShellError::SessionList(
            "agents directory has no profiles".to_string(),
        ));
    }
    Ok(out)
}

/// Resolves the agents directory from the environment lookup. Prefers
/// [`AGENTS_DIR_ENV`], then [`DEFAULT_AGENTS_DIR`] when that path is a
/// directory.
fn resolve_agents_dir(mut get: impl FnMut(&str) -> Option<String>) -> Option<PathBuf> {
    if let Some(path) = get(AGENTS_DIR_ENV).filter(|value| !value.is_empty()) {
        let path = PathBuf::from(path);
        if path.is_dir() {
            return Some(path);
        }
        return None;
    }
    let default = under_home(DEFAULT_AGENTS_DIR);
    if default.is_dir() {
        Some(default)
    } else {
        None
    }
}

/// Session records plus one wake per session that has an agent id.
///
/// `get` is the process environment on [`MachineClient::from_env`]. A
/// shared [`crate::ROUTINE_URL_ENV`] is not copied onto every session.
/// [`GATEWAY_FILE_ENV`] names the gateway file. When that lookup is empty,
/// this does not look for a gateway, so a test that did not point at one
/// does not create a mirror. The json files are not rewritten.
fn load_web_sessions(
    dir: &Path,
    mut get: impl FnMut(&str) -> Option<String>,
) -> Result<Vec<HostSession>, ShellError> {
    let sessions = load_session_records(dir)?;
    let mut sessions = drop_skipped(sessions, &skip_nicks(&mut get));
    attach_routines_from_env(&mut sessions, &mut get)?;
    Ok(sessions)
}

/// [`load_agents_dir`] minus [`SKIP_NICKS_ENV`], plus one wake per agent.
fn load_web_agents(
    dir: &Path,
    mut get: impl FnMut(&str) -> Option<String>,
) -> Result<Vec<HostSession>, ShellError> {
    let sessions = load_agents_dir(dir)?;
    let mut sessions = drop_skipped(sessions, &skip_nicks(&mut get));
    apply_session_ids(
        &mut sessions,
        &parse_session_ids(get(SESSION_IDS_ENV).as_deref().unwrap_or("")),
    );
    attach_routines_from_env(&mut sessions, &mut get)?;
    Ok(sessions)
}

fn attach_routines_from_env(
    sessions: &mut [HostSession],
    get: &mut impl FnMut(&str) -> Option<String>,
) -> Result<(), ShellError> {
    let store_root = get(STORE_ROOT_ENV).map(PathBuf::from);
    let Some(path) = get(GATEWAY_FILE_ENV).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let token = get(GATEWAY_TOKEN_ENV).filter(|value| !value.is_empty());
    attach_webhook_routines(
        sessions,
        Path::new(&path),
        token.as_deref(),
        store_root.as_deref(),
    )?;
    Ok(())
}

/// Sessions in `found`, minus skipped nicks, with session-id aliases
/// applied, that no open session holds (by store dir or nick). Each comes
/// with its nick.
fn unopened_agent_sessions(
    found: Vec<HostSession>,
    skip: &[String],
    aliases: &[(String, String)],
    store_root: &Path,
    held: &[(PathBuf, Option<String>)],
) -> Vec<(HostSession, String)> {
    let mut sessions = drop_skipped(found, skip);
    apply_session_ids(&mut sessions, aliases);
    sessions
        .into_iter()
        .filter_map(|session| {
            let nick = routine_name_for(&session)?;
            let dir = crate::session_store_dir(store_root, &session.session_id);
            let taken = held.iter().any(|(held_dir, held_nick)| {
                *held_dir == dir
                    || held_nick
                        .as_deref()
                        .is_some_and(|held| held.eq_ignore_ascii_case(&nick))
            });
            (!taken).then_some((session, nick))
        })
        .collect()
}

/// Comma-separated `agent_id=session_id` pairs. An agent listed here uses
/// that mail session id instead of its agent id, for a bot whose session
/// was registered before agent-id sessions. Machine-specific, so it lives
/// in the environment.
pub const SESSION_IDS_ENV: &str = "M4A_SESSION_IDS";

pub(crate) fn parse_session_ids(raw: &str) -> Vec<(String, String)> {
    raw.split(',')
        .filter_map(|pair| {
            let (agent, session) = pair.split_once('=')?;
            let (agent, session) = (agent.trim(), session.trim());
            (!agent.is_empty() && !session.is_empty())
                .then(|| (agent.to_string(), session.to_string()))
        })
        .collect()
}

pub(crate) fn apply_session_ids(sessions: &mut [HostSession], aliases: &[(String, String)]) {
    for session in sessions.iter_mut() {
        let Some(agent_id) = session.agent_id.as_deref() else {
            continue;
        };
        if let Some((_, alias)) = aliases.iter().find(|(agent, _)| agent == agent_id) {
            session.session_id = alias.clone();
        }
    }
}

/// Comma-separated nicks this client leaves alone: no session, no mirror,
/// no credential call. Machine-specific, so it lives in the environment
/// and not in source.
pub const SKIP_NICKS_ENV: &str = "M4A_SKIP_NICKS";

fn skip_nicks(get: &mut impl FnMut(&str) -> Option<String>) -> Vec<String> {
    parse_skip_nicks(get(SKIP_NICKS_ENV).as_deref().unwrap_or(""))
}

fn parse_skip_nicks(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|item| item.trim().to_ascii_lowercase())
        .filter(|item| !item.is_empty())
        .collect()
}

fn drop_skipped(sessions: Vec<HostSession>, skip: &[String]) -> Vec<HostSession> {
    if skip.is_empty() {
        return sessions;
    }
    sessions
        .into_iter()
        .filter(|session| match routine_name_for(session) {
            Some(nick) => !skip.iter().any(|item| item.eq_ignore_ascii_case(&nick)),
            None => true,
        })
        .collect()
}

/// Where one bot's wake stands after [`ensure_agent_webhook_routines`].
/// Carries no URL and no key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeStatus {
    /// Local mirror present and the gateway returned a URL and a key.
    Ready,
    /// Local mirror present, key null: the bot has not created its own
    /// routine with this folder id yet. Retried on the next poll. No
    /// second routine is made.
    AwaitingBackend,
    /// Nothing usable. The text names the reason, never a secret.
    Failed(String),
}

/// One bot's wake routine, by nick and folder id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutineReport {
    /// Grok Bot agent id.
    pub agent_id: String,
    /// Bot nick.
    pub nick: String,
    /// Routine name and folder id: [`crate::routine_folder_id`] of the
    /// nick, which equals the nick.
    pub folder_id: String,
    /// Outcome.
    pub status: WakeStatus,
}

/// Knobs for [`ensure_agent_webhook_routines`]. All machine-specific, so
/// they come from the environment ([`WakeOptions::from_lookup`]).
#[derive(Debug, Clone, Default)]
pub struct WakeOptions {
    /// Nicks to leave alone ([`SKIP_NICKS_ENV`]).
    pub skip_nicks: Vec<String>,
    /// Sealed store root for the per-session keychain file.
    pub store_root: Option<PathBuf>,
    /// Write the bootstrap note into the profile description of a bot that
    /// has no routine yet ([`PROFILE_NOTE_ENV`]). Off unless asked for.
    pub profile_note: bool,
    /// `agent_id -> session_id` overrides ([`SESSION_IDS_ENV`]).
    pub session_ids: Vec<(String, String)>,
}

impl WakeOptions {
    /// [`SKIP_NICKS_ENV`], [`STORE_ROOT_ENV`], [`PROFILE_NOTE_ENV`].
    pub fn from_lookup(mut get: impl FnMut(&str) -> Option<String>) -> Self {
        Self {
            skip_nicks: skip_nicks(&mut get),
            store_root: get(STORE_ROOT_ENV).map(PathBuf::from),
            profile_note: get(PROFILE_NOTE_ENV).as_deref() == Some("1"),
            session_ids: parse_session_ids(get(SESSION_IDS_ENV).as_deref().unwrap_or("")),
        }
    }
}

/// Ensures each agent's local mirror (webhook trigger, disabled, folder =
/// [`crate::routine_folder_id`] of the nick) and asks the gateway for its
/// credential. Bots whose nick is in `skip_nicks` are not touched. Does
/// not open sealed stores, does not register on the homeserver, and does
/// not log or return URLs or keys. When `store_root` is set, a ready URL
/// and key are written to that session's keychain file. With
/// `profile_note`, a bot still waiting gets the bootstrap note.
pub fn ensure_agent_webhook_routines(
    agents_dir: &Path,
    gateway_file: &Path,
    token_override: Option<&str>,
    options: &WakeOptions,
) -> Result<Vec<RoutineReport>, ShellError> {
    let store_root = options.store_root.as_deref();
    let mut sessions = drop_skipped(load_agents_dir(agents_dir)?, &options.skip_nicks);
    apply_session_ids(&mut sessions, &options.session_ids);
    let Some(gate) = open_gateway(gateway_file, token_override)? else {
        return Err(ShellError::Gateway("gateway file is missing".to_string()));
    };
    let mut reports = Vec::new();
    for session in &sessions {
        let Some(agent_id) = session.agent_id.as_deref().filter(|id| !id.is_empty()) else {
            continue;
        };
        let Some(nick) = routine_name_for(session) else {
            continue;
        };
        let outcome = ensure_wake(&gate, agent_id, &nick);
        let folder_id = crate::nick::routine_folder_id(&nick).unwrap_or_default();
        if let (WakeOutcome::Ready { url, key }, Some(root)) = (&outcome, store_root) {
            save_wake(root, &session.session_id, &folder_id, url, key);
        }
        log_outcome(&nick, &folder_id, &outcome);
        if options.profile_note && matches!(outcome, WakeOutcome::AwaitingBackend) {
            note_profile(&gate, agents_dir, agent_id, &nick);
        }
        reports.push(RoutineReport {
            agent_id: agent_id.to_string(),
            nick,
            folder_id,
            status: outcome.status(),
        });
    }
    Ok(reports)
}

/// [`ensure_agent_webhook_routines`] using the host gateway file, the
/// agents directory from the environment (or [`DEFAULT_AGENTS_DIR`]),
/// [`SKIP_NICKS_ENV`], and [`STORE_ROOT_ENV`] when set.
pub fn ensure_agent_webhook_routines_from_env() -> Result<Vec<RoutineReport>, ShellError> {
    let mut get = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());
    let agents_dir = resolve_agents_dir(&mut get)
        .ok_or_else(|| ShellError::SessionList("agents directory is missing".to_string()))?;
    let gateway = get(GATEWAY_FILE_ENV).unwrap_or_else(|| DEFAULT_GATEWAY_FILE.to_string());
    let token = get(GATEWAY_TOKEN_ENV);
    let options = WakeOptions::from_lookup(&mut get);
    ensure_agent_webhook_routines(&agents_dir, Path::new(&gateway), token.as_deref(), &options)
}

/// Set to `1` to write the bootstrap note into the profile description of
/// each bot that has no routine yet, through the gateway's `updateAgent`
/// (the host pushes profile edits to the server copy of the bot). The note
/// asks the bot to create its own routine named
/// [`crate::routine_folder_id`] of its nick on its next turn. Off by default: it edits a description the owner wrote.
pub const PROFILE_NOTE_ENV: &str = "M4A_BOOTSTRAP_PROFILE_NOTE";

const NOTE_OPEN: &str = "<!-- mail4agent:wake -->";
const NOTE_CLOSE: &str = "<!-- /mail4agent:wake -->";
/// Host limit on a profile description.
const DESCRIPTION_MAX: usize = 20_000;

/// The bootstrap note for routine name `routine` (already hyphenated). No
/// host name, no key, no agent id.
fn wake_note(routine: &str) -> String {
    format!(
        "{NOTE_OPEN}\nmail4agent wake: keep exactly one routine named \"{routine}\" with a webhook trigger, enabled. If it is missing, create it with UpdateRoutine: name \"{routine}\", trigger webhook, prompt \"A mail4agent room message woke this routine. The webhook JSON has body, from, event_id, and nick. Read that message.\" Do not rename it and do not create a second one.\n{NOTE_CLOSE}"
    )
}

/// `description` with the note for `routine` in place: an older note block is
/// replaced, otherwise the note is appended after a blank line. `None`
/// when the description already carries exactly this note.
fn with_wake_note(description: &str, routine: &str) -> Option<String> {
    let note = wake_note(routine);
    if description.contains(&note) {
        return None;
    }
    if let (Some(start), Some(end)) = (description.find(NOTE_OPEN), description.find(NOTE_CLOSE)) {
        if end > start {
            let mut out = String::with_capacity(description.len() + note.len());
            out.push_str(&description[..start]);
            out.push_str(&note);
            out.push_str(&description[end + NOTE_CLOSE.len()..]);
            return Some(out);
        }
    }
    let base = description.trim_end();
    Some(if base.is_empty() {
        note
    } else {
        format!("{base}\n\n{note}")
    })
}

/// Writes the note into one bot's profile description through the
/// gateway. Reads the rest of the profile from `profile.json` so name,
/// title, and avatar are sent back unchanged. Failures are logged only.
fn note_profile(gate: &GatewayConn, agents_dir: &Path, agent_id: &str, nick: &str) {
    match ensure_profile_note(gate, agents_dir, agent_id, nick) {
        Ok(true) => eprintln!("mail4agent: wake {nick}: bootstrap note written to the profile"),
        Ok(false) => {}
        Err(err) => eprintln!("mail4agent: wake {nick}: bootstrap note not written ({err})"),
    }
}

fn ensure_profile_note(
    gate: &GatewayConn,
    agents_dir: &Path,
    agent_id: &str,
    nick: &str,
) -> Result<bool, ShellError> {
    let text = std::fs::read_to_string(agents_dir.join(agent_id).join("profile.json"))
        .map_err(|_| ShellError::Gateway("profile is unreadable".to_string()))?;
    let profile: serde_json::Value = serde_json::from_str(&text)
        .map_err(|_| ShellError::Gateway("profile is unreadable".to_string()))?;
    let field = |key: &str| profile.get(key).and_then(|value| value.as_str());
    let Some(name) = field("name").filter(|name| !name.trim().is_empty()) else {
        return Err(ShellError::Gateway("profile has no name".to_string()));
    };
    let routine = crate::nick::routine_folder_id(nick)
        .ok_or_else(|| ShellError::Gateway("nick has no routine name".to_string()))?;
    let Some(description) = with_wake_note(field("description").unwrap_or(""), &routine) else {
        return Ok(false);
    };
    if description.chars().count() > DESCRIPTION_MAX {
        return Err(ShellError::Gateway(
            "description would be too long".to_string(),
        ));
    }
    let mut body = serde_json::json!({ "name": name, "description": description });
    for key in ["title", "avatarShape", "avatarColor"] {
        if let Some(value) = field(key) {
            body[key] = serde_json::Value::String(value.to_string());
        }
    }
    let (status, _) = gateway_post(
        gate,
        "updateAgent",
        &serde_json::json!({ "id": agent_id, "profile": body }),
    )?;
    if status != 200 {
        return Err(ShellError::Gateway(format!(
            "gateway profile status {status}"
        )));
    }
    Ok(true)
}

/// Gateway file the host already runs. [`GATEWAY_FILE_ENV`] overrides it.
/// The listener is loopback; the `host` field in the file is not used.
const DEFAULT_GATEWAY_FILE: &str = "agent-data/gateway.json";

/// Path of the gateway file. Unset on [`MachineClient::from_env`] uses
/// [`DEFAULT_GATEWAY_FILE`].
pub const GATEWAY_FILE_ENV: &str = "M4A_GATEWAY_FILE";

/// Gateway bearer. When set, this replaces the token in the gateway file.
/// It is never written to disk.
pub const GATEWAY_TOKEN_ENV: &str = "M4A_GATEWAY_TOKEN";

/// Saved prompt of the local mirror. The mirror is disabled and never runs:
/// the backend routine the bot made itself is the one the webhook wakes.
/// No host name and no key.
const MIRROR_ROUTINE_PROMPT: &str = "mail4agent wake mirror. Disabled on purpose: it only lets the local gateway hand out the webhook key for the routine with this folder id, which the bot creates itself with UpdateRoutine.";

/// Per-session keychain file under the session's sealed directory
/// ([`crate::session_store_dir`]). Mode 0600. Holds the folder id, the
/// webhook URL, and its key. Outside any repository; never logged.
pub const WAKE_KEYCHAIN_FILE: &str = "routine-wake.json";

#[derive(serde::Deserialize)]
struct GatewayFile {
    port: u16,
    scheme: String,
    #[serde(default)]
    token: Option<String>,
}

#[derive(serde::Deserialize)]
struct AutomationCard {
    id: String,
    name: String,
    #[serde(default)]
    trigger: Option<serde_json::Value>,
}

impl AutomationCard {
    /// Whether the card fires on a webhook. A card without a trigger field
    /// is not judged here; the credential call refuses it if it is not.
    fn is_webhook(&self) -> bool {
        fn has_webhook(value: &serde_json::Value) -> bool {
            match value {
                serde_json::Value::Array(items) => items.iter().any(has_webhook),
                serde_json::Value::Object(map) => {
                    map.get("type").and_then(|kind| kind.as_str()) == Some("webhook")
                        || map
                            .values()
                            .any(|inner| inner.is_array() && has_webhook(inner))
                }
                _ => false,
            }
        }
        self.trigger.as_ref().map(has_webhook).unwrap_or(true)
    }
}

#[derive(serde::Deserialize)]
struct WebhookCredential {
    url: String,
    key: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredWake {
    folder_id: String,
    url: String,
    key: String,
}

/// The bot's nick ([`crate::nick_from_display_name`] of the display name,
/// so `Alice` -> `alice`, `Привет мир` -> `privet-mir`).
/// The routine name and folder are the same string.
/// `None` when no nick derives.
fn routine_name_for(session: &HostSession) -> Option<String> {
    crate::nick::nick_from_display_name(session.bot_name.trim()).ok()
}

struct GatewayConn {
    client: reqwest::blocking::Client,
    base: String,
    token: String,
}

fn open_gateway(
    gateway_file: &Path,
    token_override: Option<&str>,
) -> Result<Option<GatewayConn>, ShellError> {
    if !gateway_file.is_file() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(gateway_file)
        .map_err(|_| ShellError::Gateway("gateway file is unreadable".to_string()))?;
    let file: GatewayFile = serde_json::from_str(&text)
        .map_err(|_| ShellError::Gateway("gateway file is unreadable".to_string()))?;
    let scheme = file.scheme.trim();
    if scheme != "http" && scheme != "https" {
        return Err(ShellError::Gateway(
            "gateway scheme is not http or https".to_string(),
        ));
    }
    if file.port == 0 {
        return Err(ShellError::Gateway("gateway port is unset".to_string()));
    }
    let token = token_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or(file.token.filter(|value| !value.trim().is_empty()));
    let Some(token) = token else {
        return Err(ShellError::Gateway("gateway token is unset".to_string()));
    };
    // The gateway listens on loopback only. Do not use the file's host.
    let base = format!("{scheme}://127.0.0.1:{}", file.port);
    Ok(Some(GatewayConn {
        client: gateway_client()?,
        base,
        token,
    }))
}

/// Result of [`ensure_wake`] for one agent. Holds the secret only in
/// memory, on its way to the session and the keychain file.
enum WakeOutcome {
    Ready { url: String, key: String },
    AwaitingBackend,
    Failed(String),
}

impl WakeOutcome {
    fn status(&self) -> WakeStatus {
        match self {
            WakeOutcome::Ready { .. } => WakeStatus::Ready,
            WakeOutcome::AwaitingBackend => WakeStatus::AwaitingBackend,
            WakeOutcome::Failed(reason) => WakeStatus::Failed(reason.clone()),
        }
    }
}

fn log_outcome(nick: &str, folder_id: &str, outcome: &WakeOutcome) {
    match outcome {
        WakeOutcome::Ready { .. } => eprintln!("mail4agent: wake {nick} ({folder_id}): ready"),
        WakeOutcome::AwaitingBackend => eprintln!(
            "mail4agent: wake {nick} ({folder_id}): no key yet; the bot has not created its own routine with this folder id; will retry"
        ),
        WakeOutcome::Failed(reason) => {
            eprintln!("mail4agent: wake {nick} ({folder_id}): {reason}")
        }
    }
}

/// One agent: make sure the disabled local mirror exists in exactly the
/// folder the bot's own routine uses, then read the credential.
///
/// The gateway mints a key only for a routine it can find locally, and it
/// mints it for `stableAutomationId(agentId, folderId)`, which is the
/// backend id of the bot's own routine with that folder id. A null key
/// means that backend routine does not exist yet. This never creates a
/// second routine: a mirror that lands in another folder (`-2`) is deleted
/// again and reported.
fn ensure_wake(gate: &GatewayConn, agent_id: &str, nick: &str) -> WakeOutcome {
    let Some(folder) = crate::nick::routine_folder_id(nick) else {
        return WakeOutcome::Failed("nick has no routine folder id".to_string());
    };
    let before = match list_agent_automations(gate, agent_id) {
        Ok(cards) => cards,
        Err(err) => return WakeOutcome::Failed(err.to_string()),
    };
    match before.iter().find(|card| card.id == folder) {
        Some(card) if !card.is_webhook() => {
            return WakeOutcome::Failed(
                "a routine in this folder is not webhook-triggered; left as is".to_string(),
            );
        }
        Some(_) => {}
        None => {
            let after = match create_mirror_routine(gate, agent_id, &folder) {
                Ok(cards) => cards,
                Err(err) => return WakeOutcome::Failed(err.to_string()),
            };
            if !after.iter().any(|card| card.id == folder) {
                for stray in after.iter().filter(|card| {
                    card.name == folder && !before.iter().any(|old| old.id == card.id)
                }) {
                    let _ = delete_agent_automation(gate, agent_id, &stray.id);
                }
                return WakeOutcome::Failed(
                    "the mirror did not land in the expected folder; removed it".to_string(),
                );
            }
        }
    }
    match read_webhook_credential(gate, agent_id, &folder) {
        Ok(CredentialRead::Ready { url, key }) => WakeOutcome::Ready { url, key },
        Ok(CredentialRead::MintFailed) => WakeOutcome::AwaitingBackend,
        Ok(CredentialRead::Missing) => {
            WakeOutcome::Failed("the mirror is gone from the gateway".to_string())
        }
        Err(err) => WakeOutcome::Failed(err.to_string()),
    }
}

/// Sets each session's wake. With a gateway: [`ensure_wake`], and a ready
/// URL and key go into the session and, when `store_root` is set, into the
/// keychain file. Without a gateway file: the keychain file, if it holds a
/// wake for this nick's folder. A session with no agent id is left alone.
fn attach_webhook_routines(
    sessions: &mut [HostSession],
    gateway_file: &Path,
    token_override: Option<&str>,
    store_root: Option<&Path>,
) -> Result<(), ShellError> {
    let gate = open_gateway(gateway_file, token_override)?;
    for session in sessions.iter_mut() {
        if session.routine_url.is_some() && session.routine_bearer.is_some() {
            continue;
        }
        // The gateway id is the Grok Bot agent, not the mail session id.
        let Some(agent_id) = session.agent_id.clone().filter(|id| !id.is_empty()) else {
            continue;
        };
        let Some(nick) = routine_name_for(session) else {
            continue;
        };
        let Some(folder) = crate::nick::routine_folder_id(&nick) else {
            continue;
        };
        let Some(gate) = gate.as_ref() else {
            if let Some(root) = store_root {
                if let Some((url, key)) = load_wake(root, &session.session_id, &folder) {
                    session.routine_url = Some(url);
                    session.routine_bearer = Some(key);
                }
            }
            continue;
        };
        let outcome = ensure_wake(gate, &agent_id, &nick);
        log_outcome(&nick, &folder, &outcome);
        match outcome {
            WakeOutcome::Ready { url, key } => {
                if let Some(root) = store_root {
                    save_wake(root, &session.session_id, &folder, &url, &key);
                }
                session.routine_url = Some(url);
                session.routine_bearer = Some(key);
            }
            WakeOutcome::AwaitingBackend => {
                // A key kept from before is not trusted once the gateway
                // says the routine has none.
                if let Some(root) = store_root {
                    clear_wake(root, &session.session_id);
                }
            }
            WakeOutcome::Failed(_) => {}
        }
    }
    Ok(())
}

/// Lock file in each sealed session directory. [`MachineClient::open`]
/// holds an exclusive lock on it for as long as the client lives, so a
/// second process (another client, or `m4a-send` opening the store itself)
/// cannot write the same Olm state at the same time.
pub const STORE_LOCK_FILE: &str = ".lock";

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

pub(crate) fn lock_store(dir: &Path) -> Result<File, ShellError> {
    std::fs::create_dir_all(dir)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(STORE_LOCK_FILE))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(_) => Err(ShellError::SessionList(
            "session store is in use by another process".to_string(),
        )),
    }
}

/// Writes `bytes` to `path` atomically, file 0600, parent created 0700.
fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no parent"))?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("secret");
    let tmp = dir.join(format!("{name}.tmp"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    std::io::Write::write_all(&mut file, bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)
}

fn keychain_path(store_root: &Path, session_id: &str) -> PathBuf {
    crate::session_store_dir(store_root, session_id).join(WAKE_KEYCHAIN_FILE)
}

/// Writes the wake atomically with mode 0600. A failure is logged without
/// the values and does not stop the client: the gateway still has the key.
fn save_wake(store_root: &Path, session_id: &str, folder_id: &str, url: &str, key: &str) {
    let stored = StoredWake {
        folder_id: folder_id.to_string(),
        url: url.to_string(),
        key: key.to_string(),
    };
    let result = serde_json::to_vec(&stored)
        .map_err(std::io::Error::other)
        .and_then(|bytes| write_secret_file(&keychain_path(store_root, session_id), &bytes));
    if result.is_err() {
        eprintln!("mail4agent: wake keychain write failed for folder {folder_id}");
    }
}

fn load_wake(store_root: &Path, session_id: &str, folder_id: &str) -> Option<(String, String)> {
    let text = std::fs::read_to_string(keychain_path(store_root, session_id)).ok()?;
    let stored: StoredWake = serde_json::from_str(&text).ok()?;
    if stored.folder_id != folder_id || stored.url.is_empty() || stored.key.is_empty() {
        return None;
    }
    Some((stored.url, stored.key))
}

fn clear_wake(store_root: &Path, session_id: &str) {
    let _ = std::fs::remove_file(keychain_path(store_root, session_id));
}

fn list_agent_automations(
    gate: &GatewayConn,
    agent_id: &str,
) -> Result<Vec<AutomationCard>, ShellError> {
    let (status, body) = gateway_post(
        gate,
        "getAgentAutomations",
        &serde_json::json!({ "id": agent_id }),
    )?;
    if status != 200 {
        return Err(ShellError::Gateway(format!("gateway list status {status}")));
    }
    serde_json::from_slice(&body)
        .map_err(|_| ShellError::Gateway("gateway list was not understood".to_string()))
}

enum CredentialRead {
    Ready {
        url: String,
        key: String,
    },
    /// The mirror exists and the gateway did not return a key.
    MintFailed,
    Missing,
}

fn gateway_client() -> Result<reqwest::blocking::Client, ShellError> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .http1_only()
        .build()
        .map_err(|_| ShellError::Gateway("gateway client could not start".to_string()))
}

fn gateway_post(
    gate: &GatewayConn,
    method: &str,
    body: &serde_json::Value,
) -> Result<(u16, Vec<u8>), ShellError> {
    let url = format!("{}/api/{method}", gate.base);
    let authorization = crate::bearer_header(&gate.token).map_err(|_| {
        ShellError::Gateway("gateway token is not a single header value".to_string())
    })?;
    let bytes = serde_json::to_vec(body)
        .map_err(|_| ShellError::Gateway("gateway request was not json".to_string()))?;
    let response = gate
        .client
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(bytes)
        .send()
        .map_err(|_| ShellError::Gateway("gateway request failed".to_string()))?;
    let status = response.status().as_u16();
    let body = response
        .bytes()
        .map_err(|_| ShellError::Gateway("gateway response failed".to_string()))?;
    Ok((status, body.to_vec()))
}

fn read_webhook_credential(
    gate: &GatewayConn,
    agent_id: &str,
    automation_id: &str,
) -> Result<CredentialRead, ShellError> {
    let (status, body) = gateway_post(
        gate,
        "getAutomationWebhookCredential",
        &serde_json::json!({
            "id": agent_id,
            "automationId": automation_id,
        }),
    )?;
    if status == 200 {
        let parsed: WebhookCredential = serde_json::from_slice(&body).map_err(|_| {
            ShellError::Gateway("gateway credential was not understood".to_string())
        })?;
        let key = parsed.key.filter(|key| !key.is_empty());
        if parsed.url.is_empty() {
            return Err(ShellError::Gateway(
                "gateway credential was not understood".to_string(),
            ));
        }
        return Ok(match key {
            Some(key) => CredentialRead::Ready {
                url: parsed.url,
                key,
            },
            None => CredentialRead::MintFailed,
        });
    }
    if credential_is_missing(status, &body) {
        return Ok(CredentialRead::Missing);
    }
    Err(ShellError::Gateway(format!(
        "gateway credential status {status}"
    )))
}

/// A missing routine is not a 200. The gateway reports that as 404 or as
/// 500 with its not-found error.
fn credential_is_missing(status: u16, body: &[u8]) -> bool {
    if status == 404 {
        return true;
    }
    if status != 500 {
        return false;
    }
    std::str::from_utf8(body)
        .map(|text| text.contains("Automation not found"))
        .unwrap_or(false)
}

/// `routine` is the routine name, equal to its folder id.
fn create_mirror_routine(
    gate: &GatewayConn,
    agent_id: &str,
    routine: &str,
) -> Result<Vec<AutomationCard>, ShellError> {
    let (status, body) = gateway_post(
        gate,
        "createAgentAutomation",
        &serde_json::json!({
            "id": agent_id,
            "spec": {
                "name": routine,
                "prompt": MIRROR_ROUTINE_PROMPT,
                "trigger": { "type": "webhook" },
                "isEnabled": false,
            },
        }),
    )?;
    if status != 200 {
        return Err(ShellError::Gateway(format!(
            "gateway create status {status}"
        )));
    }
    serde_json::from_slice(&body)
        .map_err(|_| ShellError::Gateway("gateway create was not understood".to_string()))
}

fn delete_agent_automation(
    gate: &GatewayConn,
    agent_id: &str,
    automation_id: &str,
) -> Result<(), ShellError> {
    let (status, _) = gateway_post(
        gate,
        "deleteAgentAutomation",
        &serde_json::json!({ "id": agent_id, "automationId": automation_id }),
    )?;
    if status != 200 {
        return Err(ShellError::Gateway(format!(
            "gateway delete status {status}"
        )));
    }
    Ok(())
}

pub(crate) struct Prepared {
    pub(crate) config: SessionConfig,
    pub(crate) nick: String,
    pub(crate) user_id: String,
    pub(crate) device_id: DeviceId,
    pub(crate) bearer: Zeroizing<String>,
    pub(crate) backend: Arc<dyn m4a_agent::Backend>,
    pub(crate) routine_url: Option<String>,
    pub(crate) routine_bearer: Option<String>,
}

/// The sessions on one machine, and the in-process bus they use when the
/// peer is one of them.
pub struct MachineClient {
    /// Product-session mode: one push socket per session (a handshake is vouched for one identity).
    product_mode: bool,
    sessions: Vec<OpenedStore>,
    bus: Arc<LocalBus>,
    push: m4a_agent::engine::PushLink,
    /// When set, [`Self::poll_agent_directory`] rescans this folder for new
    /// bots and creates their webhook routines. Session stores already open
    /// are left alone; a new process picks up new sealed stores.
    agents_dir: Option<PathBuf>,
    gateway_file: Option<PathBuf>,
    gateway_token: Option<String>,
    last_agent_poll: std::time::Instant,
    agent_rescan_secs: u64,
    /// Root for per-session keychain files ([`WAKE_KEYCHAIN_FILE`]).
    store_root: Option<PathBuf>,
    /// [`SKIP_NICKS_ENV`] as read at open.
    skip_nicks: Vec<String>,
    /// [`PROFILE_NOTE_ENV`] as read at open.
    profile_note: bool,
    /// [`SESSION_IDS_ENV`] as read at open.
    session_ids: Vec<(String, String)>,
    /// When every session was last driven without a push.
    last_full_drive: std::time::Instant,
    /// Open sessions whose bot has no key yet. Retried on each poll.
    pending_wakes: Vec<PendingWake>,
    /// Agent ids whose wake is already set on an open session or reported
    /// ready. Not asked again.
    ready_agents: HashSet<String>,
    /// Exclusive locks on every open session directory ([`STORE_LOCK_FILE`]).
    _locks: Vec<File>,
    /// Local socket `m4a-send` writes to ([`MachineClient::listen_for_sends`]).
    send_listener: Option<SendListener>,
    send_sock: Option<PathBuf>,
    /// Sends waiting for the peer to join the DM.
    send_queue: Vec<PendingSend>,
    /// Homeserver the sessions registered on; a bot found by
    /// [`Self::poll_agent_directory`] registers there too.
    homeserver_url: String,
    /// Next local-bus user row for a session opened after start.
    bus_next_user: i64,
    /// Session ids whose late open failed, and when. Retried after
    /// [`LATE_OPEN_RETRY_SECS`].
    failed_opens: HashMap<String, std::time::Instant>,
}

/// How long [`MachineClient::poll_agent_directory`] waits before trying
/// again to open a newly found bot's session after a failure.
const LATE_OPEN_RETRY_SECS: u64 = 60;

/// One `m4a-send` request still in progress.
struct PendingSend {
    stream: SendStream,
    request: crate::SendRequest,
    started: std::time::Instant,
    room: Option<String>,
    peer: Option<String>,
}

/// How long a send waits for the recipient to join a new DM.
const SEND_JOIN_WAIT_SECS: u64 = 120;

impl Drop for MachineClient {
    fn drop(&mut self) {
        if let Some(path) = self.send_sock.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// What one [`MachineClient::tick`] did. Nicks, event ids, room ids, and
/// error texts only.
#[derive(Debug, Default)]
pub struct TickReport {
    /// (nick, event id) for each event the push socket delivered.
    pub pushed: Vec<(String, String)>,
    /// (nick, room id) for each DM invite joined.
    pub joined: Vec<(String, String)>,
    /// (nick, error) for each session whose drive failed.
    pub errors: Vec<(String, String)>,
    /// (from nick, to nick, answer) for each `m4a-send` request finished.
    pub sent: Vec<(String, String, crate::SendReply)>,
    /// `(nick, text)` peer key-change alerts (M3).
    pub alerts: Vec<(String, String)>,
}

/// An open session still waiting for its bot's own routine.
struct PendingWake {
    store_dir: PathBuf,
    agent_id: String,
}

impl MachineClient {
    /// Registers `sessions` and opens each sealed store under `store_root`.
    ///
    /// The host built `sessions`. This does not look for bot processes.
    /// The first drive publishes public keys to the homeserver and mirrors
    /// them onto the in-process bus. A long-poll left by that drive is
    /// dropped so it is not a second sync loop.
    pub fn open(
        homeserver_url: &str,
        store_root: &Path,
        sessions: Vec<HostSession>,
    ) -> Result<Self, ShellError> {
        Self::open_with(homeserver_url, store_root, sessions, false)
    }

    /// [`Self::open`]; with `lenient`, a session that fails to register or
    /// whose store is locked is logged and left out instead of failing the
    /// whole open (at least one session must open).
    fn open_with(
        homeserver_url: &str,
        store_root: &Path,
        sessions: Vec<HostSession>,
        lenient: bool,
    ) -> Result<Self, ShellError> {
        if sessions.is_empty() {
            return Err(ShellError::SessionList("session list is empty".to_string()));
        }
        let mut prepared = Vec::with_capacity(sessions.len());
        let mut seen_ids = Vec::new();
        let mut seen_nicks = Vec::new();
        let mut locks = Vec::new();
        for session in sessions {
            let config = session.config(homeserver_url, store_root)?;
            if seen_ids.iter().any(|id: &String| id == config.session_id()) {
                return Err(ShellError::SessionList("duplicate session id".to_string()));
            }
            seen_ids.push(config.session_id().to_string());
            let lock = match lock_store(&config.store_dir()) {
                Ok(lock) => lock,
                Err(err) if lenient => {
                    eprintln!("mail4agent: session {} left out: {err}", config.session_id());
                    continue;
                }
                Err(err) => return Err(err),
            };
            let registered = match register_session(&config) {
                Ok(registered) => registered,
                Err(err) if lenient => {
                    eprintln!("mail4agent: session {} left out: {err}", config.session_id());
                    continue;
                }
                Err(err) => return Err(err),
            };
            if seen_nicks.iter().any(|nick: &String| nick.eq_ignore_ascii_case(&registered.nick)) {
                return Err(ShellError::SessionList("duplicate nick".to_string()));
            }
            seen_nicks.push(registered.nick.clone());
            locks.push(lock);
            prepared.push(Prepared {
                config,
                nick: registered.nick,
                user_id: registered.user_id,
                device_id: registered.device_id,
                bearer: registered.bearer,
                backend: registered.backend,
                routine_url: session.routine_url,
                routine_bearer: session.routine_bearer,
            });
        }
        if prepared.is_empty() {
            return Err(ShellError::SessionList(
                "no session could be opened".to_string(),
            ));
        }
        let server_name = server_name_of(&prepared[0].user_id)?;
        for item in &prepared[1..] {
            if server_name_of(&item.user_id)? != server_name {
                return Err(ShellError::SessionList(
                    "sessions disagree on the homeserver name".to_string(),
                ));
            }
        }
        ensure_server_name(server_name)?;
        let bus = Arc::new(LocalBus::open(&prepared)?);
        let peers: Vec<(String, String)> = prepared
            .iter()
            .map(|item| (item.nick.to_string(), item.user_id.clone()))
            .collect();
        let mut opened = Vec::with_capacity(prepared.len());
        for item in &prepared {
            let server_name = server_name_of(&item.user_id)?;
            let mut store = OpenedStore::open(
                &item.config.store_dir(),
                item.config.session_id(),
                item.device_id.clone(),
                &item.user_id,
                server_name,
                Arc::clone(&item.backend),
                item.bearer.as_str(),
            )?;
            store.set_registered_nick(item.nick.to_string());
            store.attach_bus(Arc::clone(&bus));
            store.set_local_peers(
                peers
                    .iter()
                    .filter(|(nick, _)| *nick != item.nick)
                    .cloned()
                    .collect(),
            );
            store.set_wake(SessionWake {
                routine_url: item.routine_url.clone(),
                routine_bearer: item.routine_bearer.clone(),
                leader_sock: None,
                leader_cwd: None,
            });
            if item.routine_url.is_none() {
                attach_detected_chain(&mut store, &item.config, &item.nick);
            }
            store.drive(1_000, false)?;
            store.abandon_inflight_sync(1_000)?;
            opened.push(store);
        }
        let tokens: Vec<String> = prepared
            .iter()
            .map(|item| item.bearer.as_str().to_string())
            .collect();
        let product_mode = true;
        let push = m4a_agent::engine::PushLink::open(&prepared[0].config.homeserver_url, prepared[0].backend.keep_prefix(), tokens, product_mode)?;
        Ok(Self {
            product_mode,
            sessions: opened,
            bus,
            push,
            agents_dir: None,
            gateway_file: None,
            gateway_token: None,
            last_agent_poll: std::time::Instant::now(),
            agent_rescan_secs: 0,
            store_root: None,
            skip_nicks: Vec::new(),
            profile_note: false,
            session_ids: Vec::new(),
            last_full_drive: std::time::Instant::now(),
            pending_wakes: Vec::new(),
            ready_agents: HashSet::new(),
            _locks: locks,
            send_listener: None,
            send_sock: None,
            send_queue: Vec::new(),
            homeserver_url: homeserver_url.to_string(),
            bus_next_user: prepared.len() as i64 + 1,
            failed_opens: HashMap::new(),
        })
    }

    /// [`load_session_records`] then [`Self::open`]. Records have no bearer
    /// and no routine URL; those stay unset.
    pub fn open_session_dir(
        homeserver_url: &str,
        store_root: &Path,
        sessions_dir: &Path,
    ) -> Result<Self, ShellError> {
        let sessions = load_session_records(sessions_dir)?;
        Self::open(homeserver_url, store_root, sessions)
    }

    /// Web machine client open path.
    ///
    /// [`HOMESERVER_URL_ENV`], [`STORE_ROOT_ENV`]. Discovery prefers the
    /// agents directory ([`AGENTS_DIR_ENV`] or [`DEFAULT_AGENTS_DIR`]) when
    /// that folder exists; otherwise [`SESSIONS_DIR_ENV`]. One webhook
    /// routine per agent, from the gateway file ([`GATEWAY_FILE_ENV`], or
    /// the host gateway file when that is unset). The token is the file's
    /// token, or [`GATEWAY_TOKEN_ENV`] when the host injected one. A missing
    /// file leaves routines unset and does not fail this open. URLs and
    /// keys are not read from disk and are not written back.
    /// [`crate::LEADER_SOCK_ENV`] is not read.
    pub fn from_env() -> Result<Self, ShellError> {
        Self::from_env_filtered(None)
    }

    /// [`Self::from_env`] with only the session whose nick is `nick`: the
    /// path `m4a-send` takes when no client is running. Does not listen
    /// for sends.
    pub fn from_env_for(nick: &str) -> Result<Self, ShellError> {
        Self::from_env_filtered(Some(nick))
    }

    fn from_env_filtered(only: Option<&str>) -> Result<Self, ShellError> {
        let homeserver_url = std::env::var(HOMESERVER_URL_ENV)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or(ShellError::HomeserverUrl)?;
        let store_root = std::env::var(STORE_ROOT_ENV)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or(ShellError::StoreRoot)?;
        let mut get = |key: &str| -> Option<String> {
            if key == GATEWAY_FILE_ENV {
                return std::env::var(GATEWAY_FILE_ENV)
                    .ok()
                    .filter(|value| !value.is_empty())
                    .or_else(|| Some(under_home(DEFAULT_GATEWAY_FILE).to_string_lossy().into_owned()));
            }
            std::env::var(key).ok().filter(|value| !value.is_empty())
        };
        let agents_dir = resolve_agents_dir(&mut get);
        let (sessions, agents_dir) = if let Some(dir) = agents_dir {
            (load_web_agents(&dir, &mut get)?, Some(dir))
        } else {
            let sessions_dir = get(SESSIONS_DIR_ENV)
                .ok_or_else(|| ShellError::SessionList("session directory is unset".to_string()))?;
            (load_web_sessions(Path::new(&sessions_dir), &mut get)?, None)
        };
        let sessions = match only {
            Some(nick) => {
                let needle = crate::nick::lookup_nick(nick)?;
                let kept: Vec<HostSession> = sessions
                    .into_iter()
                    .filter(|session| {
                        routine_name_for(session)
                            .is_some_and(|name| name.eq_ignore_ascii_case(&needle))
                    })
                    .collect();
                if kept.is_empty() {
                    return Err(ShellError::UnknownNick);
                }
                kept
            }
            None => sessions,
        };
        let gateway_file = get(GATEWAY_FILE_ENV).map(PathBuf::from);
        let gateway_token = get(GATEWAY_TOKEN_ENV);
        let agent_rescan_secs = get(AGENT_RESCAN_SECS_ENV)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let mut pending_wakes = Vec::new();
        let mut ready_agents = HashSet::new();
        for session in &sessions {
            let Some(agent_id) = session.agent_id.clone() else {
                continue;
            };
            if session.routine_url.is_some() && session.routine_bearer.is_some() {
                ready_agents.insert(agent_id);
            } else {
                pending_wakes.push(PendingWake {
                    store_dir: crate::session_store_dir(
                        Path::new(&store_root),
                        &session.session_id,
                    ),
                    agent_id,
                });
            }
        }
        let options = WakeOptions::from_lookup(&mut get);
        let mut client = Self::open_with(&homeserver_url, Path::new(&store_root), sessions, true)?;
        client.store_root = Some(PathBuf::from(&store_root));
        client.skip_nicks = options.skip_nicks;
        client.profile_note = options.profile_note;
        client.session_ids = options.session_ids;
        client.pending_wakes = pending_wakes;
        client.ready_agents = ready_agents;
        client.agents_dir = agents_dir;
        client.gateway_file = gateway_file;
        client.gateway_token = gateway_token;
        client.agent_rescan_secs = agent_rescan_secs;
        client.last_agent_poll = std::time::Instant::now();
        Ok(client)
    }

    /// Rescans the agents directory when this client was opened from one.
    ///
    /// For every bot not skipped and not ready yet: ensures the local
    /// mirror and asks for the credential again. A bot that just created
    /// its own routine turns ready here; when that bot has an open session,
    /// its wake is set in place and saved to the keychain file. A bot that
    /// appeared after open gets its mirror now; its sealed store opens with
    /// the next process. When [`AGENT_RESCAN_SECS_ENV`] is set and greater
    /// than zero, returns without scanning until that many seconds have
    /// passed since the last poll. Reports carry no URL and no key.
    pub fn poll_agent_directory(&mut self) -> Result<Vec<RoutineReport>, ShellError> {
        let Some(agents_dir) = self.agents_dir.clone() else {
            return Ok(Vec::new());
        };
        if self.agent_rescan_secs > 0 {
            let elapsed = self.last_agent_poll.elapsed().as_secs();
            if elapsed < self.agent_rescan_secs {
                return Ok(Vec::new());
            }
        }
        self.last_agent_poll = std::time::Instant::now();
        self.open_new_agent_sessions(&agents_dir);
        let gateway = self
            .gateway_file
            .clone()
            .unwrap_or_else(|| under_home(DEFAULT_GATEWAY_FILE));
        let Some(gate) = open_gateway(&gateway, self.gateway_token.as_deref())? else {
            return Ok(Vec::new());
        };
        let mut sessions = drop_skipped(load_agents_dir(&agents_dir)?, &self.skip_nicks);
        apply_session_ids(&mut sessions, &self.session_ids);
        let mut reports = Vec::new();
        for session in &sessions {
            let Some(agent_id) = session.agent_id.clone() else {
                continue;
            };
            let Some(nick) = routine_name_for(session) else {
                continue;
            };
            let folder_id = crate::nick::routine_folder_id(&nick).unwrap_or_default();
            if self.ready_agents.contains(&agent_id) {
                reports.push(RoutineReport {
                    agent_id,
                    nick,
                    folder_id,
                    status: WakeStatus::Ready,
                });
                continue;
            }
            let outcome = ensure_wake(&gate, &agent_id, &nick);
            log_outcome(&nick, &folder_id, &outcome);
            if self.profile_note && matches!(outcome, WakeOutcome::AwaitingBackend) {
                note_profile(&gate, &agents_dir, &agent_id, &nick);
            }
            if let WakeOutcome::Ready { url, key } = &outcome {
                if let Some(root) = &self.store_root {
                    save_wake(root, &session.session_id, &folder_id, url, key);
                }
                if let Some(index) = self
                    .pending_wakes
                    .iter()
                    .position(|pending| pending.agent_id == agent_id)
                {
                    let pending = self.pending_wakes.remove(index);
                    if let Some(store) = self
                        .sessions
                        .iter_mut()
                        .find(|store| store.store_dir() == pending.store_dir)
                    {
                        store.set_wake(SessionWake {
                            routine_url: Some(url.clone()),
                            routine_bearer: Some(key.clone()),
                            leader_sock: None,
                            leader_cwd: None,
                        });
                    }
                }
                self.ready_agents.insert(agent_id.clone());
                if let Some(user_id) = self
                    .sessions
                    .iter()
                    .find(|store| {
                        store
                            .nick()
                            .map(|n| n.eq_ignore_ascii_case(&nick))
                            .unwrap_or(false)
                    })
                    .map(|store| store.user_id().to_string())
                {
                    self.announce_peer_joined(&nick, &user_id);
                }
            }
            reports.push(RoutineReport {
                agent_id,
                nick,
                folder_id,
                status: outcome.status(),
            });
        }
        Ok(reports)
    }

    /// Registers and opens a session for every bot in `agents_dir` that is
    /// not skipped and has no open session yet, the same way open does:
    /// nick = slug, sealed store under the store root, device bearer to the
    /// keychain dir. A failure is logged and retried after
    /// [`LATE_OPEN_RETRY_SECS`].
    fn open_new_agent_sessions(&mut self, agents_dir: &Path) {
        let Some(store_root) = self.store_root.clone() else {
            return;
        };
        let found = match load_agents_dir(agents_dir) {
            Ok(found) => found,
            Err(err) => {
                eprintln!("mail4agent: agent rescan: {err}");
                return;
            }
        };
        let held: Vec<(PathBuf, Option<String>)> = self
            .sessions
            .iter()
            .map(|store| {
                (
                    store.store_dir().to_path_buf(),
                    store.nick().map(str::to_string),
                )
            })
            .collect();
        let fresh = unopened_agent_sessions(
            found,
            &self.skip_nicks,
            &self.session_ids,
            &store_root,
            &held,
        );
        for (session, nick) in fresh {
            if let Some(failed_at) = self.failed_opens.get(&session.session_id) {
                if failed_at.elapsed().as_secs() < LATE_OPEN_RETRY_SECS {
                    continue;
                }
            }
            let session_id = session.session_id.clone();
            match self.open_late_session(&store_root, session, &nick) {
                Ok(()) => {
                    self.failed_opens.remove(&session_id);
                    println!("mail4agent: session {nick} registered and open");
                }
                Err(err) => {
                    eprintln!("mail4agent: session {nick} not opened: {err}");
                    self.failed_opens
                        .insert(session_id, std::time::Instant::now());
                }
            }
        }
    }

    fn open_late_session(
        &mut self,
        store_root: &Path,
        mut session: HostSession,
        nick: &str,
    ) -> Result<(), ShellError> {
        if session.routine_url.is_none() || session.routine_bearer.is_none() {
            if let Some(folder) = crate::nick::routine_folder_id(nick) {
                if let Some((url, key)) = load_wake(store_root, &session.session_id, &folder) {
                    session.routine_url = Some(url);
                    session.routine_bearer = Some(key);
                }
            }
        }
        let config = session.config(&self.homeserver_url, store_root)?;
        let lock = lock_store(&config.store_dir())?;
        let registered = register_session(&config)?;
        if let Some(first) = self.sessions.first() {
            if server_name_of(&registered.user_id)? != server_name_of(first.user_id())? {
                return Err(ShellError::SessionList(
                    "sessions disagree on the homeserver name".to_string(),
                ));
            }
        }
        let item = Prepared {
            config,
            nick: registered.nick,
            user_id: registered.user_id,
            device_id: registered.device_id,
            bearer: registered.bearer,
                backend: registered.backend,
            routine_url: session.routine_url.clone(),
            routine_bearer: session.routine_bearer.clone(),
        };
        self.bus.seed(self.bus_next_user, &item)?;
        self.bus_next_user += 1;
        let mut store = OpenedStore::open(
            &item.config.store_dir(),
            item.config.session_id(),
            item.device_id.clone(),
            &item.user_id,
            server_name_of(&item.user_id)?,
            Arc::clone(&item.backend),
            item.bearer.as_str(),
        )?;
        store.set_registered_nick(item.nick.to_string());
        store.attach_bus(Arc::clone(&self.bus));
        store.set_wake(SessionWake {
            routine_url: item.routine_url.clone(),
            routine_bearer: item.routine_bearer.clone(),
            leader_sock: None,
            leader_cwd: None,
        });
        if item.routine_url.is_none() {
            attach_detected_chain(&mut store, &item.config, &item.nick);
        }
        store.drive(1_000, false)?;
        store.abandon_inflight_sync(1_000)?;
        self.sessions.push(store);
        self._locks.push(lock);
        self.refresh_local_peers();
        let tokens: Vec<String> = self
            .sessions
            .iter()
            .map(|store| store.device_bearer().to_string())
            .collect();
        match m4a_agent::engine::PushLink::open(&self.homeserver_url, self.sessions.first().is_some_and(|s| s.keep_prefix()), tokens, self.product_mode) {
            Ok(push) => {
                let old = std::mem::replace(&mut self.push, push);
                for (recipient, event) in old.drain() {
                    if let Some(store) = self
                        .sessions
                        .iter_mut()
                        .find(|store| store.user_id() == recipient)
                    {
                        store.record_push(event);
                    }
                }
            }
            Err(err) => {
                eprintln!("mail4agent: push socket not reopened for {nick}: {err}");
            }
        }
        if let Some(agent_id) = session.agent_id.clone() {
            if item.routine_url.is_some() && item.routine_bearer.is_some() {
                self.ready_agents.insert(agent_id);
                self.announce_peer_joined(nick, &item.user_id);
            } else {
                // Ask the gateway again so the wake lands on this session.
                self.ready_agents.remove(&agent_id);
                if !self.pending_wakes.iter().any(|p| p.agent_id == agent_id) {
                    self.pending_wakes.push(PendingWake {
                        store_dir: item.config.store_dir(),
                        agent_id,
                    });
                }
            }
        }
        Ok(())
    }

    /// Every open session sees every other one as a local peer.
    fn refresh_local_peers(&mut self) {
        let peers: Vec<(String, String)> = self
            .sessions
            .iter()
            .filter_map(|store| Some((store.nick()?.to_string(), store.user_id().to_string())))
            .collect();
        for store in self.sessions.iter_mut() {
            let own = store.nick().unwrap_or("").to_string();
            store.set_local_peers(
                peers
                    .iter()
                    .filter(|(nick, _)| *nick != own)
                    .cloned()
                    .collect(),
            );
        }
    }

    /// POSTs `kind=peer_joined` once to every other ready bot's webhook.
    /// Called when `joined_nick` first becomes ready. Failures are logged
    /// without the URL or key.
    fn announce_peer_joined(&self, joined_nick: &str, joined_user_id: &str) {
        let body = serde_json::json!({
            "kind": "peer_joined",
            "nick": joined_nick,
            "user_id": joined_user_id,
        });
        for store in &self.sessions {
            let Some(nick) = store.nick() else {
                continue;
            };
            if nick.eq_ignore_ascii_case(joined_nick) {
                continue;
            }
            if !store.has_routine() {
                continue;
            }
            let Some((url, bearer)) = store.routine_target() else {
                continue;
            };
            match crate::post_routine_json(&url, &body, bearer.as_deref()) {
                Ok(()) => {
                    eprintln!("mail4agent: peer_joined {joined_nick} -> {nick} status=200")
                }
                Err(err) => {
                    eprintln!("mail4agent: peer_joined {joined_nick} -> {nick}: {err}")
                }
            }
        }
    }

    /// Agent ids of open sessions that still have no wake.
    pub fn pending_wake_agents(&self) -> Vec<String> {
        self.pending_wakes
            .iter()
            .map(|pending| pending.agent_id.clone())
            .collect()
    }

    /// While `enabled`, drive does not call the homeserver. Requests are
    /// answered by the in-process bus. Turn this on for an exchange whose
    /// peer is a session [`Self::open`] holds, and off again before reaching
    /// a session that exists only on the homeserver.
    ///
    /// A public channel is not given a separate transport: with this off,
    /// create and send use the homeserver, which is what a public channel
    /// and a group with a remote member already do. An encrypted direct
    /// room between two local sessions uses the bus while this is on, and
    /// the room stays encrypted.
    pub fn set_local_delivery(&self, enabled: bool) {
        self.bus.set_local_only(enabled);
    }

    /// Homeserver calls counted across every session since [`Self::open`].
    /// In-process bus calls are not included. Registration before the first
    /// drive is not included either.
    pub fn homeserver_hits(&self) -> u64 {
        self.bus.hits()
    }

    /// The open session whose nick matches `name_or_nick`.
    pub fn session_mut(&mut self, name_or_nick: &str) -> Result<&mut OpenedStore, ShellError> {
        let needle = crate::nick::lookup_nick(name_or_nick)?;
        self.sessions
            .iter_mut()
            .find(|store| {
                store
                    .nick()
                    .is_some_and(|nick| nick.eq_ignore_ascii_case(&needle))
            })
            .ok_or(ShellError::UnknownNick)
    }

    /// Sealed directory for that nick.
    pub fn store_dir(&self, name_or_nick: &str) -> Result<PathBuf, ShellError> {
        let needle = crate::nick::lookup_nick(name_or_nick)?;
        self.sessions
            .iter()
            .find(|store| {
                store
                    .nick()
                    .is_some_and(|nick| nick.eq_ignore_ascii_case(&needle))
            })
            .map(|store| store.store_dir().to_path_buf())
            .ok_or(ShellError::UnknownNick)
    }

    /// Hands pushed room text to the session named by `recipient`.
    /// Another session on this client does not receive it. This does not
    /// start `/sync` and it does not post a routine.
    pub fn deliver_pushed(&mut self) -> usize {
        let batch = self.push.drain();
        let mut delivered = 0;
        for (recipient, event) in batch {
            let Some(session) = self
                .sessions
                .iter_mut()
                .find(|store| store.user_id() == recipient)
            else {
                continue;
            };
            session.record_push(event);
            delivered += 1;
        }
        delivered
    }

    /// One step of the long-running client loop.
    ///
    /// Drains the push socket and hands each pushed event to its session,
    /// then drives exactly those sessions (waiting for the `/sync` the push
    /// announced), which decrypts the text and POSTs the wake to that
    /// session's own routine. Every `full_drive_secs` it also drives every
    /// session once, which is how DM invites get joined
    /// ([`OpenedStore::accept_direct_invites`]) and how a missed push is
    /// caught up. Errors are returned per session, without secrets.
    pub fn tick(&mut self, now_ms: i64, full_drive_secs: u64) -> TickReport {
        let mut report = TickReport::default();
        let mut due: Vec<usize> = Vec::new();
        for (recipient, event) in self.push.drain() {
            let Some(index) = self
                .sessions
                .iter()
                .position(|store| store.user_id() == recipient)
            else {
                continue;
            };
            let nick = self.sessions[index].nick().unwrap_or("").to_string();
            report.pushed.push((nick, event.event_id.clone()));
            self.sessions[index].record_push(event);
            if !due.contains(&index) {
                due.push(index);
            }
        }
        let full = self.last_full_drive.elapsed().as_secs() >= full_drive_secs;
        if full {
            self.last_full_drive = std::time::Instant::now();
        }
        for index in 0..self.sessions.len() {
            let pushed = due.contains(&index);
            if !pushed && !full {
                continue;
            }
            let store = &mut self.sessions[index];
            let nick = store.nick().unwrap_or("").to_string();
            let drove = store.drive(now_ms, pushed);
            for text in store.take_security_alerts() {
                report.alerts.push((nick.clone(), text));
            }
            if let Err(err) = drove {
                report.errors.push((nick.clone(), err.to_string()));
                continue;
            }
            match store.accept_direct_invites(now_ms) {
                Ok(joined) => {
                    for room in joined {
                        report.joined.push((nick.clone(), room));
                    }
                }
                Err(err) => report.errors.push((nick, err.to_string())),
            }
        }
        self.serve_sends(now_ms, &mut report);
        report
    }

    /// Listens on `path` for `m4a-send` requests (one JSON line each, see
    /// [`crate::SendRequest`]). A stale socket file is replaced; a live
    /// listener is refused. Unix is mode 0600. Windows is loopback TCP and
    /// the file holds `127.0.0.1:{port}`. The file is removed when the
    /// client drops. [`Self::tick`] answers requests: the `as` session
    /// opens (or reuses) the encrypted DM with `to`, waits up to two
    /// minutes for `to` to join, and sends.
    pub fn listen_for_sends(&mut self, path: &Path) -> Result<(), ShellError> {
        let listener = SendListener::bind(path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                ShellError::SessionList(
                    "another client already listens on the send socket".to_string(),
                )
            } else {
                ShellError::Io(err)
            }
        })?;
        listener.set_nonblocking(true)?;
        self.send_listener = Some(listener);
        self.send_sock = Some(path.to_path_buf());
        Ok(())
    }

    /// [`Self::listen_for_sends`] on [`crate::SEND_SOCK_ENV`], or
    /// [`crate::DEFAULT_SOCK_NAME`] under the store root. Returns the path.
    pub fn listen_for_sends_from_env(&mut self) -> Result<PathBuf, ShellError> {
        let root = self.store_root.clone().ok_or(ShellError::StoreRoot)?;
        let path = crate::send_sock_path(
            |key| std::env::var(key).ok().filter(|value| !value.is_empty()),
            &root,
        );
        self.listen_for_sends(&path)?;
        Ok(path)
    }

    /// Sends `text` from session `as_nick` to `to` in their encrypted DM,
    /// driving until `to` has joined (up to `wait`). The direct path of
    /// `m4a-send` when no client is running.
    pub fn send_blocking(
        &mut self,
        as_nick: &str,
        to: &str,
        text: &str,
        wait: std::time::Duration,
    ) -> crate::SendReply {
        let started = std::time::Instant::now();
        let mut room = None;
        let mut peer = None;
        loop {
            let now = now_ms();
            match self.try_send(as_nick, to, text, now, &mut room, &mut peer) {
                Some(reply) => return reply,
                None if started.elapsed() >= wait => {
                    return crate::SendReply {
                        room,
                        ..crate::SendReply::failed(format!("{to} has not joined the DM yet"))
                    }
                }
                None => {
                    if let Ok(store) = self.session_mut(as_nick) {
                        let _ = store.drive(now, false);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        }
    }

    /// One attempt. `None` means the DM exists but `to` has not joined yet.
    fn try_send(
        &mut self,
        as_nick: &str,
        to: &str,
        text: &str,
        now_ms: i64,
        room: &mut Option<String>,
        peer: &mut Option<String>,
    ) -> Option<crate::SendReply> {
        let store = match self.session_mut(as_nick) {
            Ok(store) => store,
            Err(_) => {
                return Some(crate::SendReply::failed(format!(
                    "{as_nick} is not a session on this client"
                )))
            }
        };
        if peer.is_none() {
            // Local peers first, then the homeserver user directory
            // (find_nick); the directory answer may need another drive.
            let mut last_err = None;
            for attempt in 0..3 {
                if attempt > 0 {
                    let _ = store.drive(now_ms, false);
                }
                match store.find_nick(to, now_ms) {
                    Ok(found) => {
                        *peer = Some(found.user_id);
                        last_err = None;
                        break;
                    }
                    Err(err) => last_err = Some(err),
                }
            }
            if let Some(err) = last_err {
                return Some(crate::SendReply::failed(format!("find {to}: {err}")));
            }
        }
        if room.is_none() {
            match store.ensure_dm(to, now_ms) {
                Ok(room_id) => *room = Some(room_id),
                Err(err) => return Some(crate::SendReply::failed(format!("open DM: {err}"))),
            }
        }
        let (room_id, peer_id) = (room.clone()?, peer.clone()?);
        if !store.member_joined(&room_id, &peer_id) {
            return None;
        }
        match store.write_to_nick(to, text, now_ms) {
            Ok(room_id) => {
                let event_id = store
                    .texts()
                    .into_iter()
                    .rev()
                    .find(|row| row.room_id == room_id && row.body == text)
                    .and_then(|row| row.event_id);
                Some(crate::SendReply {
                    ok: true,
                    room: Some(room_id),
                    event_id,
                    error: None,
                })
            }
            Err(err) => Some(crate::SendReply {
                room: Some(room_id),
                ..crate::SendReply::failed(format!("send: {err}"))
            }),
        }
    }

    fn serve_sends(&mut self, now_ms: i64, report: &mut TickReport) {
        let mut cmds: Vec<(crate::ipc::SendStream, crate::CmdRequest)> = Vec::new();
        if let Some(listener) = &self.send_listener {
            loop {
                match listener.accept() {
                    Ok(mut stream) => match crate::send::read_incoming(&mut stream) {
                        Ok(crate::send::Incoming::Send(request)) => self.send_queue.push(PendingSend {
                            stream,
                            request,
                            started: std::time::Instant::now(),
                            room: None,
                            peer: None,
                        }),
                        Ok(crate::send::Incoming::Cmd(cmd)) => cmds.push((stream, cmd)),
                        Err(err) => {
                            crate::send::write_reply(&mut stream, &crate::SendReply::failed(err))
                        }
                    },
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        for (mut stream, cmd) in cmds {
            let reply = match self.sessions.iter_mut().find(|store| {
                store.nick().is_some_and(|n| n.eq_ignore_ascii_case(cmd.as_nick.trim()))
            }) {
                Some(store) => store.run_command(&cmd, now_ms),
                None => crate::CmdReply::failed(format!("{} is not a session on this client", cmd.as_nick)),
            };
            crate::send::write_cmd_reply(&mut stream, &reply);
        }
        let queue = std::mem::take(&mut self.send_queue);
        for mut pending in queue {
            let (as_nick, to, text) = (
                pending.request.as_nick.clone(),
                pending.request.to.clone(),
                pending.request.text.clone(),
            );
            let outcome = self.try_send(
                &as_nick,
                &to,
                &text,
                now_ms,
                &mut pending.room,
                &mut pending.peer,
            );
            let reply = match outcome {
                Some(reply) => reply,
                None if pending.started.elapsed().as_secs() >= SEND_JOIN_WAIT_SECS => {
                    crate::SendReply {
                        room: pending.room.clone(),
                        ..crate::SendReply::failed(format!("{to} has not joined the DM yet"))
                    }
                }
                None => {
                    self.send_queue.push(pending);
                    continue;
                }
            };
            crate::send::write_reply(&mut pending.stream, &reply);
            report.sent.push((as_nick, to, reply));
        }
    }

    /// Every routine POST attempted by every session, as (nick, attempt).
    /// Event ids and HTTP statuses only.
    pub fn wake_log(&self) -> Vec<(String, crate::WakeAttempt)> {
        self.sessions
            .iter()
            .flat_map(|store| {
                let nick = store.nick().unwrap_or("").to_string();
                store
                    .wake_log()
                    .iter()
                    .cloned()
                    .map(move |attempt| (nick.clone(), attempt))
            })
            .collect()
    }

    /// Whether `name_or_nick` is a session this client holds.
    pub fn holds(&self, name_or_nick: &str) -> bool {
        let Ok(needle) = crate::nick::lookup_nick(name_or_nick) else {
            return false;
        };
        self.sessions.iter().any(|store| {
            store
                .nick()
                .is_some_and(|nick| nick.eq_ignore_ascii_case(&needle))
        })
    }
}

fn server_name_of(mxid: &str) -> Result<&str, ShellError> {
    mxid.split_once(':')
        .map(|(_, server)| server)
        .filter(|server| !server.is_empty())
        .ok_or_else(|| ShellError::Register("user id has no server".to_string()))
}


/// A web session without a webhook routine, on a detected vendor host
/// (Claude web container, Codex cloud, Cursor cloud): install the
/// provider wake chain (hooks in the open session first, last-resort
/// spawn only when headless). Nothing changes on the Grok Bot box or for
/// a session that has a routine.
fn attach_detected_chain(store: &mut OpenedStore, config: &SessionConfig, nick: &str) {
    if let Some((session, chain)) = crate::provider::chain::detected_web_chain(
        config.session_id(),
        nick,
        &config.store_root,
    ) {
        store.set_wake_chain(session, chain);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rescan_opens_only_bots_without_a_session() {
        let root = Path::new("/tmp/m4a-rescan-test");
        let agent = |name: &str, id: &str| {
            let mut session = HostSession::new(name, id);
            session.agent_id = Some(id.to_string());
            session
        };
        let found = vec![
            agent("alice", "a-hatch"),
            agent("m4a-proba2", "a-proba2"),
            agent("skipme", "a-skip"),
            agent("aliased", "a-alias"),
        ];
        let held = vec![
            (crate::session_store_dir(root, "a-hatch"), Some("alice".to_string())),
            (crate::session_store_dir(root, "old-alias"), None),
        ];
        let fresh = unopened_agent_sessions(
            found,
            &["skipme".to_string()],
            &[("a-alias".to_string(), "old-alias".to_string())],
            root,
            &held,
        );
        let nicks: Vec<&str> = fresh.iter().map(|(_, nick)| nick.as_str()).collect();
        assert_eq!(nicks, vec!["m4a-proba2"]);
        assert_eq!(fresh[0].0.session_id, "a-proba2");
    }

    #[test]
    fn session_directory_is_name_and_id_only() {
        let dir = std::env::temp_dir().join(format!(
            "m4a-sessions-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(
            dir.join("alice.json"),
            r#"{"bot_name":"Alice","session_id":"web-alice"}"#,
        )
        .expect("write");
        std::fs::write(
            dir.join("chief.json"),
            "{\"bot_name\":\"Привет мир\",\"session_id\":\"web-chief\"}",
        )
        .expect("write");
        let loaded = load_session_records(&dir).expect("records");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[1].bot_name, "Привет мир");
        assert_eq!(loaded[0].bot_name, "Alice");
        assert!(loaded[1].agent_id.is_none());
        assert!(loaded[0].agent_id.is_none());
        assert!(loaded[1].routine_url.is_none());
        assert!(loaded[1].routine_bearer.is_none());
        assert!(loaded[1].invite.is_none());

        std::fs::write(
            dir.join("leaked.json"),
            r#"{"bot_name":"Courier","session_id":"web-courier","routine_url":"http://127.0.0.1/hook","routine_bearer":"not-a-file"}"#,
        )
        .expect("write");
        let refused = load_session_records(&dir).expect_err("webhook file");
        let text = refused.to_string();
        assert!(!text.contains("not-a-file"));
        assert!(!text.contains("127.0.0.1/hook"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn web_client_does_not_copy_one_routine_onto_every_session_and_node_cli_refuses_it() {
        let dir = std::env::temp_dir().join(format!(
            "m4a-split-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let record = dir.join("alice.json");
        let body = r#"{"bot_name":"Alice","session_id":"web-alice"}"#;
        std::fs::write(&record, body).expect("write");
        let routine = "http://127.0.0.1:9/routine";
        let bearer = "host-injected-bearer";
        let sessions = load_web_sessions(&dir, |key| match key {
            crate::ROUTINE_URL_ENV => Some(routine.to_string()),
            crate::ROUTINE_BEARER_ENV => Some(bearer.to_string()),
            crate::LEADER_SOCK_ENV => Some("/tmp/leader.sock".to_string()),
            _ => None,
        })
        .expect("web sessions");
        assert_eq!(sessions.len(), 1);
        assert!(sessions[0].routine_url.is_none());
        assert!(sessions[0].routine_bearer.is_none());
        assert_eq!(std::fs::read_to_string(&record).expect("reread"), body);
        let wake = crate::SessionWake::web_from_lookup(|key| match key {
            crate::ROUTINE_URL_ENV => Some(routine.to_string()),
            crate::LEADER_SOCK_ENV => Some("/tmp/leader.sock".to_string()),
            _ => None,
        });
        assert!(wake.leader_sock.is_none());
        assert!(wake.leader_cwd.is_none());

        std::fs::write(
            dir.join("leaked.json"),
            r#"{"bot_name":"Courier","session_id":"web-courier","routine_url":"http://127.0.0.1:9/from-file","routine_bearer":"file-bearer"}"#,
        )
        .expect("leak");
        let refused = load_web_sessions(&dir, |_| None).expect_err("json routine");
        let text = refused.to_string();
        assert!(!text.contains("from-file"));
        assert!(!text.contains("file-bearer"));

        let node = crate::OpenedStore::connect_node_from_lookup(
            |key| match key {
                crate::ROUTINE_URL_ENV => Some(routine.to_string()),
                crate::ROUTINE_BEARER_ENV => Some(bearer.to_string()),
                crate::LEADER_SOCK_ENV => Some("/tmp/leader.sock".to_string()),
                _ => None,
            },
            None,
        );
        let err = match node {
            Ok(_) => panic!("node cli accepted a routine url"),
            Err(err) => err,
        };
        assert!(matches!(err, crate::ShellError::NodeRoutine));
        let text = err.to_string();
        assert!(!text.contains(routine));
        assert!(!text.contains(bearer));
        assert!(!text.contains("leader.sock"));

        let node = crate::SessionWake::node_from_lookup(|key| match key {
            crate::LEADER_SOCK_ENV => Some("/tmp/node-leader.sock".to_string()),
            crate::LEADER_CWD_ENV => Some("/tmp/node".to_string()),
            _ => None,
        })
        .expect("node leader");
        assert!(node.routine_url.is_none());
        assert!(node.routine_bearer.is_none());
        assert_eq!(
            node.leader_sock.as_deref(),
            Some(std::path::Path::new("/tmp/node-leader.sock"))
        );
        assert_eq!(node.leader_cwd.as_deref(), Some("/tmp/node"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mirrors_follow_the_nick_folder_and_keys_wait_for_the_bot_routine() {
        use std::collections::HashSet;
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        use std::thread;

        struct Card {
            agent: String,
            id: String,
            name: String,
            trigger: &'static str,
            enabled: bool,
        }
        #[derive(Default)]
        struct Gateway {
            creates: usize,
            deletes: usize,
            cards: Vec<Card>,
            // (agent, folder) pairs whose routine the bot created itself.
            backend: HashSet<(String, String)>,
            // Agents whose next mirror lands in `<folder>-2`.
            clash: HashSet<String>,
            agents_seen: HashSet<String>,
            profiles: Vec<(String, serde_json::Value)>,
        }

        fn read_http(sock: &mut std::net::TcpStream) -> Option<(String, Vec<u8>)> {
            let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 2048];
            loop {
                let n = sock.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    return None;
                }
                buf.extend_from_slice(&tmp[..n]);
                let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&buf[..end]).to_string();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if buf.len() >= end + 4 + length {
                    return Some((headers, buf[end + 4..end + 4 + length].to_vec()));
                }
            }
        }
        fn reply(status: &str, body: &serde_json::Value) -> Vec<u8> {
            let payload = serde_json::to_vec(body).expect("json");
            let mut out = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            )
            .into_bytes();
            out.extend(payload);
            out
        }
        fn cards_of(gate: &Gateway, agent: &str) -> serde_json::Value {
            serde_json::Value::Array(
                gate.cards
                    .iter()
                    .filter(|card| card.agent == agent)
                    .map(|card| {
                        serde_json::json!({
                            "id": card.id,
                            "name": card.name,
                            "trigger": {"type": card.trigger},
                            "isEnabled": card.enabled,
                        })
                    })
                    .collect(),
            )
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let state = Arc::new(Mutex::new(Gateway::default()));
        {
            let mut gate = state.lock().expect("gate");
            gate.backend.insert(("agent-h".into(), "alice".into()));
            gate.clash.insert("agent-x".into());
            gate.cards.push(Card {
                agent: "agent-k".into(),
                id: "cron-bot".into(),
                name: "cron_bot".into(),
                trigger: "cron",
                enabled: true,
            });
        }
        let shared = Arc::clone(&state);
        let token = "gw-test-token";
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        let server = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                let (mut sock, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                let _ = sock.set_nonblocking(false);
                let Some((headers, body)) = read_http(&mut sock) else {
                    continue;
                };
                let lower = headers.to_ascii_lowercase();
                let authorized = lower.contains(&format!("authorization: bearer {token}"));
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let agent = request["id"].as_str().unwrap_or("").to_string();
                let mut gate = shared.lock().expect("gate");
                gate.agents_seen.insert(agent.clone());
                let response = if !authorized {
                    reply("401 Unauthorized", &serde_json::json!({}))
                } else if lower.starts_with("post /api/getagentautomations ") {
                    reply("200 OK", &cards_of(&gate, &agent))
                } else if lower.starts_with("post /api/createagentautomation ") {
                    let spec = &request["spec"];
                    assert_eq!(spec["trigger"]["type"], "webhook");
                    assert_eq!(spec["isEnabled"], false, "mirror must be disabled");
                    let name = spec["name"].as_str().unwrap_or("").to_string();
                    let prompt = spec["prompt"].as_str().unwrap_or("");
                    assert!(!prompt.is_empty());
                    assert!(!prompt.contains("http"));
                    gate.creates += 1;
                    let folder = crate::nick::routine_folder_id(&name).expect("slug");
                    let id = if gate.clash.contains(&agent) {
                        format!("{folder}-2")
                    } else {
                        folder
                    };
                    gate.cards.push(Card {
                        agent: agent.clone(),
                        id,
                        name,
                        trigger: "webhook",
                        enabled: false,
                    });
                    reply("200 OK", &cards_of(&gate, &agent))
                } else if lower.starts_with("post /api/updateagent ") {
                    gate.profiles
                        .push((agent.clone(), request["profile"].clone()));
                    reply("200 OK", &serde_json::json!({"id": agent}))
                } else if lower.starts_with("post /api/deleteagentautomation ") {
                    let id = request["automationId"].as_str().unwrap_or("");
                    gate.deletes += 1;
                    gate.cards
                        .retain(|card| !(card.agent == agent && card.id == id));
                    reply("200 OK", &cards_of(&gate, &agent))
                } else if lower.starts_with("post /api/getautomationwebhookcredential ") {
                    let id = request["automationId"].as_str().unwrap_or("").to_string();
                    let local = gate
                        .cards
                        .iter()
                        .find(|card| card.agent == agent && card.id == id);
                    match local {
                        None => reply(
                            "500 Internal Server Error",
                            &serde_json::json!({"error": format!("Automation not found: {id}")}),
                        ),
                        Some(card) if card.trigger != "webhook" => reply(
                            "500 Internal Server Error",
                            &serde_json::json!({"error": "Automation is not webhook-triggered"}),
                        ),
                        Some(_) => {
                            let minted = gate.backend.contains(&(agent.clone(), id.clone()));
                            reply(
                                "200 OK",
                                &serde_json::json!({
                                    "url": format!("https://backend.invalid/automations/webhook/{agent}-{id}"),
                                    "key": minted.then(|| format!("key-{agent}-{id}")),
                                }),
                            )
                        }
                    }
                } else {
                    reply("404 Not Found", &serde_json::json!({}))
                };
                drop(gate);
                let _ = sock.write_all(&response);
            }
        });

        let dir = std::env::temp_dir().join(format!(
            "m4a-mirror-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let agents = dir.join("agents");
        let store_root = dir.join("stores");
        let describe = |id: &str| {
            if id == "agent-c" {
                "about the chief"
            } else {
                ""
            }
        };
        for (id, name) in [
            ("agent-h", "Alice"),
            ("agent-c", "Привет мир"),
            ("agent-s", "Свой браузер"),
            ("agent-x", "Clash Bot"),
            ("agent-k", "Cron Bot"),
        ] {
            std::fs::create_dir_all(agents.join(id)).expect("agent dir");
            std::fs::write(
                agents.join(id).join("profile.json"),
                serde_json::to_vec(&serde_json::json!({"name": name, "description": describe(id)}))
                    .expect("profile"),
            )
            .expect("profile");
        }
        let gateway = dir.join("gateway-file.json");
        std::fs::write(
            &gateway,
            format!(r#"{{"host":"192.0.2.1","port":{port},"scheme":"http","token":"{token}"}}"#),
        )
        .expect("gateway");
        let skip = parse_skip_nicks(" svoi-brauzer , ");
        assert_eq!(skip, vec!["svoi-brauzer".to_string()]);
        let options = WakeOptions {
            skip_nicks: skip.clone(),
            store_root: Some(store_root.clone()),
            profile_note: false,
            session_ids: Vec::new(),
        };

        let status_of = |reports: &[RoutineReport], agent: &str| {
            reports
                .iter()
                .find(|report| report.agent_id == agent)
                .map(|report| report.status.clone())
        };
        let first =
            ensure_agent_webhook_routines(&agents, &gateway, None, &options).expect("first pass");
        assert_eq!(status_of(&first, "agent-h"), Some(WakeStatus::Ready));
        assert_eq!(
            status_of(&first, "agent-c"),
            Some(WakeStatus::AwaitingBackend)
        );
        assert!(matches!(
            status_of(&first, "agent-x"),
            Some(WakeStatus::Failed(_))
        ));
        assert!(matches!(
            status_of(&first, "agent-k"),
            Some(WakeStatus::Failed(_))
        ));
        assert_eq!(status_of(&first, "agent-s"), None);
        let chief = first
            .iter()
            .find(|r| r.agent_id == "agent-c")
            .expect("chief");
        assert_eq!(chief.nick, "privet-mir");
        assert_eq!(chief.folder_id, "privet-mir");
        let shown = format!("{first:?}");
        assert!(!shown.contains("key-"));
        assert!(!shown.contains("automations/webhook"));
        {
            let gate = state.lock().expect("gate");
            // alice, privet-mir, clash-bot. Not the skipped bot,
            // not the folder that already holds a cron routine.
            assert_eq!(gate.creates, 3);
            assert_eq!(gate.deletes, 1);
            assert!(!gate.agents_seen.contains("agent-s"));
            assert!(gate.cards.iter().all(|card| card.agent != "agent-x"));
            let cron = gate
                .cards
                .iter()
                .find(|card| card.agent == "agent-k")
                .expect("cron");
            assert_eq!(cron.trigger, "cron");
            assert!(cron.enabled);
            let mirror = gate
                .cards
                .iter()
                .find(|card| card.agent == "agent-h")
                .expect("mirror");
            assert_eq!(
                (mirror.id.as_str(), mirror.name.as_str()),
                ("alice", "alice")
            );
            let chief_mirror = gate
                .cards
                .iter()
                .find(|card| card.agent == "agent-c")
                .expect("chief mirror");
            // Nick == routine name == folder id, all with hyphens.
            assert_eq!(chief_mirror.name, "privet-mir");
            assert_eq!(chief_mirror.id, "privet-mir");
            assert!(!mirror.enabled);
        }
        // Keychain: only the ready bot, mode 0600, its folder recorded.
        let alice_file = keychain_path(&store_root, "agent-h");
        let stored: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&alice_file).expect("keychain"))
                .expect("keychain json");
        assert_eq!(stored["folder_id"], "alice");
        assert_eq!(stored["key"], "key-agent-h-alice");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&alice_file)
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(!keychain_path(&store_root, "agent-c").exists());

        // Second pass: nothing new is created; the chief still waits.
        let second =
            ensure_agent_webhook_routines(&agents, &gateway, None, &options).expect("second pass");
        assert_eq!(
            status_of(&second, "agent-c"),
            Some(WakeStatus::AwaitingBackend)
        );
        assert_eq!(
            state.lock().expect("gate").creates,
            4,
            "only the clash bot retries"
        );
        assert!(state.lock().expect("gate").profiles.is_empty());
        // Opt-in bootstrap note: only the waiting bot's profile is edited,
        // name kept, original description kept, note appended.
        let noted = WakeOptions {
            profile_note: true,
            ..options.clone()
        };
        ensure_agent_webhook_routines(&agents, &gateway, None, &noted).expect("note pass");
        {
            let gate = state.lock().expect("gate");
            assert_eq!(gate.profiles.len(), 1);
            let (agent, profile) = &gate.profiles[0];
            assert_eq!(agent, "agent-c");
            assert_eq!(profile["name"], "Привет мир");
            let description = profile["description"].as_str().unwrap_or("");
            assert!(description.starts_with("about the chief"));
            assert!(description.contains("routine named \"privet-mir\""));
            assert!(!description.contains("http"));
        }
        state.lock().expect("gate").creates = 4;
        // The chief creates its own routine; the next pass picks the key up
        // without another mirror.
        state
            .lock()
            .expect("gate")
            .backend
            .insert(("agent-c".into(), "privet-mir".into()));
        let third =
            ensure_agent_webhook_routines(&agents, &gateway, None, &options).expect("third pass");
        assert_eq!(status_of(&third, "agent-c"), Some(WakeStatus::Ready));
        assert_eq!(state.lock().expect("gate").creates, 5);
        assert!(keychain_path(&store_root, "agent-c").exists());

        // The env path: the skipped bot is not a session at all.
        let gateway_path = gateway.display().to_string();
        let root_text = store_root.display().to_string();
        let sessions = load_web_agents(&agents, |key| match key {
            GATEWAY_FILE_ENV => Some(gateway_path.clone()),
            SKIP_NICKS_ENV => Some("svoi-brauzer".to_string()),
            crate::STORE_ROOT_ENV => Some(root_text.clone()),
            _ => None,
        })
        .expect("web agents");
        assert_eq!(sessions.len(), 4);
        let alice = sessions
            .iter()
            .find(|s| s.session_id == "agent-h")
            .expect("h");
        assert!(alice
            .routine_url
            .as_deref()
            .unwrap_or("")
            .starts_with("https://"));
        assert!(alice.routine_bearer.is_some());
        assert!(!format!("{alice:?}").contains("key-"));

        // No gateway file: the keychain answers, but only for the same folder.
        let mut offline = vec![HostSession::new("Alice", "agent-h")];
        offline[0].agent_id = Some("agent-h".to_string());
        let mut renamed = HostSession::new("Alice Two", "agent-h");
        renamed.agent_id = Some("agent-h".to_string());
        offline.push(renamed);
        attach_webhook_routines(
            &mut offline,
            &dir.join("absent.json"),
            None,
            Some(&store_root),
        )
        .expect("offline");
        assert_eq!(
            offline[0].routine_bearer.as_deref(),
            Some("key-agent-h-alice")
        );
        assert!(offline[1].routine_url.is_none());
        let mut bare = vec![HostSession::new("Alice", "agent-h")];
        attach_webhook_routines(&mut bare, &dir.join("absent.json"), None, None).expect("bare");
        assert!(bare[0].routine_url.is_none());

        done.store(true, Ordering::Relaxed);
        let _ = server.join();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wake_note_is_appended_once_and_replaced_in_place() {
        let first = with_wake_note("Runs the alice.", "alice").expect("added");
        assert!(first.starts_with("Runs the alice.\n\n<!-- mail4agent:wake -->"));
        assert!(first.ends_with("<!-- /mail4agent:wake -->"));
        assert!(with_wake_note(&first, "alice").is_none());
        let renamed = with_wake_note(&first, "alice-two").expect("replaced");
        assert_eq!(renamed.matches("<!-- mail4agent:wake -->").count(), 1);
        assert!(renamed.contains("\"alice-two\""));
        assert!(!renamed.contains("\"alice\""));
        assert!(renamed.starts_with("Runs the alice."));
        assert_eq!(with_wake_note("", "carol").expect("empty"), wake_note("carol"));
    }

    #[test]
    fn agents_directory_becomes_sessions_without_hardcoded_ids() {
        let dir = std::env::temp_dir().join(format!(
            "m4a-agents-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let alice = dir.join("agent-alice");
        let chief = dir.join("agent-chief");
        std::fs::create_dir_all(&alice).expect("dir");
        std::fs::create_dir_all(&chief).expect("dir");
        std::fs::write(
            alice.join("profile.json"),
            r#"{"name":"Alice","description":"x"}"#,
        )
        .expect("profile");
        std::fs::write(
            chief.join("profile.json"),
            concat!(
                "{\"name\":\"",
                "Привет мир",
                "\",\"description\":\"x\"}"
            ),
        )
        .expect("profile");
        std::fs::write(dir.join("active-agent.json"), "{}").expect("skip file");
        let loaded = load_agents_dir(&dir).expect("agents");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[1].session_id, "agent-chief");
        assert_eq!(loaded[1].agent_id.as_deref(), Some("agent-chief"));
        assert_eq!(loaded[1].bot_name, "Привет мир");
        assert_eq!(
            routine_name_for(&loaded[1]).as_deref(),
            Some("privet-mir")
        );
        assert_ne!(
            routine_name_for(&loaded[1]).as_deref(),
            Some(loaded[1].session_id.as_str())
        );
        assert_eq!(loaded[0].bot_name, "Alice");
        assert_eq!(routine_name_for(&loaded[0]).as_deref(), Some("alice"));
        assert!(loaded.iter().all(|session| session.routine_url.is_none()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
