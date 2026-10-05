//! Web machine client: one process for every bot session on this machine.
//!
//! This is not the homeserver, and it is not the node CLI
//! ([`crate::OpenedStore::connect_node_from_env`]). Discovery prefers the
//! live agents directory ([`AGENTS_DIR_ENV`], or
//! [`DEFAULT_AGENTS_DIR`] when that folder exists): each child folder is a
//! Grok Bot agent id and `profile.json` carries the display name. The mail
//! session id is that agent id. The host may still pass a list, or this
//! process may read [`SESSIONS_DIR_ENV`] when no agents directory is
//! present. A session record is the bot display name, the mail session id,
//! and the Grok Bot agent id when this session has one. A routine URL or a
//! bearer in the file is refused.
//! [`MachineClient::from_env`] creates one webhook routine per agent,
//! through the local gateway, and keeps the URL and key in memory. It
//! skips a name that already exists (so Hostbot is not minted twice). A
//! record with no agent id does not create a routine. It does not write
//! them back and it does not log them. One URL is not shared across
//! sessions. [`ensure_agent_webhook_routines`] is the same create path
//! without opening sealed stores. [`MachineClient::poll_agent_directory`]
//! rescans the agents directory for bots that appeared after open.
//! [`crate::LEADER_SOCK_ENV`] is not this path. The node CLI does not
//! create a routine.
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

use mail4agent_messenger::{HttpResponseDescriptor, OutgoingRequest, OutgoingRequestKind};
use mail4agent_server::http::{hash_token, router, Homeserver};
use mail4agent_server::store::{self, create_matrix_schema};
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tower::util::ServiceExt;
use zeroize::Zeroizing;

use crate::{
    clip_public, percent_encode, perform_http, register_session, DeviceId, OpenedStore,
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

/// Default agents directory on the box. Used when [`AGENTS_DIR_ENV`] is
/// unset and this path is a directory.
pub const DEFAULT_AGENTS_DIR: &str = "/srv/agent-data/agents";

/// Optional rescan period in seconds for [`MachineClient::poll_agent_directory`].
/// Unset or `0` means the caller decides when to poll; open still scans once.
pub const AGENT_RESCAN_SECS_ENV: &str = "M4A_AGENT_RESCAN_SECS";

/// One bot session the host says lives on this machine.
///
/// `routine_url` and `routine_bearer` are optional and stay in memory.
/// They are not part of a session record on disk.
pub struct HostSession {
    /// Display name the host already shows (`Hostbot`, `Привет мир`).
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
    /// Device bearer from the host keychain, for a session that already
    /// registered. `None` on the first connect.
    pub device_token: Option<String>,
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
            device_token: None,
        }
    }

    /// Attaches a routine target. The bearer is kept only as this value.
    pub fn with_routine(mut self, url: impl Into<String>, bearer: Option<String>) -> Self {
        self.routine_url = Some(url.into());
        self.routine_bearer = bearer.filter(|token| !token.is_empty());
        self
    }

    /// Device bearer the host keychain already holds.
    pub fn with_device_token(mut self, token: impl Into<String>) -> Self {
        self.device_token = Some(token.into());
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
            .field(
                "device_token",
                &self.device_token.as_ref().map(|_| "[redacted]"),
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
    let default = PathBuf::from(DEFAULT_AGENTS_DIR);
    if default.is_dir() {
        Some(default)
    } else {
        None
    }
}

/// Session records plus one webhook routine per session that has an agent id.
///
/// `get` is the process environment on [`MachineClient::from_env`]. A
/// shared [`crate::ROUTINE_URL_ENV`] is not copied onto every session.
/// [`GATEWAY_FILE_ENV`] names the gateway file. When that lookup is empty,
/// this does not look for a gateway, so a test that did not point at one
/// does not create a routine. The json files are not rewritten.
fn load_web_sessions(
    dir: &Path,
    mut get: impl FnMut(&str) -> Option<String>,
) -> Result<Vec<HostSession>, ShellError> {
    let mut sessions = load_session_records(dir)?;
    attach_routines_from_env(&mut sessions, &mut get)?;
    Ok(sessions)
}

/// [`load_agents_dir`] plus one webhook routine per agent.
fn load_web_agents(
    dir: &Path,
    mut get: impl FnMut(&str) -> Option<String>,
) -> Result<Vec<HostSession>, ShellError> {
    let mut sessions = load_agents_dir(dir)?;
    attach_routines_from_env(&mut sessions, &mut get)?;
    Ok(sessions)
}

fn attach_routines_from_env(
    sessions: &mut [HostSession],
    get: &mut impl FnMut(&str) -> Option<String>,
) -> Result<(), ShellError> {
    let Some(path) = get(GATEWAY_FILE_ENV).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let token = get(GATEWAY_TOKEN_ENV).filter(|value| !value.is_empty());
    attach_webhook_routines(sessions, Path::new(&path), token.as_deref())?;
    Ok(())
}

/// Creates webhook routines for every agent under `agents_dir` that does not
/// already have a routine of the intended name. Returns the routine names
/// that exist afterwards (including ones that were already present). Does
/// not open sealed stores, does not register on the homeserver, and does
/// not log URLs or keys.
pub fn ensure_agent_webhook_routines(
    agents_dir: &Path,
    gateway_file: &Path,
    token_override: Option<&str>,
) -> Result<Vec<String>, ShellError> {
    let mut sessions = load_agents_dir(agents_dir)?;
    attach_webhook_routines(&mut sessions, gateway_file, token_override)?;
    // Re-list so a card whose credential mint returned no key still appears.
    let mut names = list_webhook_routine_names(&sessions, gateway_file, token_override)?;
    if names.is_empty() {
        names = sessions
            .iter()
            .filter(|session| session.agent_id.is_some())
            .map(routine_name_for)
            .collect();
    }
    names.sort();
    names.dedup();
    Ok(names)
}

/// [`ensure_agent_webhook_routines`] using the host gateway file and the
/// agents directory from the environment (or [`DEFAULT_AGENTS_DIR`]).
pub fn ensure_agent_webhook_routines_from_env() -> Result<Vec<String>, ShellError> {
    let agents_dir = resolve_agents_dir(|key| std::env::var(key).ok().filter(|v| !v.is_empty()))
        .ok_or_else(|| ShellError::SessionList("agents directory is missing".to_string()))?;
    let gateway = std::env::var(GATEWAY_FILE_ENV)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_GATEWAY_FILE.to_string());
    let token = std::env::var(GATEWAY_TOKEN_ENV)
        .ok()
        .filter(|value| !value.is_empty());
    ensure_agent_webhook_routines(Path::new(&agents_dir), Path::new(&gateway), token.as_deref())
}

/// Gateway file the host already runs. [`GATEWAY_FILE_ENV`] overrides it.
/// The listener is loopback; the `host` field in the file is not used.
const DEFAULT_GATEWAY_FILE: &str = "/srv/agent-data/gateway.json";

/// Path of the gateway file. Unset on [`MachineClient::from_env`] uses
/// [`DEFAULT_GATEWAY_FILE`].
pub const GATEWAY_FILE_ENV: &str = "M4A_GATEWAY_FILE";

/// Gateway bearer. When set, this replaces the token in the gateway file.
/// It is never written to disk.
pub const GATEWAY_TOKEN_ENV: &str = "M4A_GATEWAY_TOKEN";

/// Saved prompt for the webhook routine. The wake body is still the JSON
/// object [`crate::routine_json`] posts. No host name and no key.
const WEBHOOK_ROUTINE_PROMPT: &str = "A mail4agent room message woke this routine. The webhook JSON has body, from, event_id, and nick only when the sender display name is already known. Read that message.";

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
}

#[derive(serde::Deserialize)]
struct WebhookCredential {
    url: String,
    key: Option<String>,
}

/// Folder slug the gateway uses for a new routine name. ASCII letters and
/// digits only, matching the gateway's slug. Empty when `name` has none.
fn automation_slug(name: &str) -> String {
    let mut slug = String::new();
    let mut pending_dash = false;
    for ch in name.to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            if pending_dash && !slug.is_empty() {
                slug.push('-');
            }
            pending_dash = false;
            slug.push(ch);
        } else if !slug.is_empty() {
            pending_dash = true;
        }
    }
    if slug.len() > 48 {
        slug.truncate(48);
    }
    slug
}

/// Routine name for a new card. An ASCII display name is kept as written
/// so an existing card such as `Hostbot` is not minted again. A name with
/// no ASCII slug, including Cyrillic, uses the same transliteration as the
/// nick (`Привет мир` -> `privet_mir`). The session id is only
/// the fallback when that transliteration is empty. This does not rename a
/// card that already exists.
fn routine_name_for(session: &HostSession) -> String {
    if automation_slug(&session.bot_name).is_empty() {
        crate::nick::nick_from_display_name(session.bot_name.trim())
            .unwrap_or_else(|_| session.session_id.clone())
    } else {
        session.bot_name.clone()
    }
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

/// Creates each session's webhook routine, or reads the credential when
/// that name already exists. A missing gateway file leaves the sessions
/// unchanged. The URL and key stay on `sessions` and are not logged.
fn attach_webhook_routines(
    sessions: &mut [HostSession],
    gateway_file: &Path,
    token_override: Option<&str>,
) -> Result<(), ShellError> {
    let Some(gate) = open_gateway(gateway_file, token_override)? else {
        return Ok(());
    };
    for session in sessions.iter_mut() {
        if session.routine_url.is_some() && session.routine_bearer.is_some() {
            continue;
        }
        // createAgentAutomation's id is the Grok Bot agent, not the mail
        // session id. No agent id means no routine, not a call with the
        // wrong id.
        let Some(agent_id) = session.agent_id.clone().filter(|id| !id.is_empty()) else {
            continue;
        };
        let name = routine_name_for(session);
        let slug = automation_slug(&name);
        if slug.is_empty() || session.session_id.is_empty() {
            return Err(ShellError::Gateway(
                "session has no routine name".to_string(),
            ));
        }
        let existing = list_agent_automations(&gate.client, &gate.base, &gate.token, &agent_id)?;
        if let Some(card) = existing.iter().find(|card| card.name == name) {
            // Name already exists: never mint a second card (Hostbot).
            apply_credential(session, &gate, &agent_id, &card.id)?;
            continue;
        }
        match read_webhook_credential(&gate.client, &gate.base, &gate.token, &agent_id, &slug)? {
            CredentialRead::Ready { url, key } => {
                session.routine_url = Some(url);
                session.routine_bearer = Some(key);
                continue;
            }
            CredentialRead::MintFailed => continue,
            CredentialRead::Missing => {}
        }
        let cards = create_webhook_routine(&gate.client, &gate.base, &gate.token, &agent_id, &name)?;
        let Some(card) = pick_created_card(&cards, &name, &slug) else {
            return Err(ShellError::Gateway(
                "gateway create did not return the routine".to_string(),
            ));
        };
        apply_credential(session, &gate, &agent_id, &card.id)?;
    }
    Ok(())
}

fn apply_credential(
    session: &mut HostSession,
    gate: &GatewayConn,
    agent_id: &str,
    automation_id: &str,
) -> Result<(), ShellError> {
    match read_webhook_credential(
        &gate.client,
        &gate.base,
        &gate.token,
        agent_id,
        automation_id,
    )? {
        CredentialRead::Ready { url, key } => {
            session.routine_url = Some(url);
            session.routine_bearer = Some(key);
        }
        CredentialRead::MintFailed | CredentialRead::Missing => {}
    }
    Ok(())
}

fn list_agent_automations(
    client: &reqwest::blocking::Client,
    base: &str,
    token: &str,
    agent_id: &str,
) -> Result<Vec<AutomationCard>, ShellError> {
    let (status, body) = gateway_post(
        client,
        base,
        token,
        "getAgentAutomations",
        &serde_json::json!({ "id": agent_id }),
    )?;
    if status != 200 {
        return Err(ShellError::Gateway(format!(
            "gateway list status {status}"
        )));
    }
    serde_json::from_slice(&body)
        .map_err(|_| ShellError::Gateway("gateway list was not understood".to_string()))
}

fn list_webhook_routine_names(
    sessions: &[HostSession],
    gateway_file: &Path,
    token_override: Option<&str>,
) -> Result<Vec<String>, ShellError> {
    let Some(gate) = open_gateway(gateway_file, token_override)? else {
        return Ok(Vec::new());
    };
    let mut names = Vec::new();
    for session in sessions {
        let Some(agent_id) = session.agent_id.as_deref().filter(|id| !id.is_empty()) else {
            continue;
        };
        let want = routine_name_for(session);
        let cards = list_agent_automations(&gate.client, &gate.base, &gate.token, agent_id)?;
        for card in cards {
            if card.name == want {
                names.push(card.name);
            }
        }
    }
    Ok(names)
}

enum CredentialRead {
    Ready {
        url: String,
        key: String,
    },
    /// The routine exists and the gateway did not return a key.
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
    client: &reqwest::blocking::Client,
    base: &str,
    token: &str,
    method: &str,
    body: &serde_json::Value,
) -> Result<(u16, Vec<u8>), ShellError> {
    let url = format!("{base}/api/{method}");
    let authorization = crate::bearer_header(token).map_err(|_| {
        ShellError::Gateway("gateway token is not a single header value".to_string())
    })?;
    let bytes = serde_json::to_vec(body)
        .map_err(|_| ShellError::Gateway("gateway request was not json".to_string()))?;
    let response = client
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
    client: &reqwest::blocking::Client,
    base: &str,
    token: &str,
    agent_id: &str,
    automation_id: &str,
) -> Result<CredentialRead, ShellError> {
    let (status, body) = gateway_post(
        client,
        base,
        token,
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
/// 500 with its not-found error. Any other failure is not treated as
/// "create another one".
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

fn create_webhook_routine(
    client: &reqwest::blocking::Client,
    base: &str,
    token: &str,
    agent_id: &str,
    name: &str,
) -> Result<Vec<AutomationCard>, ShellError> {
    let (status, body) = gateway_post(
        client,
        base,
        token,
        "createAgentAutomation",
        &serde_json::json!({
            "id": agent_id,
            "spec": {
                "name": name,
                "prompt": WEBHOOK_ROUTINE_PROMPT,
                "trigger": { "type": "webhook" },
                "isEnabled": true,
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

fn pick_created_card<'a>(
    cards: &'a [AutomationCard],
    name: &str,
    slug: &str,
) -> Option<&'a AutomationCard> {
    let matches = cards.iter().filter(|card| card.name == name);
    if let Some(exact) = cards
        .iter()
        .find(|card| card.name == name && card.id == slug)
    {
        return Some(exact);
    }
    matches.max_by(|left, right| slug_rank(&left.id, slug).cmp(&slug_rank(&right.id, slug)))
}

fn slug_rank(id: &str, slug: &str) -> u32 {
    if id == slug {
        return 1;
    }
    let Some(rest) = id
        .strip_prefix(slug)
        .and_then(|rest| rest.strip_prefix('-'))
    else {
        return 0;
    };
    rest.parse::<u32>().unwrap_or(0)
}

struct Prepared {
    config: SessionConfig,
    user_id: String,
    device_id: DeviceId,
    bearer: Zeroizing<String>,
    routine_url: Option<String>,
    routine_bearer: Option<String>,
}

/// The sessions on one machine, and the in-process bus they use when the
/// peer is one of them.
pub struct MachineClient {
    sessions: Vec<OpenedStore>,
    bus: Arc<LocalBus>,
    push: crate::push::PushLink,
    /// When set, [`Self::poll_agent_directory`] rescans this folder for new
    /// bots and creates their webhook routines. Session stores already open
    /// are left alone; a new process picks up new sealed stores.
    agents_dir: Option<PathBuf>,
    gateway_file: Option<PathBuf>,
    gateway_token: Option<String>,
    last_agent_poll: std::time::Instant,
    agent_rescan_secs: u64,
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
        if sessions.is_empty() {
            return Err(ShellError::SessionList("session list is empty".to_string()));
        }
        let mut prepared = Vec::with_capacity(sessions.len());
        let mut seen_ids = Vec::new();
        let mut seen_nicks = Vec::new();
        for session in sessions {
            let config = SessionConfig::new(
                homeserver_url,
                &session.bot_name,
                &session.session_id,
                store_root,
                session.device_token,
            )?;
            if seen_ids.iter().any(|id: &String| id == config.session_id()) {
                return Err(ShellError::SessionList("duplicate session id".to_string()));
            }
            if seen_nicks
                .iter()
                .any(|nick: &String| nick.eq_ignore_ascii_case(config.nick()))
            {
                return Err(ShellError::SessionList("duplicate nick".to_string()));
            }
            seen_ids.push(config.session_id().to_string());
            seen_nicks.push(config.nick().to_string());
            let registered = register_session(&config)?;
            prepared.push(Prepared {
                config,
                user_id: registered.user_id,
                device_id: registered.device_id,
                bearer: registered.bearer,
                routine_url: session.routine_url,
                routine_bearer: session.routine_bearer,
            });
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
            .map(|item| (item.config.nick().to_string(), item.user_id.clone()))
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
                &item.config.homeserver_url,
                item.bearer.as_str(),
            )?;
            store.set_registered_nick(item.config.nick().to_string());
            store.attach_bus(Arc::clone(&bus));
            store.set_local_peers(
                peers
                    .iter()
                    .filter(|(nick, _)| nick != item.config.nick())
                    .cloned()
                    .collect(),
            );
            store.set_wake(SessionWake {
                routine_url: item.routine_url.clone(),
                routine_bearer: item.routine_bearer.clone(),
                leader_sock: None,
                leader_cwd: None,
            });
            store.drive(1_000, false)?;
            store.abandon_inflight_sync(1_000)?;
            opened.push(store);
        }
        let tokens: Vec<String> = prepared
            .iter()
            .map(|item| item.bearer.as_str().to_string())
            .collect();
        let push = crate::push::PushLink::open(&prepared[0].config.homeserver_url, tokens)?;
        Ok(Self {
            sessions: opened,
            bus,
            push,
            agents_dir: None,
            gateway_file: None,
            gateway_token: None,
            last_agent_poll: std::time::Instant::now(),
            agent_rescan_secs: 0,
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
                    .or_else(|| Some(DEFAULT_GATEWAY_FILE.to_string()));
            }
            std::env::var(key).ok().filter(|value| !value.is_empty())
        };
        let agents_dir = resolve_agents_dir(&mut get);
        let (sessions, agents_dir) = if let Some(dir) = agents_dir {
            (load_web_agents(&dir, &mut get)?, Some(dir))
        } else {
            let sessions_dir = get(SESSIONS_DIR_ENV).ok_or_else(|| {
                ShellError::SessionList("session directory is unset".to_string())
            })?;
            (load_web_sessions(Path::new(&sessions_dir), &mut get)?, None)
        };
        let gateway_file = get(GATEWAY_FILE_ENV).map(PathBuf::from);
        let gateway_token = get(GATEWAY_TOKEN_ENV);
        let agent_rescan_secs = get(AGENT_RESCAN_SECS_ENV)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let mut client = Self::open(&homeserver_url, Path::new(&store_root), sessions)?;
        client.agents_dir = agents_dir;
        client.gateway_file = gateway_file;
        client.gateway_token = gateway_token;
        client.agent_rescan_secs = agent_rescan_secs;
        client.last_agent_poll = std::time::Instant::now();
        Ok(client)
    }

    /// Rescans the agents directory when this client was opened from one.
    /// Creates a webhook routine for each new agent that has no card of the
    /// intended name. Does not open a new sealed store for that agent in
    /// this process; the next open picks it up. When
    /// [`AGENT_RESCAN_SECS_ENV`] is set and greater than zero, returns
    /// without scanning until that many seconds have passed since the last
    /// poll. Returns the routine names that exist for agents found on disk.
    pub fn poll_agent_directory(&mut self) -> Result<Vec<String>, ShellError> {
        let Some(agents_dir) = self.agents_dir.as_ref() else {
            return Ok(Vec::new());
        };
        if self.agent_rescan_secs > 0 {
            let elapsed = self.last_agent_poll.elapsed().as_secs();
            if elapsed < self.agent_rescan_secs {
                return Ok(Vec::new());
            }
        }
        self.last_agent_poll = std::time::Instant::now();
        let gateway = self
            .gateway_file
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_GATEWAY_FILE));
        ensure_agent_webhook_routines(
            agents_dir,
            &gateway,
            self.gateway_token.as_deref(),
        )
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

fn localpart_of(mxid: &str) -> Result<&str, ShellError> {
    let rest = mxid
        .strip_prefix('@')
        .ok_or_else(|| ShellError::Register("user id has no sigil".to_string()))?;
    let (local, _) = rest
        .split_once(':')
        .ok_or_else(|| ShellError::Register("user id has no server".to_string()))?;
    if local.is_empty() {
        return Err(ShellError::Register("user id has no localpart".to_string()));
    }
    Ok(local)
}

fn ensure_server_name(name: &str) -> Result<(), ShellError> {
    match store::set_matrix_server_name(name) {
        Ok(()) => Ok(()),
        Err(_) => {
            if store::matrix_server_name() == name {
                Ok(())
            } else {
                Err(ShellError::SessionList(
                    "homeserver name does not match this process".to_string(),
                ))
            }
        }
    }
}

/// In-process Client-Server bus. Not the homeserver. Callers reach it only
/// from the store's existing drive.
pub(crate) struct LocalBus {
    state: Arc<Homeserver>,
    runtime: tokio::runtime::Runtime,
    gate: Mutex<()>,
    local_only: AtomicBool,
    hits: AtomicU64,
    cursors: Mutex<HashMap<String, String>>,
}

impl LocalBus {
    fn open(prepared: &[Prepared]) -> Result<Self, ShellError> {
        let conn = open_keyed_memory()?;
        create_matrix_schema(&conn)
            .map_err(|_| ShellError::Http("local bus schema failed".into()))?;
        mail4agent_server::keys::create_matrix_keys_schema(&conn)
            .map_err(|_| ShellError::Http("local bus keys schema failed".into()))?;
        for (index, item) in prepared.iter().enumerate() {
            seed_session(&conn, (index as i64) + 1, item)?;
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| ShellError::Http("local bus runtime failed".into()))?;
        Ok(Self {
            state: Arc::new(Homeserver::new(conn)),
            runtime,
            gate: Mutex::new(()),
            local_only: AtomicBool::new(false),
            hits: AtomicU64::new(0),
            cursors: Mutex::new(HashMap::new()),
        })
    }

    fn set_local_only(&self, enabled: bool) {
        self.local_only.store(enabled, Ordering::Relaxed);
    }

    pub(crate) fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub(crate) fn local_only(&self) -> bool {
        self.local_only.load(Ordering::Relaxed)
    }

    /// `force_local` freezes the choice made when a `/sync` was spawned.
    /// A poll started for a local exchange must not fall through to the
    /// homeserver if the flag changes before the worker runs.
    pub(crate) fn fulfill(
        &self,
        client: &reqwest::blocking::Client,
        base_url: &reqwest::Url,
        device_token: &str,
        user_id: &str,
        request: &OutgoingRequest,
        force_local: Option<bool>,
    ) -> Result<(HttpResponseDescriptor, bool), ShellError> {
        let local = force_local.unwrap_or_else(|| self.local_only());
        if local {
            let response = self.dispatch_local(device_token, user_id, request, true)?;
            return Ok((response, false));
        }
        if request.kind == OutgoingRequestKind::KeysUpload {
            let mirrored = self.dispatch_local(device_token, user_id, request, false)?;
            if !(200..300).contains(&mirrored.status) {
                return Ok((mirrored, false));
            }
        }
        self.hits.fetch_add(1, Ordering::Relaxed);
        let response = perform_http(client, base_url, device_token, request)?;
        Ok((response, true))
    }

    fn dispatch_local(
        &self,
        device_token: &str,
        user_id: &str,
        request: &OutgoingRequest,
        isolate_sync: bool,
    ) -> Result<HttpResponseDescriptor, ShellError> {
        let remote_since = request
            .query
            .iter()
            .find(|(name, _)| name == "since")
            .map(|(_, value)| value.clone());
        let query = if isolate_sync && request.kind == OutgoingRequestKind::Sync {
            self.local_sync_query(user_id, request)
        } else {
            request.query.clone()
        };
        let uri = local_uri(&request.path, &query)?;
        let method = axum::http::Method::from_bytes(request.method.as_str().as_bytes())
            .map_err(|_| ShellError::Http("unsupported method".into()))?;
        let mut auth = axum::http::HeaderValue::from_str(&format!("Bearer {device_token}"))
            .map_err(|_| ShellError::DeviceToken)?;
        auth.set_sensitive(true);
        let bytes = match &request.body {
            Some(body) => serde_json::to_vec(body)
                .map_err(|err| ShellError::Http(clip_public(err.to_string())))?,
            None => Vec::new(),
        };
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        builder = builder.header(axum::http::header::AUTHORIZATION, auth);
        if request.body.is_some() {
            builder = builder.header(axum::http::header::CONTENT_TYPE, "application/json");
        }
        let http_request = builder
            .body(axum::body::Body::from(bytes))
            .map_err(|_| ShellError::Http("local bus request was refused".into()))?;
        let state = Arc::clone(&self.state);
        let _gate = self.gate.lock().unwrap_or_else(|err| err.into_inner());
        let response = self.runtime.block_on(async move {
            router(state)
                .oneshot(http_request)
                .await
                .map_err(|_| ShellError::Http("local bus dropped the request".into()))
        })?;
        let status = response.status().as_u16();
        let body = self
            .runtime
            .block_on(axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024))
            .map_err(|_| ShellError::Http("local bus body failed".into()))?
            .to_vec();
        drop(_gate);
        let body = if isolate_sync
            && request.kind == OutgoingRequestKind::Sync
            && (200..300).contains(&status)
        {
            self.rewrite_sync_token(user_id, body, remote_since)?
        } else {
            body
        };
        Ok(HttpResponseDescriptor { status, body })
    }

    fn local_sync_query(&self, user_id: &str, request: &OutgoingRequest) -> Vec<(String, String)> {
        let cursor = self
            .cursors
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get(user_id)
            .cloned();
        let mut query = Vec::new();
        let mut saw_timeout = false;
        for (name, value) in &request.query {
            if name == "timeout" {
                query.push((name.clone(), "0".to_string()));
                saw_timeout = true;
            } else if name == "since" {
                if let Some(cursor) = &cursor {
                    query.push((name.clone(), cursor.clone()));
                }
            } else {
                query.push((name.clone(), value.clone()));
            }
        }
        if !saw_timeout {
            query.push(("timeout".to_string(), "0".to_string()));
        }
        query
    }

    fn rewrite_sync_token(
        &self,
        user_id: &str,
        body: Vec<u8>,
        remote_since: Option<String>,
    ) -> Result<Vec<u8>, ShellError> {
        let mut value: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| ShellError::Http("local sync was not json".into()))?;
        if let Some(next) = value.get("next_batch").and_then(|item| item.as_str()) {
            self.cursors
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .insert(user_id.to_string(), next.to_string());
        }
        if let Some(remote_since) = remote_since.filter(|token| !token.is_empty()) {
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "next_batch".to_string(),
                    serde_json::Value::String(remote_since),
                );
            }
        }
        serde_json::to_vec(&value).map_err(|err| ShellError::Http(clip_public(err.to_string())))
    }
}

fn local_uri(path: &str, query: &[(String, String)]) -> Result<String, ShellError> {
    let path = path.strip_prefix("/_matrix").unwrap_or(path);
    if !path.starts_with('/') {
        return Err(ShellError::BaseUrl);
    }
    let mut raw = path.to_string();
    if !query.is_empty() {
        raw.push('?');
        for (index, (name, value)) in query.iter().enumerate() {
            if index > 0 {
                raw.push('&');
            }
            raw.push_str(&percent_encode(name));
            raw.push('=');
            raw.push_str(&percent_encode(value));
        }
    }
    Ok(raw)
}

fn open_keyed_memory() -> Result<Connection, ShellError> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|err| ShellError::Io(err))?;
    let hex = Zeroizing::new(crate::hex_encode(&bytes));
    zeroize::Zeroize::zeroize(&mut bytes);
    let conn = Connection::open_in_memory()
        .map_err(|_| ShellError::Http("local bus database failed".into()))?;
    let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex.as_str()));
    conn.execute_batch(pragma.as_str())
        .map_err(|_| ShellError::Http("local bus could not be keyed".into()))?;
    Ok(conn)
}

fn seed_session(conn: &Connection, user_id: i64, item: &Prepared) -> Result<(), ShellError> {
    let localpart = localpart_of(&item.user_id)?;
    let now = "2026-10-05T00:00:00+00:00";
    let mxid = store::ensure_matrix_user(conn, user_id, localpart, now)
        .map_err(|_| ShellError::Http("local bus could not seed a user".into()))?;
    if mxid != item.user_id {
        return Err(ShellError::SessionList(
            "local bus user id did not match the homeserver".to_string(),
        ));
    }
    let hash = hash_token(item.bearer.as_str());
    conn.execute(
        "INSERT INTO devices (user_id, device_id, credential_kind, credential_ref, display_name, created_at, last_seen_at)
         VALUES (?1, ?2, 'bearer', ?3, NULL, ?4, ?4)",
        params![user_id, item.device_id.as_str(), hash, now],
    )
    .map_err(|_| ShellError::Http("local bus could not seed a device".into()))?;
    conn.execute(
        "INSERT INTO messenger_sessions (session_id, user_id, device_id, nick) VALUES (?1, ?2, ?3, ?4)",
        params![
            item.config.session_id(),
            user_id,
            item.device_id.as_str(),
            item.config.nick()
        ],
    )
    .map_err(|_| ShellError::Http("local bus could not seed a session".into()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_directory_is_name_and_id_only() {
        let dir = std::env::temp_dir().join(format!(
            "m4a-sessions-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(
            dir.join("hostbot.json"),
            r#"{"bot_name":"Hostbot","session_id":"web-hostbot"}"#,
        )
        .expect("write");
        std::fs::write(
            dir.join("chief.json"),
            "{\"bot_name\":\"Привет мир\",\"session_id\":\"web-chief\"}",
        )
        .expect("write");
        let loaded = load_session_records(&dir).expect("records");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].bot_name, "Привет мир");
        assert_eq!(loaded[1].bot_name, "Hostbot");
        assert!(loaded[0].agent_id.is_none());
        assert!(loaded[1].agent_id.is_none());
        assert!(loaded[0].routine_url.is_none());
        assert!(loaded[0].routine_bearer.is_none());
        assert!(loaded[0].device_token.is_none());

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
                .as_millis()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let record = dir.join("hostbot.json");
        let body = r#"{"bot_name":"Hostbot","session_id":"web-hostbot"}"#;
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
    fn two_sessions_get_two_webhook_routines_and_a_second_open_does_not_mint() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        use std::thread;

        struct Card {
            agent: String,
            id: String,
            name: String,
            key: Option<String>,
        }
        struct Gateway {
            creates: usize,
            cards: Vec<Card>,
        }

        fn read_http(sock: &mut std::net::TcpStream) -> Option<(String, Vec<u8>)> {
            let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 2048];
            loop {
                let n = sock.read(&mut tmp).unwrap_or(0);
                if n == 0 && buf.is_empty() {
                    return None;
                }
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                let header_end = buf.windows(4).position(|window| window == b"\r\n\r\n")?;
                let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let length = headers.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })?;
                if buf.len() >= header_end + 4 + length {
                    let body = buf[header_end + 4..header_end + 4 + length].to_vec();
                    return Some((headers, body));
                }
            }
            None
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let state = Arc::new(Mutex::new(Gateway {
            creates: 0,
            cards: Vec::new(),
        }));
        let recorded = Arc::clone(&state);
        let token = "gw-test-token";
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        let server = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut sock, _)) => {
                        let _ = sock.set_nonblocking(false);
                        let Some((headers, body)) = read_http(&mut sock) else {
                            continue;
                        };
                        let lower = headers.to_ascii_lowercase();
                        assert!(
                            !lower.contains("x-automation-key"),
                            "gateway call must not send the routine key"
                        );
                        let authorized = headers.lines().any(|line| {
                            line.eq_ignore_ascii_case(&format!("authorization: Bearer {token}"))
                                || line == format!("Authorization: Bearer {token}")
                        });
                        let response = if !authorized {
                            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
                        } else if lower.starts_with("post /api/getagentautomations ") {
                            let request: serde_json::Value =
                                serde_json::from_slice(&body).expect("list json");
                            let agent = request["id"].as_str().unwrap_or("");
                            let gate = recorded.lock().expect("gate");
                            let list: Vec<serde_json::Value> = gate
                                .cards
                                .iter()
                                .filter(|card| card.agent == agent)
                                .map(|card| serde_json::json!({"id": card.id, "name": card.name}))
                                .collect();
                            drop(gate);
                            let payload = serde_json::to_vec(&list).expect("list");
                            let mut out = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    )
                    .into_bytes();
                            out.extend(payload);
                            out
                        } else if lower.starts_with("post /api/createagentautomation ") {
                            let request: serde_json::Value =
                                serde_json::from_slice(&body).expect("create json");
                            let agent = request["id"].as_str().unwrap_or("").to_string();
                            let name = request["spec"]["name"].as_str().unwrap_or("").to_string();
                            let trigger = request["spec"]["trigger"]["type"].as_str().unwrap_or("");
                            assert_eq!(trigger, "webhook");
                            assert!(request["spec"]["isEnabled"].as_bool().unwrap_or(false));
                            assert!(!request["spec"]["prompt"].as_str().unwrap_or("").is_empty());
                            let mut gate = recorded.lock().expect("gate");
                            gate.creates += 1;
                            let slug = automation_slug(&name);
                            let taken = gate
                                .cards
                                .iter()
                                .any(|card| card.agent == agent && card.id == slug);
                            let id = if taken { format!("{slug}-2") } else { slug };
                            let key = if name == "web-null" {
                                None
                            } else {
                                Some(format!("k-{id}"))
                            };
                            gate.cards.push(Card {
                                agent: agent.clone(),
                                id: id.clone(),
                                name: name.clone(),
                                key,
                            });
                            let list: Vec<serde_json::Value> = gate
                                .cards
                                .iter()
                                .filter(|card| card.agent == agent)
                                .map(|card| serde_json::json!({"id": card.id, "name": card.name}))
                                .collect();
                            drop(gate);
                            let payload = serde_json::to_vec(&list).expect("list");
                            let mut out = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    )
                    .into_bytes();
                            out.extend(payload);
                            out
                        } else if lower.starts_with("post /api/getautomationwebhookcredential ") {
                            let request: serde_json::Value =
                                serde_json::from_slice(&body).expect("cred json");
                            let agent = request["id"].as_str().unwrap_or("");
                            let automation = request["automationId"].as_str().unwrap_or("");
                            let gate = recorded.lock().expect("gate");
                            let found = gate
                                .cards
                                .iter()
                                .find(|card| card.agent == agent && card.id == automation);
                            let out = if let Some(card) = found {
                                let payload = serde_json::to_vec(&serde_json::json!({
                            "url": format!("https://127.0.0.1/automations/webhook/{}/{}", card.agent, card.id),
                            "key": card.key,
                        }))
                        .expect("cred");
                                let mut bytes = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            payload.len()
                        )
                        .into_bytes();
                                bytes.extend(payload);
                                bytes
                            } else {
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
                            };
                            out
                        } else {
                            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
                        };
                        let _ = sock.write_all(&response);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        let dir = std::env::temp_dir().join(format!(
            "m4a-gw-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis()
        ));
        let sessions = dir.join("sessions");
        std::fs::create_dir_all(&sessions).expect("dir");
        let hostbot =
            r#"{"bot_name":"Hostbot","session_id":"web-hostbot","agent_id":"agent-hostbot"}"#;
        let chief = "{\"bot_name\":\"Привет мир\",\"session_id\":\"web-chief\",\"agent_id\":\"agent-chief\"}";
        let null_bot = r#"{"bot_name":"web-null","session_id":"web-null","agent_id":"agent-null"}"#;
        let skip = r#"{"bot_name":"Skipper","session_id":"web-skip"}"#;
        std::fs::write(sessions.join("hostbot.json"), hostbot).expect("hostbot");
        std::fs::write(sessions.join("chief.json"), chief).expect("chief");
        std::fs::write(sessions.join("null.json"), null_bot).expect("null");
        std::fs::write(sessions.join("skip.json"), skip).expect("skip");
        let gateway = dir.join("gateway-file.json");
        std::fs::write(
            &gateway,
            format!(
                r#"{{"host":"192.0.2.1","port":{port},"scheme":"http","token":"{token}","pid":1}}"#
            ),
        )
        .expect("gateway");
        let gateway_path = gateway.display().to_string();
        let load = |sessions: &std::path::Path| {
            load_web_sessions(sessions, |key| match key {
                GATEWAY_FILE_ENV => Some(gateway_path.clone()),
                _ => None,
            })
        };
        let first = load(&sessions).expect("first open");
        assert_eq!(first.len(), 4);
        let hostbot_session = first
            .iter()
            .find(|session| session.session_id == "web-hostbot")
            .expect("hostbot");
        let chief_session = first
            .iter()
            .find(|session| session.session_id == "web-chief")
            .expect("chief");
        let null_session = first
            .iter()
            .find(|session| session.session_id == "web-null")
            .expect("null");
        let skip_session = first
            .iter()
            .find(|session| session.session_id == "web-skip")
            .expect("skip");
        assert_eq!(hostbot_session.agent_id.as_deref(), Some("agent-hostbot"));
        assert_eq!(chief_session.agent_id.as_deref(), Some("agent-chief"));
        assert_ne!(
            hostbot_session.agent_id.as_deref(),
            Some(hostbot_session.session_id.as_str())
        );
        assert_ne!(
            hostbot_session.routine_url.as_deref(),
            chief_session.routine_url.as_deref()
        );
        assert!(hostbot_session
            .routine_url
            .as_deref()
            .unwrap_or("")
            .starts_with("https://"));
        assert!(chief_session
            .routine_url
            .as_deref()
            .unwrap_or("")
            .starts_with("https://"));
        assert!(hostbot_session.routine_bearer.is_some());
        assert!(chief_session.routine_bearer.is_some());
        assert_ne!(
            hostbot_session.routine_bearer.as_deref(),
            chief_session.routine_bearer.as_deref()
        );
        assert!(null_session.routine_url.is_none());
        assert!(null_session.routine_bearer.is_none());
        assert!(skip_session.agent_id.is_none());
        assert!(skip_session.routine_url.is_none());
        assert!(skip_session.routine_bearer.is_none());
        let shown = format!("{hostbot_session:?} {chief_session:?}");
        assert!(!shown.contains("k-"));
        assert!(!shown.contains("automations/webhook"));
        assert!(!shown.contains(token));
        assert_eq!(
            std::fs::read_to_string(sessions.join("hostbot.json")).expect("reread"),
            hostbot
        );
        assert_eq!(
            std::fs::read_to_string(sessions.join("chief.json")).expect("reread"),
            chief
        );
        let gate = state.lock().expect("state");
        let creates_after_first = gate.creates;
        assert_eq!(creates_after_first, 3);
        let agents: Vec<&str> = gate.cards.iter().map(|card| card.agent.as_str()).collect();
        assert!(agents.contains(&"agent-hostbot"));
        assert!(agents.contains(&"agent-chief"));
        assert!(agents.contains(&"agent-null"));
        assert!(!agents.iter().any(|agent| {
            *agent == "web-hostbot"
                || *agent == "web-chief"
                || *agent == "web-null"
                || *agent == "web-skip"
        }));
        drop(gate);
        let second = load(&sessions).expect("second open");
        assert_eq!(state.lock().expect("state").creates, creates_after_first);
        let again = second
            .iter()
            .find(|session| session.session_id == "web-hostbot")
            .expect("again");
        assert_eq!(again.routine_url, hostbot_session.routine_url);
        assert_eq!(again.routine_bearer, hostbot_session.routine_bearer);
        let missing = dir.join("absent.json");
        let mut bare = vec![HostSession::new("Hostbot", "web-hostbot")];
        attach_webhook_routines(&mut bare, &missing, None).expect("absent file");
        assert!(bare[0].routine_url.is_none());
        assert!(bare[0].routine_bearer.is_none());
        done.store(true, Ordering::Relaxed);
        let _ = server.join();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn agents_directory_becomes_sessions_without_hardcoded_ids() {
        let dir = std::env::temp_dir().join(format!(
            "m4a-agents-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis()
        ));
        let hostbot = dir.join("agent-hostbot");
        let chief = dir.join("agent-chief");
        std::fs::create_dir_all(&hostbot).expect("dir");
        std::fs::create_dir_all(&chief).expect("dir");
        std::fs::write(
            hostbot.join("profile.json"),
            r#"{"name":"Hostbot","description":"x"}"#,
        )
        .expect("profile");
        std::fs::write(
            chief.join("profile.json"),
            concat!("{\"name\":\"", "Привет мир", "\",\"description\":\"x\"}"),
        )
        .expect("profile");
        std::fs::write(dir.join("active-agent.json"), "{}").expect("skip file");
        let loaded = load_agents_dir(&dir).expect("agents");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].session_id, "agent-chief");
        assert_eq!(loaded[0].agent_id.as_deref(), Some("agent-chief"));
        assert_eq!(loaded[0].bot_name, "Привет мир");
        assert_eq!(routine_name_for(&loaded[0]), "privet_mir");
        assert_ne!(routine_name_for(&loaded[0]), loaded[0].session_id);
        assert_eq!(loaded[1].bot_name, "Hostbot");
        assert_eq!(routine_name_for(&loaded[1]), "Hostbot");
        assert!(loaded.iter().all(|session| session.routine_url.is_none()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
