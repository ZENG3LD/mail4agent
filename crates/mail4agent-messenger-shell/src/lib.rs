//! Client shell of the messenger: the store key (random, in the client vault), the one web-bot wake,
//! and the HTTP a released [`OutgoingRequest`] actually performs.
//!
//! (Historical: the store key was SHA-256 of the session id string; it is now random and lives in the vault, see `store_key`.) `store_seal_key` is that old derivation. The client derives
//! it when it opens the store. It is not a passphrase, it is not stored
//! beside the records, and nothing here is a KDF or a vault.
//!
//! The private Olm account stays in this store. `MessengerCore::open_sealed`
//! calls `OlmAccountState::load_or_create` and pickles it under the seal.
//! Clients exchange only public keys with the server, through the existing
//! keys upload and keys query paths.
//!
//! Outbound mail to other agents is `MessengerCommand::SendMessage` and
//! `/sync`, not `POST /mail/send` and not `POST /admin/listener`.
//!
//! Inbound wake is not a second mailbox. After the engine has a readable
//! room text from someone else, this shell posts a small JSON object to
//! one routine URL through [`post_decrypted`], or pushes the same text on
//! the leader socket. The plaintext stays in `body`. `from` is the sender
//! mxid, `event_id` is the Matrix event id, and `nick` is the sender's
//! display name only when this shell already has one. Which of those two
//! triggers is armed depends on the open path, not on a file. Missing the
//! one this path uses skips that trigger. It does not drop the message
//! and it is not an error. Routine replay skips texts already loaded.
//! A leader prompt skips keys already listed in `leader-prompted`. When
//! that file records nothing, joined rooms with an empty timeline are
//! paged once from the stored sync token, and only the newest inbound
//! text in each room is prompted.
//!
//! The session bearer stays in memory on [`OpenedStore`]. It comes from the client's own
//! key-signature login (the identity lives in the vault; see `m4a-agent`), is sent as
//! `Authorization: Bearer` and is never written next to the sealed records. No password, token or
//! device bearer is ever read from the environment or handed in by a host.
//! Paths the engine builds under `/_matrix` are sent without that prefix:
//! `mail4agent-server-bin` mounts the Client-Server router at `/client/v3`.
//!
//! Two open paths, one shell. This is not a second product.
//!
//! The web machine client is [`MachineClient::from_env`]. One process
//! uses the agents directory only when [`AGENTS_DIR_ENV`] names one:
//! each folder is an agent id (also the mail session id) and
//! `profile.json` has the display name. The home Grok Bot directory is
//! not opened by default. Otherwise it reads [`SESSIONS_DIR_ENV`]. The nick is
//! [`nick_from_display_name`] of that display name. Mail between sessions
//! this client holds is in process
//! ([`MachineClient::set_local_delivery`]). A peer that is not in the list
//! uses the homeserver. Wake is the bot's own webhook routine, named by
//! its nick, which only the bot can create (`UpdateRoutine`). This process
//! keeps a disabled local mirror in the same folder so the gateway hands
//! out that routine's URL and key; a null key is retried, never replaced
//! by a second routine. [`ensure_agent_webhook_routines`] does that without
//! opening stores. [`MachineClient::poll_agent_directory`] retries and
//! rescans for new bots. The URL and key live in memory and in the
//! session's keychain file under the store root, and are not logged. This
//! path does not read [`LEADER_SOCK_ENV`].
//!
//! A node is [`OpenedStore::connect_node_from_env`]. One CLI session, woken
//! by ACP on [`LEADER_SOCK_ENV`]. A routine URL or bearer in the environment
//! is refused before register. This path does not gain a webhook config.
//! [`OpenedStore::connect`] still registers one session a caller already
//! built; it is not either of those open paths and it does not read a wake
//! from the environment.

pub mod cli;
mod cmd;
#[cfg(feature = "wake-grok")]
mod grok_listen;
mod ipc;
mod machine;
#[cfg(feature = "local-bus")]
mod local_bus;
#[cfg(not(feature = "local-bus"))]
#[path = "local_bus_off.rs"]
mod local_bus;
mod nick;
mod webhook;
#[cfg(feature = "wake-grok")]
mod node;
pub mod provider;
mod bus_backend;
pub mod resolve;
mod send;
pub mod store_key;

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mail4agent_messenger::store::sealed::SealedRecordCodec;
use mail4agent_messenger::wire::Membership;
use mail4agent_messenger::{
    CoreConfig, CoreSecrets, ItemContent, Jitter, MessengerCore,
    MessengerError, OutgoingRequest, OutgoingRequestKind, RecordKey, SealedRecord, SendState,
    StoreError,
};
use sha2::{Digest, Sha256};
use m4a_agent::engine::Driver;
use m4a_agent::{AgentError, Backend};
use zeroize::Zeroizing;

pub use machine::{
    ensure_agent_webhook_routines, ensure_agent_webhook_routines_from_env, load_agents_dir,
    load_session_records, HostSession, MachineClient, RoutineReport, TickReport, WakeOptions,
    WakeStatus, AGENTS_DIR_ENV, AGENT_RESCAN_SECS_ENV, DEFAULT_AGENTS_DIR,
    PROFILE_NOTE_ENV, SESSIONS_DIR_ENV, SESSION_IDS_ENV, SKIP_NICKS_ENV, STORE_LOCK_FILE,
    WAKE_KEYCHAIN_FILE,
};
pub use mail4agent_messenger::{
    CreateRoomKind, DeviceId, MessageKind, MessengerCommand, OutgoingMessage, RoomId, RoomKind,
    UserId,
};
pub use cmd::{CmdReply, CmdRequest};
pub use mail4agent_messenger::EventId;
#[cfg(feature = "wake-grok")]
pub use grok_listen::{hear, GrokListener, Heard, ListenReport};
pub use nick::{nick_from_display_name, routine_folder_id};
#[cfg(feature = "wake-grok")]
pub use node::{NodeClient, NodeTickReport, NODE_DEFAULT_SOCK_NAME};
pub use provider::{
    plan_chain, HostEnv, HookFlavor, ResumeSpawnAdapter, SessionRecord, WakeChain, WebVendor,
    adapter_for, wake_prompt, AdapterConfig, ClaudeChannelAdapter, ClaudeRoutineFireAdapter,
    CodexAppServerAdapter, CodexCloudAdapter, CodexEndpoint, CursorAgentAdapter, GrokLeaderAdapter,
    KimiServerAdapter, NoInboundAdapter, ProviderKind, ProviderSession, RoutineWebhookAdapter,
    SessionKind, Surface, WakeAdapter, WakeError, WakeLetter, WakeOutcome, INBOX_DIR_ENV,
    PROVIDER_ENV,
};
pub use m4a_agent::engine::PushedRoomEvent;
pub use send::{
    load_env_file, load_env_file_named, send_cmd_via_socket, send_sock_path, send_sock_path_named,
    send_via_socket,
    SendReply, SendRequest, DEFAULT_SOCK_NAME, ENV_FILE_ENV, MAX_SEND_BYTES, SEND_SOCK_ENV,
};

/// SHA-256 of `session_id`'s UTF-8 bytes. That digest is the check that this
/// session may open the store. The bytes are not written to disk.
pub fn store_seal_key(session_id: &str) -> [u8; 32] {
    let digest = Sha256::digest(session_id.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// Shared store root on this machine. The caller supplies it. Unset is not
/// a shared fallback outside tests.
pub const STORE_ROOT_ENV: &str = "M4A_STORE_ROOT";

/// Homeserver origin for a Grok Bot web session, for example
/// `http://127.0.0.1:8741`. Wins over [`CONFIG_ENV`] / `mail4agent.toml`.
/// There is no built-in host.
pub const HOMESERVER_URL_ENV: &str = "M4A_HOMESERVER_URL";

/// Optional path of a toml file whose `homeserver_url` is used when
/// [`HOMESERVER_URL_ENV`] is unset. Unset looks at `./mail4agent.toml` and
/// ignores it when that file is absent.
pub const CONFIG_ENV: &str = "M4A_CONFIG";

/// Display name of this Grok Bot web session, the name the host already
/// shows. The nick is derived from it. This is not a nick slug.
pub const BOT_NAME_ENV: &str = "M4A_BOT_NAME";

/// Session id the web host already assigned. The store directory is
/// [`session_store_dir`] of this id. The same id reopens the same store.
pub const SESSION_ID_ENV: &str = "M4A_SESSION_ID";

/// Product-session mode: base URL of the product server. Every Client-Server
/// call goes through its proxy with the product session token as bearer.
pub const PRODUCT_URL_ENV: &str = "M4A_PRODUCT_URL";
/// Identity mode: the operator's one-time invite code (read by the CLIENT process, once; the agent
/// is never given it). Not needed after the identity is enrolled.
pub const PRODUCT_INVITE_ENV: &str = "M4A_PRODUCT_INVITE";
/// Identity mode: `server` (our product API, default) or `matrix` (the Matrix client API).
pub const TIER_ENV: &str = "M4A_TIER";
/// Identity mode: the client owns an ed25519 identity and logs in by signature. There is no
/// password and no token the agent could be handed; `invite` is the operator's one-time code,
/// needed only until the identity is enrolled.
#[derive(Clone)]
#[cfg_attr(not(any(feature = "tier-server", feature = "tier-matrix")), allow(dead_code))]
struct IdentityAuth {
    tier: m4a_agent::BackendKind,
    invite: Option<Zeroizing<String>>,
    /// The nick to ask for at the first enrollment: the session name as a nick.
    nick_request: Option<String>,
}

/// Directory for `session_id` under `root`.
///
/// The final component is the lowercase hex of [`store_seal_key`]. Different
/// session ids get different directories. The same id gets the same directory
/// again. The component is only hex, so it cannot leave `root`. Callers stop
/// pointing two processes at one path by hand. The device bearer is not an
/// input and is not written into the directory.
pub fn session_store_dir(root: &Path, session_id: &str) -> PathBuf {
    root.join(hex_encode(&store_seal_key(session_id)))
}

/// [`STORE_ROOT_ENV`] when set and non-empty. Tests with it unset get one
/// temp directory for this process. Other builds return [`ShellError::StoreRoot`]
/// and do not invent a path two agents would share.
pub fn store_root() -> Result<PathBuf, ShellError> {
    if let Some(root) = nonempty_var(STORE_ROOT_ENV) {
        return Ok(PathBuf::from(root));
    }
    #[cfg(test)]
    {
        return Ok(std::env::temp_dir().join(format!(
            "mail4agent-messenger-shell-root-{}",
            std::process::id()
        )));
    }
    #[cfg(not(test))]
    {
        Err(ShellError::StoreRoot)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// One routine POST: the Matrix event id it carried and the HTTP status
/// (`None` when no response arrived). `200` means the routine woke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeAttempt {
    /// Event id of the room text that was posted.
    pub event_id: String,
    /// HTTP status of the POST, if one came back.
    pub status: Option<u16>,
}

/// One URL per bot, already created. Neighbors are addressed by nick or mxid
/// on the server.
pub struct RoutineWake {
    /// The bot's own routine URL. Configured once. Not a per-letter token.
    pub url: String,
}

/// Routine POST target. Unset or empty: no POST. There is no default URL.
pub const ROUTINE_URL_ENV: &str = "M4A_ROUTINE_URL";

/// Optional `Authorization: Bearer` for [`ROUTINE_URL_ENV`]. Sent only when
/// that URL is also set. A host keychain injects this into the process
/// environment from outside. It is never written to disk and never read
/// from source.
pub const ROUTINE_BEARER_ENV: &str = "M4A_ROUTINE_BEARER";

/// Leader socket for a local session (`leader.sock`). Unset: no ACP push.
pub const LEADER_SOCK_ENV: &str = "M4A_LEADER_SOCK";

/// `session/load` working directory when [`LEADER_SOCK_ENV`] is set.
/// Unset uses the process current directory.
pub const LEADER_CWD_ENV: &str = "M4A_LEADER_CWD";

/// Wake targets for one shell. Empty fields mean that trigger is off.
/// `routine_bearer` is kept only in memory and only attached when
/// `routine_url` is set. The caller fills it from the environment, never
/// from a literal in source.
pub struct SessionWake {
    /// Routine URL. `None` or empty skips the POST.
    pub routine_url: Option<String>,
    /// Bearer for the routine POST. `None` or empty sends no
    /// `Authorization` header.
    pub routine_bearer: Option<String>,
    /// Path of an already-running `leader.sock`. `None` skips ACP.
    pub leader_sock: Option<PathBuf>,
    /// Working directory for `session/load`. `None` uses the env or cwd.
    pub leader_cwd: Option<String>,
}

impl Default for SessionWake {
    fn default() -> Self {
        Self {
            routine_url: None,
            routine_bearer: None,
            leader_sock: None,
            leader_cwd: None,
        }
    }
}

impl SessionWake {
    /// Web machine client. The host injected [`ROUTINE_URL_ENV`] and, when
    /// that URL is set, [`ROUTINE_BEARER_ENV`]. [`LEADER_SOCK_ENV`] is not
    /// read. Nothing is taken from a file.
    pub fn web_host() -> Self {
        Self::web_from_lookup(|key| nonempty_var(key))
    }

    /// Same as [`Self::web_host`] with an explicit lookup. A leader socket
    /// returned by `get` is ignored.
    pub fn web_from_lookup(mut get: impl FnMut(&str) -> Option<String>) -> Self {
        let routine_url = get(ROUTINE_URL_ENV).filter(|value| !value.is_empty());
        let routine_bearer = if routine_url.is_some() {
            get(ROUTINE_BEARER_ENV).filter(|value| !value.is_empty())
        } else {
            None
        };
        Self {
            routine_url,
            routine_bearer,
            leader_sock: None,
            leader_cwd: None,
        }
    }

    /// Node CLI. [`LEADER_SOCK_ENV`] and [`LEADER_CWD_ENV`] only. A routine
    /// URL or bearer is refused. The refused value is not copied into the
    /// error.
    pub fn node_cli() -> Result<Self, ShellError> {
        Self::node_from_lookup(|key| nonempty_var(key))
    }

    /// Same as [`Self::node_cli`] with an explicit lookup.
    pub fn node_from_lookup(
        mut get: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self, ShellError> {
        let routine_url = get(ROUTINE_URL_ENV).filter(|value| !value.is_empty());
        let routine_bearer = get(ROUTINE_BEARER_ENV).filter(|value| !value.is_empty());
        if routine_url.is_some() || routine_bearer.is_some() {
            return Err(ShellError::NodeRoutine);
        }
        Ok(Self {
            routine_url: None,
            routine_bearer: None,
            leader_sock: get(LEADER_SOCK_ENV)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            leader_cwd: get(LEADER_CWD_ENV).filter(|value| !value.is_empty()),
        })
    }
}

pub(crate) fn nonempty_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// One session of the client, ready to log in. Built from the host environment
/// ([`SessionConfig::from_env`]) or [`SessionConfig::new_identity`]. The nick is the one the
/// operator assigned with the invite; it is known after the first login.
pub struct SessionConfig {
    homeserver_url: String,
    session_id: String,
    store_root: PathBuf,
    identity: IdentityAuth,
}

impl SessionConfig {
    /// The session's identity is generated and kept by the client's vault under `store_root`, it
    /// enrolls with the operator's `invite` once, and logs in by signature afterwards. `tier`
    /// picks the product API (tier 2) or the Matrix API (tier 3).
    pub fn new_identity(
        product_url: impl Into<String>,
        tier: m4a_agent::BackendKind,
        session_id: impl Into<String>,
        store_root: impl Into<PathBuf>,
        invite: Option<String>,
    ) -> Result<Self, ShellError> {
        let homeserver_url = product_url.into();
        parse_base_url(&homeserver_url)?;
        let session_id = session_id.into();
        validate_session_id(&session_id)?;
        let store_root = store_root.into();
        let invite = invite.filter(|i| !i.is_empty()).or_else(|| read_invite_file(&store_root, &session_id));
        Ok(Self {
            homeserver_url,
            session_id,
            store_root,
            identity: IdentityAuth { tier, invite: invite.map(Zeroizing::new), nick_request: None },
        })
    }

    /// Asks the server, at the first enrollment, for the nick of this session's name
    /// ([`nick_from_display_name`] of `name`; a name that makes no nick asks for nothing). The
    /// operator's invite still decides, and a nick the invite reserved wins.
    pub fn with_nick_request(mut self, name: &str) -> Self {
        self.identity.nick_request = nick_from_display_name(name.trim()).ok();
        self
    }

    /// A session on `url`: the tier from [`TIER_ENV`] and the operator's invite from the invite
    /// file (`<store_root>/invites/<hash of the session id>`), if the operator left one.
    pub fn for_session(url: &str, session_id: &str, store_root: &Path) -> Result<Self, ShellError> {
        let tier = match nonempty_var(TIER_ENV).as_deref() {
            None | Some("server") => m4a_agent::BackendKind::Server,
            Some("matrix") => m4a_agent::BackendKind::Matrix,
            Some(_) => return Err(ShellError::Register(format!("{TIER_ENV} is server or matrix"))),
        };
        Self::new_identity(url, tier, session_id, store_root, None)
    }

    /// Host environment. Required: [`PRODUCT_URL_ENV`] (or [`HOMESERVER_URL_ENV`] / `homeserver_url`
    /// in toml), [`SESSION_ID_ENV`], [`STORE_ROOT_ENV`]. Optional: [`PRODUCT_INVITE_ENV`] (first
    /// login only), [`TIER_ENV`]. [`ROUTINE_URL_ENV`] and [`LEADER_SOCK_ENV`] are not read here.
    pub fn from_env() -> Result<Self, ShellError> {
        let toml_text = load_homeserver_toml()?;
        Self::from_lookup(
            |key| std::env::var(key).ok().filter(|value| !value.is_empty()),
            toml_text.as_deref(),
        )
    }

    pub(crate) fn from_lookup(
        mut get: impl FnMut(&str) -> Option<String>,
        toml_text: Option<&str>,
    ) -> Result<Self, ShellError> {
        let from_toml = match toml_text {
            Some(text) => homeserver_url_from_toml(text)?,
            None => None,
        };
        let url = get(PRODUCT_URL_ENV)
            .or_else(|| get(HOMESERVER_URL_ENV))
            .or(from_toml)
            .ok_or(ShellError::HomeserverUrl)?;
        let tier = match get(TIER_ENV).as_deref() {
            None | Some("server") => m4a_agent::BackendKind::Server,
            Some("matrix") => m4a_agent::BackendKind::Matrix,
            Some(_) => return Err(ShellError::Register(format!("{TIER_ENV} is server or matrix"))),
        };
        let session_id = get(SESSION_ID_ENV).ok_or(ShellError::EmptySession)?;
        let store_root = get(STORE_ROOT_ENV).ok_or(ShellError::StoreRoot)?;
        // A nick is asked for only when the host named the session; a bare session id is not a name.
        let config = Self::new_identity(url, tier, session_id, store_root, get(PRODUCT_INVITE_ENV))?;
        Ok(match get(BOT_NAME_ENV) {
            Some(name) => config.with_nick_request(&name),
            None => config,
        })
    }

    /// Homeserver (or product) origin this session logs in at.
    pub fn homeserver_url(&self) -> &str {
        &self.homeserver_url
    }

    /// [`session_store_dir`] for this session under the configured root.
    pub fn store_dir(&self) -> PathBuf {
        session_store_dir(&self.store_root, &self.session_id)
    }

    /// Session id the host assigned. Not a secret.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

impl std::fmt::Debug for SessionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionConfig")
            .field("homeserver_url", &self.homeserver_url)
            .field("session_id", &self.session_id)
            .field("store_root", &self.store_root)
            .field("tier", &self.identity.tier)
            .finish()
    }
}

/// Where the operator leaves the one-time invite for a session: a file the client reads and
/// deletes after the identity is enrolled. The agent is never given the code.
fn invite_path(store_root: &Path, session_id: &str) -> PathBuf {
    store_root.join("invites").join(hex_encode(&store_seal_key(session_id)))
}

fn read_invite_file(store_root: &Path, session_id: &str) -> Option<String> {
    let text = std::fs::read_to_string(invite_path(store_root, session_id)).ok()?;
    let code = text.trim().to_string();
    (!code.is_empty()).then_some(code)
}

fn validate_session_id(session_id: &str) -> Result<(), ShellError> {
    if session_id.is_empty()
        || session_id.len() > 128
        || session_id.starts_with("legacy-user-")
        || session_id
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(ShellError::EmptySession);
    }
    Ok(())
}

fn load_homeserver_toml() -> Result<Option<String>, ShellError> {
    let path = if let Some(configured) = nonempty_var(CONFIG_ENV) {
        PathBuf::from(configured)
    } else {
        let cwd = PathBuf::from("mail4agent.toml");
        if !cwd.exists() {
            return Ok(None);
        }
        cwd
    };
    if !path.is_file() {
        return Err(ShellError::Config("config file is missing".to_string()));
    }
    std::fs::read_to_string(&path)
        .map(Some)
        .map_err(|err| ShellError::Config(clip_public(err.to_string())))
}

fn homeserver_url_from_toml(text: &str) -> Result<Option<String>, ShellError> {
    #[derive(serde::Deserialize)]
    struct File {
        #[serde(default)]
        homeserver_url: Option<String>,
    }
    let file: File =
        toml::from_str(text).map_err(|err| ShellError::Config(clip_public(err.to_string())))?;
    Ok(file
        .homeserver_url
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty()))
}

/// A session found by nick. No routine URL and no bearer.
pub struct FoundSession {
    /// The nick stored for that session.
    pub nick: String,
    /// That session's Matrix user id.
    pub user_id: String,
}

/// One decrypted room text the routine should learn about.
///
/// Serialized as a JSON object. `body` is the plaintext a routine that
/// only reads the message still finds. `from` is the sender mxid.
/// `event_id` is the Matrix event id. `nick` is omitted when this shell
/// does not already know a display name; it is never invented.
#[derive(Default)]
pub struct DecryptedWake<'a> {
    /// Plaintext body.
    pub body: &'a str,
    /// Sender mxid.
    pub from: &'a str,
    /// Sender display name, if the room state already has one.
    pub nick: Option<&'a str>,
    /// Matrix event id.
    pub event_id: &'a str,
    /// Room id the text arrived in (`room`).
    pub room: Option<&'a str>,
    /// Sender nick: the localpart of `from` (`from_nick`).
    pub from_nick: Option<&'a str>,
    /// Recipient nick: the session this wake is for (`to`).
    pub to: Option<&'a str>,
    /// One-line reply command for the recipient (`reply`), e.g.
    /// `m4a-send --as <to> --to <from_nick> '<text>'`.
    pub reply: Option<&'a str>,
}

/// Command a woken bot runs to answer, as shown in the wake's `reply`.
pub const SEND_COMMAND: &str = "m4a-send";

/// The `reply` hint for a wake from `from_nick` to `to`.
pub fn reply_hint(to: &str, from_nick: &str) -> String {
    format!("{SEND_COMMAND} --as {to} --to {from_nick} '<your reply>'")
}

/// Localpart of a Matrix user id (`@alice:server` -> `alice`).
pub fn mxid_localpart(mxid: &str) -> &str {
    let rest = mxid.strip_prefix('@').unwrap_or(mxid);
    rest.split_once(':').map(|(local, _)| local).unwrap_or(rest)
}

/// POSTs `wake` once, as a JSON object, to `url`. No mailbox path and no
/// `Authorization` header. `url` is the bot's already-configured routine.
/// `http` and `https` are both followed; anything else is refused before
/// a socket is opened.
pub fn post_decrypted(url: &str, wake: &DecryptedWake<'_>) -> Result<(), ShellError> {
    post_decrypted_with_bearer(url, wake, None)
}

/// [`post_decrypted`] plus the routine key. When `bearer` is `Some` and
/// non-empty, that same value is sent as `Authorization: Bearer` and as
/// `X-Automation-Key`. `Content-Type` is `application/json`. One JSON body.
/// One attempt, 8 seconds. A 200 means the routine woke. Anything else is
/// a failure and is not retried here. The key and the URL are not included
/// in the error. The value must come from memory, not from source.
pub fn post_decrypted_with_bearer(
    url: &str,
    wake: &DecryptedWake<'_>,
    bearer: Option<&str>,
) -> Result<(), ShellError> {
    let bytes = routine_json(wake)?;
    post_routine_bytes(url, bytes, bearer)
}

/// [`post_decrypted_with_bearer`] with any JSON object as the body: the
/// machine client's own events (`kind` = `peer_joined`) go to a bot's
/// routine this way. Same headers, one attempt, 8 seconds, 200 or error.
/// The key and the URL are not included in the error.
pub fn post_routine_json(
    url: &str,
    body: &serde_json::Value,
    bearer: Option<&str>,
) -> Result<(), ShellError> {
    let bytes = serde_json::to_vec(body)
        .map_err(|err| ShellError::RoutineTransport(clip_public(err.to_string())))?;
    post_routine_bytes(url, bytes, bearer)
}

fn post_routine_bytes(url: &str, bytes: Vec<u8>, bearer: Option<&str>) -> Result<(), ShellError> {
    let target = parse_routine_url(url)?;
    let client = routine_client()?;
    let token = bearer.map(str::trim).filter(|token| !token.is_empty());
    let mut builder = client
        .post(target)
        .header(reqwest::header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        let authorization = bearer_header(token)?;
        let mut automation_key =
            reqwest::header::HeaderValue::from_str(token).map_err(|_| ShellError::RoutineBearer)?;
        automation_key.set_sensitive(true);
        builder = builder
            .header(reqwest::header::AUTHORIZATION, authorization)
            .header("x-automation-key", automation_key);
    }
    let response = builder.body(bytes).send().map_err(|err| {
        ShellError::RoutineTransport(redact_wake(public_reqwest(&err), url, token))
    })?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(ShellError::RoutineStatus(status));
    }
    Ok(())
}

fn redact_wake(mut text: String, url: &str, bearer: Option<&str>) -> String {
    if !url.is_empty() {
        text = text.replace(url, "[redacted]");
    }
    if let Some(token) = bearer.filter(|token| token.len() >= 4) {
        text = text.replace(token, "[redacted]");
    }
    text
}

fn routine_json(wake: &DecryptedWake<'_>) -> Result<Vec<u8>, ShellError> {
    let mut object = serde_json::Map::new();
    object.insert(
        "body".to_string(),
        serde_json::Value::String(wake.body.to_string()),
    );
    object.insert(
        "from".to_string(),
        serde_json::Value::String(wake.from.to_string()),
    );
    object.insert(
        "event_id".to_string(),
        serde_json::Value::String(wake.event_id.to_string()),
    );
    if let Some(nick) = wake.nick.map(str::trim).filter(|nick| !nick.is_empty()) {
        object.insert(
            "nick".to_string(),
            serde_json::Value::String(nick.to_string()),
        );
    }
    for (key, value) in [
        ("room", wake.room),
        ("from_nick", wake.from_nick),
        ("to", wake.to),
        ("reply", wake.reply),
    ] {
        if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
            object.insert(
                key.to_string(),
                serde_json::Value::String(value.to_string()),
            );
        }
    }
    serde_json::to_vec(&object)
        .map_err(|err| ShellError::RoutineTransport(clip_public(err.to_string())))
}

fn bearer_header(token: &str) -> Result<reqwest::header::HeaderValue, ShellError> {
    // One rule for both delivery paths (the Grok doorbell's and the routine POST): the Grok crate's.
    let token = webhook::bearer_token(token).ok_or(ShellError::RoutineBearer)?;
    let mut header = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| ShellError::RoutineBearer)?;
    header.set_sensitive(true);
    Ok(header)
}

fn routine_client() -> Result<reqwest::blocking::Client, ShellError> {
    // Workspace feature unification also turns on native-tls. Without this,
    // Windows uses schannel and a localized chain error instead of rustls.
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .http1_only()
        .use_rustls_tls()
        .build()
        .map_err(|err| ShellError::RoutineTransport(public_reqwest(&err)))
}

fn public_reqwest(err: &reqwest::Error) -> String {
    let mut text = err.to_string();
    let mut source = std::error::Error::source(err);
    while let Some(inner) = source {
        text.push_str(": ");
        text.push_str(&inner.to_string());
        source = inner.source();
        if text.len() > 400 {
            break;
        }
    }
    clip_public(text)
}

fn parse_routine_url(url: &str) -> Result<reqwest::Url, ShellError> {
    // One rule for both delivery paths: the Grok crate's operator-URL check runs first.
    if !webhook::url_ok(url) {
        return Err(ShellError::RoutineUrl);
    }
    let parsed = reqwest::Url::parse(url).map_err(|_| ShellError::RoutineUrl)?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err(ShellError::RoutineUrl),
    }
    if parsed.host_str().is_none() || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ShellError::RoutineUrl);
    }
    Ok(parsed)
}

/// A sealed messenger core opened for one session, plus the homeserver it
/// performs released requests against. The Olm account was loaded or created
/// into it. Private key material stays here. The device bearer stays in
/// memory and is zeroed when this value is dropped.
pub struct OpenedStore {
    dir: PathBuf,
    driver: Driver<SealedRecordCodec>,
    device_token: Zeroizing<String>,
    base_url: String,
    /// Session id this store was opened with. Also the ACP `sessionId`
    /// when a leader socket is configured. Not a secret.
    session_id: String,
    /// Set by [`OpenedStore::connect`]. Empty when opened with a bearer
    /// the caller already held.
    nick: Option<String>,
    routine_url: Option<String>,
    routine_bearer: Option<Zeroizing<String>>,
    leader_sock: Option<PathBuf>,
    leader_cwd: Option<String>,
    /// Inbound event keys whose routine POST already succeeded.
    routine_sent: HashSet<String>,
    /// When true, the next [`Self::wake_inbound`] with timeline rows seeds
    /// older keys into [`ROUTINE_WOKEN_FILE`] (newest still POSTs once) —
    /// first open after a missing/empty ledger, once tip/history has landed.
    routine_woken_seed_pending: bool,
    /// Restart with an existing [`ROUTINE_WOKEN_FILE`]: tip/history may show
    /// more rows than the ledger. While true, remember every inbound key
    /// without POSTing. Cleared at the end of the first [`Self::drive`].
    routine_restart_catchup: bool,
    /// Inbound event keys whose leader prompt already succeeded.
    leader_sent: HashSet<String>,
    /// Last wake failure, clipped. No bearer and no message body.
    wake_note: Option<String>,
    wake_log: Vec<WakeAttempt>,
    /// Provider wake chain for a session that has no leader socket
    /// (Codex, Kimi, Claude, Cursor; Claude web / Codex cloud). Uses the
    /// same `leader-prompted` ledger as the leader path.
    wake_chain: Option<(provider::ProviderSession, provider::WakeChain)>,
    /// `<link id> delivered|queued` for the newest chain wake.
    wake_route: Option<String>,
    /// In-process bus for sessions this machine's client already holds.
    /// `None` on a store opened by itself: every request goes to the homeserver.
    bus: Option<Arc<machine::LocalBus>>,
    /// Nick and mxid of the other sessions in that client. Lookup does not
    /// ask the homeserver.
    local_peers: Vec<(String, String)>,
    /// Room texts pushed on the machine socket for this session. Not `/sync`.
    pushed_room_events: Vec<PushedRoomEvent>,
    /// Joined rooms already paged once. Timelines are not stored, so a
    /// resumed process asks `/messages` from the sync token a single time.
    history_pulled: HashSet<String>,
    /// Joined rooms whose tip page has already landed in this process.
    /// A `/sync` token that has moved past an event will not replay it.
    tip_pulled: HashSet<String>,
}

struct ZeroJitter;

impl Jitter for ZeroJitter {
    fn next_unit(&mut self) -> f64 {
        0.0
    }
}

/// One room this store currently holds, from this account's own view.
pub struct RoomView {
    /// The room id.
    pub room_id: String,
    /// This account's membership: `join`, `invite`, `leave`, `ban`, `knock`,
    /// `unknown`, or `absent`.
    pub membership: String,
    /// Whether `m.room.encryption` is set.
    pub encrypted: bool,
}

/// One text-like timeline row. Ciphertext is not included.
pub struct TextView {
    /// The room the row is in.
    pub room_id: String,
    /// The decrypted or plaintext body.
    pub body: String,
    /// `sent`, `sending`, `failed`, or `undecryptable`.
    pub outcome: String,
    /// Matrix event id once the server has one. Empty for a local echo
    /// that has not been accepted yet.
    pub event_id: Option<String>,
}

impl OpenedStore {
    /// Derives the seal key from `session_id`, reads `dir`, and opens the
    /// core. A different session id cannot open records this session sealed.
    ///
    /// The host keychain injects `device_token`. [`STORE_ROOT_ENV`] plus
    /// `session_id` ([`session_store_dir`]) picks `dir`. This does not read
    /// a routine URL or a leader socket. The web machine client and the
    /// node CLI set wake on their own open paths. The device bearer stays
    /// in memory and is not written under `dir`.
    pub fn open(
        dir: &Path,
        session_id: &str,
        device_id: DeviceId,
        user_id: &str,
        server_name: &str,
        backend: Arc<dyn Backend>,
        device_token: &str,
    ) -> Result<Self, ShellError> {
        if session_id.is_empty() {
            return Err(ShellError::EmptySession);
        }
        if device_token.is_empty()
            || device_token
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || !byte.is_ascii())
        {
            return Err(ShellError::DeviceToken);
        }
        let base_url = backend.server_ref().to_string();
        fs_create_dir(dir)?;
        let user_id = UserId::parse(user_id)?;
        let secrets = CoreSecrets {
            store_seal_key: Some(store_key::store_key(dir, session_id)?),
            backup_key: None,
        };
        let config = CoreConfig {
            user_id,
            device_id,
            server_name: server_name.to_string(),
        };
        let records = read_records(dir)?;
        let mut core =
            match MessengerCore::open_sealed(records, secrets, config, 0, Box::new(ZeroJitter)) {
                Ok(core) => core,
                Err(MessengerError::Store(err)) => return Err(ShellError::Store(err)),
                Err(err) => return Err(ShellError::Messenger(err)),
            };
        persist(dir, &mut core)?;
        let mut opened = Self {
            dir: dir.to_path_buf(),
            driver: Driver::new(core, backend, {
                let dir = dir.to_path_buf();
                Box::new(move |core| persist(&dir, core).map_err(|e| AgentError::Store(clip_public(e.to_string()))))
            }),
            base_url,
            device_token: Zeroizing::new(device_token.to_string()),
            session_id: session_id.to_string(),
            nick: None,
            routine_url: None,
            routine_bearer: None,
            leader_sock: None,
            leader_cwd: None,
            routine_sent: HashSet::new(),
            routine_woken_seed_pending: false,
            routine_restart_catchup: false,
            leader_sent: HashSet::new(),
            wake_chain: None,
            wake_route: None,
            wake_note: None,
            wake_log: Vec::new(),
            bus: None,
            local_peers: Vec::new(),
            pushed_room_events: Vec::new(),
            history_pulled: HashSet::new(),
            tip_pulled: HashSet::new(),
        };
        // Routine replay is suppressed for whatever is already on disk.
        // A leader prompt is not. Only a recorded successful prompt is.
        opened.note_already_present();
        Ok(opened)
    }

    /// Registers this Grok Bot web session, then opens its sealed store.
    ///
    /// `POST /client/v3/register` with the derived nick, the session id, and
    /// a public id equal to that nick. The bearer from a creating response
    /// stays in memory. A repeat of the same session id returns no bearer;
    /// [`DEVICE_TOKEN_ENV`] (already copied into `config`) is used instead.
    /// One [`Self::drive`] publishes this device's public keys. The private
    /// Olm account stays in the store.
    pub fn connect(config: &SessionConfig) -> Result<Self, ShellError> {
        Self::connect_with_wake(config, SessionWake::default())
    }

    pub(crate) fn connect_with_wake(config: &SessionConfig, wake: SessionWake) -> Result<Self, ShellError> {
        let registered = register_session(config)?;
        let server_name = registered
            .user_id
            .split_once(':')
            .map(|(_, server)| server)
            .filter(|server| !server.is_empty())
            .ok_or(ShellError::Register("user id has no server".to_string()))?;
        let mut opened = Self::open(
            &config.store_dir(),
            &config.session_id,
            registered.device_id,
            &registered.user_id,
            server_name,
            registered.backend,
            &registered.bearer,
        )?;
        opened.nick = Some(registered.nick.clone());
        opened.set_wake(wake);
        // The first sync is what publishes the public keys.
        opened.drive(1_000, false)?;
        Ok(opened)
    }

    /// [`SessionConfig::from_env`] then [`Self::connect`]. No routine URL
    /// and no leader socket. The web machine client is
    /// [`MachineClient::from_env`]. The node CLI is
    /// [`Self::connect_node_from_env`].
    pub fn connect_from_env() -> Result<Self, ShellError> {
        Self::connect(&SessionConfig::from_env()?)
    }

    /// Node CLI open path. One session from the host environment, woken by
    /// ACP on [`LEADER_SOCK_ENV`]. [`ROUTINE_URL_ENV`] or
    /// [`ROUTINE_BEARER_ENV`] is refused before register, is not stored, and
    /// is not logged. This does not read a session json.
    pub fn connect_node_from_env() -> Result<Self, ShellError> {
        let wake = SessionWake::node_cli()?;
        Self::connect_with_wake(&SessionConfig::from_env()?, wake)
    }

    #[cfg(test)]
    pub(crate) fn connect_node_from_lookup(
        mut get: impl FnMut(&str) -> Option<String>,
        toml_text: Option<&str>,
    ) -> Result<Self, ShellError> {
        let wake = SessionWake::node_from_lookup(&mut get)?;
        let config = SessionConfig::from_lookup(&mut get, toml_text)?;
        Self::connect_with_wake(&config, wake)
    }

    /// Bearer for the host keychain. Not written to disk and not logged.
    pub(crate) fn keep_prefix(&self) -> bool {
        self.driver.backend().keep_prefix()
    }

    pub fn device_bearer(&self) -> &str {
        self.device_token.as_str()
    }

    /// This session's derived nick, when [`Self::connect`] stored one.
    /// [`Self::open`] leaves this empty.
    pub fn nick(&self) -> Option<&str> {
        self.nick.as_deref()
    }

    /// Session / device id used for the seal and for ACP `sessionId`.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Homeserver origin this store performs Client-Server calls against.
    pub fn homeserver_url(&self) -> &str {
        self.base_url.trim_end_matches('/')
    }

    /// Whether an ACP leader socket is configured for wake.
    pub fn has_leader(&self) -> bool {
        self.leader_sock.is_some()
    }

    /// Directory this store seals into. Not shared with another session.
    pub fn store_dir(&self) -> &Path {
        &self.dir
    }

    /// Homeserver calls this store's client has counted. In-process bus
    /// calls are not included. Zero when this store has no bus.
    pub fn homeserver_hits(&self) -> u64 {
        self.bus.as_ref().map(|bus| bus.hits()).unwrap_or(0)
    }

    /// Room texts this session received on the machine push socket.
    pub fn pushed_room_events(&self) -> &[PushedRoomEvent] {
        &self.pushed_room_events
    }

    pub(crate) fn record_push(&mut self, event: PushedRoomEvent) {
        self.pushed_room_events.push(event);
    }

    pub(crate) fn attach_bus(&mut self, bus: Arc<machine::LocalBus>) {
        let inner = Arc::clone(self.driver.backend());
        self.driver.set_backend(Arc::new(bus_backend::BusBackend { inner, bus: Arc::clone(&bus), user_id: self.driver.core.user_id().as_str().to_string(), force_local: None }));
        self.bus = Some(bus);
    }

    pub(crate) fn set_registered_nick(&mut self, nick: String) {
        self.nick = Some(nick);
    }

    pub(crate) fn set_local_peers(&mut self, peers: Vec<(String, String)>) {
        self.local_peers = peers;
    }

    /// Drops a `/sync` left on the wire by [`Self::drive`] so the next drive
    /// is not blocked on that poll. The engine retries the sync later. This
    /// does not start another poll.
    pub(crate) fn abandon_inflight_sync(&mut self, now_ms: i64) -> Result<(), ShellError> {
        if self.driver.sync_inflight() {
            self.driver.abandon_sync(now_ms);
            self.persist_core()?;
        }
        Ok(())
    }

    /// This account's Matrix user id.
    pub fn user_id(&self) -> &str {
        self.driver.core.user_id().as_str()
    }

    /// Whether `user_id` is a joined member of `room_id` in this store.
    pub fn member_joined(&self, room_id: &str, user_id: &str) -> bool {
        let Ok(room_id) = RoomId::parse(room_id) else {
            return false;
        };
        let Ok(user_id) = UserId::parse(user_id) else {
            return false;
        };
        self.driver.core.room_state(&room_id).is_some_and(|state| {
            state
                .members
                .get(&user_id)
                .is_some_and(|member| member.membership == Membership::Join)
        })
    }

    /// Looks up `name_or_nick` in the user directory. A display name is
    /// derived first when it is not already a nick. The hit is nick plus
    /// user id. No routine URL is returned or sent.
    pub fn find_nick(
        &mut self,
        name_or_nick: &str,
        now_ms: i64,
    ) -> Result<FoundSession, ShellError> {
        let needle = nick::lookup_nick(name_or_nick)?;
        if let Some((nick, user_id)) = self
            .local_peers
            .iter()
            .find(|(nick, _)| nick.eq_ignore_ascii_case(&needle))
        {
            return Ok(FoundSession {
                nick: nick.clone(),
                user_id: user_id.clone(),
            });
        }
        self.dispatch(
            MessengerCommand::SearchUsers {
                term: needle.clone(),
            },
            now_ms,
        )?;
        self.drive(now_ms, false)?;
        let mut hits: Vec<FoundSession> = self
            .driver.core
            .user_search_result()
            .iter()
            .filter_map(|entry| {
                let nick = entry.display_name.as_deref()?.trim();
                if !nick.eq_ignore_ascii_case(&needle) {
                    return None;
                }
                Some(FoundSession {
                    nick: nick.to_string(),
                    user_id: entry.user_id.as_str().to_string(),
                })
            })
            .collect();
        hits.sort_by(|left, right| left.user_id.cmp(&right.user_id));
        hits.dedup_by(|left, right| left.user_id == right.user_id);
        match hits.len() {
            1 => Ok(hits.remove(0)),
            0 => Err(ShellError::UnknownNick),
            _ => Err(ShellError::UnknownNick),
        }
    }

    /// Looks `name_or_nick` up and opens the encrypted DM, creating it when
    /// this account does not already have one. Does not send. The peer may
    /// still be invited: [`Self::write_to_nick`] sends only after they join.
    pub fn ensure_dm(&mut self, name_or_nick: &str, mut now_ms: i64) -> Result<String, ShellError> {
        let (_peer, room_id) = self.open_dm(name_or_nick, &mut now_ms)?;
        Ok(room_id)
    }

    /// Joins direct-message invites already visible to this store.
    ///
    /// Returns the room ids this call asked to join. A room that is not an
    /// `is_direct` invite is left alone. This does not register the inviter.
    pub fn accept_direct_invites(&mut self, mut now_ms: i64) -> Result<Vec<String>, ShellError> {
        let me = self.driver.core.user_id().clone();
        let invited: Vec<RoomId> = self
            .driver.core
            .room_ids()
            .cloned()
            .filter(|room_id| {
                let Some(state) = self.driver.core.room_state(room_id) else {
                    return false;
                };
                state.members.get(&me).is_some_and(|member| {
                    member.membership == Membership::Invite && member.is_direct
                })
            })
            .collect();
        let mut ids = Vec::new();
        for room_id in invited {
            self.dispatch(
                MessengerCommand::JoinRoom {
                    room_id: room_id.clone(),
                },
                now_ms,
            )?;
            ids.push(room_id.as_str().to_string());
        }
        if ids.is_empty() {
            return Ok(ids);
        }
        for _ in 0..8 {
            now_ms += 1_000;
            self.drive(now_ms, false)?;
            let still_invited = ids.iter().any(|room_id| {
                self.rooms()
                    .iter()
                    .any(|room| room.room_id == *room_id && room.membership == "invite")
            });
            if !still_invited {
                break;
            }
        }
        Ok(ids)
    }

    /// Writes `text` to the session named by `name_or_nick`.
    ///
    /// The caller is already registered. This looks the nick up, reuses the
    /// encrypted DM when one exists, otherwise creates one, and sends only
    /// after the peer's membership is `join`. A peer who is still invited
    /// gets no ciphertext: the caller joins them first
    /// ([`Self::accept_direct_invites`]) and calls this again. It does not
    /// register the other session and it does not put a routine URL in the room.
    pub fn write_to_nick(
        &mut self,
        name_or_nick: &str,
        text: &str,
        mut now_ms: i64,
    ) -> Result<String, ShellError> {
        let (peer, room_id) = self.open_dm(name_or_nick, &mut now_ms)?;
        if !self.member_joined(&room_id, peer.as_str()) {
            return Err(ShellError::Dm);
        }
        let encrypted = self
            .rooms()
            .into_iter()
            .any(|room| room.room_id == room_id && room.encrypted);
        if !encrypted {
            return Err(ShellError::Dm);
        }
        self.dispatch(
            MessengerCommand::SendMessage {
                room_id: RoomId::parse(&room_id)?,
                message: OutgoingMessage {
                    kind: MessageKind::Text,
                    body: text.to_string(),
                    reply_to: None,
                    edit_of: None,
                },
                txn_id: None,
            },
            now_ms,
        )?;
        for _ in 0..20 {
            now_ms += 1_000;
            self.drive(now_ms, false)?;
            if let Some(row) = self
                .texts()
                .into_iter()
                .find(|row| row.room_id == room_id && row.body == text)
            {
                if row.outcome == "sent" {
                    return Ok(room_id);
                }
                if row.outcome.starts_with("failed") {
                    return Err(ShellError::Dm);
                }
            }
        }
        Err(ShellError::Dm)
    }

    fn open_dm(
        &mut self,
        name_or_nick: &str,
        now_ms: &mut i64,
    ) -> Result<(UserId, String), ShellError> {
        let found = self.find_nick(name_or_nick, *now_ms)?;
        let peer = UserId::parse(&found.user_id)?;
        if &peer == self.driver.core.user_id() {
            return Err(ShellError::UnknownNick);
        }
        let room_id = if let Some(room_id) = self.dm_room(&peer) {
            room_id
        } else {
            self.dispatch(
                MessengerCommand::CreateRoom {
                    kind: CreateRoomKind::Dm { peer: peer.clone() },
                },
                *now_ms,
            )?;
            self.wait_for_dm(&peer, now_ms)?
        };
        Ok((peer, room_id))
    }

    fn wait_for_dm(&mut self, peer: &UserId, now_ms: &mut i64) -> Result<String, ShellError> {
        for attempt in 0..6 {
            *now_ms += 1_000;
            self.drive(*now_ms, attempt == 5)?;
            if let Some(room_id) = self.dm_room(peer) {
                return Ok(room_id);
            }
        }
        Err(ShellError::Dm)
    }

    fn dm_room(&self, peer: &UserId) -> Option<String> {
        let me = self.driver.core.user_id().clone();
        let ids: Vec<RoomId> = self.driver.core.room_ids().cloned().collect();
        for room_id in &ids {
            let (joined, has_peer) = {
                let Some(state) = self.driver.core.room_state(room_id) else {
                    continue;
                };
                let joined = state
                    .members
                    .get(&me)
                    .is_some_and(|member| member.membership == Membership::Join);
                let has_peer = state.members.contains_key(peer);
                (joined, has_peer)
            };
            if !joined || !has_peer {
                continue;
            }
            if self.driver.core.room_kind(room_id) == Some(RoomKind::Dm) {
                return Some(room_id.as_str().to_string());
            }
        }
        None
    }

    /// Replaces the wake targets. `None` or empty turns that trigger off.
    /// The bearer is stored in [`Zeroizing`] memory and is not written to
    /// disk. [`Self::open`] does not read a wake; the web machine client
    /// and the node CLI set one on their open paths.
    pub fn set_wake(&mut self, wake: SessionWake) {
        self.routine_url = wake.routine_url.filter(|url| !url.is_empty());
        self.routine_bearer = wake
            .routine_bearer
            .filter(|token| !token.is_empty())
            .map(Zeroizing::new);
        self.leader_sock = wake.leader_sock.filter(|path| !path.as_os_str().is_empty());
        self.leader_cwd = wake.leader_cwd.filter(|cwd| !cwd.is_empty());
    }

    /// Installs the provider wake chain ([`provider::plan_chain`]). Used
    /// only while no leader socket is set; the Grok leader path and the
    /// routine POST are unchanged by it.
    pub fn set_wake_chain(
        &mut self,
        session: provider::ProviderSession,
        chain: provider::WakeChain,
    ) {
        self.wake_chain = Some((session, chain));
    }

    /// Link ids of the installed chain, in order. Empty when none.
    pub fn wake_chain_ids(&self) -> Vec<&'static str> {
        self.wake_chain
            .as_ref()
            .map(|(_, chain)| chain.ids())
            .unwrap_or_default()
    }

    /// `<link id> delivered|queued` for the newest chain wake.
    pub fn wake_route(&self) -> Option<&str> {
        self.wake_route.as_deref()
    }

    /// [`Self::wake_route`], cleared, so a listener prints it once.
    pub fn take_wake_route(&mut self) -> Option<String> {
        self.wake_route.take()
    }

    /// Whether this store has a routine to wake (URL set).
    pub fn has_routine(&self) -> bool {
        self.routine_url.is_some()
    }

    /// Routine URL and key, for the machine client's own events. Memory
    /// only; never logged.
    pub(crate) fn routine_target(&self) -> Option<(String, Option<String>)> {
        let url = self.routine_url.clone()?;
        let bearer = self.routine_bearer.as_ref().map(|token| token.as_str().to_string());
        Some((url, bearer))
    }

    /// Last wake failure that did not drop the room text. `None` if the
    /// last attempt worked or nothing has been attempted. The bearer and
    /// the plaintext are not included.
    pub fn wake_note(&self) -> Option<&str> {
        self.wake_note.as_deref()
    }

    /// Routine POSTs this store attempted since open, oldest first. Holds
    /// the event id and the HTTP status only: no URL, key, or body.
    pub fn wake_log(&self) -> &[WakeAttempt] {
        &self.wake_log
    }

    /// Queues `command` on the engine. It does not perform HTTP; [`Self::drive`]
    /// does that for whatever the engine then releases.
    pub fn dispatch(&mut self, command: MessengerCommand, now_ms: i64) -> Result<(), ShellError> {
        self.driver.core.dispatch(command, now_ms)?;
        self.persist_core()?;
        Ok(())
    }

    /// Queues [`MessengerCommand::SendMessage`] and releases whatever the
    /// engine will send next. That is a room send on an unencrypted room,
    /// or the key-setup requests the engine emits first when the room is
    /// encrypted. Nothing here calls the old mailbox. The returned requests
    /// are already in flight; a caller that wants them performed uses
    /// [`Self::drive`] instead of this method.
    pub fn send_room_message(
        &mut self,
        room_id: &str,
        text: &str,
        now_ms: i64,
    ) -> Result<Vec<OutgoingRequest>, ShellError> {
        let room_id = RoomId::parse(room_id)?;
        self.driver.core.dispatch(
            MessengerCommand::SendMessage {
                room_id,
                message: OutgoingMessage {
                    kind: MessageKind::Text,
                    body: text.to_string(),
                    reply_to: None,
                    edit_of: None,
                },
                txn_id: None,
            },
            now_ms,
        )?;
        self.persist_core()?;
        let mut released = self.driver.core.releasable_requests(now_ms);
        self.persist_core()?;
        if !released
            .iter()
            .any(|request| request.kind == OutgoingRequestKind::RoomSend)
        {
            released.extend(self.driver.core.releasable_requests(now_ms));
            self.persist_core()?;
        }
        Ok(released)
    }

    /// Performs every released request against `base_url`.
    ///
    /// `/sync` with `timeout=0` is always waited on. A long-poll `/sync` is
    /// started immediately and joined only when `wait_for_sync` is set, and
    /// at most once per call, so an idle 30s poll does not run back to back
    /// while key-setup requests are still in flight. The long-poll that is
    /// left on the wire is the engine's own request, including its timeout.
    /// A homeserver that wakes that poll (this server does) delivers the
    /// event without the shell polling twice.
    pub fn drive(&mut self, now_ms: i64, wait_for_sync: bool) -> Result<(), ShellError> {
        self.driver.core.decrypt_loaded_timeline();
        let trace_at = self.driver.http_trace.len();
        let history = self.request_missing_history(now_ms)?;
        self.pull_room_tips()?;
        let mut waited_long_poll = false;
        if wait_for_sync && self.driver.sync_inflight() {
            // A poll that already finished is a stale catch-up. Do not count it: the caller is
            // waiting for whatever is current, which is the next `/sync` this call starts.
            waited_long_poll = self.driver.harvest_sync(now_ms, true)?;
        } else {
            self.driver.harvest_sync(now_ms, false)?;
        }
        self.wake_inbound();
        for _ in 0..24 {
            if !self.driver.step(now_ms, wait_for_sync, &mut waited_long_poll)? {
                break;
            }
            self.wake_inbound();
        }
        self.note_history_pages(&history, trace_at);
        self.note_room_tips();
        self.routine_restart_catchup = false;
        Ok(())
    }

    /// Newest page of each joined room, once the timeline is still empty.
    /// [`MessengerCore::pull_latest_page`] does not use the sync token.
    fn pull_room_tips(&mut self) -> Result<(), ShellError> {
        let me = self.driver.core.user_id().clone();
        let ids: Vec<RoomId> = self.driver.core.room_ids().cloned().collect();
        for room_id in ids {
            if self.tip_pulled.contains(room_id.as_str()) {
                continue;
            }
            if self
                .driver.core
                .timeline(&room_id)
                .is_some_and(|timeline| !timeline.items().is_empty())
            {
                self.tip_pulled.insert(room_id.as_str().to_string());
                continue;
            }
            let joined = self.driver.core.room_state(&room_id).is_some_and(|state| {
                state
                    .members
                    .get(&me)
                    .is_some_and(|member| matches!(member.membership, Membership::Join))
            });
            if !joined {
                continue;
            }
            self.driver.core.pull_latest_page(room_id)?;
        }
        Ok(())
    }

    fn note_room_tips(&mut self) {
        let ids: Vec<RoomId> = self.driver.core.room_ids().cloned().collect();
        for room_id in ids {
            if self
                .driver.core
                .timeline(&room_id)
                .is_some_and(|timeline| !timeline.items().is_empty())
            {
                self.tip_pulled.insert(room_id.as_str().to_string());
            }
        }
    }

    /// Joined rooms whose timeline is still empty. The engine does not
    /// store timeline rows, and `/sync?since=` does not replay them. One
    /// backward `/messages` from the stored sync token loads that gap.
    fn request_missing_history(&mut self, now_ms: i64) -> Result<Vec<String>, ShellError> {
        let me = self.driver.core.user_id().clone();
        let ids: Vec<RoomId> = self.driver.core.room_ids().cloned().collect();
        let mut requested = Vec::new();
        for room_id in ids {
            if !self.room_needs_history(&room_id, &me) {
                continue;
            }
            let label = room_id.as_str().to_string();
            self.driver.core
                .dispatch(MessengerCommand::LoadOlder { room_id }, now_ms)?;
            requested.push(label);
        }
        Ok(requested)
    }

    fn room_needs_history(&self, room_id: &RoomId, me: &UserId) -> bool {
        if self.history_pulled.contains(room_id.as_str()) {
            return false;
        }
        let joined = match self
            .driver.core
            .room_state(room_id)
            .and_then(|state| state.members.get(me))
        {
            Some(member) => matches!(member.membership, Membership::Join),
            None => false,
        };
        if !joined {
            return false;
        }
        match self.driver.core.timeline(room_id) {
            Some(timeline) => timeline.items().is_empty(),
            None => true,
        }
    }

    fn note_history_pages(&mut self, requested: &[String], trace_at: usize) {
        if requested.is_empty() {
            return;
        }
        let ok = self.driver.http_trace[trace_at..]
            .iter()
            .filter(|(kind, status)| {
                *kind == OutgoingRequestKind::RoomMessages && (200..300).contains(status)
            })
            .count();
        if ok < requested.len() {
            return;
        }
        for room_id in requested {
            self.history_pulled.insert(room_id.clone());
        }
    }

    /// Rooms this account has state for.
    pub fn rooms(&self) -> Vec<RoomView> {
        let me = self.driver.core.user_id().clone();
        let mut rooms: Vec<RoomView> = self
            .driver.core
            .room_ids()
            .map(|room_id| {
                let state = self.driver.core.room_state(room_id);
                let membership = state
                    .and_then(|state| state.members.get(&me))
                    .map(|member| membership_name(&member.membership).to_string())
                    .unwrap_or_else(|| "absent".to_string());
                let encrypted = state.and_then(|state| state.encryption.as_ref()).is_some();
                RoomView {
                    room_id: room_id.as_str().to_string(),
                    membership,
                    encrypted,
                }
            })
            .collect();
        rooms.sort_by(|left, right| left.room_id.cmp(&right.room_id));
        rooms
    }

    /// Text-like timeline rows. Encrypted payloads that have not decrypted
    /// are reported as `undecryptable` without their ciphertext.
    pub fn texts(&self) -> Vec<TextView> {
        let mut out = Vec::new();
        for room_id in self.driver.core.room_ids() {
            let Some(timeline) = self.driver.core.timeline(room_id) else {
                continue;
            };
            for item in timeline.items() {
                match &item.content {
                    ItemContent::Text(text)
                    | ItemContent::Notice(text)
                    | ItemContent::Emote(text) => {
                        out.push(TextView {
                            room_id: room_id.as_str().to_string(),
                            body: text.body.clone(),
                            outcome: outcome_name(&item.send_state),
                            event_id: item.event_id.as_ref().map(|id| id.as_str().to_string()),
                        });
                    }
                    ItemContent::Undecryptable { reason } => out.push(TextView {
                        room_id: room_id.as_str().to_string(),
                        body: String::new(),
                        outcome: format!("undecryptable:{reason}"),
                        event_id: item.event_id.as_ref().map(|id| id.as_str().to_string()),
                    }),
                    _ => {}
                }
            }
        }
        out
    }

    /// HTTP status codes this store has seen, oldest first. Bodies are not kept.
    pub fn sync_inflight(&self) -> bool {
        self.driver.sync_inflight()
    }

    pub fn http_trace(&self) -> Vec<String> {
        self.driver.http_trace
            .iter()
            .map(|(kind, status)| format!("{kind:?} {status}"))
            .collect()
    }

    /// The last response this core failed to ingest, once.
    pub fn take_ingest_error(&mut self) -> Option<String> {
        self.driver.core.take_ingest_error().map(clip_public)
    }

    fn persist_core(&mut self) -> Result<(), ShellError> {
        self.driver.persist().map_err(ShellError::from)
    }

    /// Drains peer key-change alerts (M3).
    pub fn take_security_alerts(&mut self) -> Vec<String> {
        std::mem::take(&mut self.driver.security_alerts)
    }

    fn inbound_plaintexts(&self) -> Vec<InboundPlaintext> {
        let me = self.driver.core.user_id();
        let mut out = Vec::new();
        for room_id in self.driver.core.room_ids() {
            let Some(timeline) = self.driver.core.timeline(room_id) else {
                continue;
            };
            for item in timeline.items() {
                if item.redacted || &item.sender == me || item.send_state != SendState::Sent {
                    continue;
                }
                let body = match &item.content {
                    ItemContent::Text(text)
                    | ItemContent::Notice(text)
                    | ItemContent::Emote(text) => text.body.clone(),
                    _ => continue,
                };
                let Some(event_id) = item.event_id.as_ref() else {
                    continue;
                };
                let key = format!("{}\n{}", room_id.as_str(), event_id.as_str());
                out.push(InboundPlaintext {
                    room_id: room_id.as_str().to_string(),
                    key,
                    body,
                    from: item.sender.as_str().to_string(),
                    nick: self.sender_nick(room_id, &item.sender),
                    event_id: event_id.as_str().to_string(),
                });
            }
        }
        out
    }

    /// Display name already stored for `sender` in this room. Empty and
    /// missing names stay `None`. This does not query the network and
    /// does not invent a nick from the mxid.
    fn sender_nick(&self, room_id: &RoomId, sender: &UserId) -> Option<String> {
        let name = self
            .driver.core
            .room_state(room_id)?
            .members
            .get(sender)?
            .displayname
            .as_deref()?
            .trim();
        if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        }
    }

    fn note_already_present(&mut self) {
        self.load_routine_woken();
        self.load_leader_prompted();
    }

    /// Load [`ROUTINE_WOKEN_FILE`]. A missing file means seed once tip/history
    /// has filled the timeline (see [`Self::wake_inbound`]).
    fn load_routine_woken(&mut self) {
        let path = self.dir.join(ROUTINE_WOKEN_FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) if !text.trim().is_empty() => {
                for line in text.lines() {
                    let Some((room, event)) = line.split_once('\t') else {
                        continue;
                    };
                    if room.is_empty() || event.is_empty() {
                        continue;
                    }
                    self.routine_sent.insert(format!("{room}\n{event}"));
                }
                self.routine_woken_seed_pending = false;
                // Tip/history after restart can surface rows the ledger never
                // saw; silence them for the first drive instead of re-POSTing.
                self.routine_restart_catchup = true;
            }
            Ok(_) | Err(_) => {
                // Missing or empty ledger: seed once tip/history fills the timeline.
                self.routine_woken_seed_pending = true;
                self.routine_restart_catchup = false;
            }
        }
    }

    /// Mark every inbound plaintext except the newest in each room as already
    /// woken, and persist. The newest still fires once (then
    /// [`Self::remember_routine_wake`] lasting across restarts). Mirrors
    /// [`Self::seed_leader_prompted_except_newest`].
    fn seed_routine_woken_from_timeline(&mut self) {
        let path = self.dir.join(ROUTINE_WOKEN_FILE);
        let items = self.inbound_plaintexts();
        let mut newest: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for item in &items {
            newest.insert(item.room_id.clone(), item.key.clone());
        }
        let mut lines = String::new();
        for item in &items {
            if newest.get(&item.room_id) == Some(&item.key) {
                continue;
            }
            self.routine_sent.insert(item.key.clone());
            if let Some((room, event)) = item.key.split_once('\n') {
                lines.push_str(room);
                lines.push('\t');
                lines.push_str(event);
                lines.push('\n');
            }
        }
        let _ = std::fs::write(path, lines);
        self.routine_woken_seed_pending = false;
    }

    fn remember_routine_wake(&mut self, key: &str) {
        self.routine_sent.insert(key.to_string());
        let Some((room, event)) = key.split_once('\n') else {
            return;
        };
        if room.is_empty() || event.is_empty() {
            return;
        }
        let path = self.dir.join(ROUTINE_WOKEN_FILE);
        let mut file = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(file) => file,
            Err(_) => return,
        };
        use std::io::Write;
        let _ = write!(file, "{room}\t{event}\n");
    }

    /// Keys already given to `session/prompt`. A missing file is the first
    /// run of this trigger: older rows stay quiet, and the newest inbound
    /// text in each room is left unmarked so the trigger fires for it.
    fn load_leader_prompted(&mut self) {
        let path = self.dir.join(LEADER_PROMPTED_FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                for line in text.lines() {
                    let Some((room, event)) = line.split_once('\t') else {
                        continue;
                    };
                    if room.is_empty() || event.is_empty() {
                        continue;
                    }
                    self.leader_sent.insert(format!("{room}\n{event}"));
                }
            }
            Err(_) => self.seed_leader_prompted_except_newest(&path),
        }
    }

    fn seed_leader_prompted_except_newest(&mut self, path: &Path) {
        let items = self.inbound_plaintexts();
        let mut newest: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for item in &items {
            newest.insert(item.room_id.clone(), item.key.clone());
        }
        let mut lines = String::new();
        for item in &items {
            if newest.get(&item.room_id) == Some(&item.key) {
                continue;
            }
            self.leader_sent.insert(item.key.clone());
            if let Some((room, event)) = item.key.split_once('\n') {
                lines.push_str(room);
                lines.push('\t');
                lines.push_str(event);
                lines.push('\n');
            }
        }
        let _ = std::fs::write(path, lines);
    }

    fn remember_leader_prompt(&mut self, key: &str) {
        self.leader_sent.insert(key.to_string());
        let Some((room, event)) = key.split_once('\n') else {
            return;
        };
        if room.is_empty() || event.is_empty() {
            return;
        }
        let path = self.dir.join(LEADER_PROMPTED_FILE);
        let mut file = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(file) => file,
            Err(_) => return,
        };
        use std::io::Write;
        let _ = write!(file, "{room}\t{event}\n");
    }

    /// Posts and/or prompts each new inbound plaintext. A missing URL or
    /// socket skips that trigger. A failed trigger is remembered on
    /// [`Self::wake_note`] and retried on a later [`Self::drive`]. The
    /// timeline row stays either way.
    /// An empty `leader-prompted` was often written before any timeline
    /// row existed. Once history is in memory, keep every inbound except
    /// the newest in each room off the leader.
    fn arm_unprompted_newest(&mut self) {
        if (self.leader_sock.is_none() && self.wake_chain.is_none()) || !self.leader_sent.is_empty() {
            return;
        }
        if self.inbound_plaintexts().is_empty() {
            return;
        }
        let path = self.dir.join(LEADER_PROMPTED_FILE);
        self.seed_leader_prompted_except_newest(&path);
    }

    #[cfg_attr(not(feature = "wake-grok"), allow(unused_variables))]
    fn wake_inbound(&mut self) {
        if self.routine_url.is_none() && self.leader_sock.is_none() && self.wake_chain.is_none() {
            return;
        }
        if self.routine_restart_catchup && self.routine_url.is_some() {
            // Existing ledger + tip/history catch-up: persist every inbound
            // key without POSTing. Cleared when this drive finishes.
            for item in self.inbound_plaintexts() {
                if !self.routine_sent.contains(&item.key) {
                    self.remember_routine_wake(&item.key);
                }
            }
        } else if self.routine_woken_seed_pending && self.routine_url.is_some() {
            // Tip/history may have just filled an empty timeline. Mark older
            // rows woken without POSTing; newest still fires once, then the
            // ledger persists across restarts.
            if !self.inbound_plaintexts().is_empty() {
                self.seed_routine_woken_from_timeline();
            }
        }
        self.arm_unprompted_newest();
        let url = self.routine_url.clone();
        let bearer = self.routine_bearer.clone();
        let sock = self.leader_sock.clone();
        let cwd = self.leader_cwd.clone();
        let session_id = self.session_id.clone();
        let items = self.inbound_plaintexts();
        for item in items {
            if let Some(url) = url.as_deref() {
                // Restart catch-up already remembered keys; skip POSTs.
                if !self.routine_restart_catchup && !self.routine_sent.contains(&item.key) {
                    let from_nick = mxid_localpart(&item.from).to_string();
                    let to = self.nick.clone();
                    let reply = to.as_deref().map(|to| reply_hint(to, &from_nick));
                    let wake = DecryptedWake {
                        body: &item.body,
                        from: &item.from,
                        nick: item.nick.as_deref(),
                        event_id: &item.event_id,
                        room: Some(&item.room_id),
                        from_nick: Some(&from_nick),
                        to: to.as_deref(),
                        reply: reply.as_deref(),
                    };
                    match post_decrypted_with_bearer(
                        url,
                        &wake,
                        bearer.as_ref().map(|token| token.as_str()),
                    ) {
                        Ok(()) => {
                            self.remember_routine_wake(&item.key);
                            self.wake_log.push(WakeAttempt {
                                event_id: item.event_id.clone(),
                                status: Some(200),
                            });
                        }
                        Err(err) => {
                            let status = match &err {
                                ShellError::RoutineStatus(code) => Some(*code),
                                _ => None,
                            };
                            self.wake_log.push(WakeAttempt {
                                event_id: item.event_id.clone(),
                                status,
                            });
                            self.wake_note = Some(clip_public(err.to_string()));
                        }
                    }
                }
            }
            if let Some(sock) = sock.as_deref() {
                if !self.leader_sent.contains(&item.key) {
                    let cwd = cwd.clone().or_else(|| {
                        std::env::current_dir()
                            .ok()
                            .map(|path| path.display().to_string())
                    });
                    let Some(cwd) = cwd.filter(|cwd| !cwd.is_empty()) else {
                        self.wake_note = Some("leader cwd is empty".to_string());
                        continue;
                    };
                    #[cfg(feature = "wake-grok")]
                    {
                    match mail4agent_grok::wake_decrypted_room_blocking(
                        sock,
                        &session_id,
                        &cwd,
                        &item.body,
                    ) {
                        Ok(()) => {
                            self.remember_leader_prompt(&item.key);
                        }
                        Err(err) => {
                            self.wake_note = Some(clip_public(err.to_string()));
                        }
                    }
                    #[cfg(not(feature = "wake-grok"))]
                    {
                        let _ = (sock, &session_id, &cwd);
                        self.wake_note = Some("this build was made without feature wake-grok".to_string());
                    }
                    }
                }
            }
            if sock.is_none() && !self.leader_sent.contains(&item.key) {
                let Some((session, mut chain)) = self.wake_chain.take() else {
                    continue;
                };
                let from_nick = mxid_localpart(&item.from).to_string();
                let letter = provider::WakeLetter {
                    body: &item.body,
                    from_nick: &from_nick,
                    event_id: &item.event_id,
                    room: Some(&item.room_id),
                };
                match chain.wake(&session, &letter) {
                    Ok((id, outcome)) => {
                        self.remember_leader_prompt(&item.key);
                        let how = match outcome {
                            provider::WakeOutcome::Delivered => "delivered",
                            provider::WakeOutcome::Queued(_) => "queued",
                        };
                        self.wake_route = Some(format!("{id} {how}"));
                    }
                    Err(err) => {
                        self.wake_note = Some(clip_public(err.to_string()));
                    }
                }
                self.wake_chain = Some((session, chain));
            }
        }
    }
}

struct InboundPlaintext {
    room_id: String,
    key: String,
    body: String,
    from: String,
    nick: Option<String>,
    event_id: String,
}

fn membership_name(membership: &Membership) -> &'static str {
    match membership {
        Membership::Invite => "invite",
        Membership::Join => "join",
        Membership::Knock => "knock",
        Membership::Leave => "leave",
        Membership::Ban => "ban",
        Membership::Unknown => "unknown",
    }
}

fn outcome_name(state: &SendState) -> String {
    match state {
        SendState::Sent => "sent".to_string(),
        SendState::Sending | SendState::LocalEcho => "sending".to_string(),
        SendState::Failed { reason } => format!("failed:{reason}"),
    }
}

fn parse_base_url(raw: &str) -> Result<reqwest::Url, ShellError> {
    let url = reqwest::Url::parse(raw).map_err(|_| ShellError::BaseUrl)?;
    match url.scheme() {
        "http" | "https" => {}
        _ => return Err(ShellError::BaseUrl),
    }
    if url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ShellError::BaseUrl);
    }
    Ok(url)
}

struct RegisteredSession {
    user_id: String,
    device_id: DeviceId,
    bearer: Zeroizing<String>,
    /// Identity mode: the nick the operator assigned.
    nick: String,
    /// The backend that logged in; it executes this session's requests from now on.
    backend: Arc<dyn Backend>,
}

/// Identity mode: the client's own identity logs in by signature (enrolling first when it has to).
#[cfg(any(feature = "tier-server", feature = "tier-matrix"))]
fn identity_session(config: &SessionConfig, auth: &IdentityAuth) -> Result<RegisteredSession, ShellError> {
    let fail = |e: AgentError| ShellError::Register(clip_public(e.to_string()));
    parse_base_url(&config.homeserver_url)?;
    let ids = m4a_agent::IdentityStore::new(store_key::vault(&config.store_root)?);
    let backend: Arc<dyn Backend> = match auth.tier {
        #[cfg(feature = "tier-server")]
        m4a_agent::BackendKind::Server => Arc::new(m4a_agent::backend::server::ServerBackend::new(&config.homeserver_url).map_err(fail)?),
        // The domain's `.well-known` may name the real server; the spec prefix and sliding sync are
        // asked of the server, never assumed.
        #[cfg(feature = "tier-matrix")]
        m4a_agent::BackendKind::Matrix => Arc::new(m4a_agent::backend::matrix::MatrixBackend::discover(&config.homeserver_url).map_err(fail)?),
        #[allow(unreachable_patterns)]
        _ => return Err(ShellError::Register("this build does not include that tier".into())),
    };
    let mut id = ids.resolve(&config.session_id, auth.tier, backend.server_ref()).map_err(fail)?;
    if !id.enrolled && id.requested_nick != auth.nick_request {
        id.requested_nick = auth.nick_request.clone();
    }
    let session = backend.ensure_session(&ids, &mut id, auth.invite.as_ref().map(|i| i.as_str())).map_err(fail)?;
    // The invite is spent; the file the operator left is not kept.
    let _ = std::fs::remove_file(invite_path(&config.store_root, &config.session_id));
    ids.adopt_nick(&mut id, &session.nick).map_err(fail)?;
    let (user_id, device_raw) = match (&session.user_id, &session.device_id) {
        (Some(u), Some(d)) => (u.clone(), d.clone()),
        _ => {
            backend.whoami().map_err(fail)?
        }
    };
    if user_id.is_empty() || device_raw.is_empty() {
        return Err(ShellError::Register("whoami missed an id".into()));
    }
    Ok(RegisteredSession { user_id, device_id: DeviceId::parse(&device_raw)?, bearer: session.token.clone(), nick: session.nick, backend })
}

#[cfg(not(any(feature = "tier-server", feature = "tier-matrix")))]
fn identity_session(_: &SessionConfig, _: &IdentityAuth) -> Result<RegisteredSession, ShellError> {
    Err(ShellError::Register("this build has no tier for identity login".into()))
}

fn register_session(config: &SessionConfig) -> Result<RegisteredSession, ShellError> {
    identity_session(config, &config.identity)
}

fn clip_public(text: String) -> String {
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

fn fs_create_dir(dir: &Path) -> Result<(), ShellError> {
    std::fs::create_dir_all(dir)?;
    Ok(())
}

/// Why opening the client store, releasing a send, or posting a routine failed.
/// The seal key and the device bearer are never included.
#[derive(Debug, thiserror::Error)]
pub enum ShellError {
    /// No session id, so there is nothing to hash.
    #[error("session id is empty")]
    EmptySession,
    /// [`STORE_ROOT_ENV`] is unset outside tests.
    #[error("store root is unset")]
    StoreRoot,
    /// [`HOMESERVER_URL_ENV`] and toml `homeserver_url` are both unset.
    #[error("homeserver url is unset")]
    HomeserverUrl,
    /// [`BOT_NAME_ENV`] is unset. The display name is required for a web session.
    #[error("bot display name is unset")]
    BotName,
    /// The display name did not yield a nick.
    #[error("nick could not be derived from the bot display name")]
    Nick,
    /// The host's session list was missing or refused. No bearer is included.
    #[error("session list: {0}")]
    SessionList(String),
    /// Homeserver register failed. The text is a status and errcode, not a bearer.
    #[error("homeserver register failed: {0}")]
    Register(String),
    /// No session nick matched.
    #[error("no session with that nick")]
    UnknownNick,
    /// A direct room was not opened or its encrypted send did not finish.
    #[error("direct room was not ready")]
    Dm,
    /// Toml for the homeserver URL could not be read.
    #[error("config: {0}")]
    Config(String),
    /// The bearer is empty or not a single header value.
    #[error("device token is empty or not a single header value")]
    DeviceToken,
    /// `base_url` is not an `http` or `https` origin.
    #[error("base url must be http or https")]
    BaseUrl,
    /// A record key tried to leave the store directory.
    #[error("record key escapes the store directory")]
    BadRecordKey,
    /// The routine URL is not an `http` or `https` URL this shell can post to.
    #[error("routine url is not an http or https url")]
    RoutineUrl,
    /// Node CLI open path saw a routine URL or bearer. The value is not included.
    #[error("node cli does not take a routine url")]
    NodeRoutine,
    /// The local gateway did not yield a routine. No token, URL, or key.
    #[error("gateway: {0}")]
    Gateway(String),
    /// The routine bearer is not a single header value. The value is not included.
    #[error("routine bearer is empty or not a single header value")]
    RoutineBearer,
    /// The routine answered once and was not a success. The body is not included.
    #[error("routine status {0}")]
    RoutineStatus(u16),
    /// The routine socket or TLS handshake failed. The body is not included.
    #[error("routine post failed: {0}")]
    RoutineTransport(String),
    /// A homeserver call failed before a status line. The body is not included.
    #[error("homeserver http failed: {0}")]
    Http(String),
    /// The engine rejected a successful HTTP body. Long blobs are omitted.
    #[error("homeserver response was not ingested: {0}")]
    Ingest(String),
    /// Reading or writing the store directory failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The seal did not authenticate. A different session id produces this.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The engine rejected the command or could not load the Olm account.
    #[error(transparent)]
    Messenger(#[from] MessengerError),
}

impl From<AgentError> for ShellError {
    fn from(err: AgentError) -> Self {
        match err {
            AgentError::Transport(text) => ShellError::Http(text),
            AgentError::Ingest(text) => ShellError::Ingest(text),
            other => ShellError::Register(clip_public(other.to_string())),
        }
    }
}

fn persist(dir: &Path, core: &mut MessengerCore<SealedRecordCodec>) -> Result<(), ShellError> {
    while let Some(batch) = core.take_flush_batch() {
        for record in &batch.records {
            let path = record_path(dir, &record.key)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, &record.bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        for key in &batch.deletes {
            let path = record_path(dir, key)?;
            if path.exists() {
                std::fs::remove_file(path)?;
            }
        }
        core.ack_flush(batch.id);
    }
    Ok(())
}

/// Files in a session directory that are not sealed records.
const NOT_RECORDS: &[&str] = &[
    machine::WAKE_KEYCHAIN_FILE,
    machine::STORE_LOCK_FILE,
    LEADER_PROMPTED_FILE,
    ROUTINE_WOKEN_FILE,
];

/// Event ids this process has already handed to the leader. Presence in the
/// timeline is not a prompt. One line is `room \t event_id`.
const LEADER_PROMPTED_FILE: &str = "leader-prompted";
/// Persisted `room\tevent_id` lines: routine webhook already woke this key.
/// Without it, restart + tip-page re-POSTs historical plaintext to the routine.
const ROUTINE_WOKEN_FILE: &str = "routine-woken";

fn read_records(dir: &Path) -> Result<Vec<SealedRecord>, ShellError> {
    let mut records = Vec::new();
    if dir.exists() {
        walk(dir, dir, &mut records)?;
    }
    Ok(records)
}

fn walk(dir: &Path, root: &Path, records: &mut Vec<SealedRecord>) -> Result<(), ShellError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk(&path, root, records)?;
            continue;
        }
        // Keychain and lock files share the session directory; they are
        // not sealed records.
        if dir == root
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| NOT_RECORDS.contains(&name))
        {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .map_err(|_| ShellError::BadRecordKey)?;
        let key = rel
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        let bytes = std::fs::read(&path)?;
        records.push(SealedRecord {
            key: RecordKey::new(key),
            bytes,
        });
    }
    Ok(())
}

fn record_path(dir: &Path, key: &RecordKey) -> Result<PathBuf, ShellError> {
    let rel = Path::new(key.as_str());
    if rel.is_absolute()
        || rel.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(ShellError::BadRecordKey);
    }
    Ok(dir.join(rel))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_config_is_identity_only_and_reads_no_secret() {
        let get = |extra: &'static [(&'static str, &'static str)]| {
            move |key: &str| {
                extra.iter().find(|(k, _)| *k == key).map(|(_, v)| v.to_string()).or_else(|| match key {
                    SESSION_ID_ENV => Some("web-session-1".to_string()),
                    STORE_ROOT_ENV => Some("/tmp/m4a-root".to_string()),
                    // Retired inputs are never consulted, even when present.
                    "M4A_PRODUCT_PASSWORD" | "M4A_PRODUCT_TOKEN" | "M4A_DEVICE_TOKEN" => Some("must-not-be-read".to_string()),
                    _ => None,
                })
            }
        };
        let config = SessionConfig::from_lookup(get(&[(HOMESERVER_URL_ENV, "http://127.0.0.1:9")]), None).expect("config");
        assert_eq!(config.store_dir(), session_store_dir(Path::new("/tmp/m4a-root"), "web-session-1"));
        assert!(!format!("{config:?}").contains("must-not-be-read"));
        assert_eq!(config.identity.tier, m4a_agent::BackendKind::Server);
        let matrix = SessionConfig::from_lookup(get(&[(PRODUCT_URL_ENV, "http://127.0.0.1:8"), (TIER_ENV, "matrix")]), None).expect("matrix");
        assert_eq!(matrix.identity.tier, m4a_agent::BackendKind::Matrix);
        assert!(SessionConfig::from_lookup(get(&[(TIER_ENV, "other"), (PRODUCT_URL_ENV, "http://127.0.0.1:8")]), None).is_err());
        let from_toml = SessionConfig::from_lookup(get(&[]), Some("homeserver_url = \"http://127.0.0.1:9\"\nother = \"ignored\"\n")).expect("toml url");
        assert_eq!(from_toml.homeserver_url, "http://127.0.0.1:9");
        assert!(SessionConfig::from_lookup(get(&[]), None).is_err(), "no server given");
    }
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;

    fn plain(base: &str, token: &str) -> Arc<dyn Backend> {
        Arc::new(m4a_agent::backend::attached::AttachedBackend::with_prefix(m4a_agent::BackendKind::Server, base, token, false).expect("backend"))
    }

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(name: &str) -> TempDir {
        let dir = TempDir(std::env::temp_dir().join(format!(
            "mail4agent-messenger-shell-{}-{name}",
            std::process::id()
        )));
        let _ = std::fs::remove_dir_all(&dir.0);
        dir
    }

    fn open_alice(dir: &Path, session: &str) -> OpenedStore {
        let device = DeviceId::parse("DEVICE1").expect("device id");
        OpenedStore::open(
            dir,
            session,
            device,
            "@alice:localhost",
            "localhost",
            plain("http://127.0.0.1:9", "fake-token"),
            "fake-token",
        )
        .expect("open")
    }

    #[test]
    fn same_session_opens_and_a_different_session_fails_the_seal() {
        let dir = temp_dir("seal");
        open_alice(&dir.0, "session-a");
        open_alice(&dir.0, "session-a");

        let device = DeviceId::parse("DEVICE1").expect("device id");
        match OpenedStore::open(
            &dir.0,
            "session-b",
            device,
            "@alice:localhost",
            "localhost",
            plain("http://127.0.0.1:9", "fake-token"),
            "fake-token",
        ) {
            Err(ShellError::Store(StoreError::CodecOpen { .. })) => {}
            Ok(_) => panic!("different session opened the sealed store"),
            Err(err) => panic!("expected seal auth failure, got {err}"),
        }
    }

    #[test]
    fn two_sessions_under_one_root_seal_and_reopen_only_with_their_own_id() {
        let root = temp_dir("isolate");
        let dir_a = session_store_dir(&root.0, "session-a");
        let dir_b = session_store_dir(&root.0, "session-b");
        assert_ne!(dir_a, dir_b);
        assert_eq!(dir_a.parent(), Some(root.0.as_path()));
        assert_eq!(dir_b.parent(), Some(root.0.as_path()));
        assert_eq!(session_store_dir(&root.0, "session-a"), dir_a);
        let slipped = session_store_dir(&root.0, "../session-a");
        assert_eq!(slipped.parent(), Some(root.0.as_path()));
        let name = slipped.file_name().expect("name").to_string_lossy();
        assert_eq!(name.len(), 64);
        assert!(name.chars().all(|ch| ch.is_ascii_hexdigit()));

        let bearer = "isolation-bearer-7c2e";
        let device = DeviceId::parse("DEVICE1").expect("device id");
        let open_with = |dir: &Path, session: &str| {
            OpenedStore::open(
                dir,
                session,
                device.clone(),
                "@alice:localhost",
                "localhost",
                plain("http://127.0.0.1:9", bearer),
                bearer,
            )
        };
        open_with(&dir_a, "session-a").expect("seal a");
        open_with(&dir_b, "session-b").expect("seal b");
        open_with(&dir_a, "session-a").expect("reopen a");
        open_with(&dir_b, "session-b").expect("reopen b");

        for (dir, session) in [(&dir_a, "session-b"), (&dir_b, "session-a")] {
            match open_with(dir, session) {
                Err(ShellError::Store(StoreError::CodecOpen { .. })) => {}
                Ok(_) => panic!("{session} opened the other sealed store"),
                Err(err) => panic!("expected seal auth failure, got {err}"),
            }
        }

        fn contains_bearer(dir: &Path, needle: &str) -> bool {
            if !dir.exists() {
                return false;
            }
            for entry in std::fs::read_dir(dir).expect("read") {
                let entry = entry.expect("entry");
                let path = entry.path();
                if path.to_string_lossy().contains(needle) {
                    return true;
                }
                if path.is_dir() {
                    if contains_bearer(&path, needle) {
                        return true;
                    }
                } else if std::fs::read(&path)
                    .expect("file")
                    .windows(needle.len())
                    .any(|window| window == needle.as_bytes())
                {
                    return true;
                }
            }
            false
        }
        assert!(
            !contains_bearer(&root.0, bearer),
            "raw bearer was written under the store root"
        );
    }

    #[test]
    fn post_decrypted_reaches_the_loopback_routine() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            sock.set_read_timeout(Some(Duration::from_secs(2)))
                .expect("timeout");
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = sock.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(header_end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            if name.eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    if buf.len() >= header_end + 4 + length {
                        let body = buf[header_end + 4..header_end + 4 + length].to_vec();
                        let _ = sock.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        return (headers, body);
                    }
                }
            }
            (String::new(), buf)
        });

        let wake = RoutineWake {
            url: format!("http://{addr}/routine"),
        };
        post_decrypted(
            &wake.url,
            &DecryptedWake {
                body: "hello-from-room",
                from: "@bob:localhost",
                nick: None,
                event_id: "$m1:localhost",
                ..Default::default()
            },
        )
        .expect("post");
        let (headers, body) = server.join().expect("listener stopped");
        assert!(headers.starts_with("POST /routine HTTP/1.1"), "{headers}");
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("content-type: application/json"),
            "{headers}"
        );
        assert!(
            !headers.to_ascii_lowercase().contains("authorization"),
            "routine post must not add a bearer"
        );
        assert!(
            !headers.to_ascii_lowercase().contains("x-automation-key"),
            "routine post must not add a key without a bearer"
        );
        assert!(!headers.contains("/mail/send"), "{headers}");
        assert_wake_json(
            &body,
            "hello-from-room",
            "@bob:localhost",
            "$m1:localhost",
            None,
        );
    }

    #[test]
    fn post_decrypted_attempts_https_against_a_local_self_signed_listener() {
        let dir = temp_dir("https");
        std::fs::create_dir_all(&dir.0).expect("dir");
        let cert = dir.0.join("cert.pem");
        let key = dir.0.join("key.pem");
        let generated = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key.to_str().expect("utf-8"),
                "-out",
                cert.to_str().expect("utf-8"),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=127.0.0.1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("openssl req");
        assert!(generated.success(), "openssl did not write a local cert");

        let probe = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        let mut server = Command::new("openssl")
            .args([
                "s_server",
                "-accept",
                &format!("127.0.0.1:{port}"),
                "-cert",
                cert.to_str().expect("utf-8"),
                "-key",
                key.to_str().expect("utf-8"),
                "-www",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("openssl s_server");
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_secs(3) {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }

        let err = post_decrypted(
            &format!("https://127.0.0.1:{port}/hook"),
            &DecryptedWake {
                body: "hello-https",
                from: "@bob:localhost",
                nick: None,
                event_id: "$m1:localhost",
                ..Default::default()
            },
        )
        .expect_err("a self-signed cert must not verify");
        let _ = server.kill();
        let _ = server.wait();
        assert!(
            !matches!(err, ShellError::RoutineUrl),
            "https was refused before the client tried it: {err}"
        );
        let text = err.to_string().to_ascii_lowercase();
        assert!(
            text.contains("cert")
                || text.contains("tls")
                || text.contains("handshake")
                || text.contains("ssl")
                || text.contains("unknownissuer")
                || text.contains("invalidpeer"),
            "https did not reach a tls failure: {err}"
        );
    }

    #[test]
    fn a_base_url_carries_no_fragment_credentials_or_query() {
        assert!(parse_base_url("http://127.0.0.1:9").is_ok());
        assert!(parse_base_url("http://127.0.0.1:9/#other").is_err());
        assert!(parse_base_url("http://u:p@127.0.0.1:9").is_err());
        assert!(parse_base_url("ftp://127.0.0.1:9").is_err());
    }

    #[test]
    fn send_message_releases_a_matrix_room_send() {
        let dir = temp_dir("send");
        let mut store = open_alice(&dir.0, "session-a");
        let released = store
            .send_room_message("!room:localhost", "hello room", 0)
            .expect("release");
        let send = released
            .iter()
            .find(|request| request.kind == OutgoingRequestKind::RoomSend)
            .unwrap_or_else(|| {
                panic!(
                    "engine did not release a RoomSend: {:?}",
                    released
                        .iter()
                        .map(|request| request.kind)
                        .collect::<Vec<_>>()
                )
            });
        assert!(
            send.path.starts_with("/_matrix/client/v3/rooms/")
                && send.path.contains("/send/m.room.message/"),
            "not a matrix room send: {}",
            send.path
        );
        assert!(!send.path.contains("/mail/send"), "{}", send.path);
        assert!(!send.path.contains("/admin/listener"), "{}", send.path);
        let body = send.body.as_ref().expect("room send body");
        assert_eq!(body["msgtype"], "m.text");
        assert_eq!(body["body"], "hello room");
    }

    #[test]
    fn drive_performs_the_released_request_with_bearer_and_no_matrix_prefix() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen_worker = Arc::clone(&seen);
        listener.set_nonblocking(true).expect("nonblocking");
        let server = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            loop {
                if std::time::Instant::now() > deadline {
                    break;
                }
                let sock = match listener.accept() {
                    Ok((sock, _)) => sock,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                        continue;
                    }
                    Err(_) => break,
                };
                let mut sock = sock;
                let _ = sock.set_nonblocking(false);
                let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
                let mut buf = Vec::new();
                let mut tmp = [0u8; 2048];
                loop {
                    let n = sock.read(&mut tmp).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(header_end) =
                        buf.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                if name.eq_ignore_ascii_case("content-length") {
                                    value.trim().parse::<usize>().ok()
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        if buf.len() >= header_end + 4 + length {
                            let body = buf[header_end + 4..header_end + 4 + length].to_vec();
                            let first = headers.lines().next().unwrap_or("").to_string();
                            let bearer_ok = headers.lines().any(|line| {
                                let (name, value) = line.split_once(':').unwrap_or(("", ""));
                                name.eq_ignore_ascii_case("authorization")
                                    && value.trim() == "Bearer fake-token"
                            });
                            let note = format!(
                                "{first} bearer_ok={bearer_ok} body={}",
                                String::from_utf8_lossy(&body)
                            );
                            seen_worker.lock().expect("seen").push(note);
                            let request = first;
                            let response_body = if request.contains("/send/") {
                                br#"{"event_id":"$e:localhost"}"#.to_vec()
                            } else if request.contains("/keys/") {
                                br#"{"one_time_key_counts":{"signed_curve25519":50}}"#.to_vec()
                            } else {
                                br#"{"next_batch":"s1","device_one_time_keys_count":{"signed_curve25519":50},"device_unused_fallback_key_types":["signed_curve25519"]}"#.to_vec()
                            };
                            let head = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                response_body.len()
                            );
                            let _ = sock.write_all(head.as_bytes());
                            let _ = sock.write_all(&response_body);
                            break;
                        }
                    }
                }
            }
        });

        let dir = temp_dir("drive");
        let device = DeviceId::parse("DEVICE1").expect("device id");
        let mut store = OpenedStore::open(
            &dir.0,
            "session-a",
            device,
            "@alice:localhost",
            "localhost",
            plain(&format!("http://{addr}"), "fake-token"),
            "fake-token",
        )
        .expect("open");
        store
            .dispatch(
                MessengerCommand::SendMessage {
                    room_id: RoomId::parse("!room:localhost").expect("room"),
                    message: OutgoingMessage {
                        kind: MessageKind::Text,
                        body: "hello room".to_string(),
                        reply_to: None,
                        edit_of: None,
                    },
                    txn_id: None,
                },
                0,
            )
            .expect("dispatch");
        store.drive(0, false).expect("drive");
        thread::sleep(Duration::from_millis(200));
        drop(store);
        let _ = server.join();
        let seen = seen.lock().expect("seen");
        assert!(
            seen.iter().any(|line| {
                line.contains("PUT /client/v3/rooms/")
                    && line.contains("/send/m.room.message/")
                    && line.contains("bearer_ok=true")
                    && line.contains("hello room")
                    && !line.contains("/_matrix")
            }),
            "released room send was not performed: {seen:?}"
        );
        assert!(
            seen.iter().all(|line| !line.contains("/_matrix")),
            "prefix was not stripped: {seen:?}"
        );
    }

    struct Hit {
        headers: String,
        body: Vec<u8>,
    }

    fn read_http(sock: &mut std::net::TcpStream) -> Option<(String, Vec<u8>)> {
        let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
        let mut buf = Vec::new();
        let mut tmp = [0u8; 2048];
        loop {
            let n = sock.read(&mut tmp).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(header_end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        if name.eq_ignore_ascii_case("content-length") {
                            value.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                if buf.len() >= header_end + 4 + length {
                    let body = buf[header_end + 4..header_end + 4 + length].to_vec();
                    return Some((headers, body));
                }
            }
        }
        None
    }

    fn write_http(sock: &mut std::net::TcpStream, status: &str, body: &[u8]) {
        let head = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = sock.write_all(head.as_bytes());
        let _ = sock.write_all(body);
    }

    fn assert_wake_json(bytes: &[u8], body: &str, from: &str, event_id: &str, nick: Option<&str>) {
        let parsed: serde_json::Value = serde_json::from_slice(bytes).expect("json wake");
        assert_eq!(parsed["body"], body);
        assert_eq!(parsed["from"], from);
        assert_eq!(parsed["event_id"], event_id);
        match nick {
            Some(nick) => assert_eq!(parsed["nick"], nick),
            None => assert!(
                parsed.get("nick").is_none() || parsed["nick"].is_null(),
                "unknown nick must be omitted or null, not invented: {parsed}"
            ),
        }
    }

    fn sync_with_text_nick(body: &str, nick: Option<&str>) -> Vec<u8> {
        let mut state = Vec::new();
        if let Some(nick) = nick {
            state.push(serde_json::json!({
                "event_id": "$mem:localhost",
                "type": "m.room.member",
                "state_key": "@bob:localhost",
                "sender": "@bob:localhost",
                "origin_server_ts": 1,
                "content": { "membership": "join", "displayname": nick }
            }));
        }
        serde_json::json!({
            "next_batch": "s1",
            "rooms": {
                "join": {
                    "!r:localhost": {
                        "state": { "events": state },
                        "timeline": {
                            "events": [{
                                "event_id": "$m1:localhost",
                                "type": "m.room.message",
                                "sender": "@bob:localhost",
                                "origin_server_ts": 10,
                                "content": { "msgtype": "m.text", "body": body }
                            }]
                        }
                    }
                }
            },
            "device_one_time_keys_count": { "signed_curve25519": 50 },
            "device_unused_fallback_key_types": ["signed_curve25519"]
        })
        .to_string()
        .into_bytes()
    }

    fn sync_empty() -> Vec<u8> {
        serde_json::json!({
            "next_batch": "s2",
            "device_one_time_keys_count": { "signed_curve25519": 50 },
            "device_unused_fallback_key_types": ["signed_curve25519"]
        })
        .to_string()
        .into_bytes()
    }

    fn spawn_homeserver(text: &'static str) -> (String, Arc<AtomicBool>, thread::JoinHandle<()>) {
        spawn_homeserver_nick(text, None)
    }

    fn spawn_homeserver_nick(
        text: &'static str,
        nick: Option<&'static str>,
    ) -> (String, Arc<AtomicBool>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        listener.set_nonblocking(true).expect("nonblocking");
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(8);
            while !flag.load(Ordering::Relaxed) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut sock, _)) => {
                        let _ = sock.set_nonblocking(false);
                        let Some((headers, _)) = read_http(&mut sock) else {
                            continue;
                        };
                        let line = headers.lines().next().unwrap_or("");
                        let resp = if line.contains("/sync") && line.contains("since=") {
                            sync_empty()
                        } else if line.contains("/sync") {
                            sync_with_text_nick(text, nick)
                        } else if line.contains("/keys/") {
                            br#"{"one_time_key_counts":{"signed_curve25519":50}}"#.to_vec()
                        } else {
                            b"{}".to_vec()
                        };
                        write_http(&mut sock, "200 OK", &resp);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(15));
                    }
                    Err(_) => break,
                }
            }
        });
        (format!("http://{addr}"), done, handle)
    }

    fn spawn_routine() -> (
        String,
        Arc<Mutex<Vec<Hit>>>,
        Arc<AtomicBool>,
        thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        listener.set_nonblocking(true).expect("nonblocking");
        let hits = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&hits);
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(8);
            while !flag.load(Ordering::Relaxed) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut sock, _)) => {
                        let _ = sock.set_nonblocking(false);
                        if let Some((headers, body)) = read_http(&mut sock) {
                            recorded.lock().expect("hits").push(Hit { headers, body });
                            let _ = sock.write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            );
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(15));
                    }
                    Err(_) => break,
                }
            }
        });
        (format!("http://{addr}/routine"), hits, done, handle)
    }

    fn stop(flag: &AtomicBool, handle: thread::JoinHandle<()>) {
        flag.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }

    fn open_against(base: &str, dir: &Path, session: &str) -> OpenedStore {
        let device = DeviceId::parse("DEVICE1").expect("device id");
        OpenedStore::open(
            dir,
            session,
            device,
            "@alice:localhost",
            "localhost",
            plain(base, "fake-token"),
            "fake-token",
        )
        .expect("open")
    }

    #[test]
    fn inbound_room_text_goes_through_the_provider_chain_once() {
        let (base, home_done, home) = spawn_homeserver("wake-chain");
        let dir = temp_dir("wake-chain");
        let inbox_dir = dir.0.join("inbox");
        let mut store = open_against(&base, &dir.0, "session-c");
        let session = provider::ProviderSession {
            kind: provider::SessionKind::local(provider::ProviderKind::Codex),
            session_id: "thread-c".into(),
            nick: "builder".into(),
            cwd: None,
            headless: false,
        };
        let host = provider::HostEnv {
            surface: provider::Surface::Local,
            vendor: None,
            os: "linux",
        };
        let config = provider::AdapterConfig {
            inbox_dir: Some(inbox_dir.clone()),
            spawn_program: Some("/bin/false".into()),
            ..provider::AdapterConfig::default()
        };
        let chain = provider::plan_chain(&session, &host, &config);
        store.set_wake_chain(session, chain);
        assert_eq!(store.wake_chain_ids()[0], "codex-app-server-turn");
        store.drive(1_000, false).expect("drive");
        store.drive(3_000, false).expect("drive again");
        let route = store.take_wake_route();
        let note = store.wake_note().unwrap_or("").to_string();
        drop(store);
        stop(&home_done, home);
        // No app-server and no hook armed: the durable queue took it, once.
        assert_eq!(route.as_deref(), Some("inbox-queue queued"), "note={note}");
        let letters = provider::inbox::drain(&inbox_dir);
        assert_eq!(letters.len(), 1);
        assert!(letters[0].letter.prompt.ends_with("wake-chain"));
        assert!(letters[0].letter.prompt.contains("m4a-send --as builder"));
    }

    #[test]
    fn inbound_room_text_hits_the_routine_once() {
        let (base, home_done, home) = spawn_homeserver("wake-plain");
        let (routine, hits, routine_done, routine_thread) = spawn_routine();
        let dir = temp_dir("wake-once");
        let mut store = open_against(&base, &dir.0, "session-a");
        store.set_wake(SessionWake {
            routine_url: Some(routine),
            ..SessionWake::default()
        });
        store.drive(1_000, false).expect("drive");
        store.drive(3_000, false).expect("drive again");
        let note = store.wake_note().unwrap_or("").to_string();
        let saw_text = store.texts().iter().any(|text| text.body == "wake-plain");
        let trace = store.http_trace();
        drop(store);
        stop(&routine_done, routine_thread);
        stop(&home_done, home);
        assert!(
            saw_text,
            "engine did not surface the inbound text; http={trace:?} note={note}"
        );
        let hits = hits.lock().expect("hits");
        assert_eq!(
            hits.len(),
            1,
            "routine was not hit exactly once; note={note}"
        );
        let hit = &hits[0];
        assert!(
            hit.headers.starts_with("POST /routine HTTP/1.1"),
            "{}",
            hit.headers.lines().next().unwrap_or("")
        );
        assert!(
            !hit.headers.to_ascii_lowercase().contains("authorization"),
            "no bearer was passed, so the routine post must not send one"
        );
        assert!(
            !hit.headers
                .to_ascii_lowercase()
                .contains("x-automation-key"),
            "no bearer was passed, so the routine post must not send a key"
        );
        assert!(!hit.headers.contains("/mail/send"));
        assert!(!hit.headers.contains("/admin/listener"));
        assert!(
            hit.headers
                .to_ascii_lowercase()
                .contains("content-type: application/json"),
            "{}",
            hit.headers
        );
        assert_wake_json(
            &hit.body,
            "wake-plain",
            "@bob:localhost",
            "$m1:localhost",
            None,
        );
    }

    #[test]
    fn routine_wake_stays_once_across_store_reopen() {
        let (base, home_done, home) = spawn_homeserver("wake-persist");
        let (routine, hits, routine_done, routine_thread) = spawn_routine();
        let dir = temp_dir("wake-persist");
        let mut store = open_against(&base, &dir.0, "session-a");
        store.set_wake(SessionWake {
            routine_url: Some(routine.clone()),
            ..SessionWake::default()
        });
        store.drive(1_000, false).expect("drive");
        let ledger = dir.0.join("routine-woken");
        assert!(
            ledger.is_file(),
            "successful wake must persist routine-woken"
        );
        drop(store);
        let mut store = open_against(&base, &dir.0, "session-a");
        store.set_wake(SessionWake {
            routine_url: Some(routine),
            ..SessionWake::default()
        });
        store.drive(1_000, false).expect("drive again");
        store.drive(3_000, false).expect("drive third");
        let note = store.wake_note().unwrap_or("").to_string();
        drop(store);
        stop(&routine_done, routine_thread);
        stop(&home_done, home);
        let hits = hits.lock().expect("hits");
        assert_eq!(
            hits.len(),
            1,
            "reopen must not re-POST the same event; note={note} hits={}",
            hits.len()
        );
    }

    #[test]
    fn inbound_room_text_posts_the_sender_nick_the_shell_already_has() {
        let (base, home_done, home) = spawn_homeserver_nick("wake-named", Some("Alice"));
        let (routine, hits, routine_done, routine_thread) = spawn_routine();
        let dir = temp_dir("wake-nick");
        let mut store = open_against(&base, &dir.0, "session-a");
        store.set_wake(SessionWake {
            routine_url: Some(routine),
            ..SessionWake::default()
        });
        store.drive(1_000, false).expect("drive");
        let note = store.wake_note().unwrap_or("").to_string();
        drop(store);
        stop(&routine_done, routine_thread);
        stop(&home_done, home);
        let hits = hits.lock().expect("hits");
        assert_eq!(
            hits.len(),
            1,
            "routine was not hit exactly once; note={note}"
        );
        assert!(
            !hits[0]
                .headers
                .to_ascii_lowercase()
                .contains("authorization"),
            "no bearer was passed"
        );
        assert_wake_json(
            &hits[0].body,
            "wake-named",
            "@bob:localhost",
            "$m1:localhost",
            Some("Alice"),
        );
    }

    #[test]
    fn no_routine_url_posts_nothing() {
        let (base, home_done, home) = spawn_homeserver("wake-plain");
        let (_routine, hits, routine_done, routine_thread) = spawn_routine();
        let dir = temp_dir("wake-none");
        let mut store = open_against(&base, &dir.0, "session-a");
        store.set_wake(SessionWake::default());
        store.drive(1_000, false).expect("drive");
        let saw_text = store.texts().iter().any(|text| text.body == "wake-plain");
        let trace = store.http_trace();
        drop(store);
        stop(&routine_done, routine_thread);
        stop(&home_done, home);
        assert!(
            saw_text,
            "missing routine url dropped the inbound text; http={trace:?}"
        );
        let hits = hits.lock().expect("hits");
        assert!(hits.is_empty(), "a post happened with no routine url");
    }

    #[test]
    fn routine_bearer_header_is_sent_only_when_the_caller_passed_one() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let (headers, body) = read_http(&mut sock).expect("request");
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            (headers, body)
        });
        let bearer = "env-bearer";
        post_decrypted_with_bearer(
            &format!("http://{addr}/routine"),
            &DecryptedWake {
                body: "letter",
                from: "@bob:localhost",
                nick: Some("Bob"),
                event_id: "$m1:localhost",
                ..Default::default()
            },
            Some(bearer),
        )
        .expect("post");
        let (headers, body) = server.join().expect("server");
        let line = headers
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            .expect("authorization header");
        let (name, value) = line.split_once(':').expect("header");
        assert!(name.eq_ignore_ascii_case("authorization"));
        assert_eq!(value.trim(), format!("Bearer {bearer}"));
        let automation = headers
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("x-automation-key:"))
            .expect("automation key header");
        let (name, value) = automation.split_once(':').expect("header");
        assert!(name.eq_ignore_ascii_case("x-automation-key"));
        assert_eq!(value.trim(), bearer);
        assert_eq!(
            headers
                .lines()
                .filter(|line| line.to_ascii_lowercase().starts_with("authorization:"))
                .count(),
            1
        );
        assert_eq!(
            headers
                .lines()
                .filter(|line| line.to_ascii_lowercase().starts_with("x-automation-key:"))
                .count(),
            1
        );
        assert_wake_json(
            &body,
            "letter",
            "@bob:localhost",
            "$m1:localhost",
            Some("Bob"),
        );
    }

    #[test]
    fn post_decrypted_omits_a_missing_or_blank_nick() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let mut bodies = Vec::new();
            for _ in 0..2 {
                let (mut sock, _) = listener.accept().expect("accept");
                let (headers, body) = read_http(&mut sock).expect("request");
                assert!(
                    !headers.to_ascii_lowercase().contains("authorization"),
                    "no bearer was passed"
                );
                assert!(
                    !headers.to_ascii_lowercase().contains("x-automation-key"),
                    "no bearer was passed"
                );
                let _ = sock.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                bodies.push(body);
            }
            bodies
        });
        let url = format!("http://{addr}/routine");
        post_decrypted(
            &url,
            &DecryptedWake {
                body: "plain",
                from: "@bob:localhost",
                nick: None,
                event_id: "$m1:localhost",
                ..Default::default()
            },
        )
        .expect("missing nick");
        post_decrypted(
            &url,
            &DecryptedWake {
                body: "plain",
                from: "@bob:localhost",
                nick: Some("   "),
                event_id: "$m1:localhost",
                ..Default::default()
            },
        )
        .expect("blank nick");
        let bodies = server.join().expect("server");
        for body in &bodies {
            assert_wake_json(body, "plain", "@bob:localhost", "$m1:localhost", None);
        }
    }

    #[cfg(all(unix, feature = "wake-grok"))]
    #[test]
    fn inbound_room_text_prompts_the_leader_socket_once() {
        use std::os::unix::net::{UnixListener, UnixStream};

        fn frame_read(sock: &mut UnixStream) -> Option<Vec<u8>> {
            let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));
            let mut len_buf = [0u8; 4];
            sock.read_exact(&mut len_buf).ok()?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > 1_000_000 {
                return None;
            }
            let mut buf = vec![0u8; len];
            sock.read_exact(&mut buf).ok()?;
            Some(buf)
        }

        fn frame_write(sock: &mut UnixStream, value: &serde_json::Value) {
            let bytes = serde_json::to_vec(value).expect("json");
            let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
            out.extend_from_slice(&bytes);
            sock.write_all(&out).expect("write");
            sock.flush().expect("flush");
        }

        fn serve_one(sock: &mut UnixStream, prompts: &Mutex<Vec<String>>) {
            let Some(bytes) = frame_read(sock) else {
                return;
            };
            let register: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            assert_eq!(register["type"], "register");
            frame_write(
                sock,
                &serde_json::json!({"type": "registered", "ready": true}),
            );
            loop {
                let Some(bytes) = frame_read(sock) else {
                    break;
                };
                let value: serde_json::Value = match serde_json::from_slice(&bytes) {
                    Ok(value) => value,
                    Err(_) => break,
                };
                if value.get("type").and_then(|item| item.as_str()) == Some("disconnect") {
                    break;
                }
                if value.get("type").and_then(|item| item.as_str()) != Some("acp") {
                    continue;
                }
                let payload = value
                    .get("payload")
                    .and_then(|item| item.as_str())
                    .unwrap_or("");
                let inner: serde_json::Value = serde_json::from_str(payload).unwrap_or_default();
                if inner.get("method").and_then(|item| item.as_str()) == Some("session/prompt") {
                    let text = inner["params"]["prompt"][0]["text"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let session = inner["params"]["sessionId"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    prompts
                        .lock()
                        .expect("prompts")
                        .push(format!("{session} {text}"));
                }
                let id = inner.get("id").cloned().unwrap_or(serde_json::json!(null));
                let body = serde_json::json!({"jsonrpc":"2.0","id": id, "result": {}}).to_string();
                frame_write(sock, &serde_json::json!({"type":"acp","payload": body}));
            }
        }

        let dir = temp_dir("leader");
        let sock_dir = dir.0.join("sock");
        std::fs::create_dir_all(&sock_dir).expect("dir");
        let path = sock_dir.join("leader.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
        let recorded = Arc::clone(&prompts);
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        let leader = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(8);
            while !flag.load(Ordering::Relaxed) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut sock, _)) => {
                        let _ = sock.set_nonblocking(false);
                        serve_one(&mut sock, &recorded);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(15));
                    }
                    Err(_) => break,
                }
            }
        });

        let (base, home_done, home) = spawn_homeserver("wake-leader");
        let mut store = open_against(&base, &dir.0.join("store"), "session-a");
        store.set_wake(SessionWake {
            leader_sock: Some(path),
            leader_cwd: Some("/tmp".to_string()),
            ..SessionWake::default()
        });
        store.drive(1_000, false).expect("drive");
        store.drive(3_000, false).expect("drive again");
        let note = store.wake_note().unwrap_or("").to_string();
        let saw_text = store.texts().iter().any(|text| text.body == "wake-leader");
        drop(store);
        stop(&done, leader);
        stop(&home_done, home);
        assert!(
            saw_text,
            "engine did not surface the inbound text; note={note}"
        );
        let prompts = prompts.lock().expect("prompts");
        assert_eq!(
            prompts.as_slice(),
            ["session-a wake-leader"],
            "leader prompt was not the decrypted text once; note={note}"
        );
    }
}
