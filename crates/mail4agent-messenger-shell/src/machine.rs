//! Web machine client: one process for every bot session on this machine.
//!
//! This is not the homeserver, and it is not the node CLI
//! ([`crate::OpenedStore::connect_node_from_env`]). The host passes the
//! list, or this process reads [`SESSIONS_DIR_ENV`]. A record is the bot
//! display name and the session id. A routine URL or a bearer in the file
//! is refused. [`MachineClient::from_env`] copies [`crate::ROUTINE_URL_ENV`]
//! and [`crate::ROUTINE_BEARER_ENV`] from the process environment onto
//! those sessions, in memory only. It does not write them back and it does
//! not log them. [`crate::LEADER_SOCK_ENV`] is not this path.
//!
//! Each session still seals under [`crate::session_store_dir`]. Olm pickles
//! are not shared. While [`MachineClient::set_local_delivery`] is set, the
//! existing drive performs requests against an in-process bus instead of
//! the homeserver. Turn it off to reach a session that is not in the list.
//! The bus is called from that drive. It is not a second sync loop.

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

/// Directory of session records. Each `*.json` file is `bot_name` and
/// `session_id` only. Unset means the host passed the list to
/// [`MachineClient::open`] instead.
pub const SESSIONS_DIR_ENV: &str = "M4A_SESSIONS_DIR";

/// One bot session the host says lives on this machine.
///
/// `routine_url` and `routine_bearer` are optional and stay in memory.
/// They are not part of a session record on disk.
pub struct HostSession {
    /// Display name the host already shows (`Hostbot`, `Привет мир`).
    pub bot_name: String,
    /// Session id the host already assigned.
    pub session_id: String,
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
}

/// Reads `*.json` session records from `dir`. A file that carries anything
/// besides `bot_name` and `session_id` is refused, so a webhook URL or a
/// bearer cannot ride along in a world-readable record.
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
        out.push(HostSession::new(file.bot_name, file.session_id));
    }
    Ok(out)
}

/// [`load_session_records`] plus the host-injected routine. `get` is the
/// process environment on [`MachineClient::from_env`]. A leader socket from
/// `get` is not copied. The json files are not rewritten.
fn load_web_sessions(
    dir: &Path,
    get: impl FnMut(&str) -> Option<String>,
) -> Result<Vec<HostSession>, ShellError> {
    let mut sessions = load_session_records(dir)?;
    let wake = crate::SessionWake::web_from_lookup(get);
    for session in &mut sessions {
        session.routine_url = wake.routine_url.clone();
        session.routine_bearer = wake.routine_bearer.clone();
    }
    Ok(sessions)
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
        Ok(Self {
            sessions: opened,
            bus,
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
    /// [`HOMESERVER_URL_ENV`], [`STORE_ROOT_ENV`], and [`SESSIONS_DIR_ENV`].
    /// The routine URL and bearer are the host injection
    /// ([`crate::ROUTINE_URL_ENV`], [`crate::ROUTINE_BEARER_ENV`]), applied
    /// to every session in this process. They are not read from the json
    /// files. [`crate::LEADER_SOCK_ENV`] is not read.
    pub fn from_env() -> Result<Self, ShellError> {
        let homeserver_url = std::env::var(HOMESERVER_URL_ENV)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or(ShellError::HomeserverUrl)?;
        let store_root = std::env::var(STORE_ROOT_ENV)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or(ShellError::StoreRoot)?;
        let sessions_dir = std::env::var(SESSIONS_DIR_ENV)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ShellError::SessionList("session directory is unset".to_string()))?;
        let sessions = load_web_sessions(Path::new(&sessions_dir), |key| {
            std::env::var(key).ok().filter(|value| !value.is_empty())
        })?;
        Self::open(&homeserver_url, Path::new(&store_root), sessions)
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
    fn web_client_takes_the_routine_from_the_host_and_node_cli_refuses_it() {
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
        assert_eq!(sessions[0].routine_url.as_deref(), Some(routine));
        assert_eq!(sessions[0].routine_bearer.as_deref(), Some(bearer));
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
}
