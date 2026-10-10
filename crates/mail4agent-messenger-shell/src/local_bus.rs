//! The in-process bus: a tiny homeserver inside the client process so bots on one machine reach
//! each other without a network. It is the ONLY thing in the client that links the whole
//! `mail4agent-server` crate, so it lives behind the `local-bus` feature; without the feature
//! `local_bus_off.rs` stands in and every request goes to the real server.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use mail4agent_messenger::{HttpResponseDescriptor, OutgoingRequest, OutgoingRequestKind};
use mail4agent_server::http::{hash_token, router, Homeserver};
use mail4agent_server::store::{self, create_matrix_schema};
use rusqlite::{params, Connection};
use tower::util::ServiceExt;
use zeroize::Zeroizing;

use crate::machine::Prepared;
use crate::{clip_public, percent_encode, perform_http, ShellError};

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

pub(crate) fn ensure_server_name(name: &str) -> Result<(), ShellError> {
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
    pub(crate) fn open(prepared: &[Prepared]) -> Result<Self, ShellError> {
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

    /// Adds one session opened after start, as [`Self::open`] seeds each.
    pub(crate) fn seed(&self, user_row: i64, item: &Prepared) -> Result<(), ShellError> {
        let _gate = self.gate.lock().unwrap_or_else(|err| err.into_inner());
        self.state.conn_scope(|conn: &mut rusqlite::Connection| {
        seed_session(&conn, user_row, item)
        })
    }

    pub(crate) fn set_local_only(&self, enabled: bool) {
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


