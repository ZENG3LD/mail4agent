//! Client holder for the messenger record-seal key, the one web-bot wake,
//! and the HTTP a released [`OutgoingRequest`] actually performs.
//!
//! `store_seal_key` is SHA-256 of the session id string. The client derives
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
//! The device bearer stays in memory on [`OpenedStore`]. It is sent as
//! `Authorization: Bearer` and is not written next to the sealed records.
//! Paths the engine builds under `/_matrix` are sent without that prefix:
//! `mail4agent-server-bin` mounts the Client-Server router at `/client/v3`.

use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mail4agent_messenger::store::sealed::SealedRecordCodec;
use mail4agent_messenger::wire::Membership;
use mail4agent_messenger::{
    CoreConfig, CoreSecrets, HttpResponseDescriptor, ItemContent, Jitter, MessengerCore,
    MessengerError, OutgoingRequest, OutgoingRequestKind, RecordKey, SealedRecord, SendState,
    StoreError,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub use mail4agent_messenger::{
    CreateRoomKind, DeviceId, MessageKind, MessengerCommand, OutgoingMessage, RoomId, UserId,
};

/// SHA-256 of `session_id`'s UTF-8 bytes. That digest is the check that this
/// session may open the store. The bytes are not written to disk.
pub fn store_seal_key(session_id: &str) -> [u8; 32] {
    let digest = Sha256::digest(session_id.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// One URL per bot, already created. Neighbors are addressed by nick or mxid
/// on the server.
pub struct RoutineWake {
    /// The bot's own routine URL. Configured once. Not a per-letter token.
    pub url: String,
}

/// POSTs `text` once, as the raw body, to `url`. No mailbox path and no
/// extra bearer. `url` is the bot's already-configured routine. `http` and
/// `https` are both followed; anything else is refused before a socket
/// is opened.
pub fn post_decrypted(url: &str, text: &str) -> Result<(), ShellError> {
    let target = parse_routine_url(url)?;
    let client = routine_client()?;
    let response = client
        .post(target)
        .header(reqwest::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(text.to_string())
        .send()
        .map_err(|err| ShellError::RoutineTransport(public_reqwest(&err)))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(ShellError::RoutineStatus(status));
    }
    Ok(())
}

fn routine_client() -> Result<reqwest::blocking::Client, ShellError> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .http1_only()
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
    core: MessengerCore<SealedRecordCodec>,
    base_url: reqwest::Url,
    device_token: Zeroizing<String>,
    client: reqwest::blocking::Client,
    /// A `/sync` the engine already released, still on the wire. Idle
    /// long-polls are not joined unless the caller is waiting for events,
    /// so a 30s timeout does not stall key setup. The request is the one
    /// the engine built, including its timeout.
    sync_flight: Option<SyncFlight>,
    /// Kind and HTTP status of calls this store performed. No bodies.
    http_trace: Vec<(OutgoingRequestKind, u16)>,
}

struct SyncFlight {
    id: mail4agent_messenger::RequestId,
    rx: Receiver<Result<HttpResponseDescriptor, String>>,
    /// Kept so dropping the store does not detach a blocked poll without
    /// a handle the process can abandon on exit. Not joined on drop.
    _worker: JoinHandle<()>,
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
}

impl OpenedStore {
    /// Derives the seal key from `session_id`, reads `dir`, and opens the
    /// core. That calls [`OlmAccountState::load_or_create`] inside
    /// [`MessengerCore::open_sealed`]. A different session id cannot open
    /// records this session sealed.
    ///
    /// `base_url` is the homeserver origin (`http://127.0.0.1:port` or
    /// `https://...`) with no `/_matrix` prefix. `device_token` is the raw
    /// bearer. It is held in memory and not written to `dir`.
    pub fn open(
        dir: &Path,
        session_id: &str,
        device_id: DeviceId,
        user_id: &str,
        server_name: &str,
        base_url: &str,
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
        let base_url = parse_base_url(base_url)?;
        fs_create_dir(dir)?;
        let user_id = UserId::parse(user_id)?;
        let secrets = CoreSecrets {
            store_seal_key: Some(Zeroizing::new(store_seal_key(session_id))),
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
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(45))
            .http1_only()
            .build()
            .map_err(|err| ShellError::Http(clip_public(err.to_string())))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            core,
            base_url,
            device_token: Zeroizing::new(device_token.to_string()),
            client,
            sync_flight: None,
            http_trace: Vec::new(),
        })
    }

    /// Queues `command` on the engine. It does not perform HTTP; [`Self::drive`]
    /// does that for whatever the engine then releases.
    pub fn dispatch(&mut self, command: MessengerCommand, now_ms: i64) -> Result<(), ShellError> {
        self.core.dispatch(command, now_ms)?;
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
        self.core.dispatch(
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
        let mut released = self.core.releasable_requests(now_ms);
        self.persist_core()?;
        if !released
            .iter()
            .any(|request| request.kind == OutgoingRequestKind::RoomSend)
        {
            released.extend(self.core.releasable_requests(now_ms));
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
        let mut waited_long_poll = false;
        if wait_for_sync && self.sync_flight.is_some() {
            // A poll that already finished is a stale catch-up. Do not
            // count it: the caller is waiting for whatever is current,
            // which is the next `/sync` this call starts.
            waited_long_poll = self.harvest_sync(now_ms, true)?;
        } else {
            self.harvest_sync(now_ms, false)?;
        }
        for _ in 0..24 {
            let released = self.release_after_flush(now_ms)?;
            if released.is_empty() {
                break;
            }
            let (syncs, others): (Vec<_>, Vec<_>) = released
                .into_iter()
                .partition(|request| request.kind == OutgoingRequestKind::Sync);
            for request in &syncs {
                self.spawn_sync(request.clone())?;
            }
            for request in others {
                self.roundtrip(&request, now_ms)?;
            }
            self.persist_core()?;
            for request in &syncs {
                let timeout = sync_timeout_ms(request);
                let block = timeout == 0 || (wait_for_sync && !waited_long_poll);
                if block {
                    self.harvest_sync(now_ms, true)?;
                    if timeout != 0 {
                        waited_long_poll = true;
                    }
                }
            }
            self.persist_core()?;
            if let Some(err) = self.core.take_ingest_error() {
                return Err(ShellError::Ingest(clip_public(err)));
            }
        }
        Ok(())
    }

    /// Rooms this account has state for.
    pub fn rooms(&self) -> Vec<RoomView> {
        let me = self.core.user_id().clone();
        let mut rooms: Vec<RoomView> = self
            .core
            .room_ids()
            .map(|room_id| {
                let state = self.core.room_state(room_id);
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
        for room_id in self.core.room_ids() {
            let Some(timeline) = self.core.timeline(room_id) else {
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
                        });
                    }
                    ItemContent::Undecryptable { reason } => out.push(TextView {
                        room_id: room_id.as_str().to_string(),
                        body: String::new(),
                        outcome: format!("undecryptable:{reason}"),
                    }),
                    _ => {}
                }
            }
        }
        out
    }

    /// HTTP status codes this store has seen, oldest first. Bodies are not kept.
    pub fn sync_inflight(&self) -> bool {
        self.sync_flight.is_some()
    }

    pub fn http_trace(&self) -> Vec<String> {
        self.http_trace
            .iter()
            .map(|(kind, status)| format!("{kind:?} {status}"))
            .collect()
    }

    /// The last response this core failed to ingest, once.
    pub fn take_ingest_error(&mut self) -> Option<String> {
        self.core.take_ingest_error().map(clip_public)
    }

    fn persist_core(&mut self) -> Result<(), ShellError> {
        persist(&self.dir, &mut self.core)
    }

    fn release_after_flush(&mut self, now_ms: i64) -> Result<Vec<OutgoingRequest>, ShellError> {
        self.persist_core()?;
        let mut released = self.core.releasable_requests(now_ms);
        if released.is_empty() {
            self.persist_core()?;
            released = self.core.releasable_requests(now_ms);
        }
        Ok(released)
    }

    fn roundtrip(&mut self, request: &OutgoingRequest, now_ms: i64) -> Result<(), ShellError> {
        match perform_http(&self.client, &self.base_url, &self.device_token, request) {
            Ok(response) => {
                self.http_trace.push((request.kind, response.status));
                self.core.on_response(request.id.clone(), response, now_ms);
                Ok(())
            }
            Err(err) => {
                self.core.on_transport_error(&request.id, now_ms);
                Err(err)
            }
        }
    }

    fn spawn_sync(&mut self, request: OutgoingRequest) -> Result<(), ShellError> {
        if self.sync_flight.is_some() {
            self.core.on_transport_error(&request.id, 0);
            return Err(ShellError::Http(
                "a sync was already on the wire".to_string(),
            ));
        }
        let client = self.client.clone();
        let base_url = self.base_url.clone();
        let token = self.device_token.clone();
        let id = request.id.clone();
        let (tx, rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result =
                perform_http(&client, &base_url, &token, &request).map_err(|err| match err {
                    ShellError::Http(text) => text,
                    other => clip_public(other.to_string()),
                });
            let _ = tx.send(result);
        });
        self.sync_flight = Some(SyncFlight {
            id,
            rx,
            _worker: worker,
        });
        Ok(())
    }

    /// `Ok(true)` only when this call blocked on a poll that had not
    /// already finished. An already-buffered response is `Ok(false)`.
    fn harvest_sync(&mut self, now_ms: i64, wait: bool) -> Result<bool, ShellError> {
        let Some(flight) = self.sync_flight.as_ref() else {
            return Ok(false);
        };
        let (received, blocked) = if wait {
            match flight.rx.try_recv() {
                Ok(result) => (Some(result), false),
                Err(mpsc::TryRecvError::Empty) => {
                    match flight.rx.recv_timeout(Duration::from_secs(45)) {
                        Ok(result) => (Some(result), true),
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            let id = flight.id.clone();
                            self.sync_flight = None;
                            self.core.on_transport_error(&id, now_ms);
                            return Err(ShellError::Http("sync timed out".to_string()));
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            let id = flight.id.clone();
                            self.sync_flight = None;
                            self.core.on_transport_error(&id, now_ms);
                            return Err(ShellError::Http("sync worker dropped".to_string()));
                        }
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    let id = flight.id.clone();
                    self.sync_flight = None;
                    self.core.on_transport_error(&id, now_ms);
                    return Err(ShellError::Http("sync worker dropped".to_string()));
                }
            }
        } else {
            match flight.rx.try_recv() {
                Ok(result) => (Some(result), false),
                Err(mpsc::TryRecvError::Empty) => (None, false),
                Err(mpsc::TryRecvError::Disconnected) => {
                    let id = flight.id.clone();
                    self.sync_flight = None;
                    self.core.on_transport_error(&id, now_ms);
                    return Err(ShellError::Http("sync worker dropped".to_string()));
                }
            }
        };
        let Some(result) = received else {
            return Ok(false);
        };
        let flight = self.sync_flight.take().expect("flight present");
        match result {
            Ok(response) => {
                self.http_trace
                    .push((OutgoingRequestKind::Sync, response.status));
                self.core.on_response(flight.id, response, now_ms);
            }
            Err(err) => {
                self.core.on_transport_error(&flight.id, now_ms);
                return Err(ShellError::Http(err));
            }
        }
        self.persist_core()?;
        if let Some(err) = self.core.take_ingest_error() {
            return Err(ShellError::Ingest(clip_public(err)));
        }
        Ok(blocked)
    }
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
    if url.host_str().is_none() || url.query().is_some() || url.fragment().is_some() {
        return Err(ShellError::BaseUrl);
    }
    Ok(url)
}

fn sync_timeout_ms(request: &OutgoingRequest) -> u64 {
    request
        .query
        .iter()
        .find(|(name, _)| name == "timeout")
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0)
}

fn perform_http(
    client: &reqwest::blocking::Client,
    base_url: &reqwest::Url,
    device_token: &str,
    request: &OutgoingRequest,
) -> Result<HttpResponseDescriptor, ShellError> {
    let url = request_url(base_url, &request.path, &request.query)?;
    let method = reqwest::Method::from_bytes(request.method.as_str().as_bytes())
        .map_err(|_| ShellError::Http("unsupported method".to_string()))?;
    let mut header = reqwest::header::HeaderValue::from_str(&format!("Bearer {device_token}"))
        .map_err(|_| ShellError::DeviceToken)?;
    header.set_sensitive(true);
    let mut builder = client
        .request(method, url)
        .header(reqwest::header::AUTHORIZATION, header);
    if let Some(body) = &request.body {
        let bytes = serde_json::to_vec(body).map_err(|err| ShellError::Http(err.to_string()))?;
        builder = builder
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes);
    }
    let response = builder
        .send()
        .map_err(|err| ShellError::Http(clip_public(err.to_string())))?;
    let status = response.status().as_u16();
    let body = response
        .bytes()
        .map_err(|err| ShellError::Http(clip_public(err.to_string())))?
        .to_vec();
    Ok(HttpResponseDescriptor { status, body })
}

/// `/_matrix/client/v3/...` becomes `/client/v3/...` on `base_url`. The
/// server binary mounts the router at `/client/v3` and does not nest it
/// under `/_matrix`. A path that is already unprefixed is left alone.
fn request_url(
    base_url: &reqwest::Url,
    path: &str,
    query: &[(String, String)],
) -> Result<reqwest::Url, ShellError> {
    let path = path.strip_prefix("/_matrix").unwrap_or(path);
    if !path.starts_with('/') {
        return Err(ShellError::BaseUrl);
    }
    let mut raw = base_url.as_str().trim_end_matches('/').to_string();
    raw.push_str(path);
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
    reqwest::Url::parse(&raw).map_err(|_| ShellError::BaseUrl)
}

fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
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
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};

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
            "http://127.0.0.1:9",
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
            "http://127.0.0.1:9",
            "fake-token",
        ) {
            Err(ShellError::Store(StoreError::CodecOpen { .. })) => {}
            Ok(_) => panic!("different session opened the sealed store"),
            Err(err) => panic!("expected seal auth failure, got {err}"),
        }
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
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
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
        post_decrypted(&wake.url, "hello-from-room").expect("post");
        let (headers, body) = server.join().expect("listener stopped");
        assert!(headers.starts_with("POST /routine HTTP/1.1"), "{headers}");
        assert!(
            !headers.to_ascii_lowercase().contains("authorization"),
            "routine post must not add a bearer"
        );
        assert!(!headers.contains("/mail/send"), "{headers}");
        assert_eq!(String::from_utf8_lossy(&body), "hello-from-room");
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

        let err = post_decrypted(&format!("https://127.0.0.1:{port}/hook"), "hello-https")
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
    fn matrix_path_drops_the_underscore_matrix_prefix() {
        let base = reqwest::Url::parse("http://127.0.0.1:9").expect("base");
        let url = request_url(
            &base,
            "/_matrix/client/v3/sync",
            &[("timeout".to_string(), "0".to_string())],
        )
        .expect("url");
        assert_eq!(url.path(), "/client/v3/sync");
        assert!(!url.path().contains("_matrix"));
        assert_eq!(url.query(), Some("timeout=0"));
        let untouched = request_url(&base, "/client/v3/sync", &[]).expect("url");
        assert_eq!(untouched.path(), "/client/v3/sync");
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
            &format!("http://{addr}"),
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
}
