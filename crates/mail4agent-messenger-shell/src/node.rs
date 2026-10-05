//! Local Grok ACP node client: one CLI session per machine.
//!
//! Open path refuses webhook env ([`crate::SessionWake::node_cli`]),
//! registers on the homeserver, opens a push socket, and wakes the
//! already-running Grok leader over ACP (`M4A_LEADER_SOCK`). Replies go
//! through the local send socket (`m4a-send`) held by this process.
//! This is not [`crate::MachineClient`] and does not scan agents dirs or
//! create webhook routines.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::ipc::{SendListener, SendStream};
use crate::machine::{
    load_device_bearer, lock_store, save_device_bearer, KEYCHAIN_DIR_ENV,
};
use crate::push::PushLink;
use crate::send::{send_sock_path_named, SendReply, SendRequest};
use crate::{
    nonempty_var, OpenedStore, SessionConfig, SessionWake, ShellError, DEVICE_TOKEN_ENV,
    LEADER_SOCK_ENV, STORE_ROOT_ENV,
};

/// Default send-socket file name under the store root for the node client.
pub const NODE_DEFAULT_SOCK_NAME: &str = "node-client.sock";

/// How long a queued `m4a-send` waits for the peer to join a new DM.
const SEND_JOIN_WAIT_SECS: u64 = 120;

/// One local ACP node: a single [`OpenedStore`], its push link, and an
/// optional send socket for `m4a-send`.
pub struct NodeClient {
    store: OpenedStore,
    push: PushLink,
    send_listener: Option<SendListener>,
    send_sock: Option<PathBuf>,
    send_queue: Vec<PendingSend>,
    last_full_drive: Instant,
    store_root: PathBuf,
    _lock: File,
}

struct PendingSend {
    stream: SendStream,
    request: SendRequest,
    started: Instant,
    room: Option<String>,
    peer: Option<String>,
}

impl Drop for NodeClient {
    fn drop(&mut self) {
        if let Some(path) = self.send_sock.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// What one [`NodeClient::tick`] did. Event ids, room ids, and error texts
/// only — never URLs, keys, or bearers.
#[derive(Debug, Default)]
pub struct NodeTickReport {
    /// Event ids the push socket delivered this tick.
    pub pushed: Vec<String>,
    /// Room ids of DM invites joined this tick.
    pub joined: Vec<String>,
    /// Drive / send errors (clipped public text).
    pub errors: Vec<String>,
    /// Finished `m4a-send` requests as (as_nick, to, reply).
    pub sent: Vec<(String, String, SendReply)>,
    /// Last ACP / wake failure note from the store, if any.
    pub wake_note: Option<String>,
}

impl NodeClient {
    /// Open from the process environment: refuse webhook env, require the
    /// leader named by [`LEADER_SOCK_ENV`] to be listening, register + first
    /// key drive, open the push socket. Does not start `grok` and does not
    /// invent a leader. On Windows the path is only what grok hashes into
    /// a named pipe; the file does not have to exist.
    pub fn from_env() -> Result<Self, ShellError> {
        let wake = SessionWake::node_cli()?;
        let sock = wake.leader_sock.as_ref().ok_or_else(|| {
            ShellError::SessionList(format!(
                "node client requires {LEADER_SOCK_ENV} (ACP leader.sock)"
            ))
        })?;
        if !mail4agent_grok::leader_is_listening(sock) {
            return Err(ShellError::SessionList(
                "the leader is not listening; start grok with [cli] use_leader = true".to_string(),
            ));
        }

        // Host keychain may hold a previously minted bearer.
        if nonempty_var(DEVICE_TOKEN_ENV).is_none() {
            if let (Some(dir), Some(session_id)) = (
                nonempty_var(KEYCHAIN_DIR_ENV).map(PathBuf::from),
                nonempty_var(crate::SESSION_ID_ENV),
            ) {
                if let Some(token) = load_device_bearer(&dir, &session_id) {
                    std::env::set_var(DEVICE_TOKEN_ENV, token);
                }
            }
        }

        let config = SessionConfig::from_env()?;
        let lock = lock_store(&config.store_dir())?;
        let store = OpenedStore::connect_with_wake(&config, wake)?;

        if let Some(dir) = nonempty_var(KEYCHAIN_DIR_ENV).map(PathBuf::from) {
            save_device_bearer(&dir, config.session_id(), store.device_bearer());
        }

        let push = PushLink::open(config.homeserver_url(), vec![store.device_bearer().to_string()])?;
        let store_root = PathBuf::from(
            nonempty_var(STORE_ROOT_ENV).ok_or(ShellError::StoreRoot)?,
        );

        Ok(Self {
            store,
            push,
            send_listener: None,
            send_sock: None,
            send_queue: Vec::new(),
            last_full_drive: Instant::now(),
            store_root,
            _lock: lock,
        })
    }

    /// Derived nick of the one session, when register stored one.
    pub fn nick(&self) -> Option<&str> {
        self.store.nick()
    }

    /// Session id used for ACP `sessionId`.
    pub fn session_id(&self) -> &str {
        self.store.session_id()
    }

    /// Matrix user id of the open session.
    pub fn user_id(&self) -> &str {
        self.store.user_id()
    }

    /// Store root this client seals under.
    pub fn store_root(&self) -> &Path {
        &self.store_root
    }

    /// Underlying sealed store (for tests and advanced callers).
    pub fn store(&self) -> &OpenedStore {
        &self.store
    }

    /// Mutable underlying store.
    pub fn store_mut(&mut self) -> &mut OpenedStore {
        &mut self.store
    }

    /// Routine wake attempts since open (event id + HTTP status). Empty on
    /// the node path because webhook wake is refused.
    pub fn wake_log(&self) -> &[crate::WakeAttempt] {
        self.store.wake_log()
    }

    /// Last wake failure note (ACP errors), if any.
    pub fn wake_note(&self) -> Option<&str> {
        self.store.wake_note()
    }

    /// Listen for `m4a-send` on `path`. Replaces a stale socket file and
    /// refuses when another live client already holds it. Unix is a mode
    /// 0600 domain socket. Windows writes `127.0.0.1:{port}` and listens
    /// on that loopback port.
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
    /// [`NODE_DEFAULT_SOCK_NAME`] under the store root.
    pub fn listen_for_sends_from_env(&mut self) -> Result<PathBuf, ShellError> {
        let path = send_sock_path_named(
            |key| std::env::var(key).ok().filter(|value| !value.is_empty()),
            &self.store_root,
            NODE_DEFAULT_SOCK_NAME,
        );
        self.listen_for_sends(&path)?;
        Ok(path)
    }

    /// One step of the long-running node loop.
    ///
    /// Drains the push socket, drives the session (waiting on `/sync` when
    /// a push arrived so decrypt + ACP wake can run), accepts DM invites,
    /// and answers queued `m4a-send` requests. Every `full_drive_secs` a
    /// catch-up drive runs even without a push.
    pub fn tick(&mut self, now_ms: i64, full_drive_secs: u64) -> NodeTickReport {
        let mut report = NodeTickReport::default();
        let me = self.store.user_id().to_string();
        let mut pushed = false;
        for (recipient, event) in self.push.drain() {
            if recipient != me {
                continue;
            }
            report.pushed.push(event.event_id.clone());
            self.store.record_push(event);
            pushed = true;
        }

        let full = self.last_full_drive.elapsed().as_secs() >= full_drive_secs;
        if full {
            self.last_full_drive = Instant::now();
        }

        if pushed || full {
            if let Err(err) = self.store.drive(now_ms, pushed) {
                report.errors.push(err.to_string());
            } else {
                match self.store.accept_direct_invites(now_ms) {
                    Ok(joined) => report.joined.extend(joined),
                    Err(err) => report.errors.push(err.to_string()),
                }
            }
        }

        self.serve_sends(now_ms, &mut report);
        report.wake_note = self.store.wake_note().map(str::to_string);
        report
    }

    /// Blocking send from this node's nick to `to` (encrypted DM). Used when
    /// `m4a-send` falls through with no socket answer, or by callers that
    /// already hold the client.
    pub fn send_blocking(
        &mut self,
        to: &str,
        text: &str,
        wait: Duration,
    ) -> SendReply {
        let as_nick = self
            .store
            .nick()
            .unwrap_or("")
            .to_string();
        let started = Instant::now();
        let mut room = None;
        let mut peer = None;
        loop {
            let now = now_ms();
            match self.try_send(&as_nick, to, text, now, &mut room, &mut peer) {
                Some(reply) => return reply,
                None if started.elapsed() >= wait => {
                    return SendReply {
                        room,
                        ..SendReply::failed(format!("{to} has not joined the DM yet"))
                    }
                }
                None => {
                    let _ = self.store.drive(now, false);
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
    }

    fn try_send(
        &mut self,
        as_nick: &str,
        to: &str,
        text: &str,
        now_ms: i64,
        room: &mut Option<String>,
        peer: &mut Option<String>,
    ) -> Option<SendReply> {
        let own = self.store.nick().unwrap_or("");
        if !own.eq_ignore_ascii_case(as_nick) {
            return Some(SendReply::failed(format!(
                "{as_nick} is not this node client session"
            )));
        }
        if peer.is_none() {
            let mut last_err = None;
            for attempt in 0..3 {
                if attempt > 0 {
                    let _ = self.store.drive(now_ms, false);
                }
                match self.store.find_nick(to, now_ms) {
                    Ok(found) => {
                        *peer = Some(found.user_id);
                        last_err = None;
                        break;
                    }
                    Err(err) => last_err = Some(err),
                }
            }
            if let Some(err) = last_err {
                return Some(SendReply::failed(format!("find {to}: {err}")));
            }
        }
        if room.is_none() {
            match self.store.ensure_dm(to, now_ms) {
                Ok(room_id) => *room = Some(room_id),
                Err(err) => return Some(SendReply::failed(format!("open DM: {err}"))),
            }
        }
        let (room_id, peer_id) = (room.clone()?, peer.clone()?);
        if !self.store.member_joined(&room_id, &peer_id) {
            return None;
        }
        match self.store.write_to_nick(to, text, now_ms) {
            Ok(room_id) => {
                let event_id = self
                    .store
                    .texts()
                    .into_iter()
                    .rev()
                    .find(|row| row.room_id == room_id && row.body == text)
                    .and_then(|row| row.event_id);
                Some(SendReply {
                    ok: true,
                    room: Some(room_id),
                    event_id,
                    error: None,
                })
            }
            Err(err) => Some(SendReply {
                room: Some(room_id),
                ..SendReply::failed(format!("send: {err}"))
            }),
        }
    }

    fn serve_sends(&mut self, now_ms: i64, report: &mut NodeTickReport) {
        if let Some(listener) = &self.send_listener {
            loop {
                match listener.accept() {
                    Ok(mut stream) => match crate::send::read_request(&mut stream) {
                        Ok(request) => self.send_queue.push(PendingSend {
                            stream,
                            request,
                            started: Instant::now(),
                            room: None,
                            peer: None,
                        }),
                        Err(err) => {
                            crate::send::write_reply(&mut stream, &SendReply::failed(err))
                        }
                    },
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
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
                    SendReply {
                        room: pending.room.clone(),
                        ..SendReply::failed(format!("{to} has not joined the DM yet"))
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
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ROUTINE_BEARER_ENV, ROUTINE_URL_ENV, LEADER_CWD_ENV};

    #[test]
    fn node_wake_refuses_routine_env_and_keeps_leader_only() {
        match SessionWake::node_from_lookup(|key| match key {
            ROUTINE_URL_ENV => Some("http://127.0.0.1/hook".into()),
            LEADER_SOCK_ENV => Some("/tmp/leader.sock".into()),
            _ => None,
        }) {
            Ok(_) => panic!("routine url accepted"),
            Err(err) => {
                assert!(matches!(err, ShellError::NodeRoutine));
                let text = err.to_string();
                assert!(!text.contains("127.0.0.1"));
                assert!(!text.contains("hook"));
            }
        }

        match SessionWake::node_from_lookup(|key| match key {
            ROUTINE_BEARER_ENV => Some("secret-bearer".into()),
            _ => None,
        }) {
            Ok(_) => panic!("routine bearer accepted"),
            Err(err) => {
                assert!(matches!(err, ShellError::NodeRoutine));
                assert!(!err.to_string().contains("secret-bearer"));
            }
        }

        let wake = match SessionWake::node_from_lookup(|key| match key {
            LEADER_SOCK_ENV => Some("/tmp/node-leader.sock".into()),
            LEADER_CWD_ENV => Some("/tmp/work".into()),
            _ => None,
        }) {
            Ok(wake) => wake,
            Err(err) => panic!("leader only refused: {err}"),
        };
        assert!(wake.routine_url.is_none());
        assert!(wake.routine_bearer.is_none());
        assert_eq!(
            wake.leader_sock.as_deref(),
            Some(Path::new("/tmp/node-leader.sock"))
        );
        assert_eq!(wake.leader_cwd.as_deref(), Some("/tmp/work"));
    }

    #[test]
    fn node_default_sock_name_differs_from_web() {
        assert_ne!(NODE_DEFAULT_SOCK_NAME, crate::DEFAULT_SOCK_NAME);
        assert_eq!(NODE_DEFAULT_SOCK_NAME, "node-client.sock");
    }

    #[cfg(unix)]
    #[test]
    fn fake_acp_peer_answers_session_prompt_for_wake_framing() {
        use std::os::unix::net::UnixListener;
        use std::sync::{Arc, Mutex};
        use std::thread;

        use serde_json::{json, Value};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        fn encode(bytes: &[u8]) -> Vec<u8> {
            mail4agent_grok::encode_frame(bytes).expect("frame")
        }

        let dir = std::env::temp_dir().join(format!(
            "m4a-node-fake-acp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("leader.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
        let recorded = Arc::clone(&prompts);
        let server = thread::spawn(move || {
            let (sock, _) = listener.accept().expect("accept");
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("rt");
            runtime.block_on(async move {
                // Re-open as tokio stream via std → tokio conversion.
                sock.set_nonblocking(true).expect("nb");
                let mut stream = UnixStream::from_std(sock).expect("tokio");
                async fn read_value(stream: &mut UnixStream) -> Value {
                    let mut len_buf = [0u8; 4];
                    stream.read_exact(&mut len_buf).await.expect("len");
                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut buf = vec![0u8; len];
                    stream.read_exact(&mut buf).await.expect("body");
                    serde_json::from_slice(&buf).expect("json")
                }
                async fn write_value(stream: &mut UnixStream, value: &Value) {
                    let bytes = serde_json::to_vec(value).expect("json");
                    let frame = encode(&bytes);
                    stream.write_all(&frame).await.expect("write");
                    stream.flush().await.expect("flush");
                }
                let register = read_value(&mut stream).await;
                assert_eq!(register["type"], "register");
                write_value(&mut stream, &json!({"type": "registered", "ready": true})).await;
                loop {
                    let value = read_value(&mut stream).await;
                    if value.get("type").and_then(Value::as_str) == Some("disconnect") {
                        break;
                    }
                    if value.get("type").and_then(Value::as_str) != Some("acp") {
                        continue;
                    }
                    let payload = value["payload"].as_str().expect("payload");
                    let inner: Value = serde_json::from_str(payload).expect("inner");
                    if inner["method"].as_str() == Some("session/prompt") {
                        let text = inner["params"]["prompt"][0]["text"]
                            .as_str()
                            .unwrap_or("")
                            .to_string();
                        recorded.lock().expect("p").push(text);
                    }
                    let id = inner["id"].clone();
                    let body = json!({"jsonrpc":"2.0","id": id, "result": {}}).to_string();
                    write_value(&mut stream, &json!({"type":"acp","payload": body})).await;
                }
            });
        });

        mail4agent_grok::wake_decrypted_room_blocking(
            &path,
            "local-session-id",
            "/tmp",
            "hello-from-node-test",
        )
        .expect("fake peer answered");
        server.join().expect("server");
        let got = prompts.lock().expect("prompts");
        assert_eq!(got.as_slice(), ["hello-from-node-test"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
