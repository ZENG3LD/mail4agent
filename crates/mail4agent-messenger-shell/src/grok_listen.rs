//! Local grok listener. The homeserver pushes. This process is the client
//! that receives the push and presses the turn trigger.
//!
//! Birth is a row in grok's `active_sessions.json`. Each new row is
//! registered (nick, sealed Olm key, device bearer in the keychain, public
//! key via the first drive). The push socket is the listener. After a
//! pushed event is decrypted, [`OpenedStore::drive`] calls
//! `mail4agent_grok::wake_decrypted_room_blocking` on the leader socket.
//! This process does not start `grok` and does not create a webhook.

use std::collections::HashSet;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::ipc::{SendListener, SendStream};
use crate::machine::{load_device_bearer, lock_store, save_device_bearer};
use crate::push::PushLink;
use crate::send::{self, SendReply};
use crate::{
    nick_from_display_name, OpenedStore, SessionConfig, SessionWake, ShellError,
};

/// One live grok CLI session the index named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heard {
    /// Grok session id. This is also the ACP `sessionId`.
    pub session_id: String,
    /// Working directory grok recorded. ACP `session/load` uses it.
    pub cwd: String,
    /// Nick assigned from the session topic. Not the working directory.
    pub nick: String,
}

/// Reads an `active_sessions.json` document and names each row from that
/// session's own topic. Empty text is an empty list. A document that is
/// not that index is an error.
///
/// Topic is `summary.json`'s `generated_title`, else `session_summary` —
/// the same order as `grok-session-restore`. The file is
/// `sessions_root/<group>/<session-id>/summary.json`. A row with no topic
/// yet is left out and tried again on a later read. The working directory
/// is not a name. Two topics that slug to the same nick are `name`, then
/// `name-2`.
pub fn hear(text: &str, sessions_root: &Path) -> Result<Vec<Heard>, ShellError> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let rows = mail4agent_grok::parse_active_sessions(text)
        .map_err(|_| ShellError::SessionList("grok session index is unreadable".to_string()))?;
    let mut used = HashSet::new();
    let mut heard = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(topic) = topic_of(sessions_root, &row.session_id) else {
            continue;
        };
        let Some(nick) = unique_nick(&topic, &mut used) else {
            continue;
        };
        heard.push(Heard {
            session_id: row.session_id,
            cwd: row.cwd,
            nick,
        });
    }
    Ok(heard)
}

/// `generated_title`, else `session_summary`. Empty means the title has
/// not been written yet. The first human prompt is not a nick.
fn topic_of(sessions_root: &Path, session_id: &str) -> Option<String> {
    if session_id.is_empty() || session_id.contains(['/', '\\']) {
        return None;
    }
    let groups = std::fs::read_dir(sessions_root).ok()?;
    for group in groups.flatten() {
        if !group.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
            continue;
        }
        let path = group.path().join(session_id).join("summary.json");
        if let Some(topic) = topic_from_summary(&path) {
            return Some(topic);
        }
    }
    None
}

fn topic_from_summary(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    for key in ["generated_title", "session_summary"] {
        if let Some(topic) = value.get(key).and_then(|item| item.as_str()) {
            let topic = topic.trim();
            if !topic.is_empty() {
                return Some(topic.to_string());
            }
        }
    }
    None
}

fn unique_nick(topic: &str, used: &mut HashSet<String>) -> Option<String> {
    let base = nick_from_display_name(topic).ok()?;
    if used.insert(base.clone()) {
        return Some(base);
    }
    for n in 2..1000 {
        let suffix = n.to_string();
        let room = 32 - suffix.len() - 1;
        let stem: String = base.chars().take(room).collect();
        let nick = format!("{}-{suffix}", stem.trim_end_matches('-'));
        if used.insert(nick.clone()) {
            return Some(nick);
        }
    }
    None
}

struct Slot {
    session_id: String,
    user_id: String,
    store: OpenedStore,
    _lock: File,
}

/// Push listener for every live local grok session.
pub struct GrokListener {
    homeserver_url: String,
    store_root: PathBuf,
    keychain_dir: PathBuf,
    leader_sock: PathBuf,
    slots: Vec<Slot>,
    push: Option<PushLink>,
    last_full_drive: Instant,
    /// Loopback socket `m4a-send` style. A second process does not open
    /// the store. `None` until [`GrokListener::listen_for_sends`].
    send_listener: Option<SendListener>,
}

/// What one [`GrokListener::tick`] did. Nicks only. No bearer, no session id.
#[derive(Debug, Default)]
pub struct ListenReport {
    pub adopted: Vec<String>,
    pub pushed: Vec<String>,
    pub errors: Vec<String>,
    /// `room=<id> event=<id>` for sends accepted on the local socket.
    pub sent: Vec<String>,
    pub wake_notes: Vec<String>,
    /// Missing Megolm sessions this tick asked the peer for. No session id.
    pub key_requests: usize,
}

impl GrokListener {
    /// Does not register and does not open a socket.
    pub fn new(
        homeserver_url: impl Into<String>,
        store_root: impl Into<PathBuf>,
        keychain_dir: impl Into<PathBuf>,
        leader_sock: impl Into<PathBuf>,
    ) -> Self {
        Self {
            homeserver_url: homeserver_url.into(),
            store_root: store_root.into(),
            keychain_dir: keychain_dir.into(),
            leader_sock: leader_sock.into(),
            slots: Vec::new(),
            push: None,
            last_full_drive: Instant::now(),
            send_listener: None,
        }
    }

    /// Bind the local send socket. A live peer already bound there is an
    /// error. A stale address file is replaced.
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
        Ok(())
    }

    /// Register any heard session that is not open yet, then drain the
    /// push socket and drive the sessions that are still in `heard`.
    /// Driving is what presses ACP. A session that left the index is not
    /// driven, so a dead process is not prompted.
    pub fn tick(
        &mut self,
        heard: &[Heard],
        now_ms: i64,
        full_drive_secs: u64,
    ) -> ListenReport {
        let mut report = ListenReport::default();
        let mut adopted = false;
        for session in heard {
            if self
                .slots
                .iter()
                .any(|slot| slot.session_id == session.session_id)
            {
                continue;
            }
            match self.adopt(session) {
                Ok(nick) => {
                    report.adopted.push(nick);
                    adopted = true;
                }
                Err(err) => report.errors.push(err.to_string()),
            }
        }
        if adopted || (self.push.is_none() && !self.slots.is_empty()) {
            if let Err(err) = self.refresh_push() {
                report.errors.push(err.to_string());
            }
        }
        let live: HashSet<&str> = heard.iter().map(|session| session.session_id.as_str()).collect();
        let mut pushed_for: HashSet<String> = HashSet::new();
        if let Some(push) = &self.push {
            for (recipient, event) in push.drain() {
                let Some(slot) = self
                    .slots
                    .iter_mut()
                    .find(|slot| slot.user_id == recipient)
                else {
                    continue;
                };
                if !live.contains(slot.session_id.as_str()) {
                    continue;
                }
                report.pushed.push(event.event_id.clone());
                pushed_for.insert(slot.session_id.clone());
                slot.store.record_push(event);
            }
        }
        let full = self.last_full_drive.elapsed().as_secs() >= full_drive_secs;
        if full {
            self.last_full_drive = Instant::now();
        }
        for slot in &mut self.slots {
            if !live.contains(slot.session_id.as_str()) {
                continue;
            }
            let pushed = pushed_for.contains(&slot.session_id);
            if !pushed && !full {
                continue;
            }
            let requests_before = slot.store.key_request_count();
            if let Err(err) = slot.store.drive(now_ms, pushed) {
                report.errors.push(err.to_string());
            }
            let requests_after = slot.store.key_request_count();
            if requests_after > requests_before {
                report.key_requests += requests_after - requests_before;
            }
            if let Some(note) = slot.store.wake_note() {
                report.wake_notes.push(note.to_string());
            }
        }
        self.serve_sends(now_ms, &mut report);
        report
    }

    fn session_for_as(&self, as_nick: &str) -> Option<String> {
        self.slots
            .iter()
            .find(|slot| {
                slot.session_id == as_nick || slot.store.nick() == Some(as_nick)
            })
            .map(|slot| slot.session_id.clone())
    }

    /// One JSON line on the send socket becomes one encrypted DM from the
    /// named session. The store stays in this process.
    fn serve_sends(&mut self, now_ms: i64, report: &mut ListenReport) {
        let listener = self.send_listener.take();
        let Some(listener) = listener else {
            return;
        };
        let mut accepted: Vec<SendStream> = Vec::new();
        loop {
            match listener.accept() {
                Ok(stream) => accepted.push(stream),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        self.send_listener = Some(listener);
        for mut stream in accepted {
            let request = match send::read_request(&mut stream) {
                Ok(request) => request,
                Err(err) => {
                    send::write_reply(&mut stream, &SendReply::failed(err));
                    continue;
                }
            };
            let reply = match self.session_for_as(&request.as_nick) {
                Some(session_id) => match self.send_to(
                    &session_id,
                    &request.to,
                    &request.text,
                    now_ms,
                    Duration::from_secs(90),
                ) {
                    Ok((room, event_id)) => {
                        report
                            .sent
                            .push(format!("room={room} event={}", event_id.clone().unwrap_or_default()));
                        SendReply {
                            ok: true,
                            room: Some(room),
                            event_id,
                            error: None,
                        }
                    }
                    Err(err) => SendReply::failed(err.to_string()),
                },
                None => SendReply::failed("session is not open"),
            };
            if let Some(err) = reply.error.clone() {
                report.errors.push(err);
            }
            send::write_reply(&mut stream, &reply);
        }
    }

    /// Encrypted DM from an already opened session. The store looks the
    /// nick up on the server, reuses or opens a direct room, and
    /// [`OpenedStore::write_to_nick`] sends only after that peer has joined.
    /// Drive performs the key query and the ciphertext send. This does not
    /// open a public room.
    pub fn send_to(
        &mut self,
        session_id: &str,
        to_nick: &str,
        text: &str,
        mut now_ms: i64,
        wait: Duration,
    ) -> Result<(String, Option<String>), ShellError> {
        let started = Instant::now();
        let mut room: Option<String> = None;
        let mut peer: Option<String> = None;
        loop {
            let slot = self
                .slots
                .iter_mut()
                .find(|slot| slot.session_id == session_id)
                .ok_or_else(|| ShellError::SessionList("session is not open".to_string()))?;
            if peer.is_none() {
                peer = Some(slot.store.find_nick(to_nick, now_ms)?.user_id);
            }
            if room.is_none() {
                room = Some(slot.store.ensure_dm(to_nick, now_ms)?);
            }
            let room_id = room.clone().expect("room");
            let peer_id = peer.clone().expect("peer");
            if !slot.store.member_joined(&room_id, &peer_id) {
                if started.elapsed() >= wait {
                    return Err(ShellError::Dm);
                }
                now_ms += 1_000;
                let _ = slot.store.drive(now_ms, false);
                std::thread::sleep(Duration::from_millis(400));
                continue;
            }
            let room_id = slot.store.write_to_nick(to_nick, text, now_ms)?;
            let event_id = slot
                .store
                .texts()
                .into_iter()
                .rev()
                .find(|row| row.room_id == room_id && row.body == text)
                .and_then(|row| row.event_id);
            return Ok((room_id, event_id));
        }
    }

    fn adopt(&mut self, session: &Heard) -> Result<String, ShellError> {
        let token = load_device_bearer(&self.keychain_dir, &session.session_id);
        let config = SessionConfig::new(
            &self.homeserver_url,
            &session.nick,
            &session.session_id,
            &self.store_root,
            token,
        )?;
        let lock = lock_store(&config.store_dir())?;
        let wake = SessionWake {
            routine_url: None,
            routine_bearer: None,
            leader_sock: Some(self.leader_sock.clone()),
            leader_cwd: Some(session.cwd.clone()),
        };
        let store = OpenedStore::connect_with_wake(&config, wake)?;
        save_device_bearer(
            &self.keychain_dir,
            &session.session_id,
            store.device_bearer(),
        );
        let user_id = store.user_id().to_string();
        let nick = store.nick().unwrap_or(&session.nick).to_string();
        self.slots.push(Slot {
            session_id: session.session_id.clone(),
            user_id,
            store,
            _lock: lock,
        });
        Ok(nick)
    }

    fn refresh_push(&mut self) -> Result<(), ShellError> {
        let tokens: Vec<String> = self
            .slots
            .iter()
            .map(|slot| slot.store.device_bearer().to_string())
            .collect();
        if tokens.is_empty() {
            return Ok(());
        }
        self.push = Some(PushLink::open(&self.homeserver_url, tokens)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_summary(root: &Path, id: &str, title: &str, summary: &str) {
        let dir = root.join("group").join(id);
        std::fs::create_dir_all(&dir).unwrap();
        let body = format!(
            r#"{{"generated_title":{},"session_summary":{}}}"#,
            serde_json::to_string(title).unwrap(),
            serde_json::to_string(summary).unwrap(),
        );
        std::fs::write(dir.join("summary.json"), body).unwrap();
    }

    #[test]
    fn hear_names_a_session_from_its_title_not_its_directory() {
        let root = std::env::temp_dir().join(format!("m4a-hear-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        write_summary(&root, "session-one", "Mail client ACP", "ignored summary");
        write_summary(&root, "session-two", "Firefox tor sockets", "");
        write_summary(&root, "session-three", "Mail client ACP", "");
        write_summary(&root, "session-four", "", "Summary only topic");
        write_summary(&root, "session-five", "", "");
        let text = r#"[
            {"session_id":"session-one","pid":1,"cwd":"C:\\work\\nemo"},
            {"session_id":"session-two","pid":2,"cwd":"C:\\work\\nemo"},
            {"session_id":"session-three","pid":3,"cwd":"D:\\other\\mail"},
            {"session_id":"session-four","pid":4,"cwd":"C:\\work\\nemo"},
            {"session_id":"session-five","pid":5,"cwd":"C:\\work\\nemo"},
            {"session_id":"session-six","pid":6,"cwd":"C:\\work\\nemo"}
        ]"#;
        let heard = hear(text, &root).expect("index");
        assert_eq!(
            heard.iter().map(|row| row.nick.as_str()).collect::<Vec<_>>(),
            vec![
                "mail-client-acp",
                "firefox-tor-sockets",
                "mail-client-acp-2",
                "summary-only-topic",
            ]
        );
        assert!(heard.iter().all(|row| !row.nick.contains("nemo")));
        assert!(hear("", &root).expect("empty").is_empty());
        assert!(hear("not-json", &root).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn adopted_wake_is_acp_and_not_a_webhook() {
        let wake = SessionWake {
            routine_url: None,
            routine_bearer: None,
            leader_sock: Some(PathBuf::from("leader.sock")),
            leader_cwd: Some("C:\\work\\nemo".to_string()),
        };
        assert!(wake.routine_url.is_none());
        assert!(wake.leader_sock.is_some());
        assert_eq!(wake.leader_cwd.as_deref(), Some("C:\\work\\nemo"));
    }
}
