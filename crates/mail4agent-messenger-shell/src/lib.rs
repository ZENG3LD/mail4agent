//! Client holder for the messenger record-seal key, plus the one web-bot
//! wake and the room-send release.
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

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use mail4agent_messenger::store::sealed::SealedRecordCodec;
use mail4agent_messenger::{
    CoreConfig, CoreSecrets, DeviceId, Jitter, MessageKind, MessengerCommand, MessengerCore,
    MessengerError, OutgoingMessage, OutgoingRequest, RecordKey, RoomId, SealedRecord, StoreError,
    UserId,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

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
/// extra bearer. `url` is the bot's already-configured routine.
pub fn post_decrypted(url: &str, text: &str) -> Result<(), ShellError> {
    let target = parse_http_url(url)?;
    let mut stream = TcpStream::connect((target.host.as_str(), target.port))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let body = text.as_bytes();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
        path = target.path,
        host = target.host_header,
        len = body.len(),
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;
    let mut buf = [0u8; 128];
    let n = stream.read(&mut buf).unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n]);
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(ShellError::RoutineStatus(status));
    }
    Ok(())
}

struct HttpTarget {
    host: String,
    port: u16,
    host_header: String,
    path: String,
}

fn parse_http_url(url: &str) -> Result<HttpTarget, ShellError> {
    let rest = url.strip_prefix("http://").ok_or(ShellError::RoutineUrl)?;
    if rest.is_empty() || rest.contains('@') {
        return Err(ShellError::RoutineUrl);
    }
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], rest[index..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return Err(ShellError::RoutineUrl);
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            let port: u16 = port.parse().map_err(|_| ShellError::RoutineUrl)?;
            (host.to_string(), port)
        }
        _ => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return Err(ShellError::RoutineUrl);
    }
    let host_header = if port == 80 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path
    };
    Ok(HttpTarget {
        host,
        port,
        host_header,
        path,
    })
}

/// A sealed messenger core opened for one session. The Olm account was
/// loaded or created into it. Private key material stays here.
pub struct OpenedStore {
    dir: PathBuf,
    core: MessengerCore<SealedRecordCodec>,
}

struct ZeroJitter;

impl Jitter for ZeroJitter {
    fn next_unit(&mut self) -> f64 {
        0.0
    }
}

impl OpenedStore {
    /// Derives the seal key from `session_id`, reads `dir`, and opens the
    /// core. That calls [`OlmAccountState::load_or_create`] inside
    /// [`MessengerCore::open_sealed`]. A different session id cannot open
    /// records this session sealed.
    pub fn open(
        dir: &Path,
        session_id: &str,
        device_id: DeviceId,
        user_id: &str,
        server_name: &str,
    ) -> Result<Self, ShellError> {
        if session_id.is_empty() {
            return Err(ShellError::EmptySession);
        }
        fs::create_dir_all(dir)?;
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
        Ok(Self {
            dir: dir.to_path_buf(),
            core,
        })
    }

    /// Queues [`MessengerCommand::SendMessage`] and releases whatever the
    /// engine will send next. That is a room send on an unencrypted room,
    /// or the key-setup requests the engine emits first when the room is
    /// encrypted. Nothing here calls the old mailbox.
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
            .any(|request| request.kind == mail4agent_messenger::OutgoingRequestKind::RoomSend)
        {
            released.extend(self.core.releasable_requests(now_ms));
            self.persist_core()?;
        }
        Ok(released)
    }

    fn persist_core(&mut self) -> Result<(), ShellError> {
        persist(&self.dir, &mut self.core)
    }
}

/// Why opening the client store, releasing a send, or posting a routine failed.
/// The seal key is never included.
#[derive(Debug, thiserror::Error)]
pub enum ShellError {
    /// No session id, so there is nothing to hash.
    #[error("session id is empty")]
    EmptySession,
    /// A record key tried to leave the store directory.
    #[error("record key escapes the store directory")]
    BadRecordKey,
    /// The routine URL is not an `http` URL this shell can post to.
    #[error("routine url is not an http url")]
    RoutineUrl,
    /// The routine answered once and was not a success. The body is not included.
    #[error("routine status {0}")]
    RoutineStatus(u16),
    /// Reading or writing the store directory, or the routine socket, failed.
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
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, &record.bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            }
        }
        for key in &batch.deletes {
            let path = record_path(dir, key)?;
            if path.exists() {
                fs::remove_file(path)?;
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
    for entry in fs::read_dir(dir)? {
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
        let bytes = fs::read(&path)?;
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
    use mail4agent_messenger::OutgoingRequestKind;
    use std::io::Read;
    use std::net::TcpListener;
    use std::thread;

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(name: &str) -> TempDir {
        let dir = TempDir(std::env::temp_dir().join(format!(
            "mail4agent-messenger-shell-{}-{name}",
            std::process::id()
        )));
        let _ = fs::remove_dir_all(&dir.0);
        dir
    }

    fn open_alice(dir: &Path, session: &str) -> OpenedStore {
        let device = DeviceId::parse("DEVICE1").expect("device id");
        OpenedStore::open(dir, session, device, "@alice:localhost", "localhost").expect("open")
    }

    #[test]
    fn same_session_opens_and_a_different_session_fails_the_seal() {
        let dir = temp_dir("seal");
        open_alice(&dir.0, "session-a");
        open_alice(&dir.0, "session-a");

        let device = DeviceId::parse("DEVICE1").expect("device id");
        match OpenedStore::open(&dir.0, "session-b", device, "@alice:localhost", "localhost") {
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
                    released.iter().map(|r| r.kind).collect::<Vec<_>>()
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
}
