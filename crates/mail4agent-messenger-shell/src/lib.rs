//! Client holder for the messenger record-seal key.
//!
//! `store_seal_key` is SHA-256 of the session id string. The client derives
//! it when it opens the store. It is not a passphrase, it is not stored
//! beside the records, and nothing here is a KDF or a vault.
//!
//! The private Olm account stays in this store (`OlmAccountState::load_or_create`
//! pickles it under the seal). Clients exchange only public keys with the
//! server, through the existing keys upload and keys query paths.
//!
//! The web shell's one routine URL is configured once per bot. The shell
//! posts decrypted room text to that bot's own URL and does not take a new
//! token per letter. Outbound mail to other agents is a room send
//! (`MessengerCommand::SendMessage` and `/sync`), not `POST /mail/send` and
//! not `POST /admin/listener`.

use std::fs;
use std::path::{Component, Path, PathBuf};

use mail4agent_messenger::store::sealed::SealedRecordCodec;
use mail4agent_messenger::{DeviceId, OlmAccountState, RecordKey, SealedRecord, Store, StoreError};
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

/// A sealed messenger store opened for one session. The Olm account was
/// loaded or created into it. Private key material stays here.
pub struct OpenedStore {
    /// Held so the sealed working set stays open with the Olm account.
    #[allow(dead_code)]
    store: Store<SealedRecordCodec>,
    _account: OlmAccountState,
}

impl OpenedStore {
    /// Derives the seal key from `session_id`, reads `dir`, and calls
    /// [`OlmAccountState::load_or_create`]. A different session id cannot
    /// open records this session sealed.
    pub fn open(dir: &Path, session_id: &str, device_id: DeviceId) -> Result<Self, ShellError> {
        if session_id.is_empty() {
            return Err(ShellError::EmptySession);
        }
        fs::create_dir_all(dir)?;
        let seal_key = Zeroizing::new(store_seal_key(session_id));
        let codec = SealedRecordCodec::new(seal_key);
        let records = read_records(dir)?;
        let mut store = if records.is_empty() {
            Store::new(device_id, codec)
        } else {
            Store::load(records, codec, device_id)?
        };
        let account = OlmAccountState::load_or_create(&mut store)?;
        persist(dir, &mut store)?;
        Ok(Self {
            store,
            _account: account,
        })
    }
}

/// Why opening the client store failed. The seal key is never included.
#[derive(Debug, thiserror::Error)]
pub enum ShellError {
    /// No session id, so there is nothing to hash.
    #[error("session id is empty")]
    EmptySession,
    /// A record key tried to leave the store directory.
    #[error("record key escapes the store directory")]
    BadRecordKey,
    /// Reading or writing the store directory failed.
    #[error("store directory: {0}")]
    Io(#[from] std::io::Error),
    /// The seal did not authenticate. A different session id produces this.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The pickled Olm account could not be loaded or created.
    #[error(transparent)]
    Messenger(#[from] mail4agent_messenger::MessengerError),
}

fn persist(dir: &Path, store: &mut Store<SealedRecordCodec>) -> Result<(), ShellError> {
    while let Some(batch) = store.take_flush_batch() {
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
        store.ack_flush(batch.id);
    }
    Ok(())
}

fn read_records(dir: &Path) -> Result<Vec<SealedRecord>, ShellError> {
    let mut records = Vec::new();
    walk(dir, dir, &mut records)?;
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

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn same_session_opens_and_a_different_session_fails_the_seal() {
        let dir = TempDir(
            std::env::temp_dir().join(format!("mail4agent-messenger-shell-{}", std::process::id())),
        );
        let _ = fs::remove_dir_all(&dir.0);
        let device = DeviceId::parse("DEVICE1").expect("device id");

        OpenedStore::open(&dir.0, "session-a", device.clone()).expect("first open");
        OpenedStore::open(&dir.0, "session-a", device.clone()).expect("same session reopens");

        match OpenedStore::open(&dir.0, "session-b", device) {
            Err(ShellError::Store(StoreError::CodecOpen { .. })) => {}
            Ok(_) => panic!("different session opened the sealed store"),
            Err(err) => panic!("expected seal auth failure, got {err}"),
        }
    }
}
