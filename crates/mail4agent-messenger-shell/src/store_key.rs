//! The store key. It used to be SHA-256 of the session id: anyone who could guess the id and read
//! the directory could open the store. Now it is 32 random bytes in the client's vault
//! (`<store_root>/.m4a-agent/`), and stores sealed under the old derivation are moved over,
//! one way:
//!
//! - The new key is created first. The state label `store-key-state/<session>` is written only
//!   after every record has been re-sealed, so a crash anywhere leaves the migration to run again.
//! - Each record is handled on its own: it opens under the new key (done earlier), or under the old
//!   derivation (re-sealed to a temp file, then renamed over it), or the open fails.
//! - After the state label says `v2` the old derivation is never tried again.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use m4a_agent::vault::{random_bytes, FileVault};
use m4a_agent::KeyVault;
use mail4agent_messenger::{RecordCodec, SealedRecordCodec};
use zeroize::Zeroizing;

use crate::{read_records, record_path, store_seal_key, ShellError};

fn vault_for(store_root: &Path) -> Result<Arc<FileVault>, ShellError> {
    static VAULTS: OnceLock<Mutex<HashMap<PathBuf, Arc<FileVault>>>> = OnceLock::new();
    let mut m = VAULTS.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    if let Some(v) = m.get(store_root) {
        return Ok(v.clone());
    }
    let dir = store_root.join(".m4a-agent");
    std::fs::create_dir_all(&dir)?;
    let v = Arc::new(FileVault::open_default(&dir, "m4a-agent").map_err(|e| ShellError::Register(format!("key vault: {e}")))?);
    m.insert(store_root.to_path_buf(), v.clone());
    Ok(v)
}

/// The vault shared by every session under `store_root`.
pub fn vault(store_root: &Path) -> Result<Arc<dyn KeyVault>, ShellError> {
    Ok(vault_for(store_root)? as Arc<dyn KeyVault>)
}

/// The store key of `session_id` whose store directory is `dir` (a child of the store root).
pub fn store_key(dir: &Path, session_id: &str) -> Result<Zeroizing<[u8; 32]>, ShellError> {
    let root = dir.parent().ok_or(ShellError::StoreRoot)?;
    let v = vault_for(root)?;
    let verr = |e: m4a_agent::AgentError| ShellError::Register(format!("key vault: {e}"));
    let label = format!("store-key/{session_id}");
    let state = format!("store-key-state/{session_id}");
    let key = match v.get(&label).map_err(verr)? {
        Some(k) => Zeroizing::new(<[u8; 32]>::try_from(&k[..]).map_err(|_| ShellError::Register("key vault: store key has the wrong size".into()))?),
        None => {
            let k = random_bytes(32);
            v.put(&label, &k).map_err(verr)?;
            Zeroizing::new(<[u8; 32]>::try_from(&k[..]).expect("32 bytes"))
        }
    };
    if v.get(&state).map_err(verr)?.is_none() {
        migrate(dir, &key, &store_seal_key(session_id))?;
        v.put(&state, b"v2").map_err(verr)?;
    }
    Ok(key)
}

/// Re-seals every record of `dir` that opens under `legacy` so that it opens under `new`.
fn migrate(dir: &Path, new: &[u8; 32], legacy: &[u8; 32]) -> Result<(), ShellError> {
    let new_codec = SealedRecordCodec::new(Zeroizing::new(*new));
    let old_codec = SealedRecordCodec::new(Zeroizing::new(*legacy));
    for rec in read_records(dir)? {
        if new_codec.open(&rec.key, &rec.bytes).is_ok() {
            continue;
        }
        let plain = old_codec.open(&rec.key, &rec.bytes).map_err(ShellError::Store)?;
        let path = record_path(dir, &rec.key)?;
        let tmp = path.with_extension("resealing");
        std::fs::write(&tmp, new_codec.seal(&rec.key, &plain))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail4agent_messenger::RecordKey;

    #[test]
    fn a_legacy_store_is_moved_to_the_random_key_once_and_the_derivation_stops_working() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("s");
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = SealedRecordCodec::new(Zeroizing::new(store_seal_key("sess")));
        let rk = RecordKey::new("messenger/DEV/account");
        std::fs::create_dir_all(record_path(&dir, &rk).unwrap().parent().unwrap()).unwrap();
        std::fs::write(record_path(&dir, &rk).unwrap(), legacy.seal(&rk, b"olm-account")).unwrap();

        let k = store_key(&dir, "sess").unwrap();
        assert_ne!(&k[..], &store_seal_key("sess")[..], "the key is random now");
        let bytes = std::fs::read(record_path(&dir, &rk).unwrap()).unwrap();
        assert_eq!(SealedRecordCodec::new(Zeroizing::new(*k)).open(&rk, &bytes).unwrap(), b"olm-account");
        assert!(legacy.open(&rk, &bytes).is_err(), "no longer opens with the session-id derivation");
        // Asking again changes nothing and the same key comes back.
        assert_eq!(store_key(&dir, "sess").unwrap()[..], k[..]);
        // Another session gets another key.
        assert_ne!(store_key(&root.path().join("t"), "other").unwrap()[..], k[..]);
    }

    #[test]
    fn a_crash_between_records_is_finished_on_the_next_open() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("s");
        let legacy = SealedRecordCodec::new(Zeroizing::new(store_seal_key("sess")));
        let (a, b) = (RecordKey::new("messenger/DEV/a"), RecordKey::new("messenger/DEV/b"));
        std::fs::create_dir_all(record_path(&dir, &a).unwrap().parent().unwrap()).unwrap();
        // Make the key as a first, interrupted run would have, and re-seal only record `a`.
        let v = vault_for(root.path()).unwrap();
        let k = random_bytes(32);
        v.put("store-key/sess", &k).unwrap();
        let newc = SealedRecordCodec::new(Zeroizing::new(<[u8; 32]>::try_from(&k[..]).unwrap()));
        std::fs::write(record_path(&dir, &a).unwrap(), newc.seal(&a, b"A")).unwrap();
        std::fs::write(record_path(&dir, &b).unwrap(), legacy.seal(&b, b"B")).unwrap();
        let got = store_key(&dir, "sess").unwrap();
        assert_eq!(&got[..], &k[..]);
        let bytes = std::fs::read(record_path(&dir, &b).unwrap()).unwrap();
        assert_eq!(newc.open(&b, &bytes).unwrap(), b"B");
    }
}
