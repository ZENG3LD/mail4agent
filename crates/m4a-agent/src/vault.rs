//! The key vault: where the client keeps what the agent must never see (identity seeds, store keys,
//! session tokens). Values are looked up by label.
//!
//! [`FileVault`] is one encrypted file (AES-256-GCM) under a random master key; the master key
//! lives in the OS keychain when there is one (feature `vault-keychain`), else in a 0600 file next
//! to the vault. Once a vault has chosen its master-key home it never silently switches: a vault
//! made under the keychain that cannot reach it again is an error, not a fresh empty vault.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{AgentError, Result};

pub fn random_bytes(n: usize) -> Zeroizing<Vec<u8>> {
    let mut b = Zeroizing::new(vec![0u8; n]);
    rand::thread_rng().fill_bytes(&mut b);
    b
}

pub trait KeyVault: Send + Sync {
    fn get(&self, label: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn put(&self, label: &str, value: &[u8]) -> Result<()>;
    fn delete(&self, label: &str) -> Result<bool>;
    /// A short name for logs ("memory", "file+keychain", "file+keyfile").
    fn kind(&self) -> &'static str;
}

/// Non-persistent vault for tests and throwaway sessions.
#[derive(Default)]
pub struct MemoryVault(Mutex<HashMap<String, Vec<u8>>>);

impl MemoryVault {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyVault for MemoryVault {
    fn get(&self, label: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self.0.lock().unwrap_or_else(|e| e.into_inner()).get(label).map(|v| Zeroizing::new(v.clone())))
    }
    fn put(&self, label: &str, value: &[u8]) -> Result<()> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).insert(label.into(), value.to_vec());
        Ok(())
    }
    fn delete(&self, label: &str) -> Result<bool> {
        Ok(self.0.lock().unwrap_or_else(|e| e.into_inner()).remove(label).is_some())
    }
    fn kind(&self) -> &'static str {
        "memory"
    }
}

/// Where the vault's master key is kept.
pub trait MasterKeySource: Send + Sync {
    /// The key, created (random, 32 bytes) the first time.
    fn load_or_create(&self) -> Result<Zeroizing<Vec<u8>>>;
    fn name(&self) -> &'static str;
}

/// The master key in a file readable by the owner only.
pub struct FileMasterKey(pub PathBuf);

impl MasterKeySource for FileMasterKey {
    fn load_or_create(&self) -> Result<Zeroizing<Vec<u8>>> {
        match std::fs::read(&self.0) {
            Ok(b) if b.len() == 32 => Ok(Zeroizing::new(b)),
            Ok(_) => Err(AgentError::Vault("master key file has the wrong size".into())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let k = random_bytes(32);
                write_private(&self.0, &k)?;
                Ok(k)
            }
            Err(e) => Err(AgentError::Vault(format!("master key file: {e}"))),
        }
    }
    fn name(&self) -> &'static str {
        "keyfile"
    }
}

/// The master key in the OS keychain.
#[cfg(feature = "vault-keychain")]
pub struct KeychainMasterKey {
    pub service: String,
    pub account: String,
}

#[cfg(feature = "vault-keychain")]
impl MasterKeySource for KeychainMasterKey {
    fn load_or_create(&self) -> Result<Zeroizing<Vec<u8>>> {
        let e = |x: keyring::Error| AgentError::Vault(format!("keychain: {x}"));
        let entry = keyring::Entry::new(&self.service, &self.account).map_err(e)?;
        match entry.get_secret() {
            Ok(b) if b.len() == 32 => Ok(Zeroizing::new(b)),
            Ok(_) => Err(AgentError::Vault("keychain entry has the wrong size".into())),
            Err(keyring::Error::NoEntry) => {
                let k = random_bytes(32);
                entry.set_secret(&k).map_err(e)?;
                // Read it back: a keychain that accepts and forgets would orphan the vault.
                match entry.get_secret() {
                    Ok(b) if b[..] == k[..] => Ok(k),
                    _ => Err(AgentError::Vault("keychain did not keep the key".into())),
                }
            }
            Err(x) => Err(e(x)),
        }
    }
    fn name(&self) -> &'static str {
        "keychain"
    }
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let io = |e: std::io::Error| AgentError::Vault(format!("{}: {e}", path.display()));
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(io)?;
    }
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(io)?;
        f.write_all(data).map_err(io)?;
        f.sync_all().map_err(io)?;
    }
    std::fs::rename(&tmp, path).map_err(io)
}

const AAD: &[u8] = b"m4a-vault-v1";

/// One encrypted file holding every secret of the client, under a random master key.
pub struct FileVault {
    path: PathBuf,
    master: Box<dyn MasterKeySource>,
    kind: &'static str,
    lock: Mutex<()>,
}

impl FileVault {
    pub fn open(path: impl Into<PathBuf>, master: Box<dyn MasterKeySource>) -> Result<Self> {
        let kind = if master.name() == "keychain" { "file+keychain" } else { "file+keyfile" };
        let v = Self { path: path.into(), master, kind, lock: Mutex::new(()) };
        v.load()?; // fails now when the key does not open the file
        Ok(v)
    }

    /// The vault in `dir`: master key in the keychain when this build has one and it works,
    /// else in a key file. The choice is written down and kept (see the module docs).
    pub fn open_default(dir: &Path, service: &str) -> Result<Self> {
        let marker = dir.join("vault.home");
        let want = std::fs::read_to_string(&marker).ok().map(|s| s.trim().to_string());
        let file = || -> Box<dyn MasterKeySource> { Box::new(FileMasterKey(dir.join("vault.key"))) };
        #[cfg(feature = "vault-keychain")]
        let keychain = || -> Box<dyn MasterKeySource> { Box::new(KeychainMasterKey { service: service.to_string(), account: format!("vault:{}", dir.display()) }) };
        let path = dir.join("vault.enc");
        let (v, home) = match want.as_deref() {
            Some("keyfile") => (Self::open(&path, file())?, "keyfile"),
            #[cfg(feature = "vault-keychain")]
            Some("keychain") => (Self::open(&path, keychain())?, "keychain"),
            Some(other) => return Err(AgentError::Vault(format!("vault home {other:?} is not available in this build"))),
            None => {
                #[cfg(feature = "vault-keychain")]
                {
                    match Self::open(&path, keychain()) {
                        Ok(v) => (v, "keychain"),
                        Err(_) => (Self::open(&path, file())?, "keyfile"),
                    }
                }
                #[cfg(not(feature = "vault-keychain"))]
                {
                    let _ = service;
                    (Self::open(&path, file())?, "keyfile")
                }
            }
        };
        if want.is_none() {
            write_private(&marker, home.as_bytes())?;
        }
        Ok(v)
    }

    fn cipher(&self) -> Result<Aes256Gcm> {
        let k = self.master.load_or_create()?;
        Ok(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k)))
    }

    fn load(&self) -> Result<BTreeMap<String, String>> {
        let raw = match std::fs::read(&self.path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.cipher()?; // make sure the master key exists
                return Ok(BTreeMap::new());
            }
            Err(e) => return Err(AgentError::Vault(format!("{}: {e}", self.path.display()))),
        };
        if raw.len() < 13 {
            return Err(AgentError::Vault("vault file is truncated".into()));
        }
        let (nonce, ct) = raw.split_at(12);
        let plain = Zeroizing::new(self.cipher()?.decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: AAD }).map_err(|_| AgentError::Vault("vault does not open with its master key".into()))?);
        serde_json::from_slice(&plain).map_err(|e| AgentError::Vault(format!("vault content: {e}")))
    }

    fn store(&self, map: &BTreeMap<String, String>) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(map).map_err(|e| AgentError::Vault(e.to_string()))?);
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = self.cipher()?.encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain, aad: AAD }).map_err(|_| AgentError::Vault("encrypt failed".into()))?;
        let mut out = nonce.to_vec();
        out.extend(ct);
        write_private(&self.path, &out)
    }
}

impl KeyVault for FileVault {
    fn get(&self, label: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        Ok(self.load()?.get(label).and_then(|v| STANDARD.decode(v).ok()).map(Zeroizing::new))
    }
    fn put(&self, label: &str, value: &[u8]) -> Result<()> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut m = self.load()?;
        m.insert(label.into(), STANDARD.encode(value));
        self.store(&m)
    }
    fn delete(&self, label: &str) -> Result<bool> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut m = self.load()?;
        let had = m.remove(label).is_some();
        if had {
            self.store(&m)?;
        }
        Ok(had)
    }
    fn kind(&self) -> &'static str {
        self.kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_vault_round_trips_and_never_writes_plaintext() {
        let d = tempfile::tempdir().unwrap();
        let v = FileVault::open(d.path().join("v.enc"), Box::new(FileMasterKey(d.path().join("v.key")))).unwrap();
        assert!(v.get("a").unwrap().is_none());
        v.put("a", b"super-secret-seed").unwrap();
        v.put("b", &[1, 2, 3]).unwrap();
        assert_eq!(&v.get("a").unwrap().unwrap()[..], b"super-secret-seed");
        let raw = std::fs::read(d.path().join("v.enc")).unwrap();
        assert!(!raw.windows(12).any(|w| w == b"super-secret"));
        // A second handle (a restart) sees the same content.
        let v2 = FileVault::open(d.path().join("v.enc"), Box::new(FileMasterKey(d.path().join("v.key")))).unwrap();
        assert_eq!(&v2.get("b").unwrap().unwrap()[..], &[1, 2, 3]);
        assert!(v2.delete("a").unwrap() && !v2.delete("a").unwrap());
        assert!(v2.get("a").unwrap().is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(d.path().join("v.key")).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(d.path().join("v.enc")).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn a_wrong_or_lost_master_key_is_an_error_not_an_empty_vault() {
        let d = tempfile::tempdir().unwrap();
        let open = |k: &str| FileVault::open(d.path().join("v.enc"), Box::new(FileMasterKey(d.path().join(k))));
        open("k1").unwrap().put("a", b"x").unwrap();
        assert!(open("k2").is_err());
        // Tampering is detected too.
        let mut raw = std::fs::read(d.path().join("v.enc")).unwrap();
        let n = raw.len() - 1;
        raw[n] ^= 1;
        std::fs::write(d.path().join("v.enc"), raw).unwrap();
        assert!(open("k1").is_err());
    }

    #[test]
    fn open_default_remembers_where_the_master_key_lives() {
        let d = tempfile::tempdir().unwrap();
        // The keychain may or may not work on the machine running the tests; either way the second
        // open must find the same vault.
        let v = FileVault::open_default(d.path(), "m4a-agent-test").unwrap();
        v.put("a", b"1").unwrap();
        let kind = v.kind();
        let v = FileVault::open_default(d.path(), "m4a-agent-test").unwrap();
        assert_eq!(v.kind(), kind);
        assert_eq!(&v.get("a").unwrap().unwrap()[..], b"1");
    }
}
