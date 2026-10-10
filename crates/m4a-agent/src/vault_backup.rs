//! Encrypted backup of the whole vault: one file under a passphrase the owner holds (argon2id for
//! the key, AES-256-GCM for the content). It is the way to move a vault between master-key homes
//! and to survive a lost machine; the file is useless without the passphrase.

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{AgentError, Result};
use crate::vault::KeyVault;

const AAD: &[u8] = b"m4a-vault-backup-v1";
const MIN_PASSPHRASE: usize = 12;
const M_COST: u32 = 19_456;
const T_COST: u32 = 2;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    v: u32,
    kdf: String,
    m: u32,
    t: u32,
    salt: String,
    nonce: String,
    ct: String,
}

fn key_of(passphrase: &str, salt: &[u8], m: u32, t: u32) -> Result<Zeroizing<[u8; 32]>> {
    if passphrase.trim().len() < MIN_PASSPHRASE {
        return Err(AgentError::Vault(format!("the backup passphrase must have at least {MIN_PASSPHRASE} characters")));
    }
    let params = Params::new(m, t, 1, Some(32)).map_err(|e| AgentError::Vault(format!("kdf: {e}")))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(passphrase.trim().as_bytes(), salt, &mut *out).map_err(|e| AgentError::Vault(format!("kdf: {e}")))?;
    Ok(out)
}

/// Every entry of `vault`, encrypted under `passphrase`.
pub fn backup(vault: &dyn KeyVault, passphrase: &str) -> Result<Vec<u8>> {
    let mut all: BTreeMap<String, String> = BTreeMap::new();
    for label in vault.labels()? {
        if let Some(v) = vault.get(&label)? {
            all.insert(label, STANDARD.encode(&v[..]));
        }
    }
    let plain = Zeroizing::new(serde_json::to_vec(&all).map_err(|e| AgentError::Vault(e.to_string()))?);
    let (mut salt, mut nonce) = ([0u8; 16], [0u8; 12]);
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = key_of(passphrase, &salt, M_COST, T_COST)?;
    let ct = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key)).encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain, aad: AAD }).map_err(|_| AgentError::Vault("encrypt failed".into()))?;
    let env = Envelope { v: 1, kdf: "argon2id".into(), m: M_COST, t: T_COST, salt: STANDARD.encode(salt), nonce: STANDARD.encode(nonce), ct: STANDARD.encode(ct) };
    serde_json::to_vec(&env).map_err(|e| AgentError::Vault(e.to_string()))
}

/// Writes every entry of the backup into `vault` (an entry already there is replaced). Returns how
/// many entries were restored. A wrong passphrase or a damaged file changes nothing.
pub fn restore(vault: &dyn KeyVault, bytes: &[u8], passphrase: &str) -> Result<usize> {
    let env: Envelope = serde_json::from_slice(bytes).map_err(|_| AgentError::Vault("this is not a vault backup".into()))?;
    if env.v != 1 || env.kdf != "argon2id" || env.m > 262_144 || env.t > 10 {
        return Err(AgentError::Vault("this backup has a format this build does not read".into()));
    }
    let dec = |s: &str| STANDARD.decode(s).map_err(|_| AgentError::Vault("damaged backup".into()));
    let (salt, nonce, ct) = (dec(&env.salt)?, dec(&env.nonce)?, dec(&env.ct)?);
    if nonce.len() != 12 {
        return Err(AgentError::Vault("damaged backup".into()));
    }
    let key = key_of(passphrase, &salt, env.m, env.t)?;
    let plain = Zeroizing::new(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key)).decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: AAD }).map_err(|_| AgentError::Vault("wrong passphrase or damaged backup".into()))?);
    let all: BTreeMap<String, String> = serde_json::from_slice(&plain).map_err(|_| AgentError::Vault("damaged backup".into()))?;
    let mut decoded = Vec::with_capacity(all.len());
    for (label, v) in &all {
        decoded.push((label.clone(), dec(v)?));
    }
    for (label, v) in &decoded {
        vault.put(label, v)?;
    }
    Ok(decoded.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::MemoryVault;

    #[test]
    fn a_backup_restores_every_entry_and_only_under_its_passphrase() {
        let a = MemoryVault::new();
        a.put("identity-key/s1", b"seed-bytes").unwrap();
        a.put("store-key/s1", &[7u8; 32]).unwrap();
        let blob = backup(&a, "correct horse battery").unwrap();
        assert!(!blob.windows(10).any(|w| w == b"seed-bytes"), "no plaintext in the file");
        let b = MemoryVault::new();
        assert!(restore(&b, &blob, "wrong passphrase here").is_err());
        assert!(b.labels().unwrap().is_empty(), "a wrong passphrase writes nothing");
        assert_eq!(restore(&b, &blob, "correct horse battery").unwrap(), 2);
        assert_eq!(&b.get("identity-key/s1").unwrap().unwrap()[..], b"seed-bytes");
        assert!(backup(&a, "short").is_err(), "a short passphrase is refused");
        let mut bad = blob.clone();
        let n = bad.len() - 8;
        bad[n] ^= 1;
        assert!(restore(&MemoryVault::new(), &bad, "correct horse battery").is_err());
    }
}
