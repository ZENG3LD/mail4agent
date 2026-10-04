//! The real, production [`RecordCodec`] — AES-256-GCM under a caller-supplied
//! 32-byte key, replacing [`crate::store::InsecurePlainCodecForTests`] for
//! anything a shell actually persists.
//!
//! # Format
//!
//! `[version: u8 = 1][nonce: 12 bytes][ciphertext || 16-byte GCM tag]` —
//! the version byte lets a future format change refuse an old record
//! outright ([`SealedRecordCodec::open`]) rather than misinterpret it.
//! The nonce is drawn from [`rand::rngs::OsRng`] on every seal and stored
//! as the prefix of the ciphertext blob. The GCM tag is appended to the
//! ciphertext by `aes-gcm`.
//!
//! # AAD binds the record to its own key
//!
//! The AAD passed to AES-256-GCM is the record's own [`RecordKey`] string,
//! verbatim. Copying one record's sealed bytes onto a different key in the
//! same store fails to open rather than decrypting as if it belonged there.
//!
//! # Where randomness enters this sans-I/O crate
//!
//! The crate doc's "no function here calls ... an RNG itself" rule is about
//! [`crate::core::MessengerCore`]'s own business logic (determinism for
//! tests and replay) — it was never a claim that the crate contains no
//! randomness anywhere. A fresh, unpredictable nonce on every single seal
//! is a hard AES-GCM safety requirement (a repeated nonce under the same
//! key breaks confidentiality outright).

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::persist::RecordKey;
use crate::store::{RecordCodec, StoreError};

/// This format's own version byte — bumped only if the sealed-record byte
/// layout itself ever changes; [`SealedRecordCodec::open`] refuses any
/// other value outright rather than guess at an unknown shape.
const FORMAT_VERSION: u8 = 1;

/// AES-GCM nonce length.
const NONCE_LEN: usize = 12;

/// One AES-256-GCM seal: a fresh nonce plus ciphertext with the GCM tag
/// appended.
struct SealedBlob {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

/// Encrypts `plaintext` under `key`, binding `aad`. A 32-byte key is the
/// AES-256 key size, so constructing the cipher cannot fail. Encryption
/// with a fresh nonce cannot fail either.
fn seal_bytes(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> SealedBlob {
    let cipher = Aes256Gcm::new_from_slice(key)
        .expect("Aes256Gcm::new_from_slice cannot fail for a 32-byte key");
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .expect("AES-256-GCM encryption cannot fail for a valid key and a fresh nonce");
    SealedBlob { nonce: nonce_bytes, ciphertext }
}

/// Decrypts a blob produced by [`seal_bytes`]. A wrong key, wrong AAD, or
/// tampered bytes returns `Err`.
fn open_bytes(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, ()> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .expect("Aes256Gcm::new_from_slice cannot fail for a 32-byte key");
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| ())
}

/// The production [`RecordCodec`]: seals every record with AES-256-GCM
/// under one 32-byte key fixed at construction — the caller's
/// [`crate::core::CoreSecrets::store_seal_key`], reached through
/// [`crate::core::MessengerCore::open_sealed`]. Does not implement `Debug`:
/// nothing should be able to print this codec's key by accident.
pub struct SealedRecordCodec {
    key: Zeroizing<[u8; 32]>,
}

impl SealedRecordCodec {
    /// Builds a codec sealing every record under `key`.
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self { key }
    }
}

impl RecordCodec for SealedRecordCodec {
    fn seal(&self, key: &RecordKey, plaintext: &[u8]) -> Vec<u8> {
        let sealed = seal_bytes(&self.key, plaintext, key.as_str().as_bytes());
        let mut out = Vec::with_capacity(1 + NONCE_LEN + sealed.ciphertext.len());
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&sealed.nonce);
        out.extend_from_slice(&sealed.ciphertext);
        out
    }

    fn open(&self, key: &RecordKey, sealed: &[u8]) -> Result<Vec<u8>, StoreError> {
        let reject = || StoreError::CodecOpen { key: key.clone() };
        let (&version, rest) = sealed.split_first().ok_or_else(reject)?;
        if version != FORMAT_VERSION {
            return Err(reject());
        }
        if rest.len() < NONCE_LEN {
            return Err(reject());
        }
        let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_bytes);
        open_bytes(&self.key, &nonce, ciphertext, key.as_str().as_bytes()).map_err(|_| reject())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn codec(key_byte: u8) -> SealedRecordCodec {
        SealedRecordCodec::new(Zeroizing::new([key_byte; 32]))
    }

    #[test]
    fn sealed_record_round_trips() {
        let codec = codec(1);
        let key = RecordKey::new("messenger/DEV1/account");
        let sealed = codec.seal(&key, b"pickled-account-bytes");
        let opened = codec.open(&key, &sealed).expect("opens under the same key and record key");
        assert_eq!(opened, b"pickled-account-bytes");
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let key = RecordKey::new("messenger/DEV1/account");
        let sealed = codec(1).seal(&key, b"secret");
        assert!(matches!(codec(2).open(&key, &sealed), Err(StoreError::CodecOpen { .. })));
    }

    #[test]
    fn record_moved_under_another_key_fails_to_open() {
        let codec = codec(1);
        let original_key = RecordKey::new("messenger/DEV1/account");
        let other_key = RecordKey::new("messenger/DEV1/backup_key");
        let sealed = codec.seal(&original_key, b"secret");
        match codec.open(&other_key, &sealed) {
            Err(StoreError::CodecOpen { key }) => assert_eq!(key, other_key),
            other => panic!("expected CodecOpen naming {other_key}, got {other:?}"),
        }
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let codec = codec(1);
        let key = RecordKey::new("messenger/DEV1/account");
        let mut sealed = codec.seal(&key, b"secret");
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(matches!(codec.open(&key, &sealed), Err(StoreError::CodecOpen { .. })));
    }

    #[test]
    fn nonces_are_unique_across_many_seals() {
        let codec = codec(1);
        let key = RecordKey::new("messenger/DEV1/account");
        let mut nonces = HashSet::new();
        for _ in 0..256 {
            let sealed = codec.seal(&key, b"same plaintext every time");
            let nonce = sealed[1..1 + NONCE_LEN].to_vec();
            assert!(nonces.insert(nonce), "a repeated nonce under the same key is an AES-GCM confidentiality break");
        }
    }

    #[test]
    fn unknown_version_is_refused_naming_the_key() {
        let codec = codec(1);
        let key = RecordKey::new("messenger/DEV1/account");
        let mut sealed = codec.seal(&key, b"secret");
        sealed[0] = 0xFF;
        match codec.open(&key, &sealed) {
            Err(StoreError::CodecOpen { key: got }) => assert_eq!(got, key),
            other => panic!("expected CodecOpen naming {key}, got {other:?}"),
        }
    }
}
