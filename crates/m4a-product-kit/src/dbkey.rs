//! Encrypted SQLite for everything this kit and its example persist.
//!
//! Every database is SQLCipher: `rusqlite` is built with `bundled-sqlcipher`
//! (never `bundled`, so a consumer gets exactly one cipher build). A connection
//! is opened with [`open_cipher`]: key first, then WAL, a busy timeout and foreign
//! keys, then a read that proves the key is right. The key comes from the caller
//! (normally [`DbKey::from_env`]); it is never a constant and never printed. In-memory
//! connections (tests) are the only plaintext databases.

use std::fmt;
use std::time::Duration;

use rusqlite::Connection;

/// Raw SQLCipher key as hex (at least 32 hex characters, even length). Debug never shows it.
#[derive(Clone)]
pub struct DbKey(String);

impl DbKey {
    pub fn from_hex(hex: &str) -> Result<Self, String> {
        let h = hex.trim();
        if h.len() < 32 || h.len() % 2 != 0 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("database key must be even-length hex of at least 32 characters".into());
        }
        Ok(Self(h.to_ascii_lowercase()))
    }

    /// Reads the key from the environment variable `var`; the value is not echoed in errors.
    pub fn from_env(var: &str) -> Result<Self, String> {
        let v = std::env::var(var).map_err(|_| format!("{var} is required"))?;
        Self::from_hex(&v).map_err(|e| format!("{var}: {e}"))
    }
}

impl fmt::Debug for DbKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DbKey(<redacted>)")
    }
}

/// Opens (or creates) the encrypted database at `path` for this connection.
/// A wrong key or a plaintext/foreign file fails here, not later.
pub fn open_cipher(path: &str, key: &DbKey) -> rusqlite::Result<Connection> {
    let c = Connection::open(path)?;
    // The hex alphabet is validated in `DbKey`, so this literal cannot be broken out of.
    c.execute_batch(&format!("PRAGMA key = \"x'{}'\";", key.0))?;
    c.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))?;
    c.pragma_update(None, "journal_mode", "WAL")?;
    c.busy_timeout(Duration::from_secs(5))?;
    c.pragma_update(None, "foreign_keys", "ON")?;
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const K2: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    #[test]
    fn key_validation_and_redaction() {
        assert!(DbKey::from_hex("abc").is_err());
        assert!(DbKey::from_hex(&"zz".repeat(20)).is_err());
        let k = DbKey::from_hex(K1).unwrap();
        assert!(!format!("{k:?}").contains("0011"));
    }

    #[test]
    fn file_is_encrypted_and_needs_its_key() {
        let path = format!("/tmp/m4a-kit-cipher-{}.db", std::process::id());
        {
            let c = open_cipher(&path, &DbKey::from_hex(K1).unwrap()).unwrap();
            c.execute_batch("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('secret-row');").unwrap();
            let mode: String = c.query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
            assert_eq!(mode.to_lowercase(), "wal");
        }
        let c = open_cipher(&path, &DbKey::from_hex(K1).unwrap()).unwrap();
        assert_eq!(c.query_row::<String, _, _>("SELECT v FROM t", [], |r| r.get(0)).unwrap(), "secret-row");
        drop(c);
        assert!(open_cipher(&path, &DbKey::from_hex(K2).unwrap()).is_err(), "wrong key must fail");
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.starts_with(b"SQLite format 3"), "header must be encrypted");
        assert!(!raw.windows(10).any(|w| w == b"secret-row"), "row text must not be readable");
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path}{ext}"));
        }
    }
}
