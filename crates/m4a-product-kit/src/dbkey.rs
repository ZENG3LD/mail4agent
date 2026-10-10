//! Key handling for the encrypted stores of a product server. The storage engine itself is
//! `tesserax-store` (SQLCipher through its `cipher-native` feature, one writer, WAL, batching);
//! this module only turns a hex key from the environment into its [`DbConfig`], so a product
//! does not hand-roll that glue. The key is never a constant and never printed.

use std::sync::Arc;

use tesserax_store::keysource::StaticKeySource;
use tesserax_store::DbConfig;

/// Parses a raw 32-byte SQLCipher key given as 64 hex characters.
pub fn parse_key(hex: &str) -> Result<[u8; 32], String> {
    let h = hex.trim();
    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("database key must be 64 hex characters (32 bytes)".into());
    }
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).map_err(|_| "database key must be hex".to_string())?;
    }
    Ok(key)
}

/// Encrypted store at `path`, keyed by `key_hex`.
pub fn config(path: &str, key_hex: &str) -> Result<DbConfig, String> {
    Ok(DbConfig::encrypted_native(path, Arc::new(StaticKeySource(parse_key(key_hex)?))))
}

/// Encrypted store at `path`, keyed by the environment variable `var` (its value is not echoed in errors).
pub fn config_from_env(path: &str, var: &str) -> Result<DbConfig, String> {
    let v = std::env::var(var).map_err(|_| format!("{var} is required"))?;
    config(path, &v).map_err(|e| format!("{var}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn keys_are_exactly_32_bytes_of_hex() {
        assert!(parse_key(K).is_ok());
        assert!(parse_key("00ff").is_err());
        assert!(parse_key(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn an_encrypted_store_needs_its_key() {
        let path = format!("/tmp/m4a-kit-key-{}.db", std::process::id());
        let other = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
        {
            let db = tesserax_store::Db::open(&config(&path, K).unwrap()).unwrap();
            db.write_blocking(|c| c.execute_batch("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('plain-marker-value');")).unwrap();
        }
        assert!(tesserax_store::Db::open(&config(&path, K).unwrap()).is_ok());
        assert!(tesserax_store::Db::open(&config(&path, other).unwrap()).is_err());
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.starts_with(b"SQLite format 3") && !raw.windows(12).any(|w| w == b"plain-marker"));
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path}{ext}"));
        }
    }
}
