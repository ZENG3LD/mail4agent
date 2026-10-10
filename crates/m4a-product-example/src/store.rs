//! SQLite implementation of the kit's [`UserStore`]: the example product's own database.
//! This is part of what a real product throws away (it has its own user database). The
//! storage engine is `tesserax-store` (SQLCipher, one writer, WAL): every trait method is one
//! short closure on the writer connection, so no lock outlives a call and no async request
//! holds one across a call to the edge. The trait is synchronous, so callers on the async
//! runtime reach it through `spawn_blocking`; the engine refuses to block a runtime thread.

use m4a_product_kit::model::{StoreError, StoreResult, User, UserStore};
use tesserax_store::rusqlite::{self, params, Connection, OptionalExtension};
use tesserax_store::{Db, DbConfig};

pub struct SqliteStore {
    db: Db,
}

fn be(e: rusqlite::Error) -> StoreError {
    match &e {
        rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => StoreError::NickTaken,
        _ => StoreError::Backend(e.to_string()),
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nick TEXT NOT NULL,
    nick_ci TEXT NOT NULL UNIQUE,
    tier TEXT NOT NULL,
    secret_hash TEXT,
    nick_changes INTEGER NOT NULL DEFAULT 0,
    nick_changed_ms INTEGER NOT NULL DEFAULT 0,
    created_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
    cred_ref TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_ms INTEGER NOT NULL,
    access_expires_ms INTEGER,
    refresh_hash TEXT,
    refresh_expires_ms INTEGER
);
CREATE TABLE IF NOT EXISTS user_keys (
    key_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    label TEXT NOT NULL,
    created_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS invites (
    code_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS door_links (
    source TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (source, subject)
);
"#;

const UCOLS: &str = "id, nick, tier, nick_changes, nick_changed_ms";

fn user(r: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User { id: r.get(0)?, nick: r.get(1)?, tier: r.get(2)?, nick_changes: r.get::<_, i64>(3)? as u32, nick_changed_ms: r.get(4)? })
}

impl SqliteStore {
    /// The product database in an opened store (shared with the event queue: one writer per file).
    pub fn new(db: Db) -> Result<Self, String> {
        db.blocking(|c| {
            c.execute_batch(SCHEMA)?;
            // Databases made before expiring sessions: add the columns.
            for (col, ty) in [("access_expires_ms", "INTEGER"), ("refresh_hash", "TEXT"), ("refresh_expires_ms", "INTEGER")] {
                let have: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('credentials') WHERE name = ?1", params![col], |r| r.get::<_, i64>(0)).map(|n| n > 0)?;
                if !have {
                    c.execute_batch(&format!("ALTER TABLE credentials ADD COLUMN {col} {ty}"))?;
                }
            }
            Ok(())
        })
        .map_err(|e| e.to_string())?;
        Ok(Self { db })
    }
    /// Opens the store described by `cfg` (see `m4a_product_kit::dbkey`).
    pub fn open(cfg: &DbConfig) -> Result<Self, String> {
        Self::new(Db::open(cfg).map_err(|e| e.to_string())?)
    }
    /// Plaintext in-memory database, for tests only.
    pub fn memory() -> Result<Self, String> {
        Self::open(&DbConfig::in_memory())
    }
    /// The underlying store, to share its single writer with the event queue.
    pub fn db(&self) -> Db {
        self.db.clone()
    }
    fn with<T>(&self, f: impl FnOnce(&mut Connection) -> StoreResult<T>) -> StoreResult<T> {
        match self.db.write_blocking(|c| Ok(f(c))) {
            Ok(r) => r,
            Err(e) => Err(be(e)),
        }
    }
}

impl UserStore for SqliteStore {
    fn user_by_nick(&self, nick: &str) -> StoreResult<Option<User>> {
        self.with(|c| {
        c.query_row(&format!("SELECT {UCOLS} FROM users WHERE nick_ci = ?1"), params![nick.to_ascii_lowercase()], user).optional().map_err(be)
        })
    }
    fn insert_user(&self, nick: &str, tier: &str, secret_hash: Option<&str>, now_ms: i64) -> StoreResult<User> {
        self.with(|c| {
        c.execute("INSERT INTO users (nick, nick_ci, tier, secret_hash, created_ms) VALUES (?1, ?2, ?3, ?4, ?5)", params![nick, nick.to_ascii_lowercase(), tier, secret_hash, now_ms]).map_err(be)?;
        let id = c.last_insert_rowid();
        c.query_row(&format!("SELECT {UCOLS} FROM users WHERE id = ?1"), params![id], user).map_err(be)
        })
    }
    fn secret_hash(&self, user_id: i64) -> StoreResult<Option<String>> {
        self.with(|c| {
        Ok(c.query_row("SELECT secret_hash FROM users WHERE id = ?1", params![user_id], |r| r.get::<_, Option<String>>(0)).optional().map_err(be)?.flatten())
        })
    }
    fn update_nick(&self, user_id: i64, new_nick: &str, now_ms: i64) -> StoreResult<User> {
        self.with(|c| {
        let n = c.execute("UPDATE users SET nick = ?2, nick_ci = ?3, nick_changes = nick_changes + 1, nick_changed_ms = ?4 WHERE id = ?1", params![user_id, new_nick, new_nick.to_ascii_lowercase(), now_ms]).map_err(be)?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        c.query_row(&format!("SELECT {UCOLS} FROM users WHERE id = ?1"), params![user_id], user).map_err(be)
        })
    }
    fn set_tier(&self, user_id: i64, tier: &str) -> StoreResult<()> {
        self.with(|c| {
        match c.execute("UPDATE users SET tier = ?2 WHERE id = ?1", params![user_id, tier]).map_err(be)? {
            0 => Err(StoreError::NotFound),
            _ => Ok(()),
        }
        })
    }
    fn delete_user(&self, user_id: i64) -> StoreResult<()> {
        self.with(|c| {
        c.execute("DELETE FROM users WHERE id = ?1", params![user_id]).map_err(be).map(|_| ())
        })
    }
    fn add_credential(&self, user_id: i64, cred_ref: &str, token_hash: &str, now_ms: i64) -> StoreResult<()> {
        self.with(|c| {
        c.execute("INSERT INTO credentials (cred_ref, user_id, token_hash, created_ms) VALUES (?1, ?2, ?3, ?4)", params![cred_ref, user_id, token_hash, now_ms]).map_err(be).map(|_| ())
        })
    }
    fn user_by_token_hash(&self, token_hash: &str) -> StoreResult<Option<(User, String)>> {
        self.with(|c| {
        c
            .query_row(
                "SELECT u.id, u.nick, u.tier, u.nick_changes, u.nick_changed_ms, c.cred_ref FROM credentials c JOIN users u ON u.id = c.user_id WHERE c.token_hash = ?1 AND (c.access_expires_ms IS NULL OR c.access_expires_ms > CAST(strftime('%s','now') AS INTEGER) * 1000)",
                params![token_hash],
                |r| Ok((user(r)?, r.get::<_, String>(5)?)),
            )
            .optional()
            .map_err(be)
        })
    }
    fn delete_credential(&self, cred_ref: &str) -> StoreResult<Option<i64>> {
        self.with(|c| {
        let owner: Option<i64> = c.query_row("SELECT user_id FROM credentials WHERE cred_ref = ?1", params![cred_ref], |r| r.get(0)).optional().map_err(be)?;
        if owner.is_some() {
            c.execute("DELETE FROM credentials WHERE cred_ref = ?1", params![cred_ref]).map_err(be)?;
        }
        Ok(owner)
        })
    }
    fn credentials_of(&self, user_id: i64) -> StoreResult<Vec<String>> {
        self.with(|c| {
        let mut st = c.prepare("SELECT cred_ref FROM credentials WHERE user_id = ?1").map_err(be)?;
        let rows = st.query_map(params![user_id], |r| r.get(0)).map_err(be)?;
        rows.collect::<Result<_, _>>().map_err(be)
        })
    }
    fn live_credentials(&self) -> StoreResult<Vec<(String, Vec<String>)>> {
        self.with(|c| {
        let mut out: Vec<(String, Vec<String>)> = Vec::new();
        let mut users = c.prepare("SELECT id, nick FROM users ORDER BY id").map_err(be)?;
        let rows: Vec<(i64, String)> = users.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).map_err(be)?.collect::<Result<_, _>>().map_err(be)?;
        let mut creds = c.prepare("SELECT cred_ref FROM credentials WHERE user_id = ?1").map_err(be)?;
        for (id, nick) in rows {
            let list: Vec<String> = creds.query_map(params![id], |r| r.get(0)).map_err(be)?.collect::<Result<_, _>>().map_err(be)?;
            out.push((nick, list));
        }
        Ok(out)
        })
    }
    fn user_by_door(&self, source: &str, subject: &str) -> StoreResult<Option<User>> {
        self.with(|c| {
        c
            .query_row("SELECT u.id, u.nick, u.tier, u.nick_changes, u.nick_changed_ms FROM door_links d JOIN users u ON u.id = d.user_id WHERE d.source = ?1 AND d.subject = ?2", params![source, subject], user)
            .optional()
            .map_err(be)
        })
    }
    fn set_secret_hash(&self, user_id: i64, hash: &str) -> StoreResult<()> {
        self.with(|c| match c.execute("UPDATE users SET secret_hash = ?2 WHERE id = ?1", params![user_id, hash]).map_err(be)? {
            0 => Err(StoreError::NotFound),
            _ => Ok(()),
        })
    }
    fn supports_refresh(&self) -> bool {
        true
    }
    fn set_refresh(&self, cred_ref: &str, refresh_hash: &str, access_expires_ms: i64, refresh_expires_ms: i64) -> StoreResult<()> {
        self.with(|c| {
            c.execute("UPDATE credentials SET refresh_hash = ?2, access_expires_ms = ?3, refresh_expires_ms = ?4 WHERE cred_ref = ?1", params![cred_ref, refresh_hash, access_expires_ms, refresh_expires_ms]).map_err(be).map(|_| ())
        })
    }
    fn take_refresh(&self, refresh_hash: &str, now_ms: i64) -> StoreResult<Option<String>> {
        self.with(|c| {
            let found: Option<String> = c.query_row("SELECT cred_ref FROM credentials WHERE refresh_hash = ?1 AND refresh_expires_ms > ?2", params![refresh_hash, now_ms], |r| r.get(0)).optional().map_err(be)?;
            if let Some(cr) = &found {
                c.execute("UPDATE credentials SET refresh_hash = NULL WHERE cred_ref = ?1", params![cr]).map_err(be)?;
            }
            Ok(found)
        })
    }
    fn replace_token(&self, cred_ref: &str, token_hash: &str, access_expires_ms: i64) -> StoreResult<()> {
        self.with(|c| {
            c.execute("UPDATE credentials SET token_hash = ?2, access_expires_ms = ?3 WHERE cred_ref = ?1", params![cred_ref, token_hash, access_expires_ms]).map_err(be).map(|_| ())
        })
    }
    fn supports_keys(&self) -> bool {
        true
    }
    fn create_invite(&self, code_hash: &str, user_id: i64, expires_ms: i64) -> StoreResult<()> {
        self.with(|c| c.execute("INSERT INTO invites (code_hash, user_id, expires_ms) VALUES (?1, ?2, ?3)", params![code_hash, user_id, expires_ms]).map_err(be).map(|_| ()))
    }
    fn take_invite(&self, code_hash: &str, now_ms: i64) -> StoreResult<Option<User>> {
        self.with(|c| {
            let found = c
                .query_row(
                    "SELECT u.id, u.nick, u.tier, u.nick_changes, u.nick_changed_ms FROM invites i JOIN users u ON u.id = i.user_id WHERE i.code_hash = ?1 AND i.expires_ms > ?2",
                    params![code_hash, now_ms],
                    user,
                )
                .optional()
                .map_err(be)?;
            // Spent or expired, it goes either way.
            c.execute("DELETE FROM invites WHERE code_hash = ?1", params![code_hash]).map_err(be)?;
            Ok(found)
        })
    }
    fn add_key(&self, user_id: i64, key_id: &str, public_key: &str, label: &str, now_ms: i64) -> StoreResult<()> {
        self.with(|c| c.execute("INSERT INTO user_keys (key_id, user_id, public_key, label, created_ms) VALUES (?1, ?2, ?3, ?4, ?5)", params![key_id, user_id, public_key, label, now_ms]).map_err(be).map(|_| ()))
    }
    fn user_by_key(&self, key_id: &str) -> StoreResult<Option<(User, String)>> {
        self.with(|c| {
            c.query_row(
                "SELECT u.id, u.nick, u.tier, u.nick_changes, u.nick_changed_ms, k.public_key FROM user_keys k JOIN users u ON u.id = k.user_id WHERE k.key_id = ?1",
                params![key_id],
                |r| Ok((user(r)?, r.get::<_, String>(5)?)),
            )
            .optional()
            .map_err(be)
        })
    }
    fn delete_key(&self, key_id: &str) -> StoreResult<bool> {
        self.with(|c| c.execute("DELETE FROM user_keys WHERE key_id = ?1", params![key_id]).map_err(be).map(|n| n > 0))
    }
    fn link_door(&self, user_id: i64, source: &str, subject: &str) -> StoreResult<()> {
        self.with(|c| {
        c.execute("INSERT INTO door_links (source, subject, user_id) VALUES (?1, ?2, ?3)", params![source, subject, user_id]).map_err(be).map(|_| ())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const OTHER: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    #[test]
    fn the_product_database_is_encrypted_and_keeps_its_users() {
        let path = format!("/tmp/m4a-example-store-{}.db", std::process::id());
        let open = |k: &str| SqliteStore::open(&m4a_product_kit::dbkey::config(&path, k).unwrap());
        {
            let s = open(KEY).unwrap();
            s.insert_user("zoe_nick", "free", Some("hash"), 1).unwrap();
        }
        assert_eq!(open(KEY).unwrap().user_by_nick("zoe_nick").unwrap().unwrap().nick, "zoe_nick");
        assert!(open(OTHER).is_err());
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.starts_with(b"SQLite format 3") && !raw.windows(8).any(|w| w == b"zoe_nick"));
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path}{ext}"));
        }
    }
}
