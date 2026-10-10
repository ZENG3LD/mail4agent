//! SQLite implementation of the kit's [`UserStore`]: the example product's own database.

use std::sync::Mutex;

use m4a_product_kit::model::{StoreError, StoreResult, User, UserStore};
use rusqlite::{params, Connection, OptionalExtension};

pub struct SqliteStore {
    conn: Mutex<Connection>,
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
    created_ms INTEGER NOT NULL
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
    pub fn open(conn: Connection) -> rusqlite::Result<Self> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Mutex::new(conn) })
    }
    pub fn open_path(path: &str) -> rusqlite::Result<Self> {
        Self::open(Connection::open(path)?)
    }
    pub fn memory() -> rusqlite::Result<Self> {
        Self::open(Connection::open_in_memory()?)
    }
    fn c(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl UserStore for SqliteStore {
    fn user_by_nick(&self, nick: &str) -> StoreResult<Option<User>> {
        self.c().query_row(&format!("SELECT {UCOLS} FROM users WHERE nick_ci = ?1"), params![nick.to_ascii_lowercase()], user).optional().map_err(be)
    }
    fn insert_user(&self, nick: &str, tier: &str, secret_hash: Option<&str>, now_ms: i64) -> StoreResult<User> {
        let c = self.c();
        c.execute("INSERT INTO users (nick, nick_ci, tier, secret_hash, created_ms) VALUES (?1, ?2, ?3, ?4, ?5)", params![nick, nick.to_ascii_lowercase(), tier, secret_hash, now_ms]).map_err(be)?;
        let id = c.last_insert_rowid();
        c.query_row(&format!("SELECT {UCOLS} FROM users WHERE id = ?1"), params![id], user).map_err(be)
    }
    fn secret_hash(&self, user_id: i64) -> StoreResult<Option<String>> {
        Ok(self.c().query_row("SELECT secret_hash FROM users WHERE id = ?1", params![user_id], |r| r.get::<_, Option<String>>(0)).optional().map_err(be)?.flatten())
    }
    fn update_nick(&self, user_id: i64, new_nick: &str, now_ms: i64) -> StoreResult<User> {
        let c = self.c();
        let n = c.execute("UPDATE users SET nick = ?2, nick_ci = ?3, nick_changes = nick_changes + 1, nick_changed_ms = ?4 WHERE id = ?1", params![user_id, new_nick, new_nick.to_ascii_lowercase(), now_ms]).map_err(be)?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        c.query_row(&format!("SELECT {UCOLS} FROM users WHERE id = ?1"), params![user_id], user).map_err(be)
    }
    fn set_tier(&self, user_id: i64, tier: &str) -> StoreResult<()> {
        match self.c().execute("UPDATE users SET tier = ?2 WHERE id = ?1", params![user_id, tier]).map_err(be)? {
            0 => Err(StoreError::NotFound),
            _ => Ok(()),
        }
    }
    fn delete_user(&self, user_id: i64) -> StoreResult<()> {
        self.c().execute("DELETE FROM users WHERE id = ?1", params![user_id]).map_err(be).map(|_| ())
    }
    fn add_credential(&self, user_id: i64, cred_ref: &str, token_hash: &str, now_ms: i64) -> StoreResult<()> {
        self.c().execute("INSERT INTO credentials (cred_ref, user_id, token_hash, created_ms) VALUES (?1, ?2, ?3, ?4)", params![cred_ref, user_id, token_hash, now_ms]).map_err(be).map(|_| ())
    }
    fn user_by_token_hash(&self, token_hash: &str) -> StoreResult<Option<(User, String)>> {
        self.c()
            .query_row(
                "SELECT u.id, u.nick, u.tier, u.nick_changes, u.nick_changed_ms, c.cred_ref FROM credentials c JOIN users u ON u.id = c.user_id WHERE c.token_hash = ?1",
                params![token_hash],
                |r| Ok((user(r)?, r.get::<_, String>(5)?)),
            )
            .optional()
            .map_err(be)
    }
    fn delete_credential(&self, cred_ref: &str) -> StoreResult<Option<i64>> {
        let c = self.c();
        let owner: Option<i64> = c.query_row("SELECT user_id FROM credentials WHERE cred_ref = ?1", params![cred_ref], |r| r.get(0)).optional().map_err(be)?;
        if owner.is_some() {
            c.execute("DELETE FROM credentials WHERE cred_ref = ?1", params![cred_ref]).map_err(be)?;
        }
        Ok(owner)
    }
    fn credentials_of(&self, user_id: i64) -> StoreResult<Vec<String>> {
        let c = self.c();
        let mut st = c.prepare("SELECT cred_ref FROM credentials WHERE user_id = ?1").map_err(be)?;
        let rows = st.query_map(params![user_id], |r| r.get(0)).map_err(be)?;
        rows.collect::<Result<_, _>>().map_err(be)
    }
    fn live_credentials(&self) -> StoreResult<Vec<(String, Vec<String>)>> {
        let c = self.c();
        let mut out: Vec<(String, Vec<String>)> = Vec::new();
        let mut users = c.prepare("SELECT id, nick FROM users ORDER BY id").map_err(be)?;
        let rows: Vec<(i64, String)> = users.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).map_err(be)?.collect::<Result<_, _>>().map_err(be)?;
        let mut creds = c.prepare("SELECT cred_ref FROM credentials WHERE user_id = ?1").map_err(be)?;
        for (id, nick) in rows {
            let list: Vec<String> = creds.query_map(params![id], |r| r.get(0)).map_err(be)?.collect::<Result<_, _>>().map_err(be)?;
            out.push((nick, list));
        }
        Ok(out)
    }
    fn user_by_door(&self, source: &str, subject: &str) -> StoreResult<Option<User>> {
        self.c()
            .query_row("SELECT u.id, u.nick, u.tier, u.nick_changes, u.nick_changed_ms FROM door_links d JOIN users u ON u.id = d.user_id WHERE d.source = ?1 AND d.subject = ?2", params![source, subject], user)
            .optional()
            .map_err(be)
    }
    fn link_door(&self, user_id: i64, source: &str, subject: &str) -> StoreResult<()> {
        self.c().execute("INSERT INTO door_links (source, subject, user_id) VALUES (?1, ?2, ?3)", params![source, subject, user_id]).map_err(be).map(|_| ())
    }
}
