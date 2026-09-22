//! A small, self-contained SQLite handle: WAL + foreign_keys pragmas,
//! versioned migrations, and blocking read/write helpers -- everything
//! [`crate::store::SqliteMailStore`] needs from a connection.
//!
//! This module replaces what used to be an internal build-framework
//! dependency (`servertoolkit-db`'s own `Db`/`DbConfig`/`Migration`/
//! `MigrationRunner`), so mail4agent can be published without it. The
//! pragmas, the migration bookkeeping table's name and shape
//! (`schema_migrations(version, label, applied_at)`), and the
//! `BEGIN EXCLUSIVE` + busy_timeout bump around a migration run are
//! unchanged -- an existing `mail4agent.sqlite` written by the old
//! dependency opens and migrates exactly as before, because the runner
//! only ever checks whether a version number is already recorded before
//! re-applying its SQL (see [`MigrationRunner::run`]).

use std::path::PathBuf;
use std::sync::Arc;

use rusqlite::Connection;
use tokio::sync::Mutex;
use tracing::info;

/// Opening parameters for [`Db`]. Only the two shapes this daemon actually
/// needs: a file-backed path (WAL, production) or an in-memory connection
/// (tests, `SqliteMailStore::open_in_memory`).
#[derive(Clone)]
pub enum DbConfig {
    Path(PathBuf),
    InMemory,
}

impl DbConfig {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }

    pub fn in_memory() -> Self {
        Self::InMemory
    }

    fn is_in_memory(&self) -> bool {
        matches!(self, Self::InMemory)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("open {path}: {source}")]
    Open { path: String, source: rusqlite::Error },
    #[error("pragma init: {0}")]
    Pragma(rusqlite::Error),
    #[error("migration: {0}")]
    Migration(rusqlite::Error),
}

/// Cheaply-clonable SQLite handle. Clones share the underlying `Mutex`, so
/// a single physical connection backs every clone -- the same guarantee
/// [`crate::store::SqliteMailStore::db`]'s own doc comment relies on for
/// letting a daemon share one connection between an "engine" store handle
/// and a "reader" store handle.
#[derive(Clone)]
pub struct Db {
    inner: Arc<Mutex<Connection>>,
    label: Arc<str>,
}

impl Db {
    /// Opens the database and applies WAL (file-backed only) + foreign_keys
    /// pragmas. Does NOT run migrations -- call
    /// [`Db::run_migrations_blocking`] separately, same two-step boot the
    /// daemon (`src/main.rs`) always did.
    pub fn open(cfg: &DbConfig) -> Result<Self, DbError> {
        let (conn, label) = match cfg {
            DbConfig::Path(path) => {
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                }
                let conn = Connection::open(path)
                    .map_err(|e| DbError::Open { path: path.display().to_string(), source: e })?;
                (conn, path.display().to_string())
            }
            DbConfig::InMemory => {
                let conn = Connection::open_in_memory()
                    .map_err(|e| DbError::Open { path: ":memory:".into(), source: e })?;
                (conn, ":memory:".to_owned())
            }
        };

        if !cfg.is_in_memory() {
            conn.pragma_update(None, "journal_mode", "WAL").map_err(DbError::Pragma)?;
        }
        conn.pragma_update(None, "foreign_keys", "ON").map_err(DbError::Pragma)?;

        info!(path = %label, "db opened");
        Ok(Self { inner: Arc::new(Mutex::new(conn)), label: Arc::from(label.as_str()) })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    /// Synchronous migration runner -- for `fn main()`, before a tokio
    /// runtime exists at all (see `src/main.rs`'s own module doc comment
    /// on why that ordering is deliberate). Panics if this handle's lock
    /// is already held, which would mean a caller reached this from
    /// inside an already-running async task -- use `write_blocking`
    /// there instead, same discipline as every other mutating call this
    /// crate makes.
    pub fn run_migrations_blocking(&self, runner: MigrationRunner) -> Result<(), DbError> {
        let mut guard = self.inner.try_lock().expect(
            "run_migrations_blocking called with a held lock -- call it before any other Db handle is in use",
        );
        runner.run(&mut guard).map_err(DbError::Migration)
    }

    /// Blocking read: waits on the mutex. Callers already inside a tokio
    /// task must run this through `spawn_blocking` -- see this crate's own
    /// module doc comment (`lib.rs`) for why calling it directly from an
    /// async task panics.
    pub fn read_blocking<F, T>(&self, f: F) -> rusqlite::Result<T>
    where
        F: FnOnce(&Connection) -> rusqlite::Result<T>,
    {
        let guard = self.inner.blocking_lock();
        f(&guard)
    }

    /// Blocking write: waits on the mutex. Same discipline as
    /// [`Db::read_blocking`].
    pub fn write_blocking<F, T>(&self, f: F) -> rusqlite::Result<T>
    where
        F: FnOnce(&mut Connection) -> rusqlite::Result<T>,
    {
        let mut guard = self.inner.blocking_lock();
        f(&mut guard)
    }
}

/// One versioned schema change: `(version, label, sql)`. Versions must be
/// strictly increasing in the slice handed to [`MigrationRunner::new`].
#[derive(Debug, Clone)]
pub struct Migration {
    pub version: u32,
    pub label: String,
    pub sql: String,
}

impl Migration {
    pub fn new(version: u32, label: impl Into<String>, sql: impl Into<String>) -> Self {
        Self { version, label: label.into(), sql: sql.into() }
    }
}

pub struct MigrationRunner {
    migrations: Vec<Migration>,
}

impl MigrationRunner {
    /// Migrations must already be in strictly increasing version order --
    /// panics otherwise, loud and at boot time rather than a silently
    /// skipped migration later.
    pub fn new(migrations: Vec<Migration>) -> Self {
        for w in migrations.windows(2) {
            assert!(
                w[0].version < w[1].version,
                "migrations must be in strictly increasing version order: v{} ({:?}) >= v{} ({:?})",
                w[0].version,
                w[0].label,
                w[1].version,
                w[1].label,
            );
        }
        Self { migrations }
    }

    /// Applies every pending migration inside one `BEGIN EXCLUSIVE`
    /// transaction, tracked in `schema_migrations(version, label,
    /// applied_at)` -- the exact table name and shape the previous
    /// dependency used, so an already-migrated `mail4agent.sqlite` opens
    /// with every version already recorded and nothing re-applied.
    /// `busy_timeout` is bumped to 30s for the duration of the exclusive
    /// lock so a second instance starting concurrently waits rather than
    /// failing outright, then restored to whatever it was before.
    pub fn run(self, conn: &mut Connection) -> rusqlite::Result<()> {
        let prev_busy_ms: i64 = conn.query_row("PRAGMA busy_timeout;", [], |r| r.get(0)).unwrap_or(0);
        conn.pragma_update(None, "busy_timeout", 30_000)?;

        let result = (|| -> rusqlite::Result<()> {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;

            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_migrations (
                     version INTEGER PRIMARY KEY,
                     label TEXT NOT NULL,
                     applied_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );",
            )?;

            for m in self.migrations {
                let already: Option<u32> = tx
                    .query_row("SELECT version FROM schema_migrations WHERE version = ?1", [m.version], |r| r.get(0))
                    .ok();
                if already.is_some() {
                    continue;
                }
                tx.execute_batch(&m.sql)?;
                tx.execute(
                    "INSERT INTO schema_migrations (version, label) VALUES (?1, ?2)",
                    rusqlite::params![m.version, m.label],
                )?;
                info!(version = m.version, label = %m.label, "applied migration");
            }

            tx.commit()?;
            Ok(())
        })();

        let _ = conn.pragma_update(None, "busy_timeout", prev_busy_ms);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_open_sets_foreign_keys_on() {
        let db = Db::open(&DbConfig::in_memory()).expect("opens");
        let fk: u32 =
            db.read_blocking(|c| c.query_row("PRAGMA foreign_keys;", [], |r| r.get(0))).expect("reads pragma");
        assert_eq!(fk, 1);
        assert_eq!(db.label(), ":memory:");
    }

    #[test]
    #[should_panic(expected = "strictly increasing")]
    fn out_of_order_migrations_panic() {
        let _ = MigrationRunner::new(vec![Migration::new(2, "b", "SELECT 1;"), Migration::new(1, "a", "SELECT 1;")]);
    }

    #[test]
    fn migrations_are_idempotent_when_run_twice() {
        let db = Db::open(&DbConfig::in_memory()).expect("opens");
        let migrations = || vec![Migration::new(1, "t", "CREATE TABLE t (n INTEGER);")];
        db.run_migrations_blocking(MigrationRunner::new(migrations())).expect("first run applies the schema");
        db.run_migrations_blocking(MigrationRunner::new(migrations())).expect("second run is a no-op");
        db.write_blocking(|c| c.execute("INSERT INTO t VALUES (1)", []).map(|_| ()))
            .expect("table is still usable after a repeat migration run");
    }

    #[test]
    fn appending_a_new_migration_applies_only_the_new_one() {
        let db = Db::open(&DbConfig::in_memory()).expect("opens");
        db.run_migrations_blocking(MigrationRunner::new(vec![Migration::new(
            1,
            "users",
            "CREATE TABLE users (id INTEGER PRIMARY KEY);",
        )]))
        .expect("v1 applies");

        db.run_migrations_blocking(MigrationRunner::new(vec![
            Migration::new(1, "users", "SELECT 1;"),
            Migration::new(2, "add_name", "ALTER TABLE users ADD COLUMN name TEXT;"),
        ]))
        .expect("v2 applies on top");

        let count: u32 = db
            .read_blocking(|c| c.query_row("SELECT count(*) FROM schema_migrations", [], |r| r.get(0)))
            .expect("reads the migration ledger");
        assert_eq!(count, 2);
    }
}
