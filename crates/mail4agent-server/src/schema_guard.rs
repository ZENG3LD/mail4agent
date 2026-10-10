//! Database schema versioning: forward-only, with a snapshot before a migration.
//!
//! The version lives in SQLite's `user_version` pragma. A build knows one version
//! ([`SCHEMA_VERSION`]). On open:
//!
//! - a file whose version is NEWER than the build's is refused with a clear error (a downgrade
//!   would run old code against tables it does not understand; restore the snapshot instead);
//! - a file with data and an OLDER version (0 = written before versioning, i.e. 0.4.x) is first
//!   copied, then migrated, then marked with the new version. The copy is the downgrade path.
//!
//! Environment: `M4A_DB_SNAPSHOT=off` disables the copy; `M4A_DB_SNAPSHOT_DIR` puts it in a
//! directory (default: next to the database file). The copy is named
//! `<file>.pre-schema-v<new>-<unix seconds>`.
//!
//! History: 1 = up to 0.4.x (no marker); 2 = 0.5.0 (presence, remote media cache, login tokens).

use rusqlite::Connection;

pub const SCHEMA_VERSION: i64 = 2;

#[derive(Debug)]
pub struct SchemaTooNew {
    pub found: i64,
    pub known: i64,
}

impl std::fmt::Display for SchemaTooNew {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the database has schema version {} but this build only knows up to {}: refusing to open it (use a newer build, or restore the snapshot taken before the upgrade)",
            self.found, self.known
        )
    }
}
impl std::error::Error for SchemaTooNew {}

fn has_data(conn: &Connection) -> bool {
    conn.query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'rooms'", [], |_| Ok(())).is_ok()
}

/// Called before the schema is created. Refuses a newer database; snapshots an older one.
pub fn enter(conn: &Connection) -> rusqlite::Result<()> {
    let found: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if found > SCHEMA_VERSION {
        return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(SchemaTooNew { found, known: SCHEMA_VERSION })));
    }
    if found < SCHEMA_VERSION && has_data(conn) {
        if let Err(e) = snapshot(conn) {
            return Err(rusqlite::Error::ToSqlConversionFailure(format!("could not take the pre-migration snapshot ({e}); set M4A_DB_SNAPSHOT=off to migrate without one").into()));
        }
    }
    Ok(())
}

/// Called after the schema is in place: stamps the version (forward only).
pub fn leave(conn: &Connection) -> rusqlite::Result<()> {
    let found: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if found < SCHEMA_VERSION {
        conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
    }
    Ok(())
}

fn snapshot(conn: &Connection) -> std::io::Result<()> {
    if std::env::var("M4A_DB_SNAPSHOT").map(|v| v == "off").unwrap_or(false) {
        return Ok(());
    }
    let Some(path) = conn.path().filter(|p| !p.is_empty()).map(str::to_string) else { return Ok(()) };
    let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
    let src = std::path::Path::new(&path);
    let name = src.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "db".into());
    let dir = std::env::var("M4A_DB_SNAPSHOT_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| src.parent().map(|p| p.to_path_buf()).unwrap_or_default());
    std::fs::create_dir_all(&dir)?;
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    std::fs::copy(src, dir.join(format!("{name}.pre-schema-v{SCHEMA_VERSION}-{secs}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_newer_database_is_refused_and_an_older_one_is_stamped_after_a_snapshot() {
        let dir = std::env::temp_dir().join(format!("m4a-schema-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("t.db");
        {
            let c = Connection::open(&file).unwrap();
            crate::store::create_matrix_schema(&c).unwrap();
            assert_eq!(c.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)).unwrap(), SCHEMA_VERSION);
            // Pretend the file was written by 0.4.x: no marker.
            c.execute_batch("PRAGMA user_version = 0").unwrap();
        }
        {
            let c = Connection::open(&file).unwrap();
            crate::store::create_matrix_schema(&c).unwrap();
            assert_eq!(c.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)).unwrap(), SCHEMA_VERSION);
        }
        let copies: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().contains(".pre-schema-v")).collect();
        assert_eq!(copies.len(), 1, "one snapshot of the old file");
        {
            let c = Connection::open(&file).unwrap();
            c.execute_batch(&format!("PRAGMA user_version = {}", SCHEMA_VERSION + 1)).unwrap();
        }
        let c = Connection::open(&file).unwrap();
        let err = crate::store::create_matrix_schema(&c).unwrap_err().to_string();
        assert!(err.contains("refusing to open"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
