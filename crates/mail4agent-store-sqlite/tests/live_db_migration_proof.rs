//! Opens a COPY of a real, previously-migrated `mail4agent.sqlite` (schema
//! v1+v2+v3, written by the old `servertoolkit-db`-backed store this crate
//! replaces) through this crate's own `Db`/`MigrationRunner`, proving the
//! replacement opens and migrates an existing production database
//! unchanged rather than merely a freshly-created one.
//!
//! Ignored by default -- it needs a real snapshot on disk, which CI and a
//! fresh clone do not have. Point `MAIL4AGENT_LIVE_DB_PROOF` at a COPY of
//! the live file (never the original -- this test opens it for writing)
//! and run:
//!
//! ```text
//! MAIL4AGENT_LIVE_DB_PROOF=/path/to/copy/mail4agent.sqlite \
//!     cargo test --release -p mail4agent-store-sqlite \
//!     --test live_db_migration_proof -- --ignored --nocapture
//! ```

use mail4agent_core::MailStore;
use mail4agent_store_sqlite::{migrations, Db, DbConfig, MigrationRunner, SqliteMailStore};

#[test]
#[ignore = "needs a real mail4agent.sqlite snapshot on disk; see this file's own module doc comment"]
fn a_copy_of_the_live_database_opens_and_migrates_unchanged() {
    let path = std::env::var("MAIL4AGENT_LIVE_DB_PROOF")
        .expect("set MAIL4AGENT_LIVE_DB_PROOF to a COPY of the live mail4agent.sqlite");

    let db = Db::open(&DbConfig::new(&path)).expect("opens the existing file");

    // Every version this crate knows about must already be recorded --
    // migrating this file must be a no-op, not a re-run.
    let applied_before: Vec<u32> = db
        .read_blocking(|c| {
            let mut stmt = c.prepare("SELECT version FROM schema_migrations ORDER BY version")?;
            let rows = stmt.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<u32>>>()?;
            Ok(rows)
        })
        .expect("reads the existing migration ledger");
    let expected: Vec<u32> = migrations().iter().map(|m| m.version).collect();
    assert_eq!(applied_before, expected, "every migration this crate knows must already be recorded on file");

    db.run_migrations_blocking(MigrationRunner::new(migrations()))
        .expect("migrating an already-current database is a no-op");

    let store = SqliteMailStore::new(db);
    let participants = store.list_participants().expect("reads the existing participant registry");
    assert!(!participants.is_empty(), "the live mailbox has at least the bootstrap operator registered");
    println!("participants on file: {}", participants.len());
    for p in &participants {
        println!("  - {} ({:?})", p.id, p.label);
    }

    let rooms = store.list_rooms().expect("reads the existing room registry");
    println!("rooms on file: {}", rooms.len());
}
