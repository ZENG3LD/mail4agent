//! A [`mail4agent_core::MailStore`] backed by plain SQLite (`rusqlite`,
//! bundled): versioned migrations, WAL, one transaction per mutating
//! method. This crate owns its own connection ([`db`]) -- everything it
//! adds on top is the schema ([`migrations`]) and [`SqliteMailStore`], the
//! [`mail4agent_core::MailStore`] implementation laid over it.
//!
//! `MailStore`'s methods are synchronous and fallible -- see
//! `mail4agent-core`'s own module doc comment on why a persistent store
//! cannot satisfy that trait any other way -- so every method here goes
//! through [`Db::read_blocking`] / [`Db::write_blocking`], never an async
//! helper: those would need a tokio runtime this trait has no way to
//! require of its caller.
//!
//! **Never call a [`SqliteMailStore`] method from inside an async task
//! running on a tokio runtime.** `read_blocking`/`write_blocking` block
//! the calling thread on `Db`'s own mutex and panic if that thread is
//! itself inside a tokio task. A daemon wiring this store into async
//! request handling reaches it through `tokio::task::spawn_blocking`,
//! exactly as `Db::read`/`Db::write` would if this crate exposed them.

mod db;
mod migrations;
mod store;

pub use db::{Db, DbConfig, DbError, Migration, MigrationRunner};
pub use migrations::migrations;
pub use store::SqliteMailStore;

// rusqlite re-export so a consumer (this crate's own tests included) needs
// no second direct dependency on it just to build `rusqlite::params!` calls
// or match on `rusqlite::Error`.
pub use rusqlite;

#[cfg(test)]
mod engine_tests;
#[cfg(test)]
mod tests;
