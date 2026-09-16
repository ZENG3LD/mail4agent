//! A [`mail4agent_core::MailStore`] backed by SQLite through
//! `servertoolkit-db`'s [`stk_db::Db`]: versioned migrations, WAL, one
//! transaction per mutating method.
//!
//! This crate owns no connection of its own -- [`stk_db::Db`] already owns
//! the connection, the WAL and foreign-key pragmas, and the
//! `spawn_blocking` wrappers a caller stitches into async code. What this
//! crate adds is the schema ([`migrations`]) and [`SqliteMailStore`], the
//! [`mail4agent_core::MailStore`] implementation laid over it.
//!
//! `MailStore`'s methods are synchronous and fallible -- see
//! `mail4agent-core`'s own module doc comment on why a persistent store
//! cannot satisfy that trait any other way -- so every method here goes
//! through [`stk_db::Db::read_blocking`] / [`stk_db::Db::write_blocking`],
//! never the async `read`/`write` helpers: those spawn onto a tokio
//! blocking thread and would need a runtime this trait has no way to
//! require of its caller.
//!
//! **Never call a [`SqliteMailStore`] method from inside an async task
//! running on a tokio runtime.** `read_blocking`/`write_blocking` block the
//! calling thread on `Db`'s own mutex and panic if that thread is itself
//! inside a tokio task. A daemon wiring this store into async request
//! handling reaches it through `tokio::task::spawn_blocking`, exactly as
//! `Db::read`/`Db::write` do internally.

mod migrations;
mod store;

pub use migrations::migrations;
pub use store::SqliteMailStore;

#[cfg(test)]
mod engine_tests;
#[cfg(test)]
mod tests;
