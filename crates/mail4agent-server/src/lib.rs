//! Abstract messenger homeserver.
//!
//! Every decision takes an already-open [`rusqlite::Connection`] or the
//! in-memory [`typing::TypingRegistry`]. The builder owns HTTP, the process,
//! the account-to-integer-user map, display names, entitlements, and wakes.
//! Call [`store::set_matrix_server_name`] once before minting ids.
//! [`store::init_messenger_db`] runs `PRAGMA key` and expects a SQLCipher
//! build of rusqlite (crate feature `sqlcipher`).

pub mod account;
pub mod ephemeral;
pub mod error;
pub mod events;
pub mod key_ops;
pub mod keys;
pub mod messaging;
pub mod rooms;
pub mod store;
pub mod sync;
pub mod sync_token;
pub mod typing;

pub use error::MatrixError;
pub use typing::TypingRegistry;
