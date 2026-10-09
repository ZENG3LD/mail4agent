//! Messenger homeserver: protocol decisions and the Client-Server HTTP routes.
//!
//! Decision functions take an already-open [`rusqlite::Connection`].
//! [`http::router`] mounts those decisions on axum. A client session
//! autoregisters on `POST /client/v3/register`. The nick lives on that
//! session. The raw device bearer is returned once in that response and
//! stored only as a SHA-256 hex. The websession opens the database, calls
//! [`store::set_matrix_server_name`] once, and serves [`http::Homeserver`].
//! There is no paid check and no chart identity database.
//! [`store::init_messenger_db`] runs `PRAGMA key` and expects a SQLCipher
//! build of rusqlite (crate feature `sqlcipher`).

pub mod account;
pub mod ephemeral;
pub mod error;
pub mod events;
pub mod fed_rooms;
pub mod federation;
pub mod http;
pub mod key_ops;
pub mod keys;
pub mod live;
pub mod messaging;
pub mod nick;
mod push;
pub mod retention;
pub mod public_channels;
pub mod spaces;
pub mod media;
pub mod public_forum;
pub mod rooms;
pub mod store;
pub mod sync;
pub mod sync_token;
pub mod typing;

pub use error::MatrixError;
pub use http::{router, Homeserver};
pub use typing::TypingRegistry;
