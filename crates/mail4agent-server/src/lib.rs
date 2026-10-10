//! Messenger homeserver: protocol decisions and the Client-Server HTTP routes.
//!
//! Decision functions take an already-open `rusqlite::Connection`.
//! [`http::router`] mounts those decisions on axum. The process opens the
//! store with [`store::open_messenger_db`] (tesserax-store: SQLCipher, one
//! writer; [`store::open_read_pool`] adds parallel readers), calls
//! [`store::set_matrix_server_name`] once, and serves [`http::Homeserver`].
//! There is no tariff logic and no product identity database; products plug in through
//! [`identities`] (signed assertions from `m4a-seam`) and [`policy`].

pub mod account;
pub mod identities;
pub mod policy;
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
