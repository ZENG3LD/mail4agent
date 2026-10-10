//! The engine driver: runs the sans-I/O messenger core against a [`Backend`]. The shell used to
//! own this; it now only adds what is its own (wake, local bus, sealed files on disk).

pub mod driver;
pub mod http;
pub mod push;

pub use driver::Driver;
pub use http::{clip_public, HttpExec};
pub use push::{PushLink, PushedRoomEvent};

/// What [`crate::Backend::wait_for_news`] saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum News {
    /// The server pushed room events for this session (metadata only; sync fetches the content).
    Pushed(Vec<PushedRoomEvent>),
    /// The wait ended without news (timeout, or the server has no push channel: poll with sync).
    Idle,
}
