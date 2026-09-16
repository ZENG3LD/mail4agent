//! Shared axum state.
//!
//! `/mail/*` and `/mcp` handlers resolve a caller's own *session*, not just
//! its account (see `crate::identity`), and that resolution needs one fact
//! a handler cannot read off the request itself: the address this server
//! is bound to, used as `local` in `mail4agent_attest::attest(peer, local)`
//! (`peer` is this same request's own `ConnectInfo<SocketAddr>`). This
//! struct is that fact plus the mailbox facade every handler needs anyway,
//! bundled once so every route shares one `State<Arc<AppState>>` rather
//! than half the routes taking `Arc<MailboxService>` and the other half
//! something wider.
//!
//! `/admin/*` handlers read only [`AppState::service`]: they act on
//! accounts (registering a participant, creating a room), never on a
//! session, so they never need [`AppState::bind_addr`].

use std::net::SocketAddr;
use std::sync::Arc;

use crate::service::MailboxService;

pub struct AppState {
    pub service: Arc<MailboxService>,
    pub bind_addr: SocketAddr,
}
