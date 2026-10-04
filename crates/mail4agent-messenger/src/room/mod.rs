//! Room state, timeline assembly, and relation aggregation.
//!
//! # Pieces landed so far (M4)
//!
//! - [`state`]: [`state::RoomState`], folded from `m.room.*` state events
//!   (research doc §1.2) plus [`state::RoomKind`] derivation and this
//!   crate's own coarse [`state::MemberRole`] mapping.
//! - [`relations`]: [`relations::RelationsBundle`], aggregated from
//!   `m.relates_to` (research doc §1.3): reactions, edits (latest-wins,
//!   original-sender-only), replies, threads.
//! - [`timeline`]: [`timeline::Timeline`], assembled from `/sync` timeline
//!   batches and `/messages` back-pages (research doc §1.3-§1.5):
//!   local-echo reconciliation, live redaction (research doc §1.1's v11
//!   allow-list), and the unread/highlight/preview helpers plan manager
//!   decision #5 assigns to this crate.
//!
//! The Olm/Megolm crypto machine that eventually feeds
//! [`timeline::Timeline::set_decrypted`] (plan's `crypto/`, M6-M9) and the
//! sync engine that drives all of this from a parsed
//! [`crate::wire::sync::SyncResponse`] (plan's `sync_engine.rs`, M13) are
//! later pieces and are not present in this crate yet.

pub mod relations;
pub mod state;
pub mod timeline;

pub use relations::{aggregate_relation, recompute_bundle, EditRecord, RelatingEvent, RelationsBundle};
pub use state::{MemberRole, MemberState, RoomKind, RoomState};
pub use timeline::{
    highlight, last_preview, Forwarded, GapMarker, ItemContent, SendState, StateChangeSummary, Timeline, TimelineItem,
};
