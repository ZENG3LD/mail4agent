//! Building blocks of a PRODUCT server in front of the messenger server.
//!
//! The messenger (edge + core) stores messages, public keys, rooms and
//! nick+domain identities, nothing else. A product server owns the users,
//! accounts, nick rules, registration, logins (including optional doors) and
//! tariffs, and tells the messenger through the seam ([`m4a_seam`]).
//!
//! * [`model`] / [`service`]: the user store trait and the logic over it.
//! * [`nick_rules`]: grammar, lists, placeholder nicks, cooldown.
//! * [`tiers`]: tier -> opaque policy flag.
//! * [`tokens`]: one-time login tokens (`login/get_token`); refresh tokens live in the store trait.
//! * [`door`]: login doors; `matrix-address-door` is a real optional door.
//! * [`edge_link`]: authenticate, sign, forward.
//! * [`events`]: lifecycle event publisher (durable queue, retry/backoff) and startup reconcile.
//! * [`dbkey`]: hex key -> `tesserax-store` SQLCipher config. The storage engine is
//!   `tesserax-store` (one writer, parallel readers, batched writes); the durable queue sits on it.
//!
//! What a product CALLS from here: [`EdgeLink`], [`EventPublisher`], [`send_reconcile`],
//! [`UserService`] over its own [`UserStore`]. What it BRINGS: the `UserStore` over its own
//! user database, its own authentication (it builds an [`AuthUser`]), its own policy
//! (tiers/tariffs: it sets the opaque flag before forwarding). Nothing here names a product.

#[cfg(feature = "sqlite-outbox")]
pub mod dbkey;
pub mod door;
pub mod edge_link;
pub mod events;
pub mod model;
pub mod nick_rules;
pub mod push_relay;
pub mod service;
pub mod tiers;
pub mod tokens;

pub use edge_link::EdgeLink;
pub use events::{send_reconcile, EventPublisher, MemoryOutbox, Outbox};
#[cfg(feature = "sqlite-outbox")]
pub use events::SqliteOutbox;
pub use tokens::LoginTokens;
pub use model::{StoreError, User, UserStore};
pub use service::{AuthUser, ServiceError, Session, UserService};
