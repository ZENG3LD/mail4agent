//! The agent-side client. One session = one identity = one nick = one credential set, and the
//! CLIENT resolves all of it: the agent behind it never sees a password, an environment variable
//! or a key. See `plans/agent-client-tiers-2026-10.md`.
//!
//! This is step 1 of the migration: the identity and the vault, the backend trait, and login by
//! key signature. The tiers live behind cargo features (`tier-server`, `tier-matrix`); the full
//! pack is the default and a light build turns features off.

pub mod backend;
pub mod error;
pub mod identity;
pub mod keyauth;
pub mod resolver;
pub mod vault;

pub use backend::{Backend, BackendKind, Capabilities, Session};
pub use error::{AgentError, Result};
pub use identity::{IdentityStore, SessionIdentity};
pub use resolver::{ResolvedSession, ResolverChain, SessionResolver};
pub use vault::{FileVault, KeyVault, MemoryVault};
