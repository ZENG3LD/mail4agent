//! The Olm/Megolm/cross-signing state machine — plan §3's `crypto/`.
//!
//! # Pieces landed so far (M5, M6)
//!
//! **M5** — the device's own Olm account ([`account::OlmAccountState`]):
//! generate-once-and-persist identity, one-time/fallback key maintenance
//! off `/sync`'s own counters, and building the signed `device_keys`/
//! `/keys/upload` request bodies (via [`crate::canonical_json`]).
//!
//! **M6** — device-list tracking ([`device_tracker::DeviceTracker`]):
//! tracked users, outdated bookkeeping, `/keys/query` request building and
//! response validation (self-signature verification, key-change flagging);
//! and per-device Olm 1:1 sessions ([`olm_sessions::OlmSessionManager`]):
//! `/keys/claim`, to-device encryption/decryption with full payload
//! binding, and the strict-ordering/replay-rejection guarantees Olm's
//! double ratchet gives for free when this module's own append-and-persist
//! discipline is followed.
//!
//! **M7** — Megolm group sessions
//! ([`group_sessions::GroupSessionManager`]): lazy outbound-session
//! creation, rotation (message-count, time, membership-leave, and
//! device-disappearance triggers), room-key sharing batched over Olm
//! to-device, and inbound-session decrypt with bound-sender
//! authentication and message-index replay protection.
//!
//! Withheld/key-request bookkeeping, SAS verification, key backup, and
//! cross-signing (plan's `withheld.rs`, `verification.rs`, `backup.rs`,
//! `cross_signing.rs`, and the `CryptoMachine` type tying everything
//! together) are later pieces and are not present in this crate yet.

pub mod account;
pub mod cross_signing;
pub mod device_tracker;
pub mod group_sessions;
pub mod olm_sessions;
