//! [`MessengerError`], this crate's single error type.

/// Every error this crate's public API can return. Sans-I/O by
/// construction (see the crate doc): this type never itself performs I/O —
/// it only describes a failure the caller (a shell, or another module in
/// this crate) already observed.
#[derive(Debug, thiserror::Error)]
pub enum MessengerError {
    /// One of the identifier newtypes in [`crate::ids`] rejected a value.
    #[error("invalid {kind} {value:?}: {reason}")]
    InvalidId {
        /// The newtype that rejected the value (`"UserId"`, `"RoomId"`, …).
        kind: &'static str,
        /// The rejected input, verbatim.
        value: String,
        /// Why it was rejected.
        reason: String,
    },

    /// A wire payload (an HTTP response body, a `/sync` response, …) was
    /// not valid JSON, or did not match the shape this crate expected of
    /// it.
    #[error("failed to decode wire JSON: {0}")]
    WireDecode(#[from] serde_json::Error),

    /// An HTTP response came back with an error status and a Matrix-shaped
    /// `{"errcode": ..., "error": ...}` body (client-server API's own
    /// standard error response shape).
    #[error("HTTP {status} {errcode}: {error}")]
    Http {
        /// The HTTP status code.
        status: u16,
        /// The Matrix `errcode` (e.g. `"M_FORBIDDEN"`).
        errcode: String,
        /// The Matrix `error` human-readable string.
        error: String,
    },

    /// A cryptographic operation (Olm/Megolm/SAS via `mail4agent_vodozemac`,
    /// or the local record seal) failed. Wrapped as a plain message rather
    /// than the concrete upstream error type: this crate's own public API
    /// must not leak `mail4agent_vodozemac`'s error enum shape as part of
    /// its own contract.
    #[error("crypto: {0}")]
    Crypto(String),

    /// A [`crate::store::CryptoStore`]/[`crate::store::StateStore`]
    /// operation failed.
    #[error("store: {0}")]
    Store(#[from] crate::store::StoreError),

    /// Raised when a caller (`crate::outgoing_queue`/a later `sync_engine`
    /// piece) attempts to release an outgoing request while
    /// [`crate::persist::FlushEpoch::is_released`] reports it is not yet
    /// safe to do so — a state mutation the request depends on is not yet
    /// durably flushed and acknowledged. See the `persist` module doc for
    /// the exact per-request ordering guarantee this enforces.
    #[error(
        "outgoing requests are blocked: a state mutation they depend on is not yet flushed and acknowledged"
    )]
    FlushPending,

    /// [`crate::MessengerCommand::SendMessage`] named an `edit_of` target
    /// this account did not itself send (or that this core has never seen
    /// at all) — rejected outright by [`crate::MessengerCore::dispatch`]
    /// rather than silently sent as a replacement every other member's own
    /// `m.replace` aggregation would ignore anyway
    /// (`crate::room::relations`'s own module doc: "must come from the
    /// original sender").
    #[error("cannot edit {event_id}: not sent by this account, or unknown")]
    EditNotOwned {
        /// The event the caller tried to edit.
        event_id: crate::ids::EventId,
    },

    /// A [`crate::MessengerCommand`] the core refused to apply. The message
    /// names the command and the reason (an unknown room, a sealed event, ...).
    #[error("intent refused: {0}")]
    IntentRefused(String),
}

impl From<crate::canonical_json::CanonicalJsonError> for MessengerError {
    /// [`crate::canonical_json`] is its own small, dependency-light module
    /// (it only needs `mail4agent_vodozemac`'s signature types, not this crate's
    /// error type) -- this conversion is what lets `crypto::account` and
    /// later pieces use `?` against it without that module needing to know
    /// about [`MessengerError`] itself.
    fn from(err: crate::canonical_json::CanonicalJsonError) -> Self {
        MessengerError::Crypto(format!("canonical JSON: {err}"))
    }
}
