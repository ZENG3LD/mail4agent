use std::net::SocketAddr;

use thiserror::Error;

/// Why [`crate::attest`] could not name the process on the other end of a
/// loopback connection. Every variant names what was looked up and why it
/// came back empty, never a bare "internal error" -- the mailbox this crate
/// serves treats an unnamed refusal as a defect (`mail4agent/CLAUDE.md`),
/// and this crate holds itself to the same standard even though it ships
/// independently.
#[derive(Debug, Error)]
pub enum AttestError {
    /// This crate has no attestation implementation for the running
    /// target. It still compiles and links everywhere -- an MIT crate
    /// ships cross-platform -- but only Windows has a real implementation
    /// today. See the module doc comment and
    /// `docs/gate4agent/research/local-workload-identity-attestation-2026-09-17.md`.
    #[error("process attestation is not implemented on this platform")]
    UnsupportedPlatform,

    /// `local` and `peer` name endpoints of different address families
    /// (one IPv4, one IPv6): they cannot be two ends of the same TCP
    /// connection, so there is nothing to resolve.
    #[error("local {local} and peer {peer} are different address families")]
    AddressFamilyMismatch { local: SocketAddr, peer: SocketAddr },

    /// The OS TCP connection table itself could not be read -- a call
    /// against `GetExtendedTcpTable` failed before any row was even
    /// considered. Carries the Win32 error detail.
    #[error("reading the OS TCP connection table failed: {detail}")]
    TableQueryFailed { detail: String },

    /// The table was read successfully, but no row's (local, remote) pair
    /// matched `(local, peer)`. The most likely explanation is that the
    /// connection already closed between accept and this call; it is also
    /// what a connection that never existed looks like.
    #[error("no TCP connection found between local {local} and peer {peer} in the OS connection table (already closed?)")]
    ConnectionNotFound { local: SocketAddr, peer: SocketAddr },

    /// A matching row was found, but the OS reports no owning process for
    /// it -- documented Windows behaviour for a connection that has moved
    /// into `TIME_WAIT`, which can outlive the process that created it.
    #[error("connection between local {local} and peer {peer} has no owning process (likely TIME_WAIT)")]
    NoOwningProcess { local: SocketAddr, peer: SocketAddr },

    /// The owning PID was resolved from the connection table, but the
    /// process was already gone -- or its creation time unreadable -- by
    /// the time this call tried to open it. This is the residual race the
    /// research names: resolving synchronously at connection time shrinks
    /// the window to the scheduling gap between the table snapshot and
    /// this call, it does not remove it.
    #[error("process {pid} could not be opened after it was found owning the connection (exited?): {detail}")]
    ProcessGone { pid: u32, detail: String },
}
