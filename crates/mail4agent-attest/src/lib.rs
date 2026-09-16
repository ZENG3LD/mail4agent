//! Attests which OS process is on the other end of a loopback TCP
//! connection -- from the operating system, never from anything the caller
//! says.
//!
//! **Why this exists**: several sessions of the same agent CLI run on one
//! machine, and every session reads the same bearer token out of the same
//! config file, so the token cannot tell them apart. Each session *is* its
//! own process, though, and the operating system can tell processes apart
//! even when a shared secret cannot. This crate is how a mailbox learns who
//! is actually calling, without ever asking the caller to name itself.
//!
//! **What this proves, and what it does not** -- read this before treating
//! anything this crate returns as more than an audit trail. The research
//! this crate implements is
//! `docs/gate4agent/research/local-workload-identity-attestation-2026-09-17.md`;
//! its bottom line, in one sentence: Windows has no cryptographic
//! peer-credential mechanism on a loopback TCP socket, so the honest
//! ceiling is *"resolve `(pid, start-time)` from the kernel at connection
//! time and treat that as the identity, instead of trusting anything the
//! client claims."* [`PeerProcess::pid`] and
//! [`PeerProcess::started_at_unix_ms`] are exactly that pair; [`is_alive`]
//! is the check that makes the pair, not the bare PID, do the work -- a PID
//! alone is reused the moment its process exits.
//!
//! [`PeerProcess::exe`] is the same kind of fact: read from the kernel's
//! own record of which file backs the process's image, not from anything
//! the process could rewrite about itself. [`PeerProcess::command_line`]
//! and [`PeerProcess::cwd`], by contrast, are read out of the process's
//! *own* memory and wrapped in [`Declared`] for that reason -- see that
//! type's doc comment before treating either as anything more than a log
//! line.
//!
//! **Resolve at call time; never cache a PID and trust it later.** The
//! research names the exact race this closes: between reading the OS
//! connection table and acting on the PID it names, the original process
//! can exit and the OS can hand that same PID to something else entirely.
//! [`attest`] does the whole resolution -- connection table, then process
//! creation time, then process detail -- synchronously, for the one
//! connection it was asked about, so there is nothing left to go stale
//! between steps.

mod declared;
mod error;

#[cfg(windows)]
mod windows_impl;

use std::net::SocketAddr;

pub use declared::Declared;
pub use error::AttestError;

/// The OS process the kernel says owns the peer side of a loopback TCP
/// connection, resolved at the moment [`attest`] was called.
///
/// See the module doc comment for the attested/declared split this struct
/// encodes: `pid`, `started_at_unix_ms` and `exe` come from the kernel and
/// cannot be rewritten by the process they describe; `command_line` and
/// `cwd` come from that process's own memory and can be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerProcess {
    /// Kernel-attested: the PID `GetExtendedTcpTable` reports as owning the
    /// connection's peer-side socket, at resolution time.
    pub pid: u32,
    /// Kernel-attested: `pid`'s creation time from `GetProcessTimes`, as
    /// milliseconds since the Unix epoch. `(pid, started_at_unix_ms)`
    /// together are the identity -- see [`is_alive`] for why `pid` alone is
    /// not.
    pub started_at_unix_ms: u64,
    /// Kernel-attested: `pid`'s executable image path, from
    /// `QueryFullProcessImageName` -- the kernel's own record of which file
    /// backs the process's image, not something the process can rewrite
    /// about itself. `None` if the process was already gone, or otherwise
    /// inaccessible, by the time this was read.
    pub exe: Option<String>,
    /// **Declared, not attested.** Read out of the process's own memory;
    /// see [`Declared`] before using this for anything beyond an audit
    /// trail. `None` under the same conditions as `exe`.
    pub command_line: Option<Declared<String>>,
    /// **Declared, not attested.** Read the same way, and with the same
    /// caveat, as `command_line`. `None` under the same conditions as
    /// `exe`.
    pub cwd: Option<Declared<String>>,
}

/// Resolves the OS process on the other end of a loopback TCP connection.
///
/// `peer` is the connecting party's address as this process's own socket
/// API reports it (`TcpStream::peer_addr()` on the accepted stream);
/// `local` is this process's own bound address for that same connection
/// (`TcpStream::local_addr()`). Both must be the same address family --
/// IPv4 throughout, or IPv6 throughout -- since they describe two ends of
/// one connection.
///
/// Resolves synchronously, from the kernel, for this one connection: see
/// the module doc comment on why a caller must not cache the result of one
/// call and reuse it for a later connection on the same addresses.
///
/// # Errors
///
/// Every failure is a named [`AttestError`] variant: an address-family
/// mismatch, an unreadable OS connection table, no matching row (the
/// connection has likely already closed), a matching row with no owning
/// process (`TIME_WAIT`), or a resolved PID that was already gone by the
/// time its creation time was read. Never a panic, and never a fabricated
/// [`PeerProcess`].
pub fn attest(peer: SocketAddr, local: SocketAddr) -> Result<PeerProcess, AttestError> {
    #[cfg(windows)]
    {
        windows_impl::attest(peer, local)
    }
    #[cfg(not(windows))]
    {
        let _ = (peer, local);
        Err(AttestError::UnsupportedPlatform)
    }
}

/// Whether `pid` is, right now, still the same process that started at
/// `started_at_unix_ms`.
///
/// A bare PID answers a different question -- "is some process running
/// under this number" -- because the OS reuses a PID the moment its process
/// exits. This checks both: if a process is running under `pid` but its
/// actual creation time no longer matches `started_at_unix_ms`, the number
/// has already been handed to an unrelated process, and this returns
/// `false`.
///
/// Resolves the current creation time itself, from the kernel, at the
/// moment of the call -- it never consults a value [`attest`] returned
/// earlier.
///
/// On a target this crate has no attestation implementation for, always
/// returns `false`: nothing on that target could have produced a
/// trustworthy `started_at_unix_ms` in the first place (see
/// [`AttestError::UnsupportedPlatform`]), so treating an unverifiable claim
/// as alive would be the wrong default.
pub fn is_alive(pid: u32, started_at_unix_ms: u64) -> bool {
    #[cfg(windows)]
    {
        windows_impl::is_alive(pid, started_at_unix_ms)
    }
    #[cfg(not(windows))]
    {
        let _ = (pid, started_at_unix_ms);
        false
    }
}

#[cfg(all(test, windows))]
mod tests;
