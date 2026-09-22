use std::fmt;

/// A value read out of the *target process's own memory* -- its Process
/// Environment Block -- rather than recorded by the kernel about that
/// process independently.
///
/// The distinction is the whole reason this crate can be trusted for
/// anything: [`crate::PeerProcess::pid`] and
/// [`crate::PeerProcess::started_at_unix_ms`] come from `GetExtendedTcpTable`
/// and `GetProcessTimes` -- the kernel's own bookkeeping about the socket
/// and the process, which the process on the other end cannot rewrite about
/// itself. A `Declared<T>` did not come from the kernel: it was read from
/// the process's own address space, and a sufficiently capable process can
/// rewrite that memory before -- or after -- this crate reads it. This is
/// not a theoretical concern: rewriting a process's own PEB strings to
/// forge what a caller sees ("Masquerade-PEB") is a documented technique
/// seen in the wild. So a `Declared` value is real in one narrow sense --
/// *some* process at that PID held this data in memory at read time -- and
/// is never proof of what that process actually is or was launched with.
/// See
/// `docs/gate4agent/research/local-workload-identity-attestation-2026-09-17.md`
/// (sections 3 and 5) for the primary sources behind this split.
///
/// The wrapper exists so a caller cannot read
/// [`crate::PeerProcess::command_line`] or [`crate::PeerProcess::cwd`] off
/// a struct field and treat it with the same weight as `pid` by accident:
/// getting the inner value means calling [`Declared::into_inner`] or
/// [`Declared::inner_ref`], not a plain field read, so the caller has to
/// spell out that what they are holding is a declaration, not a fact the
/// kernel attested.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declared<T>(T);

impl<T> Declared<T> {
    /// Wraps a self-reported value. Crate-private: [`crate::attest`] is the
    /// only producer, and only for the two fields this crate has no
    /// kernel-backed source for.
    pub(crate) fn new(value: T) -> Self {
        Self(value)
    }

    /// Consumes the wrapper and returns the declared value.
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Borrows the declared value without consuming the wrapper. Named
    /// `inner_ref` rather than `as_ref` so it cannot be confused for
    /// `std::convert::AsRef::as_ref` (this type deliberately does not
    /// implement that trait).
    pub fn inner_ref(&self) -> &T {
        &self.0
    }
}

impl<T: fmt::Display> fmt::Display for Declared<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
