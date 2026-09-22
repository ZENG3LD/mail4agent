//! The real implementation for macOS: everything in this module runs only
//! there. See the crate doc comment for what each call proves.
//!
//! `<libproc.h>`'s `proc_listpids`/`proc_pidinfo`/`proc_pidfdinfo`/
//! `proc_pidpath` and the plain scalar structs they fill for a process
//! overall (`proc_bsdinfo`, `proc_fdinfo`) are already bound in the `libc`
//! crate -- this crate already depends on it for `sysinfo`'s sake, and it
//! needs no build-time code generation to carry them. The one thing `libc`
//! does not carry is the socket-detail structures `PROC_PIDFDSOCKETINFO`
//! fills in (`socket_fdinfo`/`socket_info`/`in_sockinfo`/`tcp_sockinfo`),
//! declared below.
//!
//! Those were **not** hand-typed from memory: they are transcribed
//! field-for-field from Apple's own `<sys/proc_info.h>`, cross-checked
//! against the pre-generated bindgen output the `libproc` crate ships for
//! docs.rs builds (`libproc-0.14.11/docs_rs/osx_libproc_bindings.rs`) rather
//! than generated fresh here. A `bindgen`-based crate (`libproc` itself,
//! `netstat2`) was rejected for this job specifically because both pull in
//! `bindgen` + `clang-sys` as an unconditional macOS build dependency --
//! meaning a real `libclang` install and a hardcoded Xcode SDK header path,
//! on a build host this crate cannot assume has either -- to bind a small,
//! stable, decades-unchanged corner of a public BSD header. `libc`'s own
//! bound functions plus these few hand-declared structs need nothing beyond
//! what `rustc` already links against on macOS.
//!
//! [`SocketInfo::soi_proto`] carries every one of `socket_info`'s real union
//! variants (`in_sockinfo`, `tcp_sockinfo`, `un_sockinfo`, `ndrv_info`,
//! `kern_event_info`, `kern_ctl_info`, `vsock_sockinfo`), not just the two
//! ([`InSockInfo`], [`TcpSockInfo`]) this module ever reads. This was found
//! the hard way, on real hardware, not reasoned out in advance: an earlier
//! version of this module declared only the two variants it reads, on the
//! theory that a smaller union costs nothing because `soi_proto` is the
//! *last* field of `socket_info`. That theory is wrong for this call:
//! `proc_pidfdinfo` checks `buffersize` against the kernel's own, full-sized
//! `socket_fdinfo` and refuses anything smaller with `ENOMEM`, rather than
//! copying out a truncated prefix -- unlike, say,
//! `QueryFullProcessImageName` on Windows, which happily fills less than it
//! was asked for. So every variant needs its full byte width declared here,
//! even though only two are ever read: only the *value* of the other five
//! is unused, never their *size*. [`UnSockInfo`]'s two 255-byte
//! `sockaddr_un`-or-raw-bytes fields are declared as plain byte arrays
//! rather than `libc::sockaddr_un` unions for the same reason in reverse --
//! this module needs their width to be right and never touches their
//! content.
//!
//! **Connection -> owning pid.** Unlike Windows (`GetExtendedTcpTable`) or
//! Linux (`/proc/net/tcp`), macOS's `libproc` API exposes no single
//! system-wide connection table -- only a per-process file-descriptor
//! listing. So [`resolve_owning_pid`] walks every pid on the machine
//! ([`libc::proc_listpids`]), lists each one's socket file descriptors
//! ([`libc::proc_pidinfo`] with [`libc::PROC_PIDLISTFDS`]), and reads each
//! one's connection detail ([`libc::proc_pidfdinfo`] with
//! [`PROC_PIDFDSOCKETINFO`]) until one matches the 4-tuple asked for. A
//! connection whose owning process has already closed the file descriptor
//! (the macOS analogue of Windows's `TIME_WAIT`-with-no-owner case) is
//! therefore indistinguishable from one that never existed on this
//! platform -- both surface as [`AttestError::ConnectionNotFound`], never a
//! wrong pid.
//!
//! **Process creation time.** [`libc::proc_pidinfo`] with
//! [`libc::PROC_PIDTBSDINFO`] fills a [`libc::proc_bsdinfo`], whose
//! `pbi_start_tvsec`/`pbi_start_tvusec` are this platform's answer to what
//! `GetProcessTimes` gives directly on Windows.
//!
//! **Executable path.** [`libc::proc_pidpath`] is the kernel's own record of
//! which file backs a process's image -- the same kind of fact
//! `QueryFullProcessImageName` is on Windows, not something the process can
//! rewrite about itself by editing its own memory.

use std::ffi::c_void;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use libc::{c_char, c_int, c_short, c_uchar, c_ushort, pid_t};

use crate::{AttestError, PeerProcess};

/// `proc_listpids`'s `PROC_ALL_PIDS` type selector -- every pid on the
/// machine, not `libc`'s own constant because `libc` does not carry this
/// one.
const PROC_ALL_PIDS: u32 = 1;

/// `proc_pidfdinfo`'s socket-detail flavour -- `libc` carries the sibling
/// `PROC_PIDLISTFDS`/`PROC_PIDTBSDINFO` flavours but not this one.
const PROC_PIDFDSOCKETINFO: c_int = 3;

/// `socket_info.soi_kind`'s value for a TCP socket -- the tag that makes
/// [`SocketInfoProto::pri_tcp`] the union's live reading.
const SOCKINFO_TCP: c_int = 2;

// ── `<sys/proc_info.h>`'s socket-detail structs, not carried by `libc` ──
//
// Field order, names and types below are transcribed verbatim from
// `libproc-0.14.11/docs_rs/osx_libproc_bindings.rs` -- see the module doc
// comment for why that source, not memory or a fresh `bindgen` run.

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: libc::off_t,
    fi_type: i32,
    fi_guardflags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct In4In6Addr {
    i46a_pad32: [u32; 3],
    i46a_addr4: libc::in_addr,
}

#[repr(C)]
#[derive(Clone, Copy)]
union InSockAddr {
    ina_46: In4In6Addr,
    ina_6: libc::in6_addr,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InSockInfoV4 {
    in4_tos: c_uchar,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InSockInfoV6 {
    in6_hlim: u8,
    in6_cksum: c_int,
    in6_ifindex: c_ushort,
    in6_hops: c_short,
}

/// Kept byte-exact with the real `in_sockinfo` (including the trailing
/// `insi_v4`/`insi_v6` fields this module never reads): it is embedded *by
/// value* inside [`TcpSockInfo`], which has real fields after it, so
/// truncating it here (unlike [`SocketInfoProto`] below) would silently
/// misalign every field `tcpsi_ini` precedes.
#[repr(C)]
#[derive(Clone, Copy)]
struct InSockInfo {
    insi_fport: c_int,
    insi_lport: c_int,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    rfu_1: u32,
    insi_faddr: InSockAddr,
    insi_laddr: InSockAddr,
    insi_v4: InSockInfoV4,
    insi_v6: InSockInfoV6,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TcpSockInfo {
    tcpsi_ini: InSockInfo,
    tcpsi_state: c_int,
    tcpsi_timer: [c_int; 4],
    tcpsi_mss: c_int,
    tcpsi_flags: u32,
    rfu_1: u32,
    tcpsi_tp: u64,
}

/// The two 255-byte address fields `un_sockinfo` carries -- kept as plain
/// byte arrays rather than a `ua_sun: libc::sockaddr_un` /
/// `ua_dummy: [c_char; 255]` union, since this module needs only their
/// width (for [`SocketInfoProto`]'s own size) and never their content. See
/// the module doc comment.
#[repr(C)]
#[derive(Clone, Copy)]
struct UnSockInfo {
    unsi_conn_so: u64,
    unsi_conn_pcb: u64,
    unsi_addr: [u8; 255],
    unsi_caddr: [u8; 255],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NdrvInfo {
    ndrvsi_if_family: u32,
    ndrvsi_if_unit: u32,
    ndrvsi_if_name: [c_char; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KernEventInfo {
    kesi_vendor_code_filter: u32,
    kesi_class_filter: u32,
    kesi_subclass_filter: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KernCtlInfo {
    kcsi_id: u32,
    kcsi_reg_unit: u32,
    kcsi_flags: u32,
    kcsi_recvbufsize: u32,
    kcsi_sendbufsize: u32,
    kcsi_unit: u32,
    kcsi_name: [c_char; 96],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VsockSockInfo {
    local_cid: u32,
    local_port: u32,
    remote_cid: u32,
    remote_port: u32,
}

/// Every real `socket_info.soi_proto` variant, not just the two
/// ([`InSockInfo`], [`TcpSockInfo`]) this module ever reads -- see the
/// module doc comment for why `proc_pidfdinfo` requires the full width
/// here, unlike a plain "give me at most this many bytes" API.
#[repr(C)]
#[derive(Clone, Copy)]
union SocketInfoProto {
    pri_in: InSockInfo,
    pri_tcp: TcpSockInfo,
    pri_un: UnSockInfo,
    pri_ndrv: NdrvInfo,
    pri_kern_event: KernEventInfo,
    pri_kern_ctl: KernCtlInfo,
    pri_vsock: VsockSockInfo,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockBufInfo {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: c_short,
    sbi_timeo: c_short,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketInfo {
    soi_stat: libc::vinfo_stat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: c_int,
    soi_protocol: c_int,
    soi_family: c_int,
    soi_options: c_short,
    soi_linger: c_short,
    soi_state: c_short,
    soi_qlen: c_short,
    soi_incqlen: c_short,
    soi_qlimit: c_short,
    soi_timeo: c_short,
    soi_error: c_ushort,
    soi_oobmark: u32,
    soi_rcv: SockBufInfo,
    soi_snd: SockBufInfo,
    soi_kind: c_int,
    rfu_1: u32,
    soi_proto: SocketInfoProto,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketFdInfo {
    pfi: ProcFileInfo,
    psi: SocketInfo,
}

// ── entry points ─────────────────────────────────────────────────────────

pub(crate) fn attest(peer: SocketAddr, local: SocketAddr) -> Result<PeerProcess, AttestError> {
    let pid = resolve_owning_pid(peer, local)?;
    let started_at_unix_ms =
        process_creation_time_ms(pid).map_err(|detail| AttestError::ProcessGone { pid: pid as u32, detail })?;
    let exe = query_pid_path(pid);
    let (command_line, cwd) = crate::common::process_command_line_and_cwd(pid as u32);
    Ok(PeerProcess { pid: pid as u32, started_at_unix_ms, exe, command_line, cwd })
}

pub(crate) fn is_alive(pid: u32, started_at_unix_ms: u64) -> bool {
    matches!(process_creation_time_ms(pid as pid_t), Ok(current) if current == started_at_unix_ms)
}

// ── connection -> owning pid ─────────────────────────────────────────────

fn resolve_owning_pid(peer: SocketAddr, local: SocketAddr) -> Result<pid_t, AttestError> {
    match (local, peer) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_)) => {}
        _ => return Err(AttestError::AddressFamilyMismatch { local, peer }),
    }

    for pid in list_all_pids()? {
        for fd in list_socket_fds(pid).unwrap_or_default() {
            let Some(info) = socket_fd_info(pid, fd) else { continue };
            if matches_connection(&info, peer, local) {
                return Ok(pid);
            }
        }
    }

    Err(AttestError::ConnectionNotFound { local, peer })
}

fn list_all_pids() -> Result<Vec<pid_t>, AttestError> {
    // SAFETY: a null buffer with buffersize 0 is `proc_listpids`'s
    // documented way to report how many bytes a full listing needs; the
    // call only reads its own arguments in this mode.
    let needed = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        return Err(AttestError::TableQueryFailed {
            detail: format!("proc_listpids size probe failed: {}", std::io::Error::last_os_error()),
        });
    }

    // A margin over the probed size: pids can appear between the probe and
    // the real call, the same growth race `windows_impl`'s own
    // `fetch_tcp_table` documents for `GetExtendedTcpTable`.
    let capacity = (needed as usize / mem::size_of::<pid_t>()) + 64;
    let mut buf = vec![0 as pid_t; capacity];
    let buffer_bytes = (buf.len() * mem::size_of::<pid_t>()) as c_int;
    // SAFETY: `buf` holds exactly `buffer_bytes` bytes; the call never
    // writes past the `buffersize` it is given.
    let written =
        unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, buf.as_mut_ptr().cast::<c_void>(), buffer_bytes) };
    if written <= 0 {
        return Err(AttestError::TableQueryFailed {
            detail: format!("proc_listpids failed: {}", std::io::Error::last_os_error()),
        });
    }

    let count = (written as usize / mem::size_of::<pid_t>()).min(buf.len());
    buf.truncate(count);
    Ok(buf.into_iter().filter(|&pid| pid > 0).collect())
}

fn list_socket_fds(pid: pid_t) -> Option<Vec<c_int>> {
    // SAFETY: same size-probe pattern as `list_all_pids`.
    let needed = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        return None;
    }

    let capacity = (needed as usize / mem::size_of::<libc::proc_fdinfo>()) + 16;
    let mut buf = vec![libc::proc_fdinfo { proc_fd: 0, proc_fdtype: 0 }; capacity];
    let buffer_bytes = (buf.len() * mem::size_of::<libc::proc_fdinfo>()) as c_int;
    // SAFETY: `buf` holds exactly `buffer_bytes` bytes of `proc_fdinfo`
    // records; the call never writes past the `buffersize` it is given.
    let written = unsafe {
        libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, buf.as_mut_ptr().cast::<c_void>(), buffer_bytes)
    };
    if written <= 0 {
        return None;
    }

    let count = (written as usize / mem::size_of::<libc::proc_fdinfo>()).min(buf.len());
    Some(
        buf[..count]
            .iter()
            .filter(|entry| entry.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
            .map(|entry| entry.proc_fd)
            .collect(),
    )
}

fn socket_fd_info(pid: pid_t, fd: c_int) -> Option<SocketFdInfo> {
    // SAFETY: an all-zero bit pattern is a valid instance of every field in
    // this struct (integers, arrays of integers, and unions whose own
    // fields are the same) -- there is no enum discriminant or reference
    // anywhere in it for zeroing to violate.
    let mut info: SocketFdInfo = unsafe { mem::zeroed() };
    let size = mem::size_of::<SocketFdInfo>() as c_int;
    // SAFETY: `info` is a stack-local buffer of exactly `size` bytes; the
    // call writes at most `size` bytes into it. `size` matches the kernel's
    // own `socket_fdinfo` width -- see the module doc comment for why that
    // match is required, not merely sufficient.
    let written = unsafe {
        libc::proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, (&mut info as *mut SocketFdInfo).cast::<c_void>(), size)
    };
    if written <= 0 {
        return None;
    }
    Some(info)
}

fn matches_connection(info: &SocketFdInfo, peer: SocketAddr, local: SocketAddr) -> bool {
    if info.psi.soi_kind != SOCKINFO_TCP {
        return false;
    }
    // SAFETY: `soi_kind == SOCKINFO_TCP` is exactly the tag that makes
    // `pri_tcp` the union's live variant.
    let ini = unsafe { info.psi.soi_proto.pri_tcp }.tcpsi_ini;

    let Some(row_local) = socket_addr_from(&ini.insi_laddr, ini.insi_lport, info.psi.soi_family) else {
        return false;
    };
    let Some(row_remote) = socket_addr_from(&ini.insi_faddr, ini.insi_fport, info.psi.soi_family) else {
        return false;
    };

    // The fd being inspected is the *peer's* own socket: its local endpoint
    // is what we call `peer`, and its remote endpoint is what we call
    // `local` -- see the module doc comment on `attest` in `lib.rs`.
    row_local == peer && row_remote == local
}

fn socket_addr_from(addr: &InSockAddr, raw_port: c_int, family: c_int) -> Option<SocketAddr> {
    // `insi_lport`/`insi_fport` are declared as a full `int`, but the kernel
    // only ever assigns a `u_short` into them (`inp_lport`/`inp_fport`,
    // themselves kept in network byte order) -- a widening conversion that
    // preserves the numeric value, never reinterprets its bytes. So the low
    // 16 bits, read back through the same "true wire bytes, then read as
    // big-endian" step [`Ipv4Addr`] below uses for the address, are the
    // port -- not a plain `u16::from(raw_port)`.
    let port = u16::from_be_bytes((raw_port as u16).to_le_bytes());
    match family {
        libc::AF_INET => {
            // SAFETY: `family == AF_INET` is exactly the tag that makes
            // `ina_46`'s embedded IPv4 address the union's live reading.
            let addr4 = unsafe { addr.ina_46 }.i46a_addr4;
            let ip = Ipv4Addr::from(addr4.s_addr.to_le_bytes());
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            // SAFETY: `family == AF_INET6` is exactly the tag that makes
            // `ina_6` the union's live reading.
            let addr6 = unsafe { addr.ina_6 };
            Some(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(addr6.s6_addr), port, 0, 0)))
        }
        _ => None,
    }
}

// ── pid -> creation time / exe path ─────────────────────────────────────

fn process_creation_time_ms(pid: pid_t) -> Result<u64, String> {
    // SAFETY: an all-zero `proc_bsdinfo` (a struct of plain integers and
    // char arrays) is a valid instance to hand the kernel to fill in.
    let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };
    let size = mem::size_of::<libc::proc_bsdinfo>() as c_int;
    // SAFETY: `info` is a stack-local buffer of exactly `size` bytes; the
    // call writes at most `size` bytes into it.
    let written = unsafe {
        libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&mut info as *mut libc::proc_bsdinfo).cast::<c_void>(), size)
    };
    if written < size {
        return Err(format!(
            "proc_pidinfo(PROC_PIDTBSDINFO, {pid}) returned {written} of {size} expected bytes: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(info.pbi_start_tvsec.saturating_mul(1000).saturating_add(info.pbi_start_tvusec / 1000))
}

fn query_pid_path(pid: pid_t) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buf` is exactly `buf.len()` bytes; the call never writes past
    // the `buffersize` it is given.
    let written = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast::<c_void>(), buf.len() as u32) };
    if written <= 0 {
        return None;
    }
    buf.truncate(written as usize);
    String::from_utf8(buf).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every currently-shipping Mac (Intel and Apple Silicon alike) is
    /// little-endian, so a raw field's value, as this test constructs it, is
    /// exactly what `proc_pidfdinfo` would hand back on real hardware for
    /// the same wire bytes: `u32::from_le_bytes`/`u16::from_le_bytes` of the
    /// address/port's *true*, network-order byte sequence, not
    /// `from_be_bytes` of it -- see `socket_addr_from`'s own doc comment for
    /// why loading network-order bytes on a little-endian host produces a
    /// value that reads "reversed" until this function undoes it.
    #[test]
    fn socket_addr_from_decodes_ipv4_loopback() {
        let addr = InSockAddr {
            ina_46: In4In6Addr {
                i46a_pad32: [0; 3],
                i46a_addr4: libc::in_addr { s_addr: u32::from_le_bytes([127, 0, 0, 1]) },
            },
        };
        let raw_port = i32::from(u16::from_le_bytes([0x1F, 0x90]));
        let resolved = socket_addr_from(&addr, raw_port, libc::AF_INET).expect("decodes");
        assert_eq!(resolved, SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)));
    }

    #[test]
    fn socket_addr_from_rejects_an_unknown_family() {
        let addr = InSockAddr { ina_6: libc::in6_addr { s6_addr: [0; 16] } };
        assert_eq!(socket_addr_from(&addr, 0, 0), None);
    }
}
