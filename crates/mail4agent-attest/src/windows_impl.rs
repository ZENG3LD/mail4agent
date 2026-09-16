//! The real implementation: everything in this module runs only on
//! Windows. See the crate doc comment for what each call proves.

use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use sysinfo::{Pid as SysPid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::{AttestError, Declared, PeerProcess};

/// FILETIME ticks (100 ns each) between the Windows epoch (1601-01-01) and
/// the Unix epoch (1970-01-01): 11_644_473_600 seconds, in 100 ns units.
const UNIX_EPOCH_AS_FILETIME_100NS: u64 = 116_444_736_000_000_000;

pub(crate) fn attest(peer: SocketAddr, local: SocketAddr) -> Result<PeerProcess, AttestError> {
    let pid = resolve_owning_pid(peer, local)?;
    let started_at_unix_ms =
        process_creation_time_ms(pid).map_err(|detail| AttestError::ProcessGone { pid, detail })?;
    let exe = query_full_process_image_name(pid);
    let (command_line, cwd) = process_command_line_and_cwd(pid);
    Ok(PeerProcess {
        pid,
        started_at_unix_ms,
        exe,
        command_line,
        cwd,
    })
}

pub(crate) fn is_alive(pid: u32, started_at_unix_ms: u64) -> bool {
    matches!(process_creation_time_ms(pid), Ok(current) if current == started_at_unix_ms)
}

// ── Connection table -> owning PID ──────────────────────────────────────

fn resolve_owning_pid(peer: SocketAddr, local: SocketAddr) -> Result<u32, AttestError> {
    match (local, peer) {
        (SocketAddr::V4(local_v4), SocketAddr::V4(peer_v4)) => resolve_owning_pid_v4(local_v4, peer_v4),
        (SocketAddr::V6(local_v6), SocketAddr::V6(peer_v6)) => resolve_owning_pid_v6(local_v6, peer_v6),
        _ => Err(AttestError::AddressFamilyMismatch { local, peer }),
    }
}

/// Grows a buffer until `GetExtendedTcpTable` fills it, or gives up after a
/// bounded number of retries. The table can grow between the size probe and
/// the real read (a new connection opens); this is that race, not the
/// PID-reuse race the crate doc comment discusses, and it is bounded rather
/// than looped forever against a pathological growth rate.
fn fetch_tcp_table(af: u32) -> Result<Vec<u8>, AttestError> {
    let mut size: u32 = 0;
    // SAFETY: a null table pointer with a valid `size` out-param is the
    // documented way to learn the required buffer size; the call only
    // writes to `size` in this mode.
    unsafe {
        GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, af, TCP_TABLE_OWNER_PID_ALL, 0);
    }

    for _ in 0..4 {
        let mut buf = vec![0u8; size as usize];
        let mut buf_len = size;
        // SAFETY: `buf` is exactly `buf_len` bytes, and both are passed to
        // the same call; the OS never writes past `buf_len`.
        let ret = unsafe {
            GetExtendedTcpTable(buf.as_mut_ptr().cast(), &mut buf_len, 0, af, TCP_TABLE_OWNER_PID_ALL, 0)
        };
        if ret == 0 {
            buf.truncate(buf_len as usize);
            return Ok(buf);
        }
        if ret != ERROR_INSUFFICIENT_BUFFER {
            return Err(AttestError::TableQueryFailed {
                detail: format!("GetExtendedTcpTable returned Win32 error {ret}"),
            });
        }
        size = buf_len;
    }

    Err(AttestError::TableQueryFailed {
        detail: "GetExtendedTcpTable's required buffer size kept growing across retries".into(),
    })
}

fn resolve_owning_pid_v4(local: SocketAddrV4, peer: SocketAddrV4) -> Result<u32, AttestError> {
    let buf = fetch_tcp_table(u32::from(AF_INET))?;
    let table_off = mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
    if buf.len() < table_off {
        return Err(AttestError::TableQueryFailed {
            detail: "TCP table buffer smaller than its own header".into(),
        });
    }
    // SAFETY: bounds-checked above; the header (`dwNumEntries`) is a plain
    // `u32` at offset 0, exactly the layout `GetExtendedTcpTable` documents
    // it writes.
    let num_entries = unsafe { (*buf.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>()).dwNumEntries } as usize;
    let entry_size = mem::size_of::<MIB_TCPROW_OWNER_PID>();

    for i in 0..num_entries {
        let offset = table_off + i * entry_size;
        if offset + entry_size > buf.len() {
            break;
        }
        // SAFETY: bounds-checked above; `MIB_TCPROW_OWNER_PID` is a
        // `#[repr(C)]` struct of five 4-byte-aligned `u32` fields, which is
        // exactly what this row's byte range holds.
        let row = unsafe { &*buf.as_ptr().add(offset).cast::<MIB_TCPROW_OWNER_PID>() };

        let row_local_ip = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
        let row_local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let row_remote_ip = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
        let row_remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);

        // The row we want is the *peer's* own socket: its local endpoint is
        // what we call `peer`, and its remote endpoint is what we call
        // `local` -- see the module doc comment on `attest`.
        if row_local_ip == *peer.ip() && row_local_port == peer.port() && row_remote_ip == *local.ip() && row_remote_port == local.port() {
            if row.dwOwningPid == 0 {
                return Err(AttestError::NoOwningProcess { local: SocketAddr::V4(local), peer: SocketAddr::V4(peer) });
            }
            return Ok(row.dwOwningPid);
        }
    }

    Err(AttestError::ConnectionNotFound { local: SocketAddr::V4(local), peer: SocketAddr::V4(peer) })
}

fn resolve_owning_pid_v6(local: SocketAddrV6, peer: SocketAddrV6) -> Result<u32, AttestError> {
    let buf = fetch_tcp_table(u32::from(AF_INET6))?;
    let table_off = mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
    if buf.len() < table_off {
        return Err(AttestError::TableQueryFailed {
            detail: "TCPv6 table buffer smaller than its own header".into(),
        });
    }
    // SAFETY: see resolve_owning_pid_v4 -- same layout guarantee for the
    // header field.
    let num_entries = unsafe { (*buf.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>()).dwNumEntries } as usize;
    let entry_size = mem::size_of::<MIB_TCP6ROW_OWNER_PID>();

    for i in 0..num_entries {
        let offset = table_off + i * entry_size;
        if offset + entry_size > buf.len() {
            break;
        }
        // SAFETY: bounds-checked above; `MIB_TCP6ROW_OWNER_PID` is a
        // `#[repr(C)]` struct whose byte layout is exactly this row's byte
        // range (two 16-byte address arrays plus naturally-aligned `u32`
        // fields, with no inserted padding -- see the crate's implementation
        // notes).
        let row = unsafe { &*buf.as_ptr().add(offset).cast::<MIB_TCP6ROW_OWNER_PID>() };

        let row_local_ip = Ipv6Addr::from(row.ucLocalAddr);
        let row_local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let row_remote_ip = Ipv6Addr::from(row.ucRemoteAddr);
        let row_remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);

        if row_local_ip == *peer.ip() && row_local_port == peer.port() && row_remote_ip == *local.ip() && row_remote_port == local.port() {
            if row.dwOwningPid == 0 {
                return Err(AttestError::NoOwningProcess { local: SocketAddr::V6(local), peer: SocketAddr::V6(peer) });
            }
            return Ok(row.dwOwningPid);
        }
    }

    Err(AttestError::ConnectionNotFound { local: SocketAddr::V6(local), peer: SocketAddr::V6(peer) })
}

// ── PID -> kernel-attested facts ────────────────────────────────────────

/// Closes a process handle exactly once, even on an early return via `?`.
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` was returned by a successful `OpenProcess` call
        // and is only ever wrapped here once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn open_process_query_limited(pid: u32) -> Result<HandleGuard, String> {
    // SAFETY: `PROCESS_QUERY_LIMITED_INFORMATION` is enough for
    // `GetProcessTimes`/`QueryFullProcessImageName` and does not require
    // the target to be at or below the caller's integrity level; a null
    // return means failure, checked below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(format!("OpenProcess({pid}) failed: {}", std::io::Error::last_os_error()));
    }
    Ok(HandleGuard(handle))
}

fn process_creation_time_ms(pid: u32) -> Result<u64, String> {
    let handle = open_process_query_limited(pid)?;

    let mut creation = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut exit = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut kernel = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut user = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    // SAFETY: `handle.0` is a valid, open process handle for the lifetime
    // of this call; the four out-params are stack-local `FILETIME`s sized
    // exactly as the call expects.
    let ok = unsafe { GetProcessTimes(handle.0, &mut creation, &mut exit, &mut kernel, &mut user) };
    if ok == 0 {
        return Err(format!("GetProcessTimes({pid}) failed: {}", std::io::Error::last_os_error()));
    }

    Ok(filetime_to_unix_ms(creation))
}

fn filetime_to_unix_ms(ft: FILETIME) -> u64 {
    let ticks_100ns = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
    ticks_100ns.saturating_sub(UNIX_EPOCH_AS_FILETIME_100NS) / 10_000
}

fn query_full_process_image_name(pid: u32) -> Option<String> {
    let handle = open_process_query_limited(pid).ok()?;

    // A generous fixed buffer rather than a size-probe loop: unlike
    // `GetExtendedTcpTable`, `QueryFullProcessImageNameW` has no documented
    // way to ask for the required length up front, only to fail with
    // `ERROR_INSUFFICIENT_BUFFER` and no length -- so growing and retrying
    // buys nothing a large-enough single buffer doesn't.
    let mut buf = [0u16; 4096];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` is exactly `len` `u16` elements; the call never writes
    // past `len` and reports the written length back into it.
    let ok = unsafe { QueryFullProcessImageNameW(handle.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

fn process_command_line_and_cwd(pid: u32) -> (Option<Declared<String>>, Option<Declared<String>>) {
    let sys_pid = SysPid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[sys_pid]),
        false,
        ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always).with_cwd(UpdateKind::Always),
    );

    let Some(process) = system.process(sys_pid) else {
        return (None, None);
    };

    let command_line = {
        let parts: Vec<String> = process.cmd().iter().map(|s| s.to_string_lossy().into_owned()).collect();
        if parts.is_empty() {
            None
        } else {
            Some(Declared::new(parts.join(" ")))
        }
    };
    let cwd = process.cwd().map(|p| Declared::new(p.display().to_string()));

    (command_line, cwd)
}
