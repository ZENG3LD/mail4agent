//! The real implementation for Linux: everything in this module runs only
//! there. See the crate doc comment for what each call proves.
//!
//! There is no single kernel call here the way Windows has
//! `GetExtendedTcpTable`/`GetProcessTimes`: this module reads the same
//! `/proc` files `ss`/`netstat`/`lsof` do -- kernel-exposed, but as text, not
//! through a typed syscall.
//!
//! - **Connection -> owning pid.** `/proc/net/tcp` (`/proc/net/tcp6` for
//!   IPv6) lists every socket in this network namespace as one row per
//!   connection, keyed by its inode -- but the row itself does not name a
//!   pid. [`resolve_owning_pid`] gets there in two steps: match the row by
//!   its `(local, remote)` 4-tuple, then hand the row's inode to
//!   [`find_pid_owning_inode`], which scans every `/proc/<pid>/fd/*` symlink
//!   on the system for the one that reads `socket:[<that inode>]` -- the
//!   same technique `lsof` uses, because the kernel exposes no more direct
//!   inode -> pid mapping than that. A row whose inode is `0`, or whose
//!   inode no process's fd table currently holds, is treated the same way
//!   Windows treats `dwOwningPid == 0`: [`AttestError::NoOwningProcess`],
//!   not a wrong pid.
//! - **Process creation time.** `/proc/<pid>/stat`'s 22nd field is the
//!   process's start time in clock ticks since boot; `/proc/stat`'s `btime`
//!   line is the boot time itself, in seconds since the Unix epoch. Adding
//!   the two, after converting ticks to milliseconds via
//!   `sysconf(_SC_CLK_TCK)`, is this platform's answer to what
//!   `GetProcessTimes` gives directly on Windows -- see
//!   [`process_creation_time_ms`].
//! - **Executable path.** `/proc/<pid>/exe` is a symlink the kernel itself
//!   maintains to point at the file backing the process's image -- the same
//!   kernel-sourced fact `QueryFullProcessImageName` is on Windows, not
//!   something the process can rewrite about itself by editing its own
//!   memory.
//!
//! `/proc/net/tcp[6]`'s address fields are the one part of this file format
//! that is genuinely easy to misread: each is a native-endian `u32` dump of
//! the address, which on every architecture this crate ships for stores the
//! address's bytes in the *reverse* of their dotted-decimal order --
//! `"0100007F"` is `127.0.0.1`, not `1.0.0.127`. [`parse_hex_ipv4`] and
//! [`parse_hex_ipv6`] undo exactly that, and nothing else -- the port field
//! alongside it is already in ordinary big-endian form and needs no such
//! correction.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::{AttestError, PeerProcess};

pub(crate) fn attest(peer: SocketAddr, local: SocketAddr) -> Result<PeerProcess, AttestError> {
    let pid = resolve_owning_pid(peer, local)?;
    let started_at_unix_ms =
        process_creation_time_ms(pid).map_err(|detail| AttestError::ProcessGone { pid, detail })?;
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|path| path.to_string_lossy().into_owned());
    let (command_line, cwd) = crate::common::process_command_line_and_cwd(pid);
    Ok(PeerProcess { pid, started_at_unix_ms, exe, command_line, cwd })
}

pub(crate) fn is_alive(pid: u32, started_at_unix_ms: u64) -> bool {
    matches!(process_creation_time_ms(pid), Ok(current) if current == started_at_unix_ms)
}

// ── /proc/net/tcp[6] -> owning pid ──────────────────────────────────────

fn resolve_owning_pid(peer: SocketAddr, local: SocketAddr) -> Result<u32, AttestError> {
    let (path, expect_v6) = match (local, peer) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => ("/proc/net/tcp", false),
        (SocketAddr::V6(_), SocketAddr::V6(_)) => ("/proc/net/tcp6", true),
        _ => return Err(AttestError::AddressFamilyMismatch { local, peer }),
    };

    let table = std::fs::read_to_string(path)
        .map_err(|err| AttestError::TableQueryFailed { detail: format!("reading {path} failed: {err}") })?;

    // The header line names the columns; every row after it is one socket.
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(local_field), Some(remote_field), Some(inode_field)) =
            (fields.get(1), fields.get(2), fields.get(9))
        else {
            continue;
        };
        let (Some(row_local), Some(row_remote)) =
            (parse_proc_net_addr(local_field, expect_v6), parse_proc_net_addr(remote_field, expect_v6))
        else {
            continue;
        };

        // The row we want is the *peer's* own socket: its local endpoint is
        // what we call `peer`, and its remote endpoint is what we call
        // `local` -- see the crate doc comment on `attest`.
        if row_local != peer || row_remote != local {
            continue;
        }

        let inode: u64 = inode_field.parse().unwrap_or(0);
        if inode == 0 {
            return Err(AttestError::NoOwningProcess { local, peer });
        }
        return find_pid_owning_inode(inode).ok_or(AttestError::NoOwningProcess { local, peer });
    }

    Err(AttestError::ConnectionNotFound { local, peer })
}

fn parse_proc_net_addr(field: &str, expect_v6: bool) -> Option<SocketAddr> {
    let (addr_hex, port_hex) = field.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if expect_v6 {
        let ip = parse_hex_ipv6(addr_hex)?;
        Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
    } else {
        let ip = parse_hex_ipv4(addr_hex)?;
        Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    }
}

/// See the module doc comment's closing paragraph for why the byte order
/// here is not the naive reading of the hex text.
fn parse_hex_ipv4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let word = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(word.to_le_bytes()))
}

/// Same correction as [`parse_hex_ipv4`], applied to each of the address's
/// four 32-bit words in turn -- the words themselves stay in their original
/// order; only the bytes within each one are reversed.
fn parse_hex_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for word_index in 0..4 {
        let chunk = hex.get(word_index * 8..word_index * 8 + 8)?;
        let word = u32::from_str_radix(chunk, 16).ok()?;
        octets[word_index * 4..word_index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(Ipv6Addr::from(octets))
}

/// Scans every `/proc/<pid>/fd/*` symlink on the system for the one that
/// resolves to `socket:[<inode>]`. Best-effort: a `/proc/<pid>/fd` this
/// process cannot read (a different user's process) is skipped, not treated
/// as an error, the same way a Windows connection whose owning process
/// cannot be opened is a `None`-shaped absence rather than a hard failure.
fn find_pid_owning_inode(inode: u64) -> Option<u32> {
    let target = format!("socket:[{inode}]");
    let proc_entries = std::fs::read_dir("/proc").ok()?;
    for proc_entry in proc_entries.flatten() {
        let Some(pid) = proc_entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(fd_entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd_entry in fd_entries.flatten() {
            if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                if link.to_str() == Some(target.as_str()) {
                    return Some(pid);
                }
            }
        }
    }
    None
}

// ── pid -> creation time ────────────────────────────────────────────────

fn process_creation_time_ms(pid: u32) -> Result<u64, String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|err| format!("reading /proc/{pid}/stat failed: {err}"))?;
    let starttime_ticks =
        parse_starttime_ticks(&stat).ok_or_else(|| format!("/proc/{pid}/stat did not have the expected field layout"))?;
    let clk_tck = clock_ticks_per_second()?;
    let boot_time_unix_s = boot_time_unix_seconds()?;
    let ticks_ms = starttime_ticks.saturating_mul(1000) / clk_tck;
    Ok(boot_time_unix_s.saturating_mul(1000).saturating_add(ticks_ms))
}

/// `/proc/<pid>/stat`'s process-name field (its 2nd) is parenthesised and
/// may itself contain spaces or even parentheses, so this finds the *last*
/// `)` on the line before splitting the remainder on whitespace -- the same
/// reason `ps`/`top` parse this file the same way rather than a naive
/// `split_whitespace` over the whole line.
fn parse_starttime_ticks(stat: &str) -> Option<u64> {
    let close_paren = stat.rfind(')')?;
    let rest = stat.get(close_paren + 1..)?;
    // `rest`'s fields start at the original file's 3rd field (`state`), so
    // the 22nd field (`starttime`) is this iterator's 19th (`22 - 3`).
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn clock_ticks_per_second() -> Result<u64, String> {
    // SAFETY: `_SC_CLK_TCK` is a well-known, always-valid `sysconf` name;
    // this call only reads a kernel-reported constant and writes nothing.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks <= 0 {
        return Err(format!("sysconf(_SC_CLK_TCK) returned a non-positive value: {ticks}"));
    }
    Ok(ticks as u64)
}

fn boot_time_unix_seconds() -> Result<u64, String> {
    let stat = std::fs::read_to_string("/proc/stat").map_err(|err| format!("reading /proc/stat failed: {err}"))?;
    for line in stat.lines() {
        if let Some(value) = line.strip_prefix("btime ") {
            return value.trim().parse::<u64>().map_err(|err| format!("parsing /proc/stat's btime line failed: {err}"));
        }
    }
    Err("/proc/stat has no btime line".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_ipv4_decodes_the_reversed_byte_order() {
        assert_eq!(parse_hex_ipv4("0100007F"), Some(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn parse_hex_ipv4_rejects_the_wrong_length() {
        assert_eq!(parse_hex_ipv4("7F"), None);
    }

    #[test]
    fn parse_hex_ipv6_rejects_the_wrong_length() {
        assert_eq!(parse_hex_ipv6("0100007F"), None);
    }

    #[test]
    fn parse_starttime_ticks_reads_field_22_past_a_parenthesised_comm() {
        // A real `/proc/<pid>/stat` line, comm field holding a space and a
        // stray `)` on purpose -- exactly what `parse_starttime_ticks` must
        // not be confused by.
        let stat = "4242 (weird ) name) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 1 0 0 20 0 4 0 123456 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        assert_eq!(parse_starttime_ticks(stat), Some(123456));
    }
}
