//! Process-detail lookup shared by every platform implementation in this
//! crate: command line and current working directory, for one already-known
//! pid.
//!
//! Both fields are [`Declared`], never attested -- see `declared.rs` for why.
//! `sysinfo` reaches them the same way on every target this crate supports
//! (`/proc/<pid>/{cmdline,cwd}` on Linux, `proc_pidinfo`/`sysctl` on macOS,
//! the PEB on Windows): refreshing a single already-known pid through
//! `System` is far less unsafe code than hand-rolling each platform's own
//! call for the same two fields, and the answer is declared regardless of
//! which platform produced it, so there is nothing platform-specific to gain
//! by doing it by hand here the way `attest`'s own connection-to-pid step
//! must be.
use sysinfo::{Pid as SysPid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::Declared;

pub(crate) fn process_command_line_and_cwd(pid: u32) -> (Option<Declared<String>>, Option<Declared<String>>) {
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
