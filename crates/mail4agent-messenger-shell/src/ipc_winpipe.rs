//! Windows send socket: a named pipe that only this OS user can open.
//!
//! The pipe is created with a protected DACL granting GENERIC_ALL to the creating user's SID
//! only (plus SYSTEM), `PIPE_REJECT_REMOTE_CLIENTS`, and the first instance flag (a second daemon
//! cannot squat the name). On accept the client's process token is checked again: a client whose
//! user SID differs from ours is disconnected. This replaces the loopback TCP port, which any local
//! user could reach. Accept is non-blocking (`PIPE_NOWAIT` while listening); a connected instance
//! is switched to blocking mode for reads and writes.

#![cfg(windows)]

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, GENERIC_READ, GENERIC_WRITE,
    HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows_sys::Win32::Security::{EqualSid, GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId, SetNamedPipeHandleState, PIPE_NOWAIT,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: we own this handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}
unsafe impl Send for Handle {}

/// The user SID of a process token (bytes), or an error.
fn token_user_sid(process: HANDLE) -> io::Result<Vec<u8>> {
    let mut token: HANDLE = null_mut();
    // SAFETY: plain Win32 calls with valid out-pointers.
    unsafe {
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Handle(token);
        let mut len = 0u32;
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        if GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr() as *mut c_void, len, &mut len) == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(buf)
    }
}

fn sid_ptr(token_user: &[u8]) -> *mut c_void {
    // SAFETY: buffer was filled by GetTokenInformation(TokenUser).
    unsafe { (*(token_user.as_ptr() as *const TOKEN_USER)).User.Sid }
}

fn own_sid() -> io::Result<Vec<u8>> {
    // SAFETY: pseudo handle of the current process.
    token_user_sid(unsafe { GetCurrentProcess() })
}

fn sid_string(token_user: &[u8]) -> io::Result<String> {
    let mut out: *mut u16 = null_mut();
    // SAFETY: valid SID; the string is freed with LocalFree.
    unsafe {
        if ConvertSidToStringSidW(sid_ptr(token_user), &mut out) == 0 {
            return Err(io::Error::last_os_error());
        }
        let len = (0..).take_while(|&i| *out.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(out, len));
        LocalFree(out as *mut c_void);
        Ok(s)
    }
}

/// Pipe name for this user: `\\.\pipe\m4a-<tag>` where `tag` is chosen by the caller (a hash of
/// the socket path), so two daemons of one user on different store roots do not collide.
pub(crate) fn pipe_name(tag: &str) -> String {
    format!(r"\\.\pipe\m4a-{tag}")
}

pub(crate) struct PipeListener {
    name: Vec<u16>,
    sddl: Vec<u16>,
    current: std::sync::Mutex<Handle>,
    nonblocking: std::sync::atomic::AtomicBool,
    sid: Vec<u8>,
}

impl PipeListener {
    pub(crate) fn bind(name: &str) -> io::Result<Self> {
        let sid = own_sid()?;
        // Protected DACL: only this user and SYSTEM; nobody else may open the pipe.
        let sddl = wide(&format!("D:P(A;;GA;;;{})(A;;GA;;;SY)", sid_string(&sid)?));
        let name = wide(name);
        let current = Self::instance(&name, &sddl, true)?;
        Ok(Self { name, sddl, current: std::sync::Mutex::new(current), nonblocking: false.into(), sid })
    }

    fn instance(name: &[u16], sddl: &[u16], first: bool) -> io::Result<Handle> {
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: SDDL is NUL-terminated; descriptor freed below.
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) == 0 {
                return Err(io::Error::last_os_error());
            }
            let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
            let open_mode = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
            let h = CreateNamedPipeW(
                name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                &sa,
            );
            LocalFree(sd as *mut c_void);
            if h == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            Ok(Handle(h))
        }
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.nonblocking.store(nonblocking, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// One connected client of this OS user, or `WouldBlock` (non-blocking) when none is waiting.
    pub(crate) fn accept(&self) -> io::Result<PipeStream> {
        let mut current = self.current.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            // SAFETY: valid pipe handle in PIPE_NOWAIT mode.
            let connected = unsafe { ConnectNamedPipe(current.0, null_mut()) } != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
            if !connected {
                let err = unsafe { GetLastError() };
                if err == ERROR_PIPE_LISTENING {
                    if self.nonblocking.load(std::sync::atomic::Ordering::Relaxed) {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    continue;
                }
                if err == ERROR_NO_DATA {
                    // A client came and went: reset this instance.
                    unsafe { DisconnectNamedPipe(current.0) };
                    continue;
                }
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            let next = Self::instance(&self.name, &self.sddl, false)?;
            let handle = std::mem::replace(&mut *current, next);
            let wait = PIPE_READMODE_BYTE | PIPE_WAIT;
            // SAFETY: valid connected handle.
            unsafe { SetNamedPipeHandleState(handle.0, &wait, null(), null()) };
            if !client_is_user(handle.0, &self.sid) {
                unsafe { DisconnectNamedPipe(handle.0) };
                continue;
            }
            return Ok(PipeStream { h: handle });
        }
    }
}

/// The client process of a connected pipe runs as `sid`'s user.
fn client_is_user(pipe: HANDLE, sid: &[u8]) -> bool {
    let mut pid = 0u32;
    // SAFETY: valid pipe handle and out-pointer.
    unsafe {
        if GetNamedPipeClientProcessId(pipe, &mut pid) == 0 {
            return false;
        }
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return false;
        }
        let process = Handle(process);
        match token_user_sid(process.0) {
            Ok(theirs) => EqualSid(sid_ptr(&theirs), sid_ptr(sid)) != 0,
            Err(_) => false,
        }
    }
}

pub(crate) struct PipeStream {
    h: Handle,
}

impl PipeStream {
    pub(crate) fn connect(name: &str) -> io::Result<Self> {
        let w = wide(name);
        // SAFETY: NUL-terminated name.
        let h = unsafe { CreateFileW(w.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, null(), OPEN_EXISTING, 0, null_mut()) };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { h: Handle(h) })
    }
}

impl io::Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut n = 0u32;
        // SAFETY: valid handle, buffer and length.
        if unsafe { ReadFile(self.h.0, buf.as_mut_ptr(), buf.len().min(u32::MAX as usize) as u32, &mut n, null_mut()) } == 0 {
            let err = io::Error::last_os_error();
            // Broken pipe at EOF reads as end of stream.
            if err.raw_os_error() == Some(109) {
                return Ok(0);
            }
            return Err(err);
        }
        Ok(n as usize)
    }
}

impl io::Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut n = 0u32;
        // SAFETY: valid handle and buffer.
        if unsafe { WriteFile(self.h.0, buf.as_ptr(), buf.len().min(u32::MAX as usize) as u32, &mut n, null_mut()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
    fn flush(&mut self) -> io::Result<()> {
        // SAFETY: valid handle.
        unsafe { FlushFileBuffers(self.h.0) };
        Ok(())
    }
}
