//! Local send socket shared by `m4a-send` and the machine / node clients.
//!
//! Unix is a mode-0600 domain socket at `path`. Windows does not create a
//! domain socket: the listener binds `127.0.0.1:0` and `path` is a file
//! whose only contents are `127.0.0.1:{port}\n`. Connect refuses any other
//! host. No path is included in bind errors.

use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

#[cfg(unix)]
type ListenerInner = std::os::unix::net::UnixListener;
#[cfg(unix)]
type StreamInner = std::os::unix::net::UnixStream;

#[cfg(windows)]
type ListenerInner = std::net::TcpListener;
#[cfg(windows)]
type StreamInner = std::net::TcpStream;

/// Bound send socket. [`SendListener::accept`] returns the stream only.
pub(crate) struct SendListener {
    inner: ListenerInner,
}

/// One accepted or connected send socket.
pub(crate) struct SendStream {
    inner: StreamInner,
}

impl SendListener {
    /// Binds `path`. A live peer already on that path is
    /// [`io::ErrorKind::AlreadyExists`] (the message has no path). A stale
    /// file is removed. The parent directory is created.
    pub(crate) fn bind(path: &Path) -> io::Result<Self> {
        if path.exists() {
            if SendStream::connect(path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "send socket already has a listener",
                ));
            }
            std::fs::remove_file(path)?;
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        Self::bind_fresh(path)
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    pub(crate) fn accept(&self) -> io::Result<SendStream> {
        let (stream, _) = self.inner.accept()?;
        Ok(SendStream { inner: stream })
    }
}

#[cfg(unix)]
impl SendListener {
    fn bind_fresh(path: &Path) -> io::Result<Self> {
        let listener = std::os::unix::net::UnixListener::bind(path)?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self { inner: listener })
    }
}

#[cfg(windows)]
impl SendListener {
    fn bind_fresh(path: &Path) -> io::Result<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let bytes = format!("127.0.0.1:{port}\n");
        if let Err(err) = std::fs::write(path, bytes.as_bytes()) {
            let _ = std::fs::remove_file(path);
            return Err(err);
        }
        Ok(Self { inner: listener })
    }
}

impl SendStream {
    /// The connecting process's OS user, where the OS tells it: SO_PEERCRED on Linux,
    /// getpeereid on macOS/BSD. `None` elsewhere (Windows loopback TCP carries no caller identity;
    /// there the session capability is the guard, and a per-user named pipe ACL is the next step).
    pub(crate) fn peer_uid(&self) -> Option<u32> {
        peer_uid_of(&self.inner)
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    pub(crate) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }
}

#[cfg(unix)]
impl SendStream {
    pub(crate) fn connect(path: &Path) -> io::Result<Self> {
        Ok(Self {
            inner: std::os::unix::net::UnixStream::connect(path)?,
        })
    }
}

#[cfg(windows)]
impl SendStream {
    /// Reads the address file and connects only when the host is `127.0.0.1`.
    pub(crate) fn connect(path: &Path) -> io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let text = text.trim();
        let (host, port) = text.rsplit_once(':').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "send socket address is not host:port",
            )
        })?;
        if host != "127.0.0.1" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "send socket host is not 127.0.0.1",
            ));
        }
        let port: u16 = port.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "send socket port is not a number",
            )
        })?;
        let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
        Ok(Self {
            inner: std::net::TcpStream::connect(addr)?,
        })
    }
}

impl Read for SendStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for SendStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};

    use super::*;

    struct TempDir(std::path::PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn send_socket_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "m4a-send-ipc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        let _cleanup = TempDir(dir.clone());
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("send.sock");
        let listener = SendListener::bind(&path).expect("bind");
        let server = std::thread::spawn(move || {
            let stream = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).expect("read");
            line
        });
        let mut client = SendStream::connect(&path).expect("connect");
        let payload = "{\"as\":\"a\",\"to\":\"b\",\"text\":\"hi\"}\n";
        client.write_all(payload.as_bytes()).expect("write");
        client.flush().expect("flush");
        drop(client);
        let line = server.join().expect("server thread");
        assert_eq!(line, payload);
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_uid_of(stream: &StreamInner) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: valid fd, out-pointer sized for ucred.
    let rc = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut libc::c_void, &mut len) };
    (rc == 0).then_some(cred.uid)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn peer_uid_of(stream: &StreamInner) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: valid fd and out-pointers.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    (rc == 0).then_some(uid)
}

#[cfg(windows)]
fn peer_uid_of(_stream: &StreamInner) -> Option<u32> {
    None
}

/// This process's OS user (unix), for comparing with [`SendStream::peer_uid`].
pub(crate) fn own_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        // SAFETY: getuid never fails.
        Some(unsafe { libc::getuid() })
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[cfg(all(test, unix))]
mod peer_tests {
    use super::*;

    #[test]
    fn peer_uid_is_the_connecting_os_user() {
        let dir = std::env::temp_dir().join(format!("m4a-peer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.sock");
        let listener = SendListener::bind(&path).unwrap();
        let _client = SendStream::connect(&path).unwrap();
        let server = listener.accept().unwrap();
        assert_eq!(server.peer_uid(), own_uid());
        assert!(server.peer_uid().is_some());
    }
}
