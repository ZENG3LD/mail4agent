//! Windows-only: see `lib.rs`'s `#[cfg(all(test, windows))]` on this
//! module. Every test here drives a real loopback TCP connection through
//! this crate's own `attest`/`is_alive` -- no mocked OS state, because the
//! whole point of the crate is what the kernel actually reports.

use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use super::*;

/// Accepts a loopback connection from this same test process and attests
/// it. Every other test in this file leans on this once it is proven by
/// `attest_resolves_this_process_over_loopback_v4` below.
fn attest_self_v4() -> (TcpStream, TcpStream, PeerProcess) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind v4 listener");
    let addr = listener.local_addr().expect("v4 listener addr");
    let client = TcpStream::connect(addr).expect("connect v4 client");
    let (server, _) = listener.accept().expect("accept v4 connection");

    let peer = server.peer_addr().expect("v4 peer addr");
    let local = server.local_addr().expect("v4 local addr");
    let process = attest(peer, local).expect("attest must resolve a live loopback connection");
    (client, server, process)
}

/// This is the test that proves the whole crate: a connection this test
/// process both ends of must attest back to this test process's own pid,
/// with a real (non-zero) creation time.
#[test]
fn attest_resolves_this_process_over_loopback_v4() {
    let (_client, _server, process) = attest_self_v4();
    assert_eq!(process.pid, std::process::id());
    assert_ne!(process.started_at_unix_ms, 0, "creation time must be a real timestamp, not the zero sentinel");
}

/// Same connection, over `::1`. Skipped, not failed, if this host has no
/// working IPv6 loopback -- that is an environment fact, not a defect in
/// this crate.
#[test]
fn attest_resolves_this_process_over_loopback_v6() {
    let listener = match TcpListener::bind("[::1]:0") {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("skipping: IPv6 loopback unavailable on this host: {err}");
            return;
        }
    };
    let addr = listener.local_addr().expect("v6 listener addr");
    let client = match TcpStream::connect(addr) {
        Ok(client) => client,
        Err(err) => {
            eprintln!("skipping: IPv6 loopback connect failed: {err}");
            return;
        }
    };
    let (server, _) = listener.accept().expect("accept v6 connection");

    let peer = server.peer_addr().expect("v6 peer addr");
    let local = server.local_addr().expect("v6 local addr");
    let process = attest(peer, local).expect("attest must resolve a live IPv6 loopback connection");

    assert_eq!(process.pid, std::process::id());
    assert_ne!(process.started_at_unix_ms, 0, "creation time must be a real timestamp, not the zero sentinel");

    drop(client);
}

/// `is_alive` must answer true for the exact `(pid, start-time)` pair a
/// real attestation produced, and false the moment the start time is off
/// by even one second -- the whole reason the pair, not the bare pid, is
/// the identity.
#[test]
fn is_alive_true_for_exact_pair_false_one_second_off() {
    let (_client, _server, process) = attest_self_v4();

    assert!(is_alive(process.pid, process.started_at_unix_ms), "the current process must be alive under its own real start time");
    assert!(
        !is_alive(process.pid, process.started_at_unix_ms.wrapping_add(1000)),
        "a start time one second later must be treated as a different process"
    );
    assert!(
        !is_alive(process.pid, process.started_at_unix_ms.wrapping_sub(1000)),
        "a start time one second earlier must be treated as a different process"
    );
}

/// A connection that has already closed must fail by naming the closure,
/// never by panicking and never by handing back some other process's pid.
/// The connection is closed for real (shutdown on both ends of a live
/// accept), then polled -- bounded, not indefinite -- until the OS drops it
/// from the table, so this test does not depend on assuming any particular
/// TIME_WAIT timing.
#[test]
fn attest_after_close_names_the_failure_never_a_wrong_pid() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let client = TcpStream::connect(addr).expect("connect client");
    let (server, _) = listener.accept().expect("accept connection");

    let peer = server.peer_addr().expect("peer addr");
    let local = server.local_addr().expect("local addr");

    let _ = client.shutdown(std::net::Shutdown::Both);
    let _ = server.shutdown(std::net::Shutdown::Both);
    drop(client);
    drop(server);
    drop(listener);

    for _ in 0..100 {
        match attest(peer, local) {
            Err(_named_error) => return,
            Ok(process) => {
                assert_eq!(process.pid, std::process::id(), "a still-open row must report the real owner, never a fabricated pid");
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("connection local={local} peer={peer} never left the OS connection table after close");
}

/// `command_line` is declared, but it must still contain something this
/// test independently knows is true: the running test binary's own file
/// name, which is always argv[0].
#[test]
fn command_line_contains_a_known_argument() {
    let (_client, _server, process) = attest_self_v4();
    let command_line = process.command_line.expect("this process must have a command line");

    let exe = std::env::current_exe().expect("current_exe");
    let exe_name = exe.file_name().and_then(|name| name.to_str()).expect("exe file name");

    assert!(
        command_line.as_ref().to_lowercase().contains(&exe_name.to_lowercase()),
        "command line {:?} does not contain the running exe's name {exe_name:?}",
        command_line.as_ref()
    );
}
