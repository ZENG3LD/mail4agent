//! Live wake check: a throwaway session writes one encrypted DM to a nick.
//!
//! Registers a fresh session (display name `WakeTestSender`, nick
//! `waketestsender`, session id `wake-test-sender-<unix secs>`) with a store
//! under a temp directory, opens the encrypted DM with the target nick,
//! drives until the target joins (its web client accepts the invite), and
//! sends one text. Prints room id and event id only.
//!
//! `M4A_HOMESERVER_URL` is required; `M4A_TEST_TARGET` defaults to
//! `alice`; `M4A_TEST_WAIT_SECS` (default 90) bounds the wait for the join.
//!
//! cargo run -p mail4agent-messenger-shell --example wake_test_sender

use mail4agent_messenger_shell::{OpenedStore, SessionConfig};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

fn fail(step: &str, err: impl std::fmt::Display) -> ! {
    eprintln!("{step} failed: {err}");
    std::process::exit(1);
}

fn main() {
    let homeserver = std::env::var("M4A_HOMESERVER_URL")
        .unwrap_or_else(|_| fail("env", "M4A_HOMESERVER_URL is not set"));
    let target = std::env::var("M4A_TEST_TARGET").unwrap_or_else(|_| "alice".to_string());
    let wait_secs: u64 = std::env::var("M4A_TEST_WAIT_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(90);
    let stamp = now_ms() / 1000;
    let session_id = format!("wake-test-sender-{stamp}");
    let store_root = std::env::temp_dir().join(format!("m4a-wake-test-{stamp}"));
    let config = SessionConfig::new(
        &homeserver,
        "WakeTestSender",
        &session_id,
        &store_root,
        None,
    )
    .unwrap_or_else(|err| fail("config", err));
    let mut store = OpenedStore::connect(&config).unwrap_or_else(|err| fail("register", err));
    println!("registered nick={} session={session_id}", config.nick());
    let room_id = store
        .ensure_dm(&target, now_ms())
        .unwrap_or_else(|err| fail("ensure_dm", err));
    println!("dm room={room_id}");
    let started = Instant::now();
    let peer = store
        .find_nick(&target, now_ms())
        .unwrap_or_else(|err| fail("find_nick", err))
        .user_id;
    loop {
        if store.member_joined(&room_id, &peer) {
            break;
        }
        if started.elapsed().as_secs() >= wait_secs {
            fail(
                "join wait",
                format!("{target} did not join in {wait_secs}s"),
            );
        }
        store
            .drive(now_ms(), false)
            .unwrap_or_else(|err| fail("drive", err));
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("peer joined user={peer}");
    let encrypted = store
        .rooms()
        .into_iter()
        .any(|room| room.room_id == room_id && room.encrypted);
    println!("room encrypted={encrypted}");
    let text = format!("wake test {stamp}");
    store
        .write_to_nick(&target, &text, now_ms())
        .unwrap_or_else(|err| fail("write_to_nick", err));
    let event_id = store
        .texts()
        .into_iter()
        .find(|row| row.room_id == room_id && row.body == text)
        .and_then(|row| row.event_id)
        .unwrap_or_default();
    println!("sent event={event_id}");
}
