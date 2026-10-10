//! The web machine client as a process: [`MachineClient::from_env`], then
//! [`MachineClient::tick`] in a loop, and
//! [`MachineClient::poll_agent_directory`] on `M4A_AGENT_RESCAN_SECS`.
//!
//! Settings come from the environment, then from the env file
//! (`M4A_ENV_FILE`, default `~/.config/mail4agent/web-client.env`) for
//! anything unset. The client listens on the local send socket
//! (`M4A_SEND_SOCK`, default `web-client.sock` under the store root) for
//! `m4a-send`.
//!
//! Environment: everything `from_env` reads, plus `M4A_DRIVE_SECS` (full
//! drive period, default 15) and `M4A_RUN_SECS` (exit after that many
//! seconds; unset or 0 runs until killed). Prints nicks, event ids, room
//! ids, and HTTP statuses only. Never prints URLs, keys, or bearers.

use crate::MachineClient;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn env_secs(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

pub fn run(_args: Vec<String>) {
    crate::load_env_file();
    let mut client = match MachineClient::from_env() {
        Ok(client) => client,
        Err(err) => {
            eprintln!("open failed: {err}");
            std::process::exit(1);
        }
    };
    match client.listen_for_sends_from_env() {
        Ok(path) => println!("send socket {}", path.display()),
        Err(err) => eprintln!("send socket not opened: {err}"),
    }
    println!("open ok; waiting on the push socket");
    let drive_secs = env_secs("M4A_DRIVE_SECS", 15);
    let run_secs = env_secs("M4A_RUN_SECS", 0);
    let started = Instant::now();
    let mut seen = 0usize;
    loop {
        let report = client.tick(now_ms(), drive_secs);
        for (nick, event_id) in &report.pushed {
            println!("push {nick} event={event_id}");
        }
        for (nick, text) in &report.alerts {
            println!("alert {nick}: {text}");
        }
        for (nick, room) in &report.joined {
            println!("joined {nick} room={room}");
        }
        for (from, to, reply) in &report.sent {
            match (&reply.event_id, &reply.error) {
                (_, Some(err)) => println!("send {from} -> {to} failed: {err}"),
                (Some(event_id), None) => println!("send {from} -> {to} event={event_id}"),
                (None, None) => println!("send {from} -> {to} ok"),
            }
        }
        for (nick, err) in &report.errors {
            eprintln!("drive {nick}: {err}");
        }
        let log = client.wake_log();
        for (nick, attempt) in log.iter().skip(seen) {
            let status = attempt
                .status
                .map(|code| code.to_string())
                .unwrap_or_else(|| "none".to_string());
            println!("wake {nick} event={} status={status}", attempt.event_id);
        }
        seen = log.len();
        if let Err(err) = client.poll_agent_directory() {
            eprintln!("agent poll: {err}");
        }
        if run_secs > 0 && started.elapsed().as_secs() >= run_secs {
            println!("run time reached; exiting");
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}
