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

/// Streak at which the log says once more that the daemon is still retrying.
const HEAL_LOG_STREAK: u32 = 10;

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
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let stale_secs = env_secs("M4A_STALE_SECS", 180);
    let mut failing_since: Option<Instant> = None;
    let mut last_probe = Instant::now();
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
        // The log is per session, flattened: count what was printed for each nick, not overall.
        let log = client.wake_log();
        let mut now_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (nick, attempt) in &log {
            let n = now_counts.entry(nick.clone()).or_insert(0);
            *n += 1;
            if *n > seen.get(nick).copied().unwrap_or(0) {
                let status = attempt.status.map(|code| code.to_string()).unwrap_or_else(|| "queued (live deliver retried with backoff)".to_string());
                println!("wake {nick} event={} status={status}", attempt.event_id);
            }
        }
        seen = now_counts;
        if let Err(err) = client.poll_agent_directory() {
            eprintln!("agent poll: {err}");
        }
        if run_secs > 0 && started.elapsed().as_secs() >= run_secs {
            println!("run time reached; exiting");
            break;
        }
        // Sessions keep failing (homeserver down or restarting): back off instead of hammering it,
        // up to 10 s. The client rebuilds its push socket itself and the next clean tick resets this.
        let streak = client.error_streak();
        if streak == 1 || streak == HEAL_LOG_STREAK {
            eprintln!("homeserver unreachable or failing; backing off and retrying on its own");
        }
        // Health check: the client failing for minutes while a brand-new connection reaches the
        // homeserver means state inside this process went stale (seen 13.10 and 16.10: hours of
        // "error sending request" that a restart cured at once). Exit so the supervisor restarts it.
        if streak == 0 { failing_since = None; } else if failing_since.is_none() { failing_since = Some(Instant::now()); }
        if let Some(since) = failing_since {
            if stale_secs > 0 && since.elapsed().as_secs() >= stale_secs && last_probe.elapsed().as_secs() >= 60 {
                last_probe = Instant::now();
                if let Some(code) = fresh_probe() {
                    eprintln!("stale client: failing {}s while a fresh connection gets HTTP {code}; exiting for a restart", since.elapsed().as_secs());
                    std::process::exit(75);
                }
            }
        }
        let pause_ms = if streak == 0 { 250 } else { (250u64 << streak.min(6)).min(10_000) };
        std::thread::sleep(Duration::from_millis(pause_ms));
    }
}

/// One request on a brand-new HTTP client (new pool, new DNS lookup): `Some(status)` if the
/// homeserver answered at all.
fn fresh_probe() -> Option<u16> {
    let base = std::env::var("M4A_HOMESERVER_URL").or_else(|_| std::env::var("M4A_PRODUCT_URL")).ok()?;
    let url = format!("{}/_matrix/client/versions", base.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(10)).build().ok()?;
    client.get(url).send().ok().map(|r| r.status().as_u16())
}
