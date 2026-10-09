//! Local Grok ACP node client: one session per machine, woken on
//! `M4A_LEADER_SOCK`, never by webhook.
//!
//! Open path: [`mail4agent_messenger_shell::NodeClient::from_env`].
//! That refuses `M4A_ROUTINE_URL` / `M4A_ROUTINE_BEARER` before register,
//! requires an existing ACP leader socket, opens the homeserver push
//! link, and runs a drive/push loop. Replies go through the local send
//! socket (`m4a-send`, default `node-client.sock` under the store root).
//!
//! Homeserver URL, bot display name, session id, and store root come from
//! the environment / `node-client.env` (see the project documentation
//! `docs/mail4agent/local-acp-client.md`).
//! Nothing here embeds a host, URL, key, or bearer. This process does not
//! start `grok` and does not deploy to a VPS.

use mail4agent_messenger_shell::{
    load_env_file_named, NodeClient, ShellError, LEADER_SOCK_ENV,
};
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

fn main() {
    load_env_file_named("node-client.env");

    let mut client = match NodeClient::from_env() {
        Ok(client) => client,
        Err(err) => fail(&err),
    };

    match client.listen_for_sends_from_env() {
        Ok(path) => println!("send socket {}", path.display()),
        Err(err) => eprintln!("send socket not opened: {err}"),
    }

    let nick = client.nick().unwrap_or("(unknown)");
    println!("node open ok nick={nick}");
    println!("wake=acp sock_set=1");
    println!("push+drive loop; replies via m4a-send on the send socket");

    let drive_secs = env_secs("M4A_DRIVE_SECS", 15);
    let run_secs = env_secs("M4A_RUN_SECS", 0);
    let started = Instant::now();
    let mut seen_wakes = 0usize;

    loop {
        let report = client.tick(now_ms(), drive_secs);
        for event_id in &report.pushed {
            println!("push event={event_id}");
        }
        for room in &report.joined {
            println!("joined room={room}");
        }
        for (from, to, reply) in &report.sent {
            match (&reply.event_id, &reply.error) {
                (_, Some(err)) => println!("send {from} -> {to} failed: {err}"),
                (Some(event_id), None) => println!("send {from} -> {to} event={event_id}"),
                (None, None) => println!("send {from} -> {to} ok"),
            }
        }
        for err in &report.errors {
            eprintln!("drive: {err}");
        }
        if let Some(note) = &report.wake_note {
            // Public clipped note only (no bearer / body).
            if seen_wakes == 0 || client.wake_note() != Some(note.as_str()) {
                eprintln!("wake note: {note}");
            }
            seen_wakes = seen_wakes.saturating_add(1);
        }
        if run_secs > 0 && started.elapsed().as_secs() >= run_secs {
            println!("run time reached; exiting");
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn fail(err: &ShellError) -> ! {
    // ShellError never includes bearers, routine URLs, or keys.
    eprintln!("node open failed: {err}");
    if matches!(err, ShellError::NodeRoutine) {
        eprintln!(
            "node client refuses M4A_ROUTINE_URL / M4A_ROUTINE_BEARER;              webhooks are for m4a-web-client only"
        );
    }
    let _ = LEADER_SOCK_ENV;
    std::process::exit(1);
}
