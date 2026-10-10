//! Push listener for local grok sessions.
//!
//! Reads grok's `active_sessions.json`, registers each new session, and
//! holds the homeserver push socket. A pushed event is decrypted and the
//! turn is pressed with ACP `session/prompt` on the leader socket. This
//! process does not start `grok`. Webhook env is refused.

use crate::{
    hear, load_env_file_named, GrokListener, ShellError, LEADER_SOCK_ENV,
};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct SendOnce {
    session_id: String,
    to: String,
    text: String,
}

impl SendOnce {
    fn from_args(args: &[String]) -> Option<Self> {
        let mut session_id = None;
        let mut to = None;
        let mut words = Vec::new();
        let mut args = args.iter().cloned();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--session" => session_id = args.next(),
                "--to" => to = args.next(),
                _ => words.push(arg),
            }
        }
        let text = words.join(" ");
        if session_id.is_none() && to.is_none() && text.is_empty() {
            return None;
        }
        let (Some(session_id), Some(to)) = (session_id, to) else {
            eprintln!("grok listener send needs --session and --to");
            std::process::exit(2);
        };
        if text.trim().is_empty() {
            eprintln!("grok listener send needs text");
            std::process::exit(2);
        }
        Some(Self {
            session_id,
            to,
            text,
        })
    }
}

pub fn run(args: Vec<String>) {
    load_env_file_named("node-client.env");
    if std::env::var("M4A_ROUTINE_URL")
        .ok()
        .is_some_and(|value| !value.is_empty())
        || std::env::var("M4A_ROUTINE_BEARER")
            .ok()
            .is_some_and(|value| !value.is_empty())
    {
        eprintln!("grok listener refuses M4A_ROUTINE_URL / M4A_ROUTINE_BEARER");
        std::process::exit(1);
    }

    let homeserver = env_required("M4A_HOMESERVER_URL");
    let store = PathBuf::from(env_required("M4A_STORE_ROOT"));
    let grok_home = mail4agent_grok::grok_home().unwrap_or_else(|| {
        eprintln!("grok home is not set");
        std::process::exit(1);
    });
    let leader = std::env::var_os(LEADER_SOCK_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| mail4agent_grok::leader_socket(&grok_home, None));
    let index = std::env::var_os("M4A_GROK_INDEX")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| grok_home.join("active_sessions.json"));
    let sessions = grok_home.join("sessions");

    let mut listener = GrokListener::new(homeserver, store.clone(), leader);
    let send_sock = store.join("grok-listen.sock");
    if let Err(err) = listener.listen_for_sends(&send_sock) {
        eprintln!("send socket: {err}");
        std::process::exit(1);
    }
    println!("send sock=grok-listen.sock");
    let send_once = SendOnce::from_args(&args);
    let mut sent = send_once.is_none();
    println!("push listener up");
    println!("wake=acp");
    println!("wake=chain (registered codex/kimi/claude/cursor sessions)");

    loop {
        let text = std::fs::read_to_string(&index).unwrap_or_default();
        let heard = match hear(&text, &sessions) {
            Ok(heard) => heard,
            Err(ShellError::SessionList(err)) => {
                eprintln!("index: {err}");
                Vec::new()
            }
            Err(err) => {
                eprintln!("index: {err}");
                Vec::new()
            }
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as i64)
            .unwrap_or(0);
        listener.hear_providers(crate::provider::registry::live_sessions(&store));
        let report = listener.tick(&heard, now, 15);
        if !sent {
            if let Some(job) = &send_once {
                if heard.iter().any(|row| row.session_id == job.session_id) {
                    match listener.send_to(&job.session_id, &job.to, &job.text, now, Duration::from_secs(90))
                    {
                        Ok((room, event_id)) => println!(
                            "sent room={room} event={}",
                            event_id.unwrap_or_default()
                        ),
                        Err(err) => eprintln!("send: {err}"),
                    }
                    sent = true;
                }
            }
        }
        for nick in &report.adopted {
            println!("adopted nick={nick}");
        }
        for event_id in &report.pushed {
            println!("push event={event_id}");
        }
        for sent in &report.sent {
            println!("sent {sent}");
        }
        for err in &report.errors {
            eprintln!("listen: {err}");
        }
        for note in &report.wake_notes {
            eprintln!("wake note: {note}");
        }
        for route in &report.wake_routes {
            println!("wake route={route}");
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn env_required(key: &str) -> String {
    match std::env::var(key).ok().filter(|value| !value.is_empty()) {
        Some(value) => value,
        None => {
            eprintln!("missing {key}");
            std::process::exit(1);
        }
    }
}
