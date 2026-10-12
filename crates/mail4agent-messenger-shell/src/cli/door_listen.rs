//! `m4a-agent door-listen`: wake a local provider session (codex, claude, kimi,
//! grok, cursor) when mail arrives in a hatchery node mailbox.
//!
//! `--door URL` (or `M4A_DOOR_URL`), `--provider P` (or `M4A_PROVIDER`),
//! `--session ID` (Codex thread id / Claude session id; or `M4A_SESSION_ID`),
//! `--nick NICK` (or `M4A_NICK`), `--state FILE` (seen ids), optional
//! `--inbox-dir DIR` (durable inbox / Claude channel; or `M4A_INBOX_DIR`),
//! `--cwd DIR`, `--headless`, `--interval SECS` (default 10).
//! Codex: also `M4A_CODEX_APP_SERVER` (see the codex adapter).

use std::path::PathBuf;
use std::time::Duration;

use crate::door_listen::{check_door, run_loop, session_from, DoorListen};

pub fn run(args: Vec<String>) {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let (mut door, mut provider, mut session, mut nick) = (env("M4A_DOOR_URL"), env("M4A_PROVIDER"), env("M4A_SESSION_ID"), env("M4A_NICK"));
    let (mut state, mut inbox, mut cwd, mut headless, mut interval) = (None, env(crate::INBOX_DIR_ENV).map(PathBuf::from), None, false, 10u64);
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let mut v = || it.next().unwrap_or_else(|| fail(&format!("{a} needs a value")));
        match a.as_str() {
            "--door" => door = Some(v()),
            "--provider" => provider = Some(v()),
            "--session" => session = Some(v()),
            "--nick" => nick = Some(v()),
            "--state" => state = Some(PathBuf::from(v())),
            "--inbox-dir" => inbox = Some(PathBuf::from(v())),
            "--cwd" => cwd = Some(PathBuf::from(v())),
            "--interval" => interval = v().parse().unwrap_or_else(|_| fail("--interval is a number of seconds")),
            "--headless" => headless = true,
            "--help" | "-h" => { eprintln!("m4a-agent door-listen --door URL --provider codex|claude|kimi|grok|cursor --session ID --nick NICK --state FILE [--inbox-dir DIR] [--cwd DIR] [--headless] [--interval SECS]"); return; }
            other => fail(&format!("unknown argument {other:?}")),
        }
    }
    let door = door.unwrap_or_else(|| fail("--door is required"));
    check_door(&door).unwrap_or_else(|e| fail(&e));
    let session = session_from(&provider.unwrap_or_else(|| fail("--provider is required")), &session.unwrap_or_default(), &nick.unwrap_or_default(), cwd, headless)
        .unwrap_or_else(|e| fail(&e));
    let seen_file = state.unwrap_or_else(|| fail("--state is required"));
    run_loop(DoorListen { door, session, seen_file, inbox_dir: inbox, interval: Duration::from_secs(interval.max(1)) })
}

fn fail(msg: &str) -> ! {
    eprintln!("m4a-agent door-listen: {msg}");
    std::process::exit(2)
}
