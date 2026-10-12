//! `m4a-agent launch --provider <codex|kimi|...> [--session ID] [--nick NICK] -- <command...>`:
//! the per-session launcher for providers with no env-file hook (codex, kimi). It provisions this
//! session's account (one per provider session; a fresh session id when none is given), issues a
//! fresh capability, and starts the provider with this session's env only: `M4A_SESSION_ID`
//! (the account's own login id), `M4A_NICK`/`M4A_BOT_NAME`, `M4A_STORE_ROOT` (the account's own
//! root) and `M4A_SESSION_CAP`. Nothing is printed but the nick; the cap never leaves the child's
//! environment. Exit code is the child's.

use std::path::PathBuf;
use std::process::Command;

use crate::session_account::{provision_session, SESSION_CAP_ENV};
use crate::{ProviderKind, STORE_ROOT_ENV};

fn fail(msg: &str) -> ! {
    eprintln!("m4a-agent launch: {msg}");
    std::process::exit(64);
}

pub fn run(args: Vec<String>) {
    let (mut provider, mut session, mut nick) = (None, None, None);
    let mut it = args.into_iter();
    let mut cmd: Vec<String> = Vec::new();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--provider" => provider = it.next(),
            "--session" => session = it.next(),
            "--nick" => nick = it.next(),
            "--" => {
                cmd.extend(it.by_ref());
                break;
            }
            other => fail(&format!("unknown argument {other}")),
        }
    }
    let provider = provider.as_deref().and_then(ProviderKind::parse).unwrap_or_else(|| fail("--provider is required"));
    if cmd.is_empty() {
        fail("usage: m4a-agent launch --provider P [--session ID] [--nick NICK] -- <command...>");
    }
    let base = std::env::var(crate::ACCOUNTS_ROOT_ENV)
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var(STORE_ROOT_ENV).ok().filter(|v| !v.is_empty()))
        .map(PathBuf::from)
        .unwrap_or_else(|| fail("M4A_STORE_ROOT (or M4A_ACCOUNTS_ROOT) is required"));
    let session = session.unwrap_or_else(fresh_session_id);
    // A new process of the session gets a new cap; the old one stops working.
    let made = provision_session(&base, provider, &session, nick.as_deref(), true).unwrap_or_else(|e| fail(&e.to_string()));
    #[cfg(unix)]
    if made.entry.os_uid.is_none() {
        if let Ok(mut reg) = crate::session_account::AccountRegistry::open(&base) {
            if let Ok(id) = crate::session_account::SessionIdentity::new(provider, &session) {
                let _ = reg.set_os_uid(&id, crate::ipc_own_uid());
            }
        }
    }
    // Server enroll per account, by the launcher (never by the agent): only when the operator put
    // an invite for this nick in the launcher's env and the account is not enrolled yet.
    if made.entry.state != crate::session_account::ServerState::Enrolled {
        if let Some(invite) = std::env::var(crate::PRODUCT_INVITE_ENV).ok().filter(|v| !v.is_empty()) {
            let me = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("m4a-agent"));
            let mut enroll = Command::new(me);
            enroll.arg("enroll").env(crate::PRODUCT_INVITE_ENV, invite).env_remove(SESSION_CAP_ENV);
            for (k, v) in made.session_env().into_iter().filter(|(k, _)| *k != SESSION_CAP_ENV) {
                enroll.env(k, v);
            }
            match enroll.status() {
                Ok(s) if s.success() => {}
                _ => eprintln!("m4a-agent launch: enroll failed; the session starts local-only"),
            }
        }
    }
    eprintln!("m4a-agent launch: session account {} ({})", made.entry.nick, provider.id());
    let mut child = Command::new(&cmd[0]);
    child.args(&cmd[1..]).env_remove(SESSION_CAP_ENV).env_remove(crate::PRODUCT_INVITE_ENV);
    child.env("M4A_PROVIDER", provider.id()).env("M4A_PROVIDER_SESSION_ID", &session);
    for (k, v) in made.session_env() {
        child.env(k, v);
    }
    match child.status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(err) => fail(&format!("could not start {}: {}", cmd[0], err.kind())),
    }
}

fn fresh_session_id() -> String {
    let raw = m4a_agent::vault::random_bytes(16);
    let h: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    format!("launch-{h}")
}
