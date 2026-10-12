//! `m4a-agent account provision --provider P --session ID [--nick N] --cap-out FILE [--rotate]`:
//! for an environment that spawns sessions itself (the hatchery node). Creates or reuses the
//! session's account under `M4A_ACCOUNTS_ROOT` (or `M4A_STORE_ROOT`), and when a capability is
//! issued writes it to `FILE` (created 0600, must not exist) for the caller to inject into that
//! session only. stdout is one JSON line without secrets: `{"nick","account_ref","store_root","cap_issued"}`.

use std::io::Write;
use std::path::PathBuf;

use crate::session_account::provision_session;
use crate::{ProviderKind, STORE_ROOT_ENV};

fn fail(msg: &str) -> ! {
    eprintln!("m4a-agent account: {msg}");
    std::process::exit(64);
}

pub fn run(args: Vec<String>) {
    let mut it = args.into_iter();
    if it.next().as_deref() != Some("provision") {
        fail("usage: m4a-agent account provision --provider P --session ID [--nick N] --cap-out FILE [--rotate]");
    }
    let (mut provider, mut session, mut nick, mut out, mut rotate) = (None, None, None, None, false);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--provider" => provider = it.next(),
            "--session" => session = it.next(),
            "--nick" => nick = it.next(),
            "--cap-out" => out = it.next().map(PathBuf::from),
            "--rotate" => rotate = true,
            other => fail(&format!("unknown argument {other}")),
        }
    }
    let provider = provider.as_deref().and_then(ProviderKind::parse).unwrap_or_else(|| fail("--provider is required"));
    let session = session.unwrap_or_else(|| fail("--session is required"));
    let out = out.unwrap_or_else(|| fail("--cap-out is required"));
    let base = std::env::var(crate::ACCOUNTS_ROOT_ENV)
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var(STORE_ROOT_ENV).ok().filter(|v| !v.is_empty()))
        .map(PathBuf::from)
        .unwrap_or_else(|| fail("M4A_ACCOUNTS_ROOT (or M4A_STORE_ROOT) is required"));
    let made = provision_session(&base, provider, &session, nick.as_deref(), rotate).unwrap_or_else(|e| fail(&e.to_string()));
    if let Some(cap) = &made.cap {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&out).unwrap_or_else(|e| fail(&format!("cap-out: {}", e.kind())));
        f.write_all(cap.as_bytes()).unwrap_or_else(|e| fail(&format!("cap-out: {}", e.kind())));
    }
    println!(
        "{}",
        serde_json::json!({ "nick": made.entry.nick, "account_ref": made.account_ref, "store_root": made.store_root, "cap_issued": made.cap.is_some() })
    );
}
