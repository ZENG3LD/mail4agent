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
    match it.next().as_deref() {
        Some("provision") => {}
        Some("check") => return check(it.collect()),
        Some("node-enroll") => return node_enroll(it.collect()),
        _ => fail("usage: m4a-agent account provision --provider P --session ID [--nick N] --cap-out FILE [--rotate] | account check --nick N"),
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
        serde_json::json!({ "nick": made.entry.nick, "account_ref": made.account_ref, "store_root": made.store_root, "cap_issued": made.cap.is_some(), "enrolled": made.entry.state == crate::session_account::ServerState::Enrolled })
    );
}

/// `account check --nick N`: exit 0 when the caller's `M4A_SESSION_CAP` (and OS user) may act as
/// `N` -- the same gate the daemon applies to send/inbox/commands -- else exit 1 with the reason.
fn check(args: Vec<String>) {
    let mut it = args.into_iter();
    let mut nick = None;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--nick" => nick = it.next(),
            other => fail(&format!("unknown argument {other}")),
        }
    }
    let nick = nick.unwrap_or_else(|| fail("--nick is required"));
    let root = std::env::var(STORE_ROOT_ENV).ok().filter(|v| !v.is_empty()).map(PathBuf::from);
    let cap = crate::send::session_cap_from_env();
    match crate::session_gate(root.as_deref(), &nick, cap.as_deref(), crate::ipc_own_uid()) {
        Ok(()) => println!("ok {nick}"),
        Err(why) => {
            eprintln!("refused: {why}");
            std::process::exit(1);
        }
    }
}

/// `m4a-agent account node-enroll --node-id N --ts MS --nonce X --signature S [--nick NICK]`:
/// the trusted-node path (no operator invite). The caller (the node) signed
/// `m4a_product_kit`-format request bytes with its node key; this posts them to
/// `$M4A_PRODUCT_URL/product/v1/node/accounts`, receives a one-time invite and spends it at once
/// in `m4a-agent enroll` for the account in this environment (`M4A_SESSION_ID`,
/// `M4A_STORE_ROOT`, `M4A_BOT_NAME`). The invite is never printed. Prints the enroll line.
fn node_enroll(args: Vec<String>) {
    let mut it = args.into_iter();
    let (mut node, mut ts, mut nonce, mut sig, mut nick) = (None, None, None, None, None);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--node-id" => node = it.next(),
            "--ts" => ts = it.next().and_then(|v| v.parse::<i64>().ok()),
            "--nonce" => nonce = it.next(),
            "--signature" => sig = it.next(),
            "--nick" => nick = it.next(),
            other => fail(&format!("unknown argument {other}")),
        }
    }
    let (Some(node), Some(ts), Some(nonce), Some(sig)) = (node, ts, nonce, sig) else {
        fail("node-enroll needs --node-id --ts --nonce --signature");
    };
    let url = std::env::var("M4A_PRODUCT_URL").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| fail("M4A_PRODUCT_URL is required"));
    let body = serde_json::json!({ "node_id": node, "nick": nick, "ts_ms": ts, "nonce": nonce, "signature": sig });
    let client = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(30)).build().unwrap_or_else(|e| fail(&e.to_string()));
    let resp = client
        .post(format!("{}/product/v1/node/accounts", url.trim_end_matches('/')))
        .json(&body)
        .send()
        .unwrap_or_else(|e| fail(&format!("product unreachable: {}", e.without_url())));
    let status = resp.status().as_u16();
    let v: serde_json::Value = resp.json().unwrap_or_default();
    if status != 200 {
        fail(&format!("node registration refused ({status}): {}", v.get("error").and_then(|e| e.as_str()).unwrap_or("no reason")));
    }
    let Some(invite) = v.get("invite").and_then(|i| i.as_str()) else { fail("product answer has no invite") };
    let me = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("m4a-agent"));
    let out = std::process::Command::new(me)
        .arg("enroll")
        .env(crate::PRODUCT_INVITE_ENV, invite)
        .env_remove(crate::session_account::SESSION_CAP_ENV)
        .output()
        .unwrap_or_else(|e| fail(&format!("enroll: {}", e.kind())));
    std::io::stderr().write_all(&out.stderr).ok();
    std::io::stdout().write_all(&out.stdout).ok();
    if !out.status.success() {
        std::process::exit(out.status.code().unwrap_or(1));
    }
}
