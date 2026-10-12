//! Per-session accounts, slices 2+3, end to end through the binary: `inbox register` creates one
//! account per provider session and hands its env (own nick, own store root, own login session
//! id, own capability) only to that session's env file; the daemon gate and the inbox refuse a
//! foreign capability.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn tmp(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("m4a-s2-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn agent(root: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_m4a-agent"));
    c.env("M4A_STORE_ROOT", root)
        .env("M4A_ENV_FILE", root.join("none.env"))
        .env_remove("M4A_SESSION_CAP")
        .env_remove("M4A_ACCOUNTS_ROOT")
        .env_remove("M4A_REQUIRE_SESSION_CAP")
        .env_remove("CLAUDE_ENV_FILE")
        .env_remove("M4A_NICK");
    c
}

fn register(root: &Path, session: &str, env_file: &Path) -> HashMap<String, String> {
    let out = agent(root)
        .args(["inbox", "register", "--provider", "codex", "--session", session, "--nick", "codex", "--env-file"])
        .arg(env_file)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.stdout.is_empty(), "the capability must never go to stdout");
    std::fs::read_to_string(env_file)
        .unwrap()
        .lines()
        .filter_map(|l| l.strip_prefix("export ")?.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn two_sessions_of_one_provider_get_separate_accounts_and_cannot_use_each_others_key() {
    let root = tmp("two");
    let a = register(&root, "thread-a", &root.join("a.env"));
    let b = register(&root, "thread-b", &root.join("b.env"));
    for k in ["M4A_SESSION_ID", "M4A_NICK", "M4A_STORE_ROOT", "M4A_SESSION_CAP"] {
        assert!(a.contains_key(k) && b.contains_key(k), "{k}");
        assert_ne!(a[k], b[k], "{k} must differ between sessions");
    }
    // Daemon gate (send socket / commands).
    let gate = mail4agent_messenger_shell::session_gate;
    assert!(gate(Some(&root), &a["M4A_NICK"], Some(&a["M4A_SESSION_CAP"]), None).is_ok());
    assert!(gate(Some(&root), &a["M4A_NICK"], Some(&b["M4A_SESSION_CAP"]), None).is_err());
    assert!(gate(Some(&root), &a["M4A_NICK"], None, None).is_err());
    // Inbox: B's key cannot drain A's inbox.
    let drain = |cap: &str| {
        agent(&root)
            .args(["inbox", "drain", "--provider", "codex", "--session", "thread-a", "--format", "codex-stop"])
            .env("M4A_SESSION_CAP", cap)
            .output()
            .unwrap()
    };
    let foreign = drain(&b["M4A_SESSION_CAP"]);
    assert!(!foreign.status.success());
    assert!(String::from_utf8_lossy(&foreign.stderr).contains("another session"));
    let own = drain(&a["M4A_SESSION_CAP"]);
    assert!(own.status.success(), "{}", String::from_utf8_lossy(&own.stderr));
    // Re-registering the same session keeps its account and does not hand the key out again.
    let again = root.join("a2.env");
    let out = agent(&root)
        .args(["inbox", "register", "--provider", "codex", "--session", "thread-a", "--nick", "codex", "--env-file"])
        .arg(&again)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(!again.exists());
}

#[test]
fn launcher_gives_each_codex_or_kimi_process_its_own_account_env_and_no_invite() {
    let root = tmp("launch");
    let run = |provider: &str, session: &str| -> HashMap<String, String> {
        let out = agent(&root)
            .args(["launch", "--provider", provider, "--session", session, "--nick", provider, "--", "env"])
            .env("M4A_SESSION_CAP", "inherited-should-not-leak")
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split_once('='))
            .filter(|(k, _)| k.starts_with("M4A_"))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    let c1 = run("codex", "t1");
    let c2 = run("codex", "t2");
    let k1 = run("kimi", "k1");
    for e in [&c1, &c2, &k1] {
        assert!(!e.contains_key("M4A_PRODUCT_INVITE"));
        assert_ne!(e["M4A_SESSION_CAP"], "inherited-should-not-leak");
        assert!(e["M4A_STORE_ROOT"].contains("accounts"));
    }
    assert_ne!(c1["M4A_NICK"], c2["M4A_NICK"]);
    assert_ne!(c1["M4A_STORE_ROOT"], c2["M4A_STORE_ROOT"]);
    assert_ne!(c1["M4A_SESSION_ID"], k1["M4A_SESSION_ID"]);
    let gate = mail4agent_messenger_shell::session_gate;
    assert!(gate(Some(&root), &c1["M4A_NICK"], Some(&c1["M4A_SESSION_CAP"]), None).is_ok());
    assert!(gate(Some(&root), &c1["M4A_NICK"], Some(&c2["M4A_SESSION_CAP"]), None).is_err());
    // A relaunch of the same session rotates the cap: the old process's key stops working.
    let c1b = run("codex", "t1");
    assert_eq!(c1b["M4A_NICK"], c1["M4A_NICK"]);
    assert!(gate(Some(&root), &c1["M4A_NICK"], Some(&c1["M4A_SESSION_CAP"]), None).is_err());
    assert!(gate(Some(&root), &c1["M4A_NICK"], Some(&c1b["M4A_SESSION_CAP"]), None).is_ok());
}

#[test]
fn account_provision_writes_the_cap_only_to_a_new_private_file() {
    let root = tmp("acct");
    let cap = root.join("cap");
    let out = agent(&root)
        .args(["account", "provision", "--provider", "codex", "--session", "inst-1", "--cap-out"])
        .arg(&cap)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let key = std::fs::read_to_string(&cap).unwrap();
    assert!(!String::from_utf8_lossy(&out.stdout).contains(&key));
    assert_eq!(v["cap_issued"], true);
    let nick = v["nick"].as_str().unwrap();
    assert!(mail4agent_messenger_shell::session_gate(Some(&root), nick, Some(&key), None).is_ok());
    // An existing cap-out file is refused (no overwrite of something else).
    let again = agent(&root)
        .args(["account", "provision", "--provider", "codex", "--session", "inst-2", "--cap-out"])
        .arg(&cap)
        .output()
        .unwrap();
    assert!(!again.status.success());
}
