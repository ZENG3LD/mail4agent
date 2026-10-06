//! End-to-end: the real `m4a-inbox detect` binary, run with a clean
//! environment carrying only the markers a CLI session would export,
//! classifies the session (surface, vendor, provider) and picks the
//! ordered wake chain.

use std::process::Command;

fn detect(vars: &[(&str, &str)]) -> serde_json::Value {
    let home = std::env::temp_dir().join(format!("m4a-detect-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_m4a-inbox"));
    cmd.arg("detect").env_clear().env("HOME", &home);
    for (key, value) in vars {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("run m4a-inbox detect");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(!text.contains("secret-id"), "session id leaked: {text}");
    serde_json::from_str(&text).unwrap()
}

fn chain(v: &serde_json::Value) -> Vec<String> {
    v["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap().to_string())
        .collect()
}

fn check(
    vars: &[(&str, &str)],
    surface: &str,
    vendor: Option<&str>,
    provider: &str,
    expected: &[&str],
) -> serde_json::Value {
    let v = detect(vars);
    assert_eq!(v["surface"], surface, "{vars:?}: {v}");
    assert_eq!(v["vendor"].as_str(), vendor, "{vars:?}: {v}");
    assert_eq!(v["provider"], provider, "{vars:?}: {v}");
    assert_eq!(chain(&v), expected, "{vars:?}");
    // Order: in-session, hook, queue, spawn (never a spawn before the queue).
    let rank = |t: &str| {
        ["in-session", "hook", "queue", "spawn"]
            .iter()
            .position(|x| *x == t)
    };
    let tiers: Vec<usize> = v["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| rank(row["tier"].as_str().unwrap()).unwrap())
        .collect();
    assert!(
        tiers.windows(2).all(|w| w[0] <= w[1]),
        "{vars:?}: {tiers:?}"
    );
    v
}

const LOCAL: (&str, &str) = ("M4A_SURFACE", "local");

#[test]
fn local_sessions_by_cli_marker() {
    let claude = check(
        &[
            LOCAL,
            ("CLAUDECODE", "1"),
            ("CLAUDE_CODE_SESSION_ID", "secret-id"),
        ],
        "local",
        None,
        "claude",
        &[
            "claude-uds-inject",
            "claude-async-rewake",
            "claude-channel",
            "claude-stop-hook",
            "inbox-queue",
            "claude-resume-spawn",
            "claude-agent-acp-host",
        ],
    );
    assert_eq!(claude["session_id_present"], true);
    let codex = check(
        &[LOCAL, ("CODEX_THREAD_ID", "secret-id")],
        "local",
        None,
        "codex",
        &[
            "codex-app-server-turn",
            "codex-stop-hook",
            "inbox-queue",
            "codex-exec-resume-spawn",
        ],
    );
    assert_eq!(codex["session_id_present"], true);
    check(
        &[LOCAL, ("CURSOR_AGENT", "1")],
        "local",
        None,
        "cursor",
        &[
            "cursor-stop-followup",
            "inbox-queue",
            "cursor-resume-spawn",
            "cursor-agent-acp-host",
            "cursor-community-acp-host",
        ],
    );
}

#[test]
fn m4a_provider_overrides_markers_and_covers_markerless_clis() {
    check(
        &[LOCAL, ("M4A_PROVIDER", "kimi"), ("CLAUDECODE", "1")],
        "local",
        None,
        "kimi",
        &[
            "kimi-server-prompt",
            "kimi-stop-hook",
            "inbox-queue",
            "kimi-resume-spawn",
        ],
    );
    let grok = check(
        &[LOCAL, ("M4A_PROVIDER", "grok"), ("M4A_HEADLESS", "1")],
        "local",
        None,
        "grok",
        &[
            "grok-leader-acp",
            "grok-stop-hook",
            "inbox-queue",
            "grok-resume-spawn",
        ],
    );
    assert_eq!(grok["headless"], true);
    assert_eq!(grok["session_id_present"], false);
}

#[test]
fn web_surfaces_by_vendor_marker() {
    check(
        &[("CLAUDE_CODE_REMOTE", "true")],
        "web",
        Some("ClaudeWeb"),
        "claude",
        &[
            "claude-uds-inject",
            "claude-async-rewake",
            "claude-stop-hook",
            "inbox-queue",
            "claude-routine-fire",
        ],
    );
    check(
        &[
            ("M4A_WEB_VENDOR", "codex-cloud"),
            ("CODEX_THREAD_ID", "secret-id"),
        ],
        "web",
        Some("CodexCloud"),
        "codex",
        &["codex-stop-hook", "inbox-queue", "codex-cloud-exec"],
    );
    check(
        &[("M4A_WEB_VENDOR", "grok-bot"), ("M4A_PROVIDER", "grok")],
        "web",
        Some("GrokBot"),
        "grok",
        &["routine-webhook"],
    );
    check(
        &[("M4A_WEB_VENDOR", "cursor-cloud"), ("CURSOR_AGENT", "1")],
        "web",
        Some("CursorCloud"),
        "cursor",
        &["routine-webhook", "cursor-stop-followup", "inbox-queue"],
    );
    // An explicit local surface beats every web marker.
    check(
        &[LOCAL, ("CLAUDE_CODE_REMOTE", "true")],
        "local",
        None,
        "claude",
        &[
            "claude-uds-inject",
            "claude-async-rewake",
            "claude-channel",
            "claude-stop-hook",
            "inbox-queue",
            "claude-resume-spawn",
            "claude-agent-acp-host",
        ],
    );
}

#[test]
fn no_marker_means_no_provider() {
    let v = detect(&[LOCAL]);
    assert!(v["provider"].is_null(), "{v}");
    assert_eq!(chain(&v), Vec::<String>::new());
}
