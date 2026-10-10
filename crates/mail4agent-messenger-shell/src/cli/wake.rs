//! `m4a-agent wake <status|import|enable|disable|mode> --as <nick> | --session <id>`
//!
//! The owner's control of a session's wake, without a restart of anything and without a secret on
//! a command line or in a printout:
//!
//! * `status`: policy, the wake target's state and last answer, where the target comes from.
//! * `import --file <path> [--delete-source]`: reads the owner-placed `{"url","key"}` file (mode
//!   0600) into the vault. The running client picks it up at its next start.
//! * `enable` / `disable`: the policy switch (`wake.json` in the session's store directory).
//! * `mode off|dm|mention|all`: when to wake (`mention` is the default: DMs and messages that address
//!   the session).
//!
//! `M4A_WAKE=off` in the daemon's environment silences every session of that process.

use super::session_arg::{resolve, take_flag, take_switch, Target};
use crate::wake_policy::{globally_off, WakeMode, WakePolicy, WakeStatusFile};

pub fn run(args: Vec<String>) {
    match go(args) {
        Ok(text) => println!("{text}"),
        Err(e) => {
            eprintln!("wake: {e}");
            std::process::exit(if e.starts_with("usage") { 64 } else { 1 });
        }
    }
}

const USAGE: &str = "usage: m4a-agent wake <status|import|enable|disable|mode> (--as <nick>|--session <id>) [--file <path> [--delete-source]] [off|dm|mention|all]";

pub(crate) fn go(mut args: Vec<String>) -> Result<String, String> {
    if args.is_empty() {
        return Err(USAGE.into());
    }
    let sub = args.remove(0);
    let file = take_flag(&mut args, "--file")?;
    let delete_source = take_switch(&mut args, "--delete-source");
    let target = resolve(&mut args)?;
    let dir = target.store_dir();
    match sub.as_str() {
        "status" if args.is_empty() => Ok(status(&target)),
        "enable" | "disable" if args.is_empty() => {
            let mut p = WakePolicy::load(&dir);
            p.enabled = sub == "enable";
            p.save(&dir).map_err(|e| format!("cannot write the policy: {e}"))?;
            Ok(format!("wake {}: {} (mode {})", label(&target), if p.enabled { "enabled" } else { "disabled" }, p.mode.name()))
        }
        "mode" if args.len() == 1 => {
            let mode = WakeMode::parse(&args[0]).ok_or_else(|| "mode is off, dm, mention or all".to_string())?;
            let mut p = WakePolicy::load(&dir);
            p.mode = mode;
            p.save(&dir).map_err(|e| format!("cannot write the policy: {e}"))?;
            Ok(format!("wake {}: mode {} ({})", label(&target), mode.name(), if p.enabled { "enabled" } else { "disabled" }))
        }
        "import" if args.is_empty() => {
            let file = file.ok_or("import needs --file <path>")?;
            let path = std::path::PathBuf::from(&file);
            let (url, key) = crate::machine::read_routine_file(&path)?;
            let vault = crate::store_key::vault(&target.store_root).map_err(|e| e.to_string())?;
            let body = serde_json::to_vec(&serde_json::json!({ "url": url, "key": key })).map_err(|e| e.to_string())?;
            vault.put(&crate::machine::wake_label(&target.session_id), &body).map_err(|e| format!("key vault: {e}"))?;
            crate::wake_policy::note_state(&dir, "ready", "vault");
            let mut out = format!("wake {}: imported into the vault; a running client takes it at its next start", label(&target));
            if delete_source {
                std::fs::remove_file(&path).map_err(|_| "imported, but the source file could not be deleted".to_string())?;
                out.push_str("; source file deleted");
            }
            Ok(out)
        }
        _ => Err(USAGE.into()),
    }
}

fn label(t: &Target) -> String {
    t.nick.clone().unwrap_or_else(|| t.session_id.clone())
}

fn status(t: &Target) -> String {
    let dir = t.store_dir();
    let p = WakePolicy::load(&dir);
    let s = WakeStatusFile::load(&dir);
    let in_vault = crate::store_key::vault(&t.store_root).ok().and_then(|v| v.get(&crate::machine::wake_label(&t.session_id)).ok().flatten()).is_some();
    let rec = t.record.as_ref();
    let mut o = vec![format!("session: {} ({})", t.session_id, label(t))];
    o.push(format!("policy: {} / mode {}", if p.enabled { "enabled" } else { "disabled" }, p.mode.name()));
    o.push(format!("global M4A_WAKE: {}", if globally_off() { "off (in THIS process; the daemon has its own environment)" } else { "not off here" }));
    o.push(format!("target in vault: {}", if in_vault { "yes" } else { "no" }));
    o.push(format!("record names a routine file: {}", if rec.is_some_and(|r| r.routine_file.is_some()) { "yes" } else { "no" }));
    o.push(format!("record names an agent for the gateway: {}", if rec.is_some_and(|r| r.agent_id.is_some()) { "yes" } else { "no" }));
    match s {
        Some(s) => {
            o.push(format!("target: {} (from {})", s.state, s.source));
            o.push(format!("last wake answer: {}", s.last_status.map(|c| c.to_string()).unwrap_or_else(|| "none".into())));
        }
        None => o.push("target: no state recorded yet (the client has not run with this session since 0.4.4)".into()),
    }
    o.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn the_owner_controls_a_wake_without_a_secret_ever_being_printed() {
        use std::os::unix::fs::PermissionsExt;
        let _g = super::super::session_arg::ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let d = tempfile::tempdir().unwrap();
        let (root, sessions) = (d.path().join("store"), d.path().join("sessions"));
        std::fs::create_dir_all(&sessions).unwrap();
        std::fs::write(sessions.join("a.json"), r#"{"bot_name":"Courier","session_id":"web-courier"}"#).unwrap();
        std::env::set_var(crate::STORE_ROOT_ENV, &root);
        std::env::set_var(crate::machine::SESSIONS_DIR_ENV, &sessions);
        std::env::remove_var(crate::wake_policy::WAKE_ENV);
        std::env::remove_var(m4a_agent::vault::VAULT_KEY_ENV);
        let say = |a: &[&str]| go(a.iter().map(|s| s.to_string()).collect());

        let out = say(&["status", "--as", "courier"]).unwrap();
        assert!(out.contains("enabled / mode mention") && out.contains("target in vault: no"), "{out}");
        assert!(say(&["mode", "--as", "courier", "dm"]).unwrap().contains("mode dm"));
        assert!(say(&["disable", "--as", "courier"]).unwrap().contains("disabled"));
        assert!(say(&["status", "--session", "web-courier"]).unwrap().contains("disabled / mode dm"));
        assert!(say(&["enable", "--as", "courier"]).unwrap().contains("enabled"));
        assert!(say(&["mode", "--as", "courier", "sometimes"]).is_err());
        assert!(say(&["status"]).is_err() && say(&["status", "--as", "nobody"]).is_err());

        // Import: refuses a readable file, takes a private one, never echoes the value, can delete the source.
        let f = d.path().join("w.json");
        std::fs::write(&f, r#"{"url":"http://127.0.0.1:9/h","key":"k-very-secret"}"#).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = say(&["import", "--as", "courier", "--file", f.to_str().unwrap()]).unwrap_err();
        assert!(!e.contains("k-very-secret") && e.contains("0600"), "{e}");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        let out = say(&["import", "--as", "courier", "--file", f.to_str().unwrap(), "--delete-source"]).unwrap();
        assert!(!out.contains("k-very-secret") && !out.contains("127.0.0.1") && out.contains("source file deleted"), "{out}");
        assert!(!f.exists());
        let st = say(&["status", "--as", "courier"]).unwrap();
        assert!(st.contains("target in vault: yes") && st.contains("ready (from vault)") && !st.contains("k-very-secret"), "{st}");

        // The record picks the vault wake up at open.
        let mut set = vec![crate::machine::HostSession::new("Courier", "web-courier")];
        crate::machine::attach_vault_wakes_for_test(&mut set, &root);
        assert_eq!(set[0].routine_url.as_deref(), Some("http://127.0.0.1:9/h"));
        assert_eq!(set[0].routine_bearer.as_deref(), Some("k-very-secret"));
    }
}
