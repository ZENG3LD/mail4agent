//! The letter event: what m4a emits when a letter for a session arrives, for the harness
//! (g4a / hatchery node) to act on. m4a does not wake or spawn; it hands the letter over.
//!
//! `M4A_LETTER_HOOK=<program>`: for every letter, `<program>` runs once with one JSON object
//! on stdin -- `{"nick","session_id","provider","from","event_id","room","body"}` -- and no
//! secrets in its environment (`M4A_SESSION_CAP`, `M4A_PRODUCT_INVITE` removed). Exit 0 within
//! 10 s means the harness took it (`delivered`). Anything else falls through to the rest of the
//! chain (legacy adapters, then the durable inbox), so a down harness loses nothing.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::provider::{ProviderSession, WakeAdapter, WakeChain, WakeError, WakeLetter, WakeOutcome};

pub const LETTER_HOOK_ENV: &str = "M4A_LETTER_HOOK";
const HOOK_TIMEOUT: Duration = Duration::from_secs(10);

/// The letter as the hook sees it.
pub fn letter_event(session: &ProviderSession, letter: &WakeLetter<'_>) -> serde_json::Value {
    serde_json::json!({
        "nick": session.nick,
        "session_id": session.session_id,
        "provider": session.kind.provider.id(),
        "from": letter.from_nick,
        "event_id": letter.event_id,
        "room": letter.room,
        "body": letter.body,
        "kind": if letter.reaction.is_some() { "reaction" } else { "message" },
        "reaction": letter.reaction.map(|r| r.key),
        "target_event_id": letter.reaction.map(|r| r.target),
        "reply_needed": letter.reaction.is_none(),
    })
}

pub struct LetterHookAdapter {
    pub program: PathBuf,
}

impl WakeAdapter for LetterHookAdapter {
    fn kind(&self) -> crate::provider::SessionKind {
        crate::provider::SessionKind::local(crate::provider::ProviderKind::Grok)
    }

    fn probe(&self, _session: &ProviderSession) -> Result<(), WakeError> {
        if self.program.as_os_str().is_empty() {
            return Err(WakeError::Unavailable("letter hook unset".into()));
        }
        Ok(())
    }

    fn wake(&mut self, session: &ProviderSession, letter: &WakeLetter<'_>) -> Result<WakeOutcome, WakeError> {
        let bytes = serde_json::to_vec(&letter_event(session, letter)).map_err(|e| WakeError::Transport(e.to_string()))?;
        let mut child = Command::new(&self.program)
            .env_remove("M4A_SESSION_CAP")
            .env_remove("M4A_PRODUCT_INVITE")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| WakeError::Unavailable(format!("letter hook: {}", e.kind())))?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(&bytes);
        }
        let deadline = Instant::now() + HOOK_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(WakeOutcome::Delivered),
                Ok(Some(status)) => return Err(WakeError::Transport(format!("letter hook exited {status}"))),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(WakeError::Transport("letter hook timed out".into()));
                }
                Err(e) => return Err(WakeError::Transport(e.to_string())),
            }
        }
    }
}

/// Puts the hook first in `chain` when `M4A_LETTER_HOOK` is set.
pub fn prepend_from_env(chain: &mut WakeChain) {
    if let Some(program) = std::env::var_os(LETTER_HOOK_ENV).filter(|v| !v.is_empty()) {
        chain.prepend("letter-hook", Box::new(LetterHookAdapter { program: program.into() }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{ProviderKind, SessionKind};

    fn session() -> ProviderSession {
        ProviderSession { kind: SessionKind::local(ProviderKind::Codex), session_id: "s-1".into(), nick: "codex-1".into(), cwd: None, headless: false }
    }
    fn letter() -> WakeLetter<'static> {
        WakeLetter { body: "hello", from_nick: "operator", event_id: "$e", room: Some("!r"), reaction: None }
    }

    #[cfg(unix)]
    #[test]
    fn hook_gets_the_letter_without_secrets_and_a_failing_hook_falls_through() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("m4a-letter-hook-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("got.json");
        let hook = dir.join("hook.sh");
        std::fs::write(&hook, format!("#!/bin/sh\ncat > {}\nenv | grep -c M4A_SESSION_CAP >> {}.cap\nexit 0\n", out.display(), out.display())).unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut a = LetterHookAdapter { program: hook.clone() };
        assert_eq!(a.wake(&session(), &letter()).unwrap(), WakeOutcome::Delivered);
        let got: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
        assert_eq!(got["nick"], "codex-1");
        assert_eq!(got["session_id"], "s-1");
        assert_eq!(got["body"], "hello");
        assert_eq!(std::fs::read_to_string(format!("{}.cap", out.display())).unwrap().trim(), "0");

        let bad = dir.join("bad.sh");
        std::fs::write(&bad, "#!/bin/sh\nexit 3\n").unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut chain = WakeChain::new();
        chain.push("inbox-queue", Box::new(crate::provider::hook::InboxQueueAdapter::new(SessionKind::local(ProviderKind::Codex), Some(dir.join("inbox")))));
        chain.prepend("letter-hook", Box::new(LetterHookAdapter { program: bad }));
        assert_eq!(chain.ids(), vec!["letter-hook", "inbox-queue"]);
        let (id, _) = chain.wake(&session(), &letter()).unwrap();
        assert_eq!(id, "inbox-queue", "a failing hook must not lose the letter");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
