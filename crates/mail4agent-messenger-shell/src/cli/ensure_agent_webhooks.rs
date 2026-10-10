//! Ensure one disabled local mirror routine per bot on this machine and
//! report whether each bot's webhook key is available.
//!
//! Reads the agents directory (`M4A_AGENTS_DIR`, or the box default), the
//! local gateway file, and `M4A_SKIP_NICKS`. The mirror is named by the
//! bot's nick and lands in the folder the bot's own `UpdateRoutine` uses.
//! With `M4A_STORE_ROOT` set, a ready URL and key go to that session's
//! keychain file. Prints `nick<TAB>folder<TAB>status` lines only. Never
//! prints URLs, keys, or tokens.

use crate::WakeStatus;

pub fn run(_args: Vec<String>) {
    match crate::ensure_agent_webhook_routines_from_env() {
        Ok(reports) => {
            for report in reports {
                let status = match report.status {
                    WakeStatus::Ready => "ready".to_string(),
                    WakeStatus::AwaitingBackend => "awaiting-bot-routine".to_string(),
                    WakeStatus::Failed(reason) => format!("failed: {reason}"),
                };
                println!("{}\t{}\t{status}", report.nick, report.folder_id);
            }
        }
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}
