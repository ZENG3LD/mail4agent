//! `m4a-claude-channel`: Claude Code channel MCP server for mail4agent.
//!
//! Claude Code spawns it from `.mcp.json` (server name `mail4agent`) when the
//! session is started with
//! `claude --dangerously-load-development-channels server:mail4agent`.
//! It drains `M4A_INBOX_DIR` (letters queued by the local mail4agent client)
//! and emits `notifications/claude/channel`. stdout is the MCP channel;
//! diagnostics go to stderr.

use std::io::BufReader;
use std::path::PathBuf;
use std::time::Duration;

use crate::provider::claude_channel::serve;
use crate::INBOX_DIR_ENV;

pub fn run(_args: Vec<String>) {
    let Some(dir) = std::env::var_os(INBOX_DIR_ENV).filter(|v| !v.is_empty()) else {
        eprintln!("m4a-claude-channel: {INBOX_DIR_ENV} is unset");
        std::process::exit(2);
    };
    let stdin = BufReader::new(std::io::stdin());
    if let Err(err) = serve(
        stdin,
        std::io::stdout(),
        PathBuf::from(dir),
        Duration::from_millis(500),
        None,
    ) {
        eprintln!("m4a-claude-channel: {}", err.kind());
        std::process::exit(1);
    }
}
