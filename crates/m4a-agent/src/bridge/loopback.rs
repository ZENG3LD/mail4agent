//! Reference bridge skeleton: the "other messenger" is an in-memory queue, so there is nothing to
//! configure and no network. It shows the shape a real `bridge-<name>` follows: credentials from
//! the scoped vault, `outgoing` maps and delivers, `incoming` drains. A real bridge replaces the
//! queue with that messenger's client protocol and keeps its tokens in the same scoped vault.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::{Bridge, LocalEvent, ScopedVault};
use crate::error::{AgentError, Result};

/// The credential label the loopback bridge asks for. A real bridge asks for its own token here.
pub const TOKEN_LABEL: &str = "token";

#[derive(Default)]
pub struct LoopbackRemote {
    /// What was "sent" to the other messenger: `(remote_room, text)`.
    pub sent: Mutex<Vec<(String, String)>>,
    /// What the other messenger has for us: `(remote_room, author, text)`.
    pub inbox: Mutex<VecDeque<(String, String, String)>>,
}

pub struct LoopbackBridge {
    remote: Arc<LoopbackRemote>,
    connected: bool,
}

impl LoopbackBridge {
    pub fn new(remote: Arc<LoopbackRemote>) -> Self {
        Self { remote, connected: false }
    }
}

impl Bridge for LoopbackBridge {
    fn name(&self) -> &'static str {
        "loopback"
    }
    fn connect(&mut self, vault: &ScopedVault) -> Result<()> {
        vault.get(TOKEN_LABEL)?.ok_or_else(|| AgentError::Vault("the loopback bridge has no token in the vault".into()))?;
        self.connected = true;
        Ok(())
    }
    fn outgoing(&mut self, remote_room: &str, ev: &LocalEvent) -> Result<()> {
        if !self.connected {
            return Err(AgentError::Transport("not connected".into()));
        }
        self.remote.sent.lock().unwrap_or_else(|e| e.into_inner()).push((remote_room.to_string(), format!("{}: {}", ev.sender, ev.body)));
        Ok(())
    }
    fn incoming(&mut self) -> Result<Vec<(String, String, String)>> {
        Ok(self.remote.inbox.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect())
    }
}
