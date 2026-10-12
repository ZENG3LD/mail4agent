//! DEPRECATED here: provider wake/spawn adapters moved to g4a (`gate4agent-wake`).
//!
//! Layer rule: m4a is the client of LIVE sessions only (deliver a letter, send). Waking and
//! spawning belong to g4a. This module re-exports `gate4agent-wake` so existing users
//! (`m4a-grok-listen`, `m4a-door-listen`, `m4a-codex-listen`, the web client) keep working
//! unchanged; the adapters themselves are compiled only with feature `legacy-wake` (on in
//! `full`). New hosts subscribe to the letter event instead: [`crate::letter_hook`]
//! (`M4A_LETTER_HOOK`), which runs before any legacy adapter.

pub use gate4agent_wake::*;

/// Registers m4a's transports into g4a once (grok leader ACP client, routine POST).
pub fn install_transports() {
    #[cfg(feature = "wake-grok")]
    gate4agent_wake::set_grok_leader_transport(|sock, session_id, cwd, prompt| {
        mail4agent_grok::wake_decrypted_room_blocking(sock, session_id, &cwd.to_string_lossy(), prompt).map_err(|e| e.to_string())
    });
    gate4agent_wake::set_routine_transport(|url, body, bearer| crate::post_routine_json(url, body, bearer).map_err(|e| e.to_string()));
}

/// [`gate4agent_wake::plan_chain`] with m4a's transports installed and the letter hook first.
pub fn plan_chain(session: &ProviderSession, host: &HostEnv, config: &AdapterConfig) -> WakeChain {
    install_transports();
    let mut chain = gate4agent_wake::plan_chain(session, host, config);
    crate::letter_hook::prepend_from_env(&mut chain);
    chain
}

/// [`gate4agent_wake::adapter_for`] with m4a's transports installed.
pub fn adapter_for(kind: SessionKind, config: &AdapterConfig) -> Box<dyn WakeAdapter> {
    install_transports();
    gate4agent_wake::adapter_for(kind, config)
}

pub mod chain {
    pub use gate4agent_wake::chain::*;
    use std::path::Path;

    pub use super::plan_chain;

    /// [`gate4agent_wake::chain::detected_web_chain`] with transports and the letter hook.
    pub fn detected_web_chain(session_id: &str, nick: &str, store_root: &Path) -> Option<(super::ProviderSession, WakeChain)> {
        super::install_transports();
        let (session, mut chain) = gate4agent_wake::chain::detected_web_chain(session_id, nick, store_root)?;
        crate::letter_hook::prepend_from_env(&mut chain);
        Some((session, chain))
    }
}
