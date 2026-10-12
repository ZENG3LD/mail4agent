//! Session vocabulary and the letter chain. m4a is a pure messenger: it does not wake or spawn
//! sessions and links no session channel (no ACP, no routine HTTP, no app-server). A letter is
//! handed to the host through the letter hook ([`crate::letter_hook`], `M4A_LETTER_HOOK`); the
//! host (the hatchery node) decides and delivers through g4a's deliver API (`gate4agent-wake`).
//! Whatever the hook does not take stays in the durable inbox.
//!
//! The types and the inbox/registry come from `gate4agent-wake` built with no deliver features,
//! so no adapter is compiled into m4a.

pub use gate4agent_wake::{
    chain, hook, inbox, registry, HookFlavor, HostEnv, ProviderKind, ProviderSession, SessionKind, SessionRecord,
    Surface, WakeAdapter, WakeChain, WakeError, WakeLetter, WakeOutcome, INBOX_DIR_ENV, PROVIDER_ENV,
};

/// The chain m4a runs for a letter: the hook (when `M4A_LETTER_HOOK` is set), then the durable
/// inbox for `kind`. Nothing else.
pub fn letter_chain(kind: SessionKind, inbox_dir: Option<std::path::PathBuf>) -> WakeChain {
    let mut chain = WakeChain::new();
    chain.push("inbox-queue", Box::new(hook::InboxQueueAdapter::new(kind, inbox_dir)));
    crate::letter_hook::prepend_from_env(&mut chain);
    chain
}

pub mod claude_channel {
    //! Moved to g4a (`gate4agent_wake::claude_channel`); the channel server is a deliver channel.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letter_chain_is_inbox_only_without_a_hook() {
        if std::env::var_os(crate::letter_hook::LETTER_HOOK_ENV).is_some() {
            return;
        }
        let chain = letter_chain(SessionKind::local(ProviderKind::Codex), None);
        assert_eq!(chain.ids(), vec!["inbox-queue"]);
    }
}
