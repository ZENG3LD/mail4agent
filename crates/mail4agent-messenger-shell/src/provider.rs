//! Session vocabulary and the letter chain. m4a carries no session-channel code of its own (no
//! ACP, no routine HTTP): a letter goes to the letter hook ([`crate::letter_hook`],
//! `M4A_LETTER_HOOK`) when the host set one, else to g4a's deliver adapter (`gate4agent-wake`,
//! deliver features only, never spawn or terminal), and whatever is not delivered stays in the
//! durable inbox.

pub use gate4agent_wake::{
    chain, hook, inbox, registry, HookFlavor, HostEnv, ProviderKind, ProviderSession, SessionKind, SessionRecord,
    Surface, WakeAdapter, adapter_for, AdapterConfig, ReactionNote, WakeChain, WakeError, WakeLetter, WakeOutcome, INBOX_DIR_ENV, PROVIDER_ENV,
};

/// The chain m4a runs for a letter: the hook (when `M4A_LETTER_HOOK` is set), then the g4a
/// deliver adapter for `kind`, then the durable inbox. The first link that delivers wins, so a
/// letter the hook took is never also delivered by g4a.
pub fn letter_chain(kind: SessionKind, inbox_dir: Option<std::path::PathBuf>, config: &AdapterConfig) -> WakeChain {
    let mut chain = WakeChain::new();
    chain.push("deliver", adapter_for(kind, config));
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
    fn letter_chain_is_deliver_then_inbox_without_a_hook() {
        if std::env::var_os(crate::letter_hook::LETTER_HOOK_ENV).is_some() {
            return;
        }
        let chain = letter_chain(SessionKind::local(ProviderKind::Codex), None, &AdapterConfig::default());
        assert_eq!(chain.ids(), vec!["deliver", "inbox-queue"]);
    }

    struct Count(std::sync::Arc<std::sync::atomic::AtomicUsize>, bool);
    impl WakeAdapter for Count {
        fn kind(&self) -> SessionKind {
            SessionKind::web(ProviderKind::Grok)
        }
        fn probe(&self, _: &ProviderSession) -> Result<(), WakeError> {
            Ok(())
        }
        fn wake(&mut self, _: &ProviderSession, _: &WakeLetter<'_>) -> Result<WakeOutcome, WakeError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.1 { Ok(WakeOutcome::Delivered) } else { Err(WakeError::Unavailable("down".into())) }
        }
    }

    #[test]
    fn local_kimi_letter_chain_uses_g4a_deliver_then_inbox() {
        let cfg = AdapterConfig { kimi_acp_bin: None, ..Default::default() };
        let chain = letter_chain(SessionKind::local(ProviderKind::KimiCode), None, &cfg);
        assert_eq!(chain.ids(), vec!["deliver", "inbox-queue"]);
        // The deliver link is g4a's adapter (server when ACP ungated); m4a has no kimi ACP code.
        assert!(cfg.kimi_acp_bin.is_none());
    }

    #[test]
    fn a_letter_the_hook_delivered_is_not_delivered_again_by_g4a() {
        use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};
        for (hook_ok, want_deliver) in [(true, 0), (false, 1)] {
            let (hooks, delivers) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
            let mut chain = WakeChain::new();
            chain.push("deliver", Box::new(Count(delivers.clone(), true)));
            chain.prepend("letter-hook", Box::new(Count(hooks.clone(), hook_ok)));
            let session = ProviderSession { kind: SessionKind::web(ProviderKind::Grok), session_id: "s".into(), nick: "n".into(), cwd: None, headless: false };
            let letter = WakeLetter { body: "b", from_nick: "f", event_id: "$e", room: None, reaction: None };
            let (id, _) = chain.wake(&session, &letter).expect("wake");
            assert_eq!(hooks.load(Ordering::SeqCst), 1);
            assert_eq!(delivers.load(Ordering::SeqCst), want_deliver);
            assert_eq!(id, if hook_ok { "letter-hook" } else { "deliver" });
        }
    }
}
