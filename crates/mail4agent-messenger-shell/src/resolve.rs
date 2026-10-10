//! The five places a session id used to come from, as sources of ONE resolver chain
//! (`m4a_agent::ResolverChain`). Each source only names the session (and, when it knows it, the
//! tier-1 local session id); identity, nick and credentials are the client's identity store's.
//! The chain refuses two sources that name different sessions for one process.

use std::path::{Path, PathBuf};

use m4a_agent::{AgentError, ResolvedSession, SessionResolver};

fn found(session_id: &str, local: &Option<String>, source: &'static str) -> Option<ResolvedSession> {
    Some(ResolvedSession { session_id: session_id.to_string(), local_session: local.clone(), source })
}

macro_rules! with_local {
    ($t:ident) => {
        impl $t {
            /// The tier-1 (local mail node) session id of the same session, when the caller knows it.
            pub fn with_local(mut self, local_session: impl Into<String>) -> Self {
                self.local = Some(local_session.into());
                self
            }
        }
    };
}

/// 1. A host that already assigned the id (`M4A_SESSION_ID`, the node CLI, a web host).
pub struct ConfiguredResolver {
    pub session_id: Option<String>,
    local: Option<String>,
}
impl ConfiguredResolver {
    pub fn new(session_id: Option<String>) -> Self {
        Self { session_id: session_id.filter(|s| !s.is_empty()), local: None }
    }
}
with_local!(ConfiguredResolver);
impl SessionResolver for ConfiguredResolver {
    fn name(&self) -> &'static str {
        "configured"
    }
    fn resolve(&self) -> Result<Option<ResolvedSession>, AgentError> {
        Ok(self.session_id.as_deref().and_then(|s| found(s, &self.local, "configured")))
    }
}

/// 2. A Grok Bot agent: the agent id is the mail session id unless `agent=session` aliases say
/// otherwise (the same rule the machine client applies).
pub struct AgentsDirResolver {
    agents_dir: PathBuf,
    agent_id: String,
    aliases: Vec<(String, String)>,
    local: Option<String>,
}
impl AgentsDirResolver {
    pub fn new(agents_dir: impl Into<PathBuf>, agent_id: impl Into<String>, session_ids_env: &str) -> Self {
        Self { agents_dir: agents_dir.into(), agent_id: agent_id.into(), aliases: crate::machine::parse_session_ids(session_ids_env), local: None }
    }
}
with_local!(AgentsDirResolver);
impl SessionResolver for AgentsDirResolver {
    fn name(&self) -> &'static str {
        "agents-dir"
    }
    fn resolve(&self) -> Result<Option<ResolvedSession>, AgentError> {
        let mut all = match crate::machine::load_agents_dir(&self.agents_dir) {
            Ok(a) => a,
            Err(_) => return Ok(None),
        };
        all.retain(|s| s.agent_id.as_deref() == Some(self.agent_id.as_str()));
        crate::machine::apply_session_ids(&mut all, &self.aliases);
        Ok(all.first().and_then(|s| found(&s.session_id, &self.local, "agents-dir")))
    }
}

/// 3. A Grok CLI session: the row of `active_sessions.json` whose working directory is `cwd`.
#[cfg(feature = "wake-grok")]
pub struct GrokActiveResolver {
    index_text: String,
    sessions_root: PathBuf,
    cwd: String,
    local: Option<String>,
}
#[cfg(feature = "wake-grok")]
impl GrokActiveResolver {
    pub fn new(index_text: impl Into<String>, sessions_root: impl Into<PathBuf>, cwd: impl Into<String>) -> Self {
        Self { index_text: index_text.into(), sessions_root: sessions_root.into(), cwd: cwd.into(), local: None }
    }
}
#[cfg(feature = "wake-grok")]
with_local!(GrokActiveResolver);
#[cfg(feature = "wake-grok")]
impl SessionResolver for GrokActiveResolver {
    fn name(&self) -> &'static str {
        "grok-active"
    }
    fn resolve(&self) -> Result<Option<ResolvedSession>, AgentError> {
        let heard = crate::grok_listen::hear(&self.index_text, &self.sessions_root).map_err(|e| AgentError::Identity(e.to_string()))?;
        let mut rows = heard.iter().filter(|h| h.cwd == self.cwd);
        let first = rows.next();
        if rows.next().is_some() {
            return Err(AgentError::Identity("two live Grok sessions share this working directory".into()));
        }
        Ok(first.and_then(|h| found(&h.session_id, &self.local, "grok-active")))
    }
}

/// 4. A provider session that registered itself (hook or `m4a-inbox register`).
pub struct ProviderRecordResolver {
    store_root: PathBuf,
    provider: String,
    vendor_session: String,
    local: Option<String>,
}
impl ProviderRecordResolver {
    pub fn new(store_root: &Path, provider: &str, vendor_session: &str) -> Self {
        Self { store_root: store_root.to_path_buf(), provider: provider.into(), vendor_session: vendor_session.into(), local: None }
    }
}
with_local!(ProviderRecordResolver);
impl SessionResolver for ProviderRecordResolver {
    fn name(&self) -> &'static str {
        "provider-record"
    }
    fn resolve(&self) -> Result<Option<ResolvedSession>, AgentError> {
        let live = crate::provider::registry::live_sessions(&self.store_root);
        Ok(live.iter().find(|s| s.kind.provider.id() == self.provider && s.session_id == self.vendor_session).and_then(|s| found(&s.session_id, &self.local, "provider-record")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use m4a_agent::{BackendKind, IdentityStore, MemoryVault, ResolverChain};
    use std::sync::Arc;

    #[test]
    fn the_sources_agree_through_one_chain_and_link_the_local_session() {
        let root = tempfile::tempdir().unwrap();
        let agents = root.path().join("agents");
        std::fs::create_dir_all(agents.join("bot-7")).unwrap();
        std::fs::write(agents.join("bot-7/profile.json"), r#"{"name":"Alice"}"#).unwrap();
        // An alias moves the mail session id off the agent id, as the machine client does.
        let chain = ResolverChain::new()
            .with(ConfiguredResolver::new(None))
            .with(AgentsDirResolver::new(&agents, "bot-7", "bot-7=mail-7").with_local("local-7"))
            .with(ConfiguredResolver::new(Some("mail-7".into())));
        let r = chain.resolve().unwrap();
        assert_eq!((r.session_id.as_str(), r.local_session.as_deref(), r.source), ("mail-7", Some("local-7"), "agents-dir"));
        let ids = IdentityStore::new(Arc::new(MemoryVault::new()));
        let id = chain.identity(&ids, BackendKind::Server, "https://p.example").unwrap();
        assert_eq!((id.session_id.as_str(), id.local_session.as_deref()), ("mail-7", Some("local-7")));
        // Unknown agent: the source does not know, the others decide.
        assert!(ResolverChain::new().with(AgentsDirResolver::new(&agents, "nobody", "")).resolve().is_err());
        // A second source naming ANOTHER session for the same process is refused.
        let clash = ResolverChain::new().with(AgentsDirResolver::new(&agents, "bot-7", "")).with(ConfiguredResolver::new(Some("mail-7".into())));
        assert!(clash.resolve().is_err(), "agent id bot-7 vs configured mail-7");
    }
}
