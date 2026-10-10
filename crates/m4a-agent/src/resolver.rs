//! Which session is this process? One question, asked of ordered sources (a host's agents
//! directory, the CLI's active sessions, a provider hook, the OS attestation of the local mail
//! node...). Sources only name the session; identity, nick and credentials are the
//! [`IdentityStore`]'s business, so they cannot disagree about them.

use crate::error::{AgentError, Result};
use crate::identity::{IdentityStore, SessionIdentity};
use crate::backend::BackendKind;

/// What a source knows about the current session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSession {
    /// The one session id every other part of the client uses.
    pub session_id: String,
    /// The tier-1 session id (the local mail node's attested id), when the source knows it.
    pub local_session: Option<String>,
    /// Which source answered (for logs and errors).
    pub source: &'static str,
}

pub trait SessionResolver: Send + Sync {
    fn name(&self) -> &'static str;
    /// `Ok(None)`: this source does not know the session. `Err`: it should know and failed.
    fn resolve(&self) -> Result<Option<ResolvedSession>>;
}

/// A source that always answers the same (CLI flag, test).
pub struct FixedResolver(pub ResolvedSession);

impl SessionResolver for FixedResolver {
    fn name(&self) -> &'static str {
        self.0.source
    }
    fn resolve(&self) -> Result<Option<ResolvedSession>> {
        Ok(Some(self.0.clone()))
    }
}

/// Ordered sources. The first that knows wins; a lower source that knows something DIFFERENT is an
/// error, so two paths can never silently produce two identities for one process.
#[derive(Default)]
pub struct ResolverChain {
    sources: Vec<Box<dyn SessionResolver>>,
}

impl ResolverChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, r: impl SessionResolver + 'static) -> Self {
        self.sources.push(Box::new(r));
        self
    }

    pub fn resolve(&self) -> Result<ResolvedSession> {
        let mut first: Option<ResolvedSession> = None;
        for s in &self.sources {
            let Some(found) = s.resolve()? else { continue };
            match &first {
                None => first = Some(found),
                Some(f) if f.session_id != found.session_id => {
                    return Err(AgentError::Identity(format!("sources disagree about the session: {} says one id, {} another", f.source, found.source)));
                }
                Some(_) => {
                    // Same session: the tier-1 link may come from a lower source.
                    if let (Some(f), Some(l)) = (first.as_mut(), found.local_session) {
                        match &f.local_session {
                            None => f.local_session = Some(l),
                            Some(have) if *have != l => return Err(AgentError::Identity("sources disagree about the local session".into())),
                            Some(_) => {}
                        }
                    }
                }
            }
        }
        first.ok_or_else(|| AgentError::Identity("no source knows which session this is".into()))
    }

    /// Resolve the session, then its identity for `tier` on `server_ref`, with the tier-1 link
    /// recorded. The one entry point a host uses.
    pub fn identity(&self, ids: &IdentityStore, tier: BackendKind, server_ref: &str) -> Result<SessionIdentity> {
        let r = self.resolve()?;
        let mut id = ids.resolve(&r.session_id, tier, server_ref)?;
        if let Some(l) = &r.local_session {
            ids.bind_local(&mut id, l)?;
        }
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::MemoryVault;
    use std::sync::Arc;

    struct Nothing;
    impl SessionResolver for Nothing {
        fn name(&self) -> &'static str {
            "nothing"
        }
        fn resolve(&self) -> Result<Option<ResolvedSession>> {
            Ok(None)
        }
    }
    fn fixed(id: &str, local: Option<&str>, source: &'static str) -> FixedResolver {
        FixedResolver(ResolvedSession { session_id: id.into(), local_session: local.map(Into::into), source })
    }

    #[test]
    fn first_source_wins_and_lower_ones_can_add_the_local_link() {
        let c = ResolverChain::new().with(Nothing).with(fixed("s1", None, "agents-dir")).with(fixed("s1", Some("l1"), "attestation"));
        let r = c.resolve().unwrap();
        assert_eq!((r.session_id.as_str(), r.local_session.as_deref(), r.source), ("s1", Some("l1"), "agents-dir"));
        let ids = IdentityStore::new(Arc::new(MemoryVault::new()));
        let id = c.identity(&ids, BackendKind::Server, "https://p.example").unwrap();
        assert_eq!(id.local_session.as_deref(), Some("l1"));
    }

    #[test]
    fn disagreeing_sources_and_no_source_are_errors() {
        assert!(ResolverChain::new().with(fixed("s1", None, "a")).with(fixed("s2", None, "b")).resolve().is_err());
        assert!(ResolverChain::new().with(fixed("s1", Some("l1"), "a")).with(fixed("s1", Some("l2"), "b")).resolve().is_err());
        assert!(ResolverChain::new().with(Nothing).resolve().is_err());
    }
}
