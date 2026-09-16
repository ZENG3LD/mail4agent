//! [`MailboxAuth`] -- the mailbox's own `stk::AuthLayer`. Verifies the
//! presented bearer against the mailbox's own participant registry (never
//! a static key list) and grants `Authenticated`, plus `Admin` when the
//! participant carries the operator bit.
//!
//! **The participant id is never carried in the granted tiers.** A
//! `TokenTier::Scope` is a capability marker, not a place to smuggle a
//! subject. The handler that needs to know *who* called re-resolves the
//! caller from the very same bearer through [`crate::service::MailboxService`]
//! -- one indexed digest read, deliberately paid a second time per request
//! rather than threading an identity through a tier system that was never
//! designed to carry one (see `service.rs`'s doc comment on
//! [`crate::service::MailboxService::authenticate`]).

use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::HeaderMap;
use std::sync::Arc;

use crate::service::MailboxService;

pub struct MailboxAuth {
    service: Arc<MailboxService>,
}

impl MailboxAuth {
    pub fn new(service: Arc<MailboxService>) -> Self {
        Self { service }
    }
}

#[async_trait::async_trait]
impl stk::AuthLayer for MailboxAuth {
    fn name(&self) -> &str {
        "mailbox_bearer"
    }

    async fn resolve(&self, parts: &Parts) -> stk::AuthOutcome {
        let Some(token) = extract_bearer(&parts.headers) else {
            // No credential at all -- e.g. `/health`, which carries no
            // Authorization header and needs none. Abstaining (rather than
            // rejecting) leaves the request at the implicit `Public` floor
            // so a route that genuinely requires no auth still admits it.
            return stk::AuthOutcome::Abstain;
        };
        match self.service.authenticate(&token).await {
            Ok(participant) => {
                let mut tiers = vec![stk::TokenTier::Authenticated];
                if participant.operator {
                    tiers.push(stk::TokenTier::Admin);
                }
                stk::AuthOutcome::Grant(tiers)
            }
            // A credential WAS presented and did not match any
            // participant -- reject outright rather than falling through
            // to a generic "tier insufficient" 401, so the caller learns
            // its token is bad rather than merely "not enough".
            Err(_) => stk::AuthOutcome::Reject {
                reason: "unknown or invalid bearer token".to_string(),
            },
        }
    }
}

/// Extracts a bearer token from `Authorization: Bearer <token>`. Mirrors
/// stk's own internal `extract_bearer_token`
/// (`servertoolkit-auth/src/extract.rs`, `pub(crate)` there and not
/// re-exported by the facade) -- duplicated here rather than taking a
/// direct dependency on `servertoolkit-auth` for one header parse. Shared
/// by [`MailboxAuth::resolve`] and every handler's `resolve_caller` (see
/// `routes/mail.rs`), which is exactly the point: both ends of one
/// request read the same header the same way.
pub fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    let token = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "))?;
    Some(token.trim().to_string())
}
