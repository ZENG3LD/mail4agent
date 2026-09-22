//! Bearer authentication and tier gating for this daemon's own routes.
//!
//! Verifies the presented bearer against the mailbox's own participant
//! registry (never a static key list) via
//! [`crate::service::MailboxService::authenticate`], and grants the
//! [`Tier::Authenticated`] gate to any valid bearer, plus [`Tier::Admin`]
//! when the participant carries the operator bit.
//!
//! **The participant id is never carried by the tier itself.** A tier is a
//! capability marker, not a place to smuggle a subject. The handler that
//! needs to know *who* called re-resolves the caller from the very same
//! bearer through [`crate::service::MailboxService`] -- one indexed digest
//! read, deliberately paid a second time per request (see `service.rs`'s
//! own doc comment on `MailboxService::authenticate`).
//!
//! [`require_tier`] is the axum middleware every gated route in `main.rs`
//! is wired behind, one per tier group (`/mail/*` + `/mcp` at
//! [`Tier::Authenticated`], `/admin/*` at [`Tier::Admin`]). `GET /health`
//! is mounted outside every gated router entirely -- the only route
//! without authentication, as it is in every nemo service -- so there is
//! no `Public` variant here to grant.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use serde_json::json;

use crate::service::MailboxService;

/// Extracts a bearer token from `Authorization: Bearer <token>`. Shared by
/// [`require_tier`] and every handler's `resolve_caller`
/// (`routes/mail.rs`) -- both ends of one request read the same header the
/// same way.
pub fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    let token = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "))?;
    Some(token.trim().to_string())
}

/// The two gates a route in this daemon can require.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Authenticated,
    Admin,
}

impl Tier {
    /// Numeric rank so a carried tier can be compared against a required
    /// one -- `Admin` satisfies an `Authenticated` requirement, never the
    /// reverse.
    fn rank(self) -> u8 {
        match self {
            Tier::Authenticated => 1,
            Tier::Admin => 2,
        }
    }
}

/// The middleware state for one tier group: which mailbox to authenticate
/// against, and the minimum [`Tier`] every route behind this middleware
/// requires. Wired once per group in `main.rs` via
/// `middleware::from_fn_with_state`; independent of the router's own
/// `State<Arc<AppState>>`, which handlers extract separately.
#[derive(Clone)]
pub struct TierGuard {
    pub service: Arc<MailboxService>,
    pub required: Tier,
}

/// Reproduces the daemon's former `stk::AuthLayer` + tier-enforcement
/// middleware exactly:
///
/// - No bearer at all -> `tier_insufficient`, 401 (an empty carried set
///   never satisfies `Authenticated`, the lowest gate any route here
///   requires).
/// - A bearer that matches no participant -> `auth_rejected`, 401, naming
///   the credential itself as the problem rather than "not enough rights".
/// - A bearer that authenticates but does not reach `required` (an
///   ordinary participant hitting an `Admin` route) -> `tier_insufficient`,
///   403 -- this DID authenticate, so the caller learns "not enough",
///   never "who are you".
pub async fn require_tier(State(guard): State<TierGuard>, req: Request, next: Next) -> Response {
    let Some(token) = extract_bearer(req.headers()) else {
        return tier_insufficient(guard.required, StatusCode::UNAUTHORIZED);
    };
    let carried = match guard.service.authenticate(&token).await {
        Ok(participant) => {
            if participant.operator {
                Tier::Admin
            } else {
                Tier::Authenticated
            }
        }
        Err(_) => return auth_rejected("unknown or invalid bearer token"),
    };
    if carried.rank() >= guard.required.rank() {
        next.run(req).await
    } else {
        tier_insufficient(guard.required, StatusCode::FORBIDDEN)
    }
}

fn auth_rejected(reason: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({ "ok": false, "error": "auth_rejected", "reason": reason }))).into_response()
}

fn tier_insufficient(required: Tier, status: StatusCode) -> Response {
    (status, Json(json!({ "ok": false, "error": "tier_insufficient", "required": required }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;

    fn headers_with_bearer(token: &str) -> HeaderMap {
        HttpRequest::builder().header(AUTHORIZATION, format!("Bearer {token}")).body(()).unwrap().headers().clone()
    }

    #[test]
    fn extract_bearer_reads_the_token_out_of_the_header() {
        let headers = headers_with_bearer("secret-123");
        assert_eq!(extract_bearer(&headers).as_deref(), Some("secret-123"));
    }

    #[test]
    fn extract_bearer_is_case_insensitive_on_the_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "bearer secret-123".parse().unwrap());
        assert_eq!(extract_bearer(&headers).as_deref(), Some("secret-123"));
    }

    #[test]
    fn extract_bearer_is_none_without_the_header() {
        assert_eq!(extract_bearer(&HeaderMap::new()), None);
    }

    #[test]
    fn admin_rank_satisfies_an_authenticated_requirement() {
        assert!(Tier::Admin.rank() >= Tier::Authenticated.rank());
    }

    #[test]
    fn authenticated_rank_does_not_satisfy_an_admin_requirement() {
        assert!(Tier::Authenticated.rank() < Tier::Admin.rank());
    }

    #[test]
    fn tier_serializes_snake_case() {
        assert_eq!(serde_json::to_value(Tier::Authenticated).unwrap(), json!("authenticated"));
        assert_eq!(serde_json::to_value(Tier::Admin).unwrap(), json!("admin"));
    }
}
