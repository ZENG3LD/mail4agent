//! `/mail/*` -- routes for sessions. Every one of these derives the caller
//! from the presented bearer PLUS the connection it arrived on
//! (`mail4agent/CLAUDE.md`, "The rule that defines this service"; see
//! `crate::identity` for how); none of them accepts a sender. Each axum
//! handler only extracts and renders; the real work lives in the `*_impl`
//! function beside it, which takes an already-resolved caller and typed
//! arguments and returns a plain `Result<_, MailError>` -- exactly the
//! shape a later MCP `tools/call` dispatcher will call directly, without
//! moving anything (`mail4agent/CLAUDE.md`, "`POST /mcp` ... dispatching
//! into the very same `*_impl` functions the HTTP routes call").

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use mail4agent_api::{
    Ack, AckRequest, AckResponse, Address, Directory, InboxPage, InboxRequest, MailError,
    Message, MessageGetRequest, SendRequest, SendResponse, SessionDeclared, UnreadCount,
    UnreadCountRequest, INBOX_WAIT_SECS_MAX,
};

use crate::auth::extract_bearer;
use crate::dto::{StatusResponse, WhoAmIResponse};
use crate::error::{ApiError, ApiJson};
use crate::identity::{resolve_session, PeerAddr, SessionError};
use crate::service::{now_unix_ms, AuthenticatedParticipant, MailboxService};
use crate::state::AppState;

/// Authenticates the bearer against the participant registry, resolving
/// only the **account** -- no session. Shared by `/admin/*` (which acts on
/// accounts, never sessions) and by [`resolve_caller`] (the first half of
/// its own resolution).
pub(crate) async fn authenticate_caller(
    service: &MailboxService,
    headers: &HeaderMap,
) -> Result<AuthenticatedParticipant, ApiError> {
    let token = extract_bearer(headers)
        .ok_or_else(|| ApiError::Mail(MailError::PermissionDenied { need: "mail:authenticate".to_string() }))?;
    service.authenticate(&token).await.map_err(ApiError::from)
}

/// Resolves the caller's own **session** address from this request: the
/// bearer proves the account ([`authenticate_caller`]); the connection
/// this request arrived on proves which of the account's sessions is
/// calling (`crate::identity::resolve_session`, kernel attestation under
/// the hood). Shared by every `/mail/*` and `/mcp` handler -- see
/// `crate::identity`'s module doc for why there is no fallback to the bare
/// account on any failure here.
///
/// Returns the resolved account alongside the session address because a
/// caller such as `whoami` needs both, and the account was already paid
/// for by [`authenticate_caller`] -- no second bearer lookup.
pub(crate) async fn resolve_caller(
    app: &AppState,
    headers: &HeaderMap,
    peer: PeerAddr,
) -> Result<(AuthenticatedParticipant, Address), ApiError> {
    let participant = authenticate_caller(&app.service, headers).await?;
    let peer_addr = peer.0.ok_or(SessionError::MissingConnectInfo)?;
    let now = now_unix_ms();
    let address = resolve_session(&app.service, participant.id.clone(), peer_addr, app.bind_addr, now).await?;
    Ok((participant, address))
}

pub async fn send(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: PeerAddr,
    ApiJson(request): ApiJson<SendRequest>,
) -> Result<Json<SendResponse>, ApiError> {
    let (_, caller) = resolve_caller(&app, &headers, peer).await?;
    let response = send_impl(&app.service, caller, request).await?;
    Ok(Json(response))
}

pub(crate) async fn send_impl(service: &MailboxService, sender: Address, request: SendRequest) -> Result<SendResponse, MailError> {
    service.send(sender, request).await
}

pub async fn inbox(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: PeerAddr,
    ApiJson(request): ApiJson<InboxRequest>,
) -> Result<Json<InboxPage>, ApiError> {
    let (_, caller) = resolve_caller(&app, &headers, peer).await?;
    let page = inbox_impl(&app.service, caller, request).await?;
    Ok(Json(page))
}

pub(crate) async fn inbox_impl(service: &MailboxService, reader: Address, request: InboxRequest) -> Result<InboxPage, MailError> {
    request.validate()?;
    let since_unix_ms = request.since_unix_ms.unwrap_or(0);
    let wait = clamp_wait_secs(request.wait_secs);
    service.inbox(reader, since_unix_ms, request.limit, wait).await
}

/// Clamps a caller's requested `wait_secs` to [`INBOX_WAIT_SECS_MAX`]
/// rather than refusing a longer request -- see that constant's own doc
/// comment. `None` (the caller did not ask to wait at all) stays `None`;
/// there is no lower clamp because `InboxRequest::wait_secs` is a `u16` and
/// cannot be negative.
fn clamp_wait_secs(wait_secs: Option<u16>) -> Option<Duration> {
    wait_secs.map(|secs| Duration::from_secs(u64::from(secs.min(INBOX_WAIT_SECS_MAX))))
}

pub async fn ack(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: PeerAddr,
    ApiJson(request): ApiJson<AckRequest>,
) -> Result<Json<AckResponse>, ApiError> {
    let (_, caller) = resolve_caller(&app, &headers, peer).await?;
    let ack = ack_impl(&app.service, caller, request).await?;
    Ok(Json(AckResponse { ack }))
}

pub(crate) async fn ack_impl(service: &MailboxService, reader: Address, request: AckRequest) -> Result<Ack, MailError> {
    request.validate()?;
    service.ack(reader, request.message_id).await
}

pub async fn get(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: PeerAddr,
    ApiJson(request): ApiJson<MessageGetRequest>,
) -> Result<Json<Message>, ApiError> {
    let (_, caller) = resolve_caller(&app, &headers, peer).await?;
    let message = get_impl(&app.service, caller, request).await?;
    Ok(Json(message))
}

pub(crate) async fn get_impl(service: &MailboxService, reader: Address, request: MessageGetRequest) -> Result<Message, MailError> {
    request.validate()?;
    service.message_get(reader, request.message_id).await
}

pub async fn unread(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: PeerAddr,
    ApiJson(request): ApiJson<UnreadCountRequest>,
) -> Result<Json<UnreadCount>, ApiError> {
    let (_, caller) = resolve_caller(&app, &headers, peer).await?;
    let count = unread_impl(&app.service, caller, request).await?;
    Ok(Json(count))
}

pub(crate) async fn unread_impl(service: &MailboxService, caller: Address, request: UnreadCountRequest) -> Result<UnreadCount, MailError> {
    request.validate()?;
    service.unread_count_of(caller, request.target).await
}

pub async fn directory(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: PeerAddr,
) -> Result<Json<Directory>, ApiError> {
    let (_, caller) = resolve_caller(&app, &headers, peer).await?;
    let directory = directory_impl(&app.service, caller).await?;
    Ok(Json(directory))
}

pub(crate) async fn directory_impl(service: &MailboxService, caller: Address) -> Result<Directory, MailError> {
    service.directory(caller).await
}

pub async fn whoami(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: PeerAddr,
) -> Result<Json<WhoAmIResponse>, ApiError> {
    let (participant, caller) = resolve_caller(&app, &headers, peer).await?;
    let response = whoami_impl(&app.service, participant, caller).await?;
    Ok(Json(response))
}

pub(crate) async fn whoami_impl(
    service: &MailboxService,
    participant: AuthenticatedParticipant,
    caller: Address,
) -> Result<WhoAmIResponse, MailError> {
    let rooms = service.rooms_of(participant.id).await?;
    let card = match &caller {
        Address::Session { session, .. } => service.session_card(session.clone()).await?,
        Address::Direct { .. } | Address::Room { .. } => None,
    };
    Ok(WhoAmIResponse { address: caller, label: participant.label, rooms, card })
}

pub async fn status(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: PeerAddr,
    ApiJson(request): ApiJson<SessionDeclared>,
) -> Result<Json<StatusResponse>, ApiError> {
    let (_, caller) = resolve_caller(&app, &headers, peer).await?;
    let response = status_impl(&app.service, caller, request).await?;
    Ok(Json(response))
}

/// The only writer of a session's declared group
/// (`mail4agent_core::MailboxEngine::set_declared`, reached here). Refuses
/// `Malformed` if `caller` is not itself a session -- declaring what a
/// caller is working on makes no sense for a bare account, and every real
/// `/mail/*`/`/mcp` caller is session-resolved by construction, so this
/// should not fire in practice.
pub(crate) async fn status_impl(
    service: &MailboxService,
    caller: Address,
    request: SessionDeclared,
) -> Result<StatusResponse, MailError> {
    request.validate()?;
    let Address::Session { session, .. } = &caller else {
        return Err(MailError::Malformed {
            field: "caller".to_string(),
            reason: "declaring status requires a session address, not a bare account".to_string(),
        });
    };
    let session = session.clone();
    service.set_declared(session.clone(), request.working_on, request.role, request.parent).await?;
    let card = service.session_card(session.clone()).await?.ok_or(MailError::UnknownSession { session })?;
    Ok(StatusResponse { card })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_wait_secs_is_none_when_the_caller_omits_it() {
        assert_eq!(clamp_wait_secs(None), None);
    }

    #[test]
    fn clamp_wait_secs_passes_a_request_at_or_under_the_cap_through_unchanged() {
        assert_eq!(clamp_wait_secs(Some(5)), Some(Duration::from_secs(5)));
        assert_eq!(clamp_wait_secs(Some(INBOX_WAIT_SECS_MAX)), Some(Duration::from_secs(u64::from(INBOX_WAIT_SECS_MAX))));
    }

    #[test]
    fn clamp_wait_secs_clamps_a_request_over_the_cap_instead_of_refusing() {
        // There is no `Err` arm at all in `clamp_wait_secs`'s own signature
        // -- this is the type-level half of "clamp, don't refuse"; this
        // test is the behavioural half.
        let clamped = clamp_wait_secs(Some(u16::MAX)).expect("a Some request still yields a Some duration");
        assert_eq!(clamped, Duration::from_secs(u64::from(INBOX_WAIT_SECS_MAX)));
    }
}
