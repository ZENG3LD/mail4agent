//! `/mail/*` -- routes for participants. Every one of these derives the
//! caller from the presented bearer; none of them accepts a sender
//! (`mail4agent/CLAUDE.md`, "The rule that defines this service"). Each
//! axum handler only extracts and renders; the real work lives in the
//! `*_impl` function beside it, which takes an already-resolved caller and
//! typed arguments and returns a plain `Result<_, MailError>` -- exactly
//! the shape a later MCP `tools/call` dispatcher will call directly,
//! without moving anything (`mail4agent/CLAUDE.md`, "`POST /mcp` ...
//! dispatching into the very same `*_impl` functions the HTTP routes
//! call").

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use mail4agent_api::{
    Ack, AckRequest, AckResponse, Address, Directory, InboxPage, InboxRequest, MailError,
    Message, MessageGetRequest, ParticipantId, SendRequest, SendResponse, UnreadCount,
    UnreadCountRequest,
};

use crate::auth::extract_bearer;
use crate::dto::WhoAmIResponse;
use crate::error::{ApiError, ApiJson};
use crate::service::{AuthenticatedParticipant, MailboxService};

/// Resolves the caller from the request's own bearer, through the same
/// [`MailboxService::authenticate`] the auth layer already called once to
/// grant the tier that let this handler run at all. Shared by every
/// `/mail/*` and `/admin/*` handler (see `auth.rs`'s module doc for why
/// this second lookup is deliberate rather than redundant).
pub(crate) async fn resolve_caller(
    service: &MailboxService,
    headers: &HeaderMap,
) -> Result<AuthenticatedParticipant, ApiError> {
    let token = extract_bearer(headers)
        .ok_or_else(|| ApiError(MailError::PermissionDenied { need: "mail:authenticate".to_string() }))?;
    service.authenticate(&token).await.map_err(ApiError::from)
}

pub async fn send(
    State(service): State<Arc<MailboxService>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<SendRequest>,
) -> Result<Json<SendResponse>, ApiError> {
    let caller = resolve_caller(&service, &headers).await?;
    let response = send_impl(&service, caller.id, request).await?;
    Ok(Json(response))
}

pub(crate) async fn send_impl(
    service: &MailboxService,
    sender: ParticipantId,
    request: SendRequest,
) -> Result<SendResponse, MailError> {
    service.send(sender, request).await
}

pub async fn inbox(
    State(service): State<Arc<MailboxService>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<InboxRequest>,
) -> Result<Json<InboxPage>, ApiError> {
    let caller = resolve_caller(&service, &headers).await?;
    let page = inbox_impl(&service, caller.id, request).await?;
    Ok(Json(page))
}

pub(crate) async fn inbox_impl(
    service: &MailboxService,
    reader: ParticipantId,
    request: InboxRequest,
) -> Result<InboxPage, MailError> {
    request.validate()?;
    let since_unix_ms = request.since_unix_ms.unwrap_or(0);
    service.inbox(reader, since_unix_ms, request.limit).await
}

pub async fn ack(
    State(service): State<Arc<MailboxService>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<AckRequest>,
) -> Result<Json<AckResponse>, ApiError> {
    let caller = resolve_caller(&service, &headers).await?;
    let ack = ack_impl(&service, caller.id, request).await?;
    Ok(Json(AckResponse { ack }))
}

pub(crate) async fn ack_impl(service: &MailboxService, reader: ParticipantId, request: AckRequest) -> Result<Ack, MailError> {
    request.validate()?;
    service.ack(reader, request.message_id).await
}

pub async fn get(
    State(service): State<Arc<MailboxService>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<MessageGetRequest>,
) -> Result<Json<Message>, ApiError> {
    let caller = resolve_caller(&service, &headers).await?;
    let message = get_impl(&service, caller.id, request).await?;
    Ok(Json(message))
}

pub(crate) async fn get_impl(
    service: &MailboxService,
    reader: ParticipantId,
    request: MessageGetRequest,
) -> Result<Message, MailError> {
    request.validate()?;
    service.message_get(reader, request.message_id).await
}

pub async fn unread(
    State(service): State<Arc<MailboxService>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<UnreadCountRequest>,
) -> Result<Json<UnreadCount>, ApiError> {
    let caller = resolve_caller(&service, &headers).await?;
    let count = unread_impl(&service, caller.id, request).await?;
    Ok(Json(count))
}

async fn unread_impl(
    service: &MailboxService,
    caller: ParticipantId,
    request: UnreadCountRequest,
) -> Result<UnreadCount, MailError> {
    request.validate()?;
    service.unread_count_of(caller, request.participant).await
}

pub async fn directory(
    State(service): State<Arc<MailboxService>>,
    headers: HeaderMap,
) -> Result<Json<Directory>, ApiError> {
    let caller = resolve_caller(&service, &headers).await?;
    let directory = directory_impl(&service, caller.id).await?;
    Ok(Json(directory))
}

pub(crate) async fn directory_impl(service: &MailboxService, caller: ParticipantId) -> Result<Directory, MailError> {
    service.directory(caller).await
}

pub async fn whoami(
    State(service): State<Arc<MailboxService>>,
    headers: HeaderMap,
) -> Result<Json<WhoAmIResponse>, ApiError> {
    let caller = resolve_caller(&service, &headers).await?;
    let response = whoami_impl(&service, caller).await?;
    Ok(Json(response))
}

pub(crate) async fn whoami_impl(
    service: &MailboxService,
    caller: AuthenticatedParticipant,
) -> Result<WhoAmIResponse, MailError> {
    let rooms = service.rooms_of(caller.id.clone()).await?;
    Ok(WhoAmIResponse {
        address: Address::Direct { participant: caller.id },
        label: caller.label,
        rooms,
    })
}
