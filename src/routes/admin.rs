//! `/admin/*` -- the operator-only registry surface. Every handler
//! re-resolves the caller from its bearer (same helper `routes/mail.rs`
//! uses) and asserts the operator bit itself, in addition to the tier
//! middleware's own `TokenTier::Admin` gate (`auth.rs` grants `Admin` only
//! when the participant record carries `operator: true`, so this check
//! should never actually fire) -- defence in depth that costs one already-
//! paid digest read and removes any dependency on the tier system alone
//! for an operator-only mutation.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use mail4agent_api::MailError;

use crate::dto::{
    EmptyResponse, ParticipantIdRequest, RegisterParticipantRequest, RoomIdRequest,
    RoomMemberRequest, SecretResponse,
};
use crate::error::{ApiError, ApiJson};
use crate::routes::mail::resolve_caller;
use crate::service::MailboxService;

async fn require_operator(service: &MailboxService, headers: &HeaderMap) -> Result<(), ApiError> {
    let caller = resolve_caller(service, headers).await?;
    if caller.operator {
        Ok(())
    } else {
        Err(ApiError(MailError::PermissionDenied { need: "mail:operator".to_string() }))
    }
}

pub async fn register_participant(
    State(service): State<Arc<MailboxService>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<RegisterParticipantRequest>,
) -> Result<Json<SecretResponse>, ApiError> {
    require_operator(&service, &headers).await?;
    let response = register_participant_impl(&service, request).await?;
    Ok(Json(response))
}

async fn register_participant_impl(
    service: &MailboxService,
    request: RegisterParticipantRequest,
) -> Result<SecretResponse, MailError> {
    let permissions = request.permissions();
    let secret = service.register_participant(request.id.clone(), request.label, permissions).await?;
    Ok(SecretResponse { id: request.id, secret })
}

pub async fn rotate_participant(
    State(service): State<Arc<MailboxService>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<ParticipantIdRequest>,
) -> Result<Json<SecretResponse>, ApiError> {
    require_operator(&service, &headers).await?;
    let response = rotate_participant_impl(&service, request).await?;
    Ok(Json(response))
}

async fn rotate_participant_impl(
    service: &MailboxService,
    request: ParticipantIdRequest,
) -> Result<SecretResponse, MailError> {
    let secret = service.rotate_participant_secret(request.id.clone()).await?;
    Ok(SecretResponse { id: request.id, secret })
}

pub async fn remove_participant(
    State(service): State<Arc<MailboxService>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<ParticipantIdRequest>,
) -> Result<Json<EmptyResponse>, ApiError> {
    require_operator(&service, &headers).await?;
    remove_participant_impl(&service, request).await?;
    Ok(Json(EmptyResponse {}))
}

async fn remove_participant_impl(service: &MailboxService, request: ParticipantIdRequest) -> Result<(), MailError> {
    service.deregister_participant(request.id).await
}

pub async fn create_room(
    State(service): State<Arc<MailboxService>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<RoomIdRequest>,
) -> Result<Json<EmptyResponse>, ApiError> {
    require_operator(&service, &headers).await?;
    create_room_impl(&service, request).await?;
    Ok(Json(EmptyResponse {}))
}

async fn create_room_impl(service: &MailboxService, request: RoomIdRequest) -> Result<(), MailError> {
    service.create_room(request.id).await
}

pub async fn add_room_member(
    State(service): State<Arc<MailboxService>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<RoomMemberRequest>,
) -> Result<Json<EmptyResponse>, ApiError> {
    require_operator(&service, &headers).await?;
    add_room_member_impl(&service, request).await?;
    Ok(Json(EmptyResponse {}))
}

async fn add_room_member_impl(service: &MailboxService, request: RoomMemberRequest) -> Result<(), MailError> {
    service.add_room_member(request.room, request.participant).await
}

pub async fn remove_room_member(
    State(service): State<Arc<MailboxService>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<RoomMemberRequest>,
) -> Result<Json<EmptyResponse>, ApiError> {
    require_operator(&service, &headers).await?;
    remove_room_member_impl(&service, request).await?;
    Ok(Json(EmptyResponse {}))
}

async fn remove_room_member_impl(service: &MailboxService, request: RoomMemberRequest) -> Result<(), MailError> {
    service.remove_room_member(request.room, request.participant).await
}
