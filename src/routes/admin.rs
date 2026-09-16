//! `/admin/*` -- the operator-only registry surface. Every handler
//! re-resolves the caller's **account** from its bearer (`authenticate_caller`,
//! shared with `routes/mail.rs`) and asserts the operator bit itself, in
//! addition to the tier middleware's own `TokenTier::Admin` gate (`auth.rs`
//! grants `Admin` only when the participant record carries
//! `operator: true`, so this check should never actually fire) -- defence
//! in depth that costs one already-paid digest read and removes any
//! dependency on the tier system alone for an operator-only mutation.
//!
//! These routes act on **accounts** (registering a participant, creating a
//! room, granting room membership), never on a session, so they never need
//! session resolution -- `authenticate_caller` is the whole story.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use mail4agent_api::MailError;

use crate::dto::{
    EmptyResponse, ParticipantIdRequest, RegisterParticipantRequest, RemoveListenerRequest, RoomIdRequest,
    RoomMemberRequest, SecretResponse, SetListenerRequest,
};
use crate::error::{ApiError, ApiJson};
use crate::routes::mail::authenticate_caller;
use crate::service::MailboxService;
use crate::state::AppState;

async fn require_operator(app: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let caller = authenticate_caller(&app.service, headers).await?;
    if caller.operator {
        Ok(())
    } else {
        Err(ApiError::Mail(MailError::PermissionDenied { need: "mail:operator".to_string() }))
    }
}

pub async fn register_participant(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<RegisterParticipantRequest>,
) -> Result<Json<SecretResponse>, ApiError> {
    require_operator(&app, &headers).await?;
    let response = register_participant_impl(&app.service, request).await?;
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
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<ParticipantIdRequest>,
) -> Result<Json<SecretResponse>, ApiError> {
    require_operator(&app, &headers).await?;
    let response = rotate_participant_impl(&app.service, request).await?;
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
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<ParticipantIdRequest>,
) -> Result<Json<EmptyResponse>, ApiError> {
    require_operator(&app, &headers).await?;
    remove_participant_impl(&app.service, request).await?;
    Ok(Json(EmptyResponse {}))
}

async fn remove_participant_impl(service: &MailboxService, request: ParticipantIdRequest) -> Result<(), MailError> {
    service.deregister_participant(request.id).await
}

pub async fn create_room(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<RoomIdRequest>,
) -> Result<Json<EmptyResponse>, ApiError> {
    require_operator(&app, &headers).await?;
    create_room_impl(&app.service, request).await?;
    Ok(Json(EmptyResponse {}))
}

async fn create_room_impl(service: &MailboxService, request: RoomIdRequest) -> Result<(), MailError> {
    service.create_room(request.id).await
}

pub async fn add_room_member(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<RoomMemberRequest>,
) -> Result<Json<EmptyResponse>, ApiError> {
    require_operator(&app, &headers).await?;
    add_room_member_impl(&app.service, request).await?;
    Ok(Json(EmptyResponse {}))
}

async fn add_room_member_impl(service: &MailboxService, request: RoomMemberRequest) -> Result<(), MailError> {
    service.add_room_member(request.room, request.participant).await
}

pub async fn remove_room_member(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<RoomMemberRequest>,
) -> Result<Json<EmptyResponse>, ApiError> {
    require_operator(&app, &headers).await?;
    remove_room_member_impl(&app.service, request).await?;
    Ok(Json(EmptyResponse {}))
}

async fn remove_room_member_impl(service: &MailboxService, request: RoomMemberRequest) -> Result<(), MailError> {
    service.remove_room_member(request.room, request.participant).await
}

pub async fn set_listener(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<SetListenerRequest>,
) -> Result<Json<EmptyResponse>, ApiError> {
    require_operator(&app, &headers).await?;
    set_listener_impl(&app.service, request).await?;
    Ok(Json(EmptyResponse {}))
}

async fn set_listener_impl(service: &MailboxService, request: SetListenerRequest) -> Result<(), MailError> {
    service.set_listener(request.account, request.url).await
}

pub async fn remove_listener(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<RemoveListenerRequest>,
) -> Result<Json<EmptyResponse>, ApiError> {
    require_operator(&app, &headers).await?;
    remove_listener_impl(&app.service, request).await?;
    Ok(Json(EmptyResponse {}))
}

async fn remove_listener_impl(service: &MailboxService, request: RemoveListenerRequest) -> Result<(), MailError> {
    service.remove_listener(request.account).await
}
