//! HTTP rendering for [`MailError`] and [`crate::identity::SessionError`],
//! plus a JSON extractor that renders a deserialize failure the same way.
//! Every refusal a caller sees -- from the engine, from session
//! resolution, or from a malformed request body -- is named, never a bare
//! string (`mail4agent/CLAUDE.md`, "Discipline": "a caller must learn
//! *what* was refused and *why* from the refusal itself").

use std::future::Future;

use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use mail4agent_api::MailError;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::identity::SessionError;

/// Wraps either domain refusal this daemon hands back to a caller: a
/// [`MailError`] from the mailbox engine, or a [`SessionError`] from
/// resolving which session is calling. Kept as two variants rather than
/// folded into one so a session-resolution failure is never serialised as
/// a [`MailError`] variant it is not -- the two enums answer different
/// questions ("was this refused by the mailbox" vs. "could the caller be
/// identified at all").
pub enum ApiError {
    Mail(MailError),
    Session(SessionError),
}

impl From<MailError> for ApiError {
    fn from(err: MailError) -> Self {
        Self::Mail(err)
    }
}

impl From<SessionError> for ApiError {
    fn from(err: SessionError) -> Self {
        Self::Session(err)
    }
}

/// The wire shape of a [`SessionError`] -- tagged the same way
/// [`MailError`] is (`kind`, `snake_case`), so a caller learns *what* was
/// refused the same way regardless of which of the two enums produced it.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SessionErrorBody {
    MissingConnectInfo { reason: String },
    AttestationFailed { reason: String },
    SessionRegistrationRefused { reason: String },
}

impl From<&SessionError> for SessionErrorBody {
    fn from(err: &SessionError) -> Self {
        match err {
            SessionError::MissingConnectInfo => Self::MissingConnectInfo { reason: err.to_string() },
            SessionError::Attest(_) => Self::AttestationFailed { reason: err.to_string() },
            SessionError::Mailbox(_) => Self::SessionRegistrationRefused { reason: err.to_string() },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Mail(err) => {
                let status = match &err {
                    MailError::PermissionDenied { .. } => StatusCode::FORBIDDEN,
                    // A message that exists but was never addressed to the
                    // caller is refused the same way `PermissionDenied` is:
                    // it names an authorization failure, not a missing
                    // resource.
                    MailError::NotAddressedToYou { .. } => StatusCode::FORBIDDEN,
                    MailError::UnknownParticipant { .. }
                    | MailError::UnknownRoom { .. }
                    | MailError::UnknownSession { .. }
                    | MailError::UnknownMessage { .. } => StatusCode::NOT_FOUND,
                    // Names a conflict between what the caller presented
                    // and what is already on file, not a missing resource
                    // or a malformed request.
                    MailError::SessionAccountMismatch { .. } => StatusCode::CONFLICT,
                    MailError::Malformed { .. } | MailError::TooLarge { .. } => StatusCode::BAD_REQUEST,
                    MailError::StoreUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
                };
                (status, Json(err)).into_response()
            }
            Self::Session(err) => {
                let status = match &err {
                    // A wiring failure, not a caller mistake: the server
                    // is not accepting connections the way this feature
                    // needs it to.
                    SessionError::MissingConnectInfo => StatusCode::INTERNAL_SERVER_ERROR,
                    // The caller could not be identified at all -- an
                    // authentication failure, not "not enough rights".
                    SessionError::Attest(_) => StatusCode::UNAUTHORIZED,
                    SessionError::Mailbox(_) => StatusCode::BAD_REQUEST,
                };
                tracing::warn!(error = %err, "session resolution refused a request");
                let body = SessionErrorBody::from(&err);
                (status, Json(body)).into_response()
            }
        }
    }
}

/// A `Json<T>` extractor whose rejection is a [`MailError::Malformed`]
/// rather than axum's own plain-text body. Catches both syntactically
/// invalid JSON and a field that fails its own `Deserialize` (e.g. a
/// [`mail4agent_api::ParticipantId`] whose selector shape is wrong) --
/// both would otherwise leave this crate's "no bare string" discipline at
/// the door the moment a request body fails to parse.
pub struct ApiJson<T>(pub T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    fn from_request(req: Request, state: &S) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            match Json::<T>::from_request(req, state).await {
                Ok(Json(value)) => Ok(Self(value)),
                Err(rejection) => Err(ApiError::Mail(MailError::Malformed {
                    field: "body".to_string(),
                    reason: rejection.body_text(),
                })),
            }
        }
    }
}
