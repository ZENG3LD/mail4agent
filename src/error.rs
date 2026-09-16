//! HTTP rendering for [`MailError`], plus a JSON extractor that renders a
//! deserialize failure the same way. Every refusal a caller sees -- from
//! the engine or from a malformed request body -- is a named [`MailError`]
//! tagged by `kind`, never a bare string (`mail4agent/CLAUDE.md`,
//! "Discipline": "a caller must learn *what* was refused and *why* from
//! the refusal itself").

use std::future::Future;

use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use mail4agent_api::MailError;
use serde::de::DeserializeOwned;

/// Wraps a [`MailError`] so it can be returned directly from an axum
/// handler. The HTTP status is derived from the refusal's kind; the body
/// is the [`MailError`] itself, serialised with its `kind` tag -- never an
/// unnamed `Internal`.
pub struct ApiError(pub MailError);

impl From<MailError> for ApiError {
    fn from(err: MailError) -> Self {
        Self(err)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            MailError::PermissionDenied { .. } => StatusCode::FORBIDDEN,
            // A message that exists but was never addressed to the caller
            // is refused the same way `PermissionDenied` is: it names an
            // authorization failure, not a missing resource.
            MailError::NotAddressedToYou { .. } => StatusCode::FORBIDDEN,
            MailError::UnknownParticipant { .. }
            | MailError::UnknownRoom { .. }
            | MailError::UnknownMessage { .. } => StatusCode::NOT_FOUND,
            MailError::Malformed { .. } | MailError::TooLarge { .. } => StatusCode::BAD_REQUEST,
            MailError::StoreUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, Json(self.0)).into_response()
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
                Err(rejection) => Err(ApiError(MailError::Malformed {
                    field: "body".to_string(),
                    reason: rejection.body_text(),
                })),
            }
        }
    }
}
