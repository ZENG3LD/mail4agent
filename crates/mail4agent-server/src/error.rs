//! Matrix Client-Server error envelope. `status` is the HTTP status.
//! [`IntoResponse`] writes it. The body is the serde JSON. `status` itself
//! is not serialized.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::keys::MatrixKeysStoreError;
use crate::store::MatrixStoreError;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MatrixError {
    #[serde(skip)]
    pub status: u16,
    pub errcode: &'static str,
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soft_logout: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_version: Option<String>,
}

impl MatrixError {
    fn new(status: u16, errcode: &'static str, error: impl Into<String>) -> Self {
        Self {
            status,
            errcode,
            error: error.into(),
            retry_after_ms: None,
            soft_logout: None,
            current_version: None,
        }
    }

    pub fn missing_token() -> Self {
        Self::new(401, "M_MISSING_TOKEN", "Missing access token")
    }

    pub fn unknown_token() -> Self {
        Self {
            soft_logout: Some(false),
            ..Self::new(401, "M_UNKNOWN_TOKEN", "Unrecognised access token")
        }
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(403, "M_FORBIDDEN", msg)
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(404, "M_NOT_FOUND", msg)
    }

    pub fn unrecognized() -> Self {
        Self::new(404, "M_UNRECOGNIZED", "Unrecognized request")
    }

    pub fn bad_json(msg: impl Into<String>) -> Self {
        Self::new(400, "M_BAD_JSON", msg)
    }

    pub fn managed_account_data_type(msg: impl Into<String>) -> Self {
        Self::new(405, "M_BAD_JSON", msg)
    }

    pub fn invalid_param(msg: impl Into<String>) -> Self {
        Self::new(400, "M_INVALID_PARAM", msg)
    }

    pub fn duplicate_annotation() -> Self {
        Self::new(400, "M_DUPLICATE_ANNOTATION", "Already reacted with this key")
    }

    pub fn wrong_room_keys_version(current_version: Option<i64>) -> Self {
        Self {
            current_version: current_version.map(|v| v.to_string()),
            ..Self::new(403, "M_WRONG_ROOM_KEYS_VERSION", "Wrong backup version")
        }
    }

    pub fn limit_exceeded(retry_after_ms: u64) -> Self {
        Self {
            retry_after_ms: Some(retry_after_ms),
            ..Self::new(429, "M_LIMIT_EXCEEDED", "Too many requests")
        }
    }

    pub fn unknown(msg: impl Into<String>) -> Self {
        Self::new(500, "M_UNKNOWN", msg)
    }

    pub fn internal() -> Self {
        Self::unknown("Internal error")
    }
}

impl From<rusqlite::Error> for MatrixError {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!("messenger db error: {e}");
        Self::internal()
    }
}

impl From<MatrixStoreError> for MatrixError {
    fn from(e: MatrixStoreError) -> Self {
        match e {
            MatrixStoreError::Db(e) => MatrixError::from(e),
            MatrixStoreError::Json(e) => {
                tracing::error!("messenger store JSON error: {e}");
                MatrixError::bad_json("Malformed event content")
            }
            MatrixStoreError::ReservedLocalpart => MatrixError::forbidden("Reserved localpart"),
            MatrixStoreError::DuplicateAnnotation => MatrixError::duplicate_annotation(),
            MatrixStoreError::UnknownEventId(id) => MatrixError::not_found(format!("Unknown event: {id}")),
            MatrixStoreError::UnknownMxid(id) => MatrixError::not_found(format!("Unknown user: {id}")),
            MatrixStoreError::InvalidMembership(m) => MatrixError::invalid_param(format!("Invalid membership: {m}")),
            MatrixStoreError::InvalidRelationTarget(id) => {
                MatrixError::invalid_param(format!("Invalid relation target: {id}"))
            }
            MatrixStoreError::WrongRoom(id) => MatrixError::invalid_param(format!("Event is not in this room: {id}")),
            MatrixStoreError::UnredactableEvent(t) => {
                MatrixError::forbidden(format!("This event type cannot be redacted: {t}"))
            }
        }
    }
}

impl From<MatrixKeysStoreError> for MatrixError {
    fn from(e: MatrixKeysStoreError) -> Self {
        match e {
            MatrixKeysStoreError::Db(e) => MatrixError::from(e),
            MatrixKeysStoreError::OneTimeKeyConflict(key_id) => {
                MatrixError::invalid_param(format!("One-time key {key_id} already exists with different content"))
            }
            MatrixKeysStoreError::WrongBackupVersion => MatrixError::wrong_room_keys_version(None),
        }
    }
}

impl IntoResponse for MatrixError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self)).into_response()
    }
}

impl From<serde_json::Error> for MatrixError {
    fn from(e: serde_json::Error) -> Self {
        tracing::error!("messenger JSON error: {e}");
        Self::bad_json("Malformed JSON")
    }
}
