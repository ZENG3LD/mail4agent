//! HTTP client for a running [`mail4agent`](https://github.com/ZENG3LD/mail4agent) daemon.
//!
//! Covers the public mailbox surface the daemon exposes over loopback HTTP:
//! `GET /health` (no auth) and the bearer-gated `POST /mail/*` plus operator
//! `POST /admin/*` routes. Wire types for mail transport come from
//! [`mail4agent_api`]; admin / whoami / status display shapes that live only
//! in the daemon are mirrored here so a caller never needs to depend on the
//! binary crate.
//!
//! **Sender is never a field.** Every `/mail/*` call authenticates with the
//! bearer this client was constructed with; the daemon derives `from` from
//! that credential plus kernel session attestation on the TCP peer. See
//! `mail4agent` README / CLAUDE.md ("The rule that defines this service").
//!
//! Hostbot (HQ) consumes this crate as a dependency — the harness holds no
//! mailbox of its own (extraction plan
//! `mailbox-service-extraction-and-signed-session-identity-2026-09-16.md`).

use std::fmt;
use std::time::Duration;

use mail4agent_api::{
    AckRequest, AckResponse, Address, Directory, InboxPage, InboxRequest, MailError, Message,
    MessageGetRequest, ParticipantId, RoomId, SendRequest, SendResponse, SessionCard,
    SessionDeclared, UnreadCount, UnreadCountRequest,
};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default loopback bind the daemon uses when `mail4agent.toml` is absent.
pub const DEFAULT_BASE_URL: &str = "http://127.0.0.1:18301";

/// Rich liveness payload from `GET /health` (unauthenticated).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HealthReport {
    pub ok: bool,
    pub service: String,
    pub version: Option<String>,
    pub started_at: String,
    pub uptime_secs: u64,
    #[serde(default)]
    pub dependencies: Vec<serde_json::Value>,
    #[serde(default)]
    pub background_tasks: Vec<String>,
}

/// Answers `POST /mail/whoami` (daemon `dto::WhoAmIResponse`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WhoAmIResponse {
    pub address: Address,
    pub label: Option<String>,
    pub rooms: Vec<RoomId>,
    pub card: Option<SessionCard>,
}

/// Answers `POST /mail/status` (daemon `dto::StatusResponse`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub card: SessionCard,
}

/// Body for `POST /admin/participant`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisterParticipantRequest {
    pub id: ParticipantId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub may_send: bool,
    #[serde(default)]
    pub may_read: bool,
    #[serde(default)]
    pub operator: bool,
}

/// Answers `POST /admin/participant` / `…/rotate` — secret returned once.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecretResponse {
    pub id: ParticipantId,
    pub secret: String,
}

impl fmt::Display for SecretResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the secret via Display — Debug still redacts below.
        write!(f, "SecretResponse {{ id: {}, secret: [redacted] }}", self.id)
    }
}

impl fmt::Debug for SecretResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretResponse")
            .field("id", &self.id)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// Body for admin routes that take only a participant id.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ParticipantIdRequest {
    pub id: ParticipantId,
}

/// Body for `POST /admin/room`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoomIdRequest {
    pub id: RoomId,
}

/// Body for room membership add/remove.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoomMemberRequest {
    pub room: RoomId,
    pub participant: ParticipantId,
}

/// Typed failures from the HTTP client itself (transport / decode / HTTP
/// status that is not a named [`MailError`] JSON body).
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(String),
    #[error("build HTTP client: {0}")]
    Build(reqwest::Error),
    #[error("HTTP transport: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("mailbox refused: {0}")]
    Mail(#[from] MailError),
    #[error("unexpected HTTP {status}: {body}")]
    UnexpectedStatus { status: StatusCode, body: String },
    #[error("decode response: {0}")]
    Decode(String),
    #[error("base URL must be loopback HTTP for S2/local smoke (got {0})")]
    NonLoopbackBase(String),
}

/// Async HTTP client bound to one mailbox base URL and one bearer credential.
///
/// Clone is cheap (shared `reqwest::Client`). The bearer is stored so every
/// `/mail/*` and `/admin/*` call presents the same account; session identity
/// is still resolved server-side from the TCP peer.
#[derive(Clone)]
pub struct MailClient {
    http: Client,
    base: Url,
    bearer: String,
}

impl fmt::Debug for MailClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailClient")
            .field("base", &self.base)
            .field("bearer", &"[redacted]")
            .finish()
    }
}

impl MailClient {
    /// Builds a client for `base_url` (e.g. [`DEFAULT_BASE_URL`]) authenticating
    /// as `bearer`. Refuses a non-loopback base by default so a typo cannot
    /// point HQ mail at a remote host during local smoke — pass
    /// [`MailClient::builder`] when a non-loopback target is intentional.
    pub fn new(base_url: impl AsRef<str>, bearer: impl Into<String>) -> Result<Self, ClientError> {
        MailClientBuilder::new(base_url)?.bearer(bearer).build()
    }

    /// Same as [`Self::new`] but skips the loopback check (tests / explicit
    /// remote dial only). Prefer [`Self::new`] for hostbot HQ local dial.
    pub fn new_unchecked(base_url: impl AsRef<str>, bearer: impl Into<String>) -> Result<Self, ClientError> {
        MailClientBuilder::new(base_url)?
            .bearer(bearer)
            .allow_non_loopback()
            .build()
    }

    pub fn builder(base_url: impl AsRef<str>) -> Result<MailClientBuilder, ClientError> {
        MailClientBuilder::new(base_url)
    }

    pub fn base_url(&self) -> &Url {
        &self.base
    }

    /// `GET /health` — no bearer. Convenience that builds a one-shot client
    /// against `base_url` without storing credentials.
    pub async fn health_at(base_url: impl AsRef<str>) -> Result<HealthReport, ClientError> {
        let base = parse_base(base_url.as_ref(), true)?;
        let http = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(ClientError::Build)?;
        get_json(&http, base.join("health").map_err(|e| ClientError::InvalidBaseUrl(e.to_string()))?).await
    }

    /// `GET /health` on this client's base URL.
    pub async fn health(&self) -> Result<HealthReport, ClientError> {
        get_json(
            &self.http,
            self.base
                .join("health")
                .map_err(|e| ClientError::InvalidBaseUrl(e.to_string()))?,
        )
        .await
    }

    pub async fn send(&self, request: SendRequest) -> Result<SendResponse, ClientError> {
        self.post_json("mail/send", &request).await
    }

    pub async fn inbox(&self, request: InboxRequest) -> Result<InboxPage, ClientError> {
        self.post_json("mail/inbox", &request).await
    }

    pub async fn ack(&self, request: AckRequest) -> Result<AckResponse, ClientError> {
        self.post_json("mail/ack", &request).await
    }

    pub async fn get_message(&self, request: MessageGetRequest) -> Result<Message, ClientError> {
        self.post_json("mail/get", &request).await
    }

    pub async fn unread(&self, request: UnreadCountRequest) -> Result<UnreadCount, ClientError> {
        self.post_json("mail/unread", &request).await
    }

    /// `POST /mail/directory` — empty body.
    pub async fn directory(&self) -> Result<Directory, ClientError> {
        self.post_empty("mail/directory").await
    }

    /// `POST /mail/whoami` — empty body.
    pub async fn whoami(&self) -> Result<WhoAmIResponse, ClientError> {
        self.post_empty("mail/whoami").await
    }

    pub async fn status(&self, request: SessionDeclared) -> Result<StatusResponse, ClientError> {
        self.post_json("mail/status", &request).await
    }

    /// Operator: register a participant; returns the one-time secret.
    pub async fn admin_register_participant(
        &self,
        request: RegisterParticipantRequest,
    ) -> Result<SecretResponse, ClientError> {
        self.post_json("admin/participant", &request).await
    }

    pub async fn admin_rotate_participant(&self, id: ParticipantId) -> Result<SecretResponse, ClientError> {
        self.post_json("admin/participant/rotate", &ParticipantIdRequest { id })
            .await
    }

    pub async fn admin_remove_participant(&self, id: ParticipantId) -> Result<(), ClientError> {
        let _: serde_json::Value = self
            .post_json("admin/participant/remove", &ParticipantIdRequest { id })
            .await?;
        Ok(())
    }

    pub async fn admin_create_room(&self, id: RoomId) -> Result<(), ClientError> {
        let _: serde_json::Value = self.post_json("admin/room", &RoomIdRequest { id }).await?;
        Ok(())
    }

    pub async fn admin_add_room_member(&self, room: RoomId, participant: ParticipantId) -> Result<(), ClientError> {
        let _: serde_json::Value = self
            .post_json("admin/room/member/add", &RoomMemberRequest { room, participant })
            .await?;
        Ok(())
    }

    pub async fn admin_remove_room_member(
        &self,
        room: RoomId,
        participant: ParticipantId,
    ) -> Result<(), ClientError> {
        let _: serde_json::Value = self
            .post_json(
                "admin/room/member/remove",
                &RoomMemberRequest { room, participant },
            )
            .await?;
        Ok(())
    }

    /// Convenience: send a direct message to `to` with subject/body.
    pub async fn send_direct(
        &self,
        to: ParticipantId,
        subject: impl Into<String>,
        body: impl Into<String>,
    ) -> Result<SendResponse, ClientError> {
        self.send(SendRequest {
            to: Address::Direct { participant: to },
            subject: subject.into(),
            body: body.into(),
            reply_to: None,
            correlation: None,
            refs: Vec::new(),
            idempotency_key: None,
        })
        .await
    }

    /// Convenience: list inbox with default limit, no wait.
    pub async fn list_inbox(&self) -> Result<InboxPage, ClientError> {
        self.inbox(InboxRequest {
            since_unix_ms: None,
            limit: mail4agent_api::INBOX_LIMIT_DEFAULT,
            wait_secs: None,
        })
        .await
    }

    async fn post_json<B: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<R, ClientError> {
        let url = self
            .base
            .join(path)
            .map_err(|e| ClientError::InvalidBaseUrl(e.to_string()))?;
        let response = self
            .http
            .post(url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", self.bearer))
            .json(body)
            .send()
            .await?;
        decode_response(response).await
    }

    async fn post_empty<R: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<R, ClientError> {
        let url = self
            .base
            .join(path)
            .map_err(|e| ClientError::InvalidBaseUrl(e.to_string()))?;
        let response = self
            .http
            .post(url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", self.bearer))
            // daemon extractors still expect a body for some routes; empty JSON object is safe
            // for whoami/directory which take no ApiJson.
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body("{}")
            .send()
            .await?;
        decode_response(response).await
    }
}

/// Builder for [`MailClient`].
pub struct MailClientBuilder {
    base: Url,
    bearer: Option<String>,
    timeout: Duration,
    require_loopback: bool,
}

impl MailClientBuilder {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, ClientError> {
        let base = parse_base(base_url.as_ref(), false)?;
        Ok(Self {
            base,
            bearer: None,
            timeout: Duration::from_secs(30),
            require_loopback: true,
        })
    }

    pub fn bearer(mut self, bearer: impl Into<String>) -> Self {
        self.bearer = Some(bearer.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn allow_non_loopback(mut self) -> Self {
        self.require_loopback = false;
        self
    }

    pub fn build(self) -> Result<MailClient, ClientError> {
        if self.require_loopback {
            enforce_loopback(&self.base)?;
        }
        let bearer = self
            .bearer
            .filter(|b| !b.is_empty())
            .ok_or_else(|| ClientError::InvalidBaseUrl("bearer must be non-empty".into()))?;
        let http = Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(ClientError::Build)?;
        Ok(MailClient {
            http,
            base: self.base,
            bearer,
        })
    }
}

fn parse_base(raw: &str, enforce: bool) -> Result<Url, ClientError> {
    let mut url = Url::parse(raw).map_err(|e| ClientError::InvalidBaseUrl(e.to_string()))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(ClientError::InvalidBaseUrl(format!(
            "scheme must be http(s), got {}",
            url.scheme()
        )));
    }
    // Trailing slash so `join("mail/send")` appends under the base rather than
    // replacing a non-empty final segment.
    {
        let mut path = url.path().to_string();
        if path.is_empty() || path == "/" {
            path = "/".to_string();
        } else if !path.ends_with('/') {
            path.push('/');
        }
        url.set_path(&path);
    }
    if enforce {
        enforce_loopback(&url)?;
    }
    Ok(url)
}

fn enforce_loopback(url: &Url) -> Result<(), ClientError> {
    let host = url.host_str().unwrap_or("");
    let loopback = host == "localhost"
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]";
    if loopback {
        Ok(())
    } else {
        Err(ClientError::NonLoopbackBase(url.to_string()))
    }
}

async fn get_json<R: for<'de> Deserialize<'de>>(http: &Client, url: Url) -> Result<R, ClientError> {
    let response = http.get(url).send().await?;
    decode_response(response).await
}

async fn decode_response<R: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<R, ClientError> {
    let status = response.status();
    let bytes = response.bytes().await?;
    if status.is_success() {
        return serde_json::from_slice(&bytes).map_err(|e| ClientError::Decode(e.to_string()));
    }
    // Prefer a named MailError body when the daemon returned one.
    if let Ok(err) = serde_json::from_slice::<MailError>(&bytes) {
        return Err(ClientError::Mail(err));
    }
    let body = String::from_utf8_lossy(&bytes).into_owned();
    Err(ClientError::UnexpectedStatus { status, body })
}

/// Re-export common wire types so hostbot can `use mail4agent_client::*`.
pub use mail4agent_api::{
    AckRequest as MailAckRequest, Address as MailAddress, Directory as MailDirectory,
    InboxRequest as MailInboxRequest, MessageId as MailMessageId, ParticipantId as MailParticipantId,
    RoomId as MailRoomId, SendRequest as MailSendRequest, SendResponse as MailSendResponse,
    INBOX_LIMIT_DEFAULT,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_base_parses_and_is_loopback() {
        let url = parse_base(DEFAULT_BASE_URL, true).expect("default base");
        assert_eq!(url.as_str(), "http://127.0.0.1:18301/");
    }

    #[test]
    fn non_loopback_is_refused_by_default() {
        let err = parse_base("http://example.com:18301", true).expect_err("remote");
        assert!(matches!(err, ClientError::NonLoopbackBase(_)));
    }

    #[test]
    fn secret_response_display_redacts() {
        let id = ParticipantId::new("alice").unwrap();
        let s = SecretResponse {
            id,
            secret: "super-secret-value".into(),
        };
        let shown = format!("{s}");
        assert!(!shown.contains("super-secret"));
        assert!(shown.contains("[redacted]"));
    }

    #[test]
    fn join_mail_send_path() {
        let base = parse_base(DEFAULT_BASE_URL, true).unwrap();
        let joined = base.join("mail/send").unwrap();
        assert_eq!(joined.as_str(), "http://127.0.0.1:18301/mail/send");
    }
}
