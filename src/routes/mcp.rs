//! `POST /mcp` / `DELETE /mcp` -- the MCP (Model Context Protocol)
//! Streamable HTTP door onto the SAME mail surface `/mail/*` serves, per
//! `mail4agent/CLAUDE.md`'s "one implementation, two doors": every tool
//! below dispatches into the exact `*_impl` function its HTTP sibling in
//! `routes::mail` already calls -- never a second copy of the mailbox
//! logic.
//!
//! Follows `mirage2operator/crates/operator-box/src/ops/mcp.rs` closely
//! (see `docs/gate4agent/research/mailbox-service-templates-2026-09-16.md`
//! section 1 for a line-cited reading of that reference) with one
//! deliberate departure, noted below.
//!
//! # Transport
//!
//! One route, `POST /mcp`, under the SAME `TokenTier::Authenticated`
//! bearer layer `/mail/*` sits behind (wired once in `main.rs` -- nothing
//! extra here). Body is JSON-RPC 2.0 (spec 2025-03-26 / 2025-06-18), a
//! single request object or a batch array; the response is a single
//! `application/json` body (one object, or an array for a batch that
//! produced more than zero responses) -- never SSE. Every tool here
//! dispatches straight into an already-bounded `routes::mail::*_impl`
//! call, so nothing streams. `DELETE /mcp` answers `204 No Content`
//! unconditionally: this server is stateless (`initialize` records
//! nothing), so there is nothing an MCP session-end could tear down.
//!
//! # Caller resolution -- once per HTTP call, not once per batch item
//!
//! This is the one place this module's shape differs from
//! `ops/mcp.rs`'s: operator-box's `/mcp` answers to a single global
//! operator key, so its tools never resolve a per-caller identity at all.
//! This mailbox's tools are participant-scoped (`mail4agent/CLAUDE.md`,
//! "a sender is never a field the caller fills in"), so the caller is
//! resolved from the SAME bearer every `/mail/*` handler reads
//! (`routes::mail::resolve_caller`) -- exactly once per `POST /mcp` call.
//! A JSON-RPC batch shares one HTTP request and therefore one resolved
//! caller, matching the "one indexed digest read per request" discipline
//! `service.rs` already documents for the plain HTTP routes. A caller
//! that fails to resolve (should not happen past the tier middleware, but
//! is not ruled out by it) fails the whole HTTP call the same way any
//! other `/mail/*` handler would -- an [`crate::error::ApiError`]
//! response, not a JSON-RPC error, since nothing JSON-RPC-shaped has been
//! parsed yet at that point. An operator calling a mail tool is just a
//! participant: nothing here reads `caller.operator`.
//!
//! # Error shape -- the split that matters most
//!
//! A tool that could not be invoked at all (unknown tool name, arguments
//! that do not deserialise into that tool's own shape) is a JSON-RPC
//! *error* (`-32602`). A tool that ran and refused -- `PermissionDenied`,
//! `UnknownParticipant`, `NotAddressedToYou`, any other named
//! [`mail4agent_api::MailError`] -- is a normal JSON-RPC *result* carrying
//! the MCP tool-result envelope with `isError: true` and the named
//! refusal (serialised with its `kind` tag) inside. Getting this backwards
//! makes every business refusal look like a broken server -- see
//! `ops/mcp.rs`'s own module doc for the same distinction, drawn from the
//! MCP spec itself.
//!
//! # Wire-type reuse
//!
//! Every tool's `arguments` deserialises straight into [`mail4agent_api`]'s
//! own request type for that call -- [`SendRequest`], [`InboxRequest`],
//! [`AckRequest`], [`MessageGetRequest`] -- with no local args struct in
//! between. A missing `Option<T>` field decodes to `None` (serde's derive
//! defaults an absent `Option` field on its own; no `#[serde(default)]`
//! needed), so a caller that omits `reply_to`, `correlation`,
//! `since_unix_ms`, `refs` or `idempotency_key` gets exactly the same
//! [`SendRequest`]/[`InboxRequest`] value the HTTP door already builds from
//! a body that spells those out as explicit `null` -- proven by
//! [`tests::send_and_inbox_accept_arguments_with_every_optional_field_omitted`].
//! A second, locally-defined copy of these fields was tried and removed:
//! it duplicated the wire shape `mail4agent_api` already owns, which is
//! exactly the second code path the crate contract forbids -- a field
//! added to [`SendRequest`] would have silently never reached this door.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use mail4agent_api::{
    AckRequest, InboxRequest, MailError, MessageGetRequest, SendRequest, INBOX_LIMIT_DEFAULT,
    INBOX_LIMIT_MAX, REFS_MAX,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::routes::mail::{ack_impl, get_impl, inbox_impl, resolve_caller, send_impl, whoami_impl};
use crate::service::{AuthenticatedParticipant, MailboxService};

/// Echoed back from `initialize` when the client's own `protocolVersion` is
/// one this server has been reviewed against; see [`handle_initialize`].
/// Copied verbatim from `mirage2operator`'s `ops/mcp.rs`, per this crate's
/// own instruction to match that reference's negotiation exactly.
const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";
/// Every protocol revision this server has actually been reviewed
/// against. Copied verbatim from `ops/mcp.rs`.
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-03-26", "2025-06-18"];
const SERVER_NAME: &str = "mail4agent";

const JSONRPC_PARSE_ERROR: i64 = -32700;
const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const JSONRPC_INVALID_PARAMS: i64 = -32602;

// ---------------------------------------------------------------------------
// JSON-RPC envelope
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RpcRequest {
    /// Absent on a JSON-RPC *notification* -- a request with no `id` gets
    /// no response at all, per JSON-RPC 2.0.
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcErrorBody>,
}

#[derive(Debug, Serialize)]
struct RpcErrorBody {
    code: i64,
    message: String,
}

impl RpcResponse {
    fn ok(id: Value, result: Value) -> Self {
        Self { jsonrpc: "2.0", id, result: Some(result), error: None }
    }

    fn err(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self { jsonrpc: "2.0", id, result: None, error: Some(RpcErrorBody { code, message: message.into() }) }
    }
}

// ---------------------------------------------------------------------------
// HTTP door
// ---------------------------------------------------------------------------

/// `POST /mcp`. Resolves the caller once (see this module's doc), then
/// reads the body as raw [`Bytes`] -- not through an `axum::Json`
/// extractor -- so a malformed body answers JSON-RPC `-32700` instead of
/// axum's own bare-400 rejection.
pub async fn handle_mcp_post(State(service): State<Arc<MailboxService>>, headers: HeaderMap, body: Bytes) -> Response {
    let caller = match resolve_caller(&service, &headers).await {
        Ok(caller) => caller,
        Err(err) => return err.into_response(),
    };

    let value: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return Json(RpcResponse::err(Value::Null, JSONRPC_PARSE_ERROR, format!("parse error: {e}")))
                .into_response()
        }
    };

    match value {
        Value::Array(items) => {
            if items.is_empty() {
                return Json(RpcResponse::err(Value::Null, JSONRPC_INVALID_PARAMS, "empty batch")).into_response();
            }
            let mut responses = Vec::with_capacity(items.len());
            for item in items {
                if let Some(resp) = dispatch_one(&service, &caller, item).await {
                    responses.push(resp);
                }
            }
            if responses.is_empty() {
                // Every entry in the batch was a notification -- nothing
                // to answer, per JSON-RPC 2.0's own batch rule.
                StatusCode::NO_CONTENT.into_response()
            } else {
                Json(responses).into_response()
            }
        }
        single => match dispatch_one(&service, &caller, single).await {
            Some(resp) => Json(resp).into_response(),
            None => StatusCode::NO_CONTENT.into_response(),
        },
    }
}

/// `DELETE /mcp` -- session end. This server is stateless (`initialize`
/// creates no session record), so there is nothing to tear down; always
/// `204`.
pub async fn handle_mcp_delete() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

/// Dispatch one JSON-RPC request or notification. Returns `None` exactly
/// when nothing should be sent back -- either the input had no `id`
/// (notification) or it was `notifications/initialized` specifically
/// (treated as fire-and-forget regardless of a stray `id`, since nothing
/// about accepting it can fail).
async fn dispatch_one(service: &Arc<MailboxService>, caller: &AuthenticatedParticipant, raw: Value) -> Option<RpcResponse> {
    let req: RpcRequest = match serde_json::from_value(raw) {
        Ok(r) => r,
        Err(e) => return Some(RpcResponse::err(Value::Null, JSONRPC_PARSE_ERROR, format!("parse error: {e}"))),
    };
    let id = req.id.clone().unwrap_or(Value::Null);
    let is_notification = req.id.is_none();

    if req.method == "notifications/initialized" {
        return None;
    }

    let outcome: Result<Value, (i64, String)> = match req.method.as_str() {
        "initialize" => Ok(handle_initialize(&req.params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(tools_list()),
        "tools/call" => handle_tools_call(service, caller, &req.params).await,
        other => Err((JSONRPC_METHOD_NOT_FOUND, format!("unknown method {other:?}"))),
    };

    if is_notification {
        return None;
    }

    Some(match outcome {
        Ok(value) => RpcResponse::ok(id, value),
        Err((code, message)) => RpcResponse::err(id, code, message),
    })
}

/// `initialize` -- echoes the client's own `protocolVersion` when it is
/// one this server has been reviewed against, else falls back to
/// [`DEFAULT_PROTOCOL_VERSION`]. Verbatim copy of
/// `mirage2operator/crates/operator-box/src/ops/mcp.rs`'s own
/// `handle_initialize`, per this crate's instruction to match that
/// reference's negotiation exactly.
fn handle_initialize(params: &Value) -> Value {
    let requested = params.get("protocolVersion").and_then(Value::as_str);
    let protocol_version = match requested {
        Some(v) if SUPPORTED_PROTOCOL_VERSIONS.contains(&v) => v.to_string(),
        _ => DEFAULT_PROTOCOL_VERSION.to_string(),
    };
    json!({
        "protocolVersion": protocol_version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION") },
    })
}

// ---------------------------------------------------------------------------
// tools/list -- five tools, schemas kept next to the dispatch arm for the
// same tool so they cannot drift from what `arguments` actually
// deserialises into.
// ---------------------------------------------------------------------------

fn tools_list() -> Value {
    json!({
        "tools": [
            tool_mail_send(),
            tool_mail_inbox(),
            tool_mail_ack(),
            tool_mail_get(),
            tool_mail_whoami(),
        ]
    })
}

/// Shared schema for [`mail4agent_api::Address`] -- internally tagged on
/// its own `kind` field, exactly as it serialises.
fn address_schema() -> Value {
    json!({
        "type": "object",
        "description": "Where the message goes. Internally tagged on its own \"kind\" field.",
        "required": ["kind"],
        "oneOf": [
            {
                "type": "object",
                "required": ["kind", "participant"],
                "additionalProperties": false,
                "properties": {
                    "kind": { "const": "direct" },
                    "participant": { "type": "string", "description": "Addresses one participant directly." }
                }
            },
            {
                "type": "object",
                "required": ["kind", "room"],
                "additionalProperties": false,
                "properties": {
                    "kind": { "const": "room" },
                    "room": { "type": "string", "description": "Every current member of this room reads the message." }
                }
            }
        ]
    })
}

/// Shared schema for [`mail4agent_api::MessageRef`].
fn message_ref_schema() -> Value {
    json!({
        "type": "object",
        "required": ["kind", "locator"],
        "additionalProperties": false,
        "properties": {
            "kind": { "type": "string", "description": "A selector naming what this reference points at." },
            "locator": { "type": "string", "description": "An opaque pointer, meaningful only to the calling application. The mailbox stores and returns it verbatim; it never resolves one." },
            "digest": { "type": ["string", "null"], "description": "Optional lower-hex content hash of whatever locator names." }
        }
    })
}

fn tool_mail_send() -> Value {
    json!({
        "name": "m4a_mail_send",
        "description": "Send a message to one participant (direct) or to every current member of a room. The sender is derived from the caller's own credential and cannot be set here -- there is no \"from\" field, so don't look for one.",
        "inputSchema": {
            "type": "object",
            "required": ["to", "subject", "body"],
            "additionalProperties": false,
            "properties": {
                "to": address_schema(),
                "subject": { "type": "string", "description": "No control characters." },
                "body": { "type": "string", "description": "Newline and tab allowed; no other control characters." },
                "reply_to": { "type": ["string", "null"], "description": "message_id this message replies to, if any." },
                "correlation": { "type": ["string", "null"], "description": "Caller-owned grouping label (a task, a run, a conversation) -- the mailbox never reads it, only stores and returns it." },
                "refs": {
                    "type": "array",
                    "maxItems": REFS_MAX,
                    "items": message_ref_schema(),
                    "description": format!("Up to {REFS_MAX} references; the mailbox stores and returns each verbatim, it never resolves one.")
                },
                "idempotency_key": { "type": ["string", "null"], "description": "A repeated key from the same sender returns the ORIGINAL send's response instead of creating a second message. Omit it (or leave it null) to send a genuinely new message every call, including a repeat of the same text on purpose." }
            }
        }
    })
}

fn tool_mail_inbox() -> Value {
    json!({
        "name": "m4a_mail_inbox",
        "description": format!("Page through the caller's own inbox: messages addressed directly to the caller, plus messages to any room the caller currently belongs to. since_unix_ms filters to that timestamp onward (omit for the full history); limit bounds the page size (default {INBOX_LIMIT_DEFAULT}, max {INBOX_LIMIT_MAX})."),
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "since_unix_ms": { "type": ["integer", "null"], "minimum": 0 },
                "limit": { "type": ["integer", "null"], "minimum": 1, "maximum": INBOX_LIMIT_MAX }
            }
        }
    })
}

fn tool_mail_ack() -> Value {
    json!({
        "name": "m4a_mail_ack",
        "description": "Record that the caller has read one message by id. Acking a message the caller already acked just updates the timestamp -- it never creates a duplicate.",
        "inputSchema": {
            "type": "object",
            "required": ["message_id"],
            "additionalProperties": false,
            "properties": { "message_id": { "type": "string" } }
        }
    })
}

fn tool_mail_get() -> Value {
    json!({
        "name": "m4a_mail_get",
        "description": "Fetch one message by id. Refuses with a NotAddressedToYou result when the message exists but was never sent to the caller (not their direct address, and not a room they belong to).",
        "inputSchema": {
            "type": "object",
            "required": ["message_id"],
            "additionalProperties": false,
            "properties": { "message_id": { "type": "string" } }
        }
    })
}

fn tool_mail_whoami() -> Value {
    json!({
        "name": "m4a_mail_whoami",
        "description": "The caller's own address, label and room memberships. Call this first, before m4a_mail_send, if the session does not already know where it can be answered -- it is exactly what a caller that has not written yet needs to learn that.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }
    })
}

// ---------------------------------------------------------------------------
// tools/call dispatch
// ---------------------------------------------------------------------------

async fn handle_tools_call(
    service: &Arc<MailboxService>,
    caller: &AuthenticatedParticipant,
    params: &Value,
) -> Result<Value, (i64, String)> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| (JSONRPC_INVALID_PARAMS, "tools/call missing string \"name\"".to_string()))?;
    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

    match name {
        "m4a_mail_send" => {
            let req: SendRequest =
                serde_json::from_value(args).map_err(|e| (JSONRPC_INVALID_PARAMS, format!("m4a_mail_send: bad arguments: {e}")))?;
            Ok(tool_result(send_impl(service, caller.id.clone(), req).await))
        }
        "m4a_mail_inbox" => {
            let req: InboxRequest = serde_json::from_value(args)
                .map_err(|e| (JSONRPC_INVALID_PARAMS, format!("m4a_mail_inbox: bad arguments: {e}")))?;
            Ok(tool_result(inbox_impl(service, caller.id.clone(), req).await))
        }
        "m4a_mail_ack" => {
            let req: AckRequest =
                serde_json::from_value(args).map_err(|e| (JSONRPC_INVALID_PARAMS, format!("m4a_mail_ack: bad arguments: {e}")))?;
            Ok(tool_result(ack_impl(service, caller.id.clone(), req).await))
        }
        "m4a_mail_get" => {
            let req: MessageGetRequest =
                serde_json::from_value(args).map_err(|e| (JSONRPC_INVALID_PARAMS, format!("m4a_mail_get: bad arguments: {e}")))?;
            Ok(tool_result(get_impl(service, caller.id.clone(), req).await))
        }
        "m4a_mail_whoami" => Ok(tool_result(whoami_impl(service, caller.clone()).await)),
        other => Err((JSONRPC_INVALID_PARAMS, format!("unknown tool {other:?}"))),
    }
}

/// Turns a `*_impl` outcome into the MCP tool-result envelope. `Ok` is a
/// normal result (`isError: false`); `Err` -- a named [`MailError`] the
/// tool *ran and refused with* -- is STILL a normal JSON-RPC result, just
/// with `isError: true` and the refusal (serialised with its `kind` tag)
/// as the payload. See this module's doc, "Error shape".
fn tool_result<T: Serialize>(outcome: Result<T, MailError>) -> Value {
    let (value, is_error) = match outcome {
        Ok(v) => (serde_json::to_value(&v).unwrap_or_else(|_| json!({"error": "failed to serialize tool result"})), false),
        Err(e) => (serde_json::to_value(&e).unwrap_or_else(|_| json!({"error": "failed to serialize tool error"})), true),
    };
    mcp_tool_content(value, is_error)
}

/// Shared MCP tool-call result shape -- see [`tool_result`], the one
/// caller.
fn mcp_tool_content(value: Value, is_error: bool) -> Value {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": value,
        "isError": is_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::AUTHORIZATION;
    use mail4agent_api::ParticipantId;
    use mail4agent_core::ParticipantPermissions;
    use mail4agent_store_stk::SqliteMailStore;

    /// Fresh in-memory mailbox with one registered participant ("alice",
    /// may_send + may_read, not an operator). Returns the service and
    /// bearer headers ready to authenticate as that participant -- the
    /// same shape `resolve_caller` reads on every real `/mail/*` request.
    async fn service_with_bearer() -> (Arc<MailboxService>, HeaderMap) {
        let engine_store = SqliteMailStore::open_in_memory().expect("in-memory store opens and migrates");
        let reader_store = SqliteMailStore::new(engine_store.db());
        let service = Arc::new(MailboxService::new(engine_store, reader_store));

        let id = ParticipantId::new("alice").expect("valid participant id");
        let permissions = ParticipantPermissions { may_send: true, may_read: true, operator: false };
        let secret = service
            .register_participant(id, Some("alice".to_string()), permissions)
            .await
            .expect("register test participant");

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {secret}").parse().expect("valid header value"));
        (service, headers)
    }

    async fn post_raw(service: &Arc<MailboxService>, headers: &HeaderMap, body: Value) -> Response {
        handle_mcp_post(State(service.clone()), headers.clone(), Bytes::from(serde_json::to_vec(&body).expect("serialize")))
            .await
    }

    async fn post_bytes(service: &Arc<MailboxService>, headers: &HeaderMap, body: &[u8]) -> Response {
        handle_mcp_post(State(service.clone()), headers.clone(), Bytes::copy_from_slice(body)).await
    }

    async fn response_json(resp: Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("collect body");
        serde_json::from_slice(&bytes).expect("response body must be JSON")
    }

    async fn post(service: &Arc<MailboxService>, headers: &HeaderMap, body: Value) -> Value {
        response_json(post_raw(service, headers, body).await).await
    }

    #[tokio::test]
    async fn single_request_returns_a_single_response() {
        let (service, headers) = service_with_bearer().await;
        let resp = post(&service, &headers, json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })).await;
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"], json!({}));
    }

    #[tokio::test]
    async fn batch_request_returns_an_array_of_responses() {
        let (service, headers) = service_with_bearer().await;
        let resp = post(
            &service,
            &headers,
            json!([
                { "jsonrpc": "2.0", "id": 1, "method": "ping" },
                { "jsonrpc": "2.0", "id": 2, "method": "tools/list" },
            ]),
        )
        .await;
        let arr = resp.as_array().expect("batch response must be a JSON array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["id"], 1);
        assert_eq!(arr[1]["id"], 2);
    }

    #[tokio::test]
    async fn notification_without_id_returns_nothing() {
        let (service, headers) = service_with_bearer().await;
        let resp = post_raw(&service, &headers, json!({ "jsonrpc": "2.0", "method": "ping" })).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn notifications_initialized_returns_nothing_even_with_a_stray_id() {
        let (service, headers) = service_with_bearer().await;
        let resp = post_raw(&service, &headers, json!({ "jsonrpc": "2.0", "id": 99, "method": "notifications/initialized" })).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn all_notification_batch_returns_204() {
        let (service, headers) = service_with_bearer().await;
        let resp = post_raw(
            &service,
            &headers,
            json!([
                { "jsonrpc": "2.0", "method": "ping" },
                { "jsonrpc": "2.0", "method": "notifications/initialized" },
            ]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn unknown_method_returns_method_not_found() {
        let (service, headers) = service_with_bearer().await;
        let resp = post(&service, &headers, json!({ "jsonrpc": "2.0", "id": 1, "method": "bogus/method" })).await;
        assert_eq!(resp["error"]["code"], JSONRPC_METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn unknown_tool_name_returns_invalid_params() {
        let (service, headers) = service_with_bearer().await;
        let resp = post(
            &service,
            &headers,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "bogus_tool", "arguments": {} } }),
        )
        .await;
        assert_eq!(resp["error"]["code"], JSONRPC_INVALID_PARAMS);
    }

    #[tokio::test]
    async fn malformed_body_returns_parse_error() {
        let (service, headers) = service_with_bearer().await;
        let resp = response_json(post_bytes(&service, &headers, b"{ not json").await).await;
        assert_eq!(resp["error"]["code"], JSONRPC_PARSE_ERROR);
    }

    #[tokio::test]
    async fn initialize_echoes_a_supported_protocol_version() {
        let (service, headers) = service_with_bearer().await;
        let resp = post(
            &service,
            &headers,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18" } }),
        )
        .await;
        let result = &resp["result"];
        assert_eq!(result["protocolVersion"], "2025-06-18");
        assert_eq!(result["capabilities"]["tools"], json!({}));
        assert_eq!(result["serverInfo"]["name"], "mail4agent");
        assert!(result["serverInfo"]["version"].is_string());
    }

    #[tokio::test]
    async fn initialize_falls_back_to_default_for_an_unsupported_protocol_version() {
        let (service, headers) = service_with_bearer().await;
        let resp = post(
            &service,
            &headers,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "1999-01-01" } }),
        )
        .await;
        assert_eq!(resp["result"]["protocolVersion"], DEFAULT_PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn tools_list_returns_five_named_tools() {
        let (service, headers) = service_with_bearer().await;
        let resp = post(&service, &headers, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" })).await;
        let tools = resp["result"]["tools"].as_array().expect("tools must be an array");
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().expect("name must be a string")).collect();
        assert_eq!(names, vec!["m4a_mail_send", "m4a_mail_inbox", "m4a_mail_ack", "m4a_mail_get", "m4a_mail_whoami"]);
        for tool in tools {
            assert_eq!(tool["inputSchema"]["type"], "object", "{} inputSchema must be type object", tool["name"]);
        }
    }

    #[tokio::test]
    async fn a_business_refusal_comes_back_as_iserror_true_not_a_jsonrpc_error() {
        let (service, headers) = service_with_bearer().await;
        let resp = post(
            &service,
            &headers,
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "m4a_mail_get", "arguments": { "message_id": "m4a_000000000000000000000000" } }
            }),
        )
        .await;
        assert!(resp.get("error").is_none(), "a business refusal must not be a JSON-RPC error: {resp}");
        let result = &resp["result"];
        assert_eq!(result["isError"], true);
        assert_eq!(result["structuredContent"]["kind"], "unknown_message");
    }

    /// The property `MailSendArgs`/`MailInboxArgs` were once (wrongly)
    /// introduced to guarantee, proven directly against the real wire
    /// types instead: an MCP caller that says nothing about an optional
    /// field gets exactly what a caller that never touches the field
    /// should get, with no local args struct standing between `arguments`
    /// and [`SendRequest`]/[`InboxRequest`].
    #[tokio::test]
    async fn send_and_inbox_accept_arguments_with_every_optional_field_omitted() {
        let (service, headers) = service_with_bearer().await;
        let send_resp = post(
            &service,
            &headers,
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {
                    "name": "m4a_mail_send",
                    "arguments": { "to": { "kind": "direct", "participant": "alice" }, "subject": "hi", "body": "hi" }
                }
            }),
        )
        .await;
        assert_eq!(
            send_resp["result"]["isError"], false,
            "send with reply_to/correlation/refs/idempotency_key all omitted must succeed: {send_resp}"
        );

        let inbox_resp = post(
            &service,
            &headers,
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "m4a_mail_inbox", "arguments": {} } }),
        )
        .await;
        assert_eq!(
            inbox_resp["result"]["isError"], false,
            "inbox with since_unix_ms/limit both omitted must succeed: {inbox_resp}"
        );
    }

    #[tokio::test]
    async fn send_then_inbox_round_trips_through_the_same_impl_as_http() {
        let (service, headers) = service_with_bearer().await;
        let send_resp = post(
            &service,
            &headers,
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {
                    "name": "m4a_mail_send",
                    "arguments": { "to": { "kind": "direct", "participant": "alice" }, "subject": "hi", "body": "hi" }
                }
            }),
        )
        .await;
        assert_eq!(send_resp["result"]["isError"], false);
        let message_id = send_resp["result"]["structuredContent"]["message_id"]
            .as_str()
            .expect("send result carries a message_id")
            .to_string();

        let inbox_resp = post(
            &service,
            &headers,
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "m4a_mail_inbox", "arguments": {} } }),
        )
        .await;
        assert_eq!(inbox_resp["result"]["isError"], false);
        let messages = inbox_resp["result"]["structuredContent"]["messages"].as_array().expect("messages array");
        assert!(
            messages.iter().any(|m| m["message_id"] == message_id),
            "sent message must appear in the same participant's inbox"
        );
    }

    #[tokio::test]
    async fn delete_always_answers_204() {
        let resp = handle_mcp_delete().await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
}
