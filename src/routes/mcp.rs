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
//! This mailbox's tools are session-scoped (`mail4agent/CLAUDE.md`, "a
//! sender is never a field the caller fills in"; `crate::identity` for how
//! a session is named), so the caller is resolved from the SAME bearer AND
//! connection every `/mail/*` handler reads (`routes::mail::resolve_caller`)
//! -- exactly once per `POST /mcp` call. A JSON-RPC batch shares one HTTP
//! request and therefore one resolved caller, matching the "one indexed
//! digest read per request" discipline `service.rs` already documents for
//! the plain HTTP routes. A caller that fails to resolve (an unknown
//! bearer, or a session that could not be attested) fails the whole HTTP
//! call the same way any other `/mail/*` handler would -- an
//! [`crate::error::ApiError`] response, not a JSON-RPC error, since
//! nothing JSON-RPC-shaped has been parsed yet at that point.
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
//! [`AckRequest`], [`MessageGetRequest`], [`mail4agent_api::SessionDeclared`]
//! -- with no local args struct in between. A missing `Option<T>` field
//! decodes to `None` (serde's derive defaults an absent `Option` field on
//! its own; no `#[serde(default)]` needed), so a caller that omits an
//! optional field gets exactly the same value the HTTP door already builds
//! from a body that spells it out as explicit `null` -- proven by
//! [`tests::send_and_inbox_accept_arguments_with_every_optional_field_omitted`].
//! A second, locally-defined copy of these fields was tried and removed:
//! it duplicated the wire shape `mail4agent_api` already owns, which is
//! exactly the second code path the crate contract forbids -- a field
//! added to [`SendRequest`] would have silently never reached this door.
//!
//! One exception: `m4a_mail_send`'s `to` argument additionally accepts the
//! compact string form [`mail4agent_api::Address`]'s own `Display`/
//! `FromStr` produce (`"claude"`, `"claude/s-7f3a..."`, `"#room-1"`) in
//! place of the tagged JSON object, normalised to the tagged shape before
//! [`SendRequest`] ever sees it -- see [`normalize_address_argument`]. This
//! is convenience for a tool caller typing an address by hand; the tagged
//! object form still works exactly as before.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use mail4agent_api::{
    AckRequest, Address, InboxRequest, MailError, MessageGetRequest, SendRequest, SessionDeclared,
    INBOX_LIMIT_DEFAULT, INBOX_LIMIT_MAX, REFS_MAX,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::identity::PeerAddr;
use crate::routes::mail::{
    ack_impl, directory_impl, get_impl, inbox_impl, resolve_caller, send_impl, status_impl, whoami_impl,
};
use crate::service::{AuthenticatedParticipant, MailboxService};
use crate::state::AppState;

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
pub async fn handle_mcp_post(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: PeerAddr,
    body: Bytes,
) -> Response {
    let (participant, caller) = match resolve_caller(&app, &headers, peer).await {
        Ok(resolved) => resolved,
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
                if let Some(resp) = dispatch_one(&app.service, &participant, &caller, item).await {
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
        single => match dispatch_one(&app.service, &participant, &caller, single).await {
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
async fn dispatch_one(
    service: &MailboxService,
    participant: &AuthenticatedParticipant,
    caller: &Address,
    raw: Value,
) -> Option<RpcResponse> {
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
        "tools/call" => handle_tools_call(service, participant, caller, &req.params).await,
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
// tools/list -- seven tools, schemas kept next to the dispatch arm for the
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
            tool_mail_status(),
            tool_mail_peers(),
        ]
    })
}

/// Shared schema for [`mail4agent_api::Address`] -- internally tagged on
/// its own `kind` field, exactly as it serialises. `m4a_mail_send`'s `to`
/// argument additionally accepts the compact string form described in this
/// module's own doc comment; every other user of this schema (a `session`
/// address on a future tool, for instance) gets that same convenience for
/// free once it normalises the same way.
fn address_schema() -> Value {
    json!({
        "type": "object",
        "description": "Where the message goes. Internally tagged on its own \"kind\" field. A compact string is also accepted in its place: \"claude\" for an account, \"claude/s-7f3a...\" for one of its sessions, \"#room-1\" for a room.",
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
                "required": ["kind", "participant", "session"],
                "additionalProperties": false,
                "properties": {
                    "kind": { "const": "session" },
                    "participant": { "type": "string", "description": "The session's own account." },
                    "session": { "type": "string", "description": "Addresses exactly this one session, never its account or a sibling session." }
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
        "description": "Send a message to one participant (direct or session) or to every current member of a room. The sender is derived from the caller's own credential and cannot be set here -- there is no \"from\" field, so don't look for one.",
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
        "description": "The caller's own session address, its account's label, room memberships, and its own card (which parts are attested by the kernel, corroborated from its own command line, or declared by itself). Call this first, before m4a_mail_send, if the session does not already know where it can be answered.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }
    })
}

fn tool_mail_status() -> Value {
    json!({
        "name": "m4a_mail_status",
        "description": "Declare what this session is working on, its role, and which session spawned it. These are recorded as the SESSION'S OWN CLAIMS -- the mailbox does not verify any of them, unlike the attested pid/start-time/exe or the fields corroborated from the process's own command line. Call again to update; an omitted field is cleared, not left unchanged.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "working_on": { "type": ["string", "null"], "description": "A one-line description of what this session is doing right now." },
                "role": { "type": ["string", "null"], "description": "What kind of session this is, e.g. \"coordinator\" or \"worker\"." },
                "parent": { "type": ["string", "null"], "description": "The session id (e.g. \"s-7f3a...\") that spawned this one, if any -- said by this session about itself, not verified against the registry." }
            }
        }
    })
}

fn tool_mail_peers() -> Value {
    json!({
        "name": "m4a_mail_peers",
        "description": "List every account registered in the mailbox with its live sessions (each session's card, and whether it is currently live), and every room the mailbox tracks, with room membership reported relative to the caller.",
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

/// If `args[field]` is a JSON string, parses it as an
/// [`mail4agent_api::Address`] (its own `FromStr`: `"claude"`,
/// `"claude/s-7f3a..."`, `"#room-1"`) and replaces it with the tagged JSON
/// shape [`SendRequest`] actually deserialises. Leaves `args` untouched if
/// the field is absent or already an object -- the tagged form still works
/// exactly as it always has.
fn normalize_address_argument(args: &mut Value, field: &str) -> Result<(), (i64, String)> {
    let Some(object) = args.as_object_mut() else { return Ok(()) };
    let Some(Value::String(raw)) = object.get(field) else { return Ok(()) };
    let address: Address = raw
        .parse()
        .map_err(|err: MailError| (JSONRPC_INVALID_PARAMS, format!("{field}: {err}")))?;
    let encoded = serde_json::to_value(&address)
        .map_err(|err| (JSONRPC_INVALID_PARAMS, format!("{field}: failed to encode a parsed address: {err}")))?;
    object.insert(field.to_string(), encoded);
    Ok(())
}

async fn handle_tools_call(
    service: &MailboxService,
    participant: &AuthenticatedParticipant,
    caller: &Address,
    params: &Value,
) -> Result<Value, (i64, String)> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| (JSONRPC_INVALID_PARAMS, "tools/call missing string \"name\"".to_string()))?;
    let mut args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

    match name {
        "m4a_mail_send" => {
            normalize_address_argument(&mut args, "to")?;
            let req: SendRequest =
                serde_json::from_value(args).map_err(|e| (JSONRPC_INVALID_PARAMS, format!("m4a_mail_send: bad arguments: {e}")))?;
            Ok(tool_result(send_impl(service, caller.clone(), req).await))
        }
        "m4a_mail_inbox" => {
            let req: InboxRequest = serde_json::from_value(args)
                .map_err(|e| (JSONRPC_INVALID_PARAMS, format!("m4a_mail_inbox: bad arguments: {e}")))?;
            Ok(tool_result(inbox_impl(service, caller.clone(), req).await))
        }
        "m4a_mail_ack" => {
            let req: AckRequest =
                serde_json::from_value(args).map_err(|e| (JSONRPC_INVALID_PARAMS, format!("m4a_mail_ack: bad arguments: {e}")))?;
            Ok(tool_result(ack_impl(service, caller.clone(), req).await))
        }
        "m4a_mail_get" => {
            let req: MessageGetRequest =
                serde_json::from_value(args).map_err(|e| (JSONRPC_INVALID_PARAMS, format!("m4a_mail_get: bad arguments: {e}")))?;
            Ok(tool_result(get_impl(service, caller.clone(), req).await))
        }
        "m4a_mail_whoami" => Ok(tool_result(whoami_impl(service, participant.clone(), caller.clone()).await)),
        "m4a_mail_status" => {
            let req: SessionDeclared = serde_json::from_value(args)
                .map_err(|e| (JSONRPC_INVALID_PARAMS, format!("m4a_mail_status: bad arguments: {e}")))?;
            Ok(tool_result(status_impl(service, caller.clone(), req).await))
        }
        "m4a_mail_peers" => Ok(tool_result(directory_impl(service, caller.clone()).await)),
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
    use mail4agent_api::ParticipantId;
    use mail4agent_core::ParticipantPermissions;
    use mail4agent_store_stk::SqliteMailStore;

    /// Fresh in-memory mailbox with one registered participant ("alice",
    /// may_send + may_read, not an operator), and the caller already
    /// resolved to that account's session -- exactly what a real request
    /// arrives with after `routes::mail::resolve_caller` runs, minus the
    /// socket (see `crate::identity`'s own tests for why attestation itself
    /// needs one and cannot be faked into a handler path).
    async fn service_with_caller() -> (Arc<MailboxService>, AuthenticatedParticipant, Address) {
        let engine_store = SqliteMailStore::open_in_memory().expect("in-memory store opens and migrates");
        let reader_store = SqliteMailStore::new(engine_store.db());
        let service = Arc::new(MailboxService::new(engine_store, reader_store));

        let id = ParticipantId::new("alice").expect("valid participant id");
        let permissions = ParticipantPermissions { may_send: true, may_read: true, operator: false };
        service
            .register_participant(id.clone(), Some("alice".to_string()), permissions)
            .await
            .expect("register test participant");

        let participant = AuthenticatedParticipant { id: id.clone(), label: Some("alice".to_string()), operator: false };
        let peer_process = mail4agent_attest::PeerProcess {
            pid: 111,
            started_at_unix_ms: 222,
            exe: None,
            command_line: None,
            cwd: None,
        };
        let caller = crate::identity::ensure_session_from_peer_process(&service, id, &peer_process, 1_000)
            .await
            .expect("test session resolves");

        (service, participant, caller)
    }

    async fn dispatch(service: &Arc<MailboxService>, participant: &AuthenticatedParticipant, caller: &Address, body: Value) -> Value {
        let req: RpcRequest = serde_json::from_value(body).expect("test body is a valid RpcRequest shape");
        let id = req.id.clone().unwrap_or(Value::Null);
        let outcome = match req.method.as_str() {
            "initialize" => Ok(handle_initialize(&req.params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(tools_list()),
            "tools/call" => handle_tools_call(service, participant, caller, &req.params).await,
            other => Err((JSONRPC_METHOD_NOT_FOUND, format!("unknown method {other:?}"))),
        };
        match outcome {
            Ok(value) => json!({ "jsonrpc": "2.0", "id": id, "result": value }),
            Err((code, message)) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
        }
    }

    #[tokio::test]
    async fn single_request_returns_a_single_response() {
        let (service, participant, caller) = service_with_caller().await;
        let resp = dispatch(&service, &participant, &caller, json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })).await;
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"], json!({}));
    }

    #[tokio::test]
    async fn unknown_method_returns_method_not_found() {
        let (service, participant, caller) = service_with_caller().await;
        let resp = dispatch(&service, &participant, &caller, json!({ "jsonrpc": "2.0", "id": 1, "method": "bogus/method" })).await;
        assert_eq!(resp["error"]["code"], JSONRPC_METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn unknown_tool_name_returns_invalid_params() {
        let (service, participant, caller) = service_with_caller().await;
        let resp = dispatch(
            &service,
            &participant,
            &caller,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "bogus_tool", "arguments": {} } }),
        )
        .await;
        assert_eq!(resp["error"]["code"], JSONRPC_INVALID_PARAMS);
    }

    #[tokio::test]
    async fn initialize_echoes_a_supported_protocol_version() {
        let (service, participant, caller) = service_with_caller().await;
        let resp = dispatch(
            &service,
            &participant,
            &caller,
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
        let (service, participant, caller) = service_with_caller().await;
        let resp = dispatch(
            &service,
            &participant,
            &caller,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "1999-01-01" } }),
        )
        .await;
        assert_eq!(resp["result"]["protocolVersion"], DEFAULT_PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn tools_list_returns_seven_named_tools() {
        let (service, participant, caller) = service_with_caller().await;
        let resp = dispatch(&service, &participant, &caller, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" })).await;
        let tools = resp["result"]["tools"].as_array().expect("tools must be an array");
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().expect("name must be a string")).collect();
        assert_eq!(
            names,
            vec![
                "m4a_mail_send",
                "m4a_mail_inbox",
                "m4a_mail_ack",
                "m4a_mail_get",
                "m4a_mail_whoami",
                "m4a_mail_status",
                "m4a_mail_peers"
            ]
        );
        for tool in tools {
            assert_eq!(tool["inputSchema"]["type"], "object", "{} inputSchema must be type object", tool["name"]);
        }
    }

    #[tokio::test]
    async fn peers_tool_returns_the_same_content_as_directory_impl() {
        let (service, participant, caller) = service_with_caller().await;
        let _ = &participant;
        let via_direct = directory_impl(&service, caller.clone()).await.expect("directory_impl succeeds");

        let resp = dispatch(
            &service,
            &participant,
            &caller,
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "m4a_mail_peers", "arguments": {} }
            }),
        )
        .await;
        assert_eq!(resp["result"]["isError"], false);
        let via_mcp: mail4agent_api::Directory = serde_json::from_value(resp["result"]["structuredContent"].clone())
            .expect("structuredContent deserializes into Directory");

        assert_eq!(via_mcp, via_direct);
    }

    #[tokio::test]
    async fn a_business_refusal_comes_back_as_iserror_true_not_a_jsonrpc_error() {
        let (service, participant, caller) = service_with_caller().await;
        let resp = dispatch(
            &service,
            &participant,
            &caller,
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
        let (service, participant, caller) = service_with_caller().await;
        let send_resp = dispatch(
            &service,
            &participant,
            &caller,
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

        let inbox_resp = dispatch(
            &service,
            &participant,
            &caller,
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
        let (service, participant, caller) = service_with_caller().await;
        let send_resp = dispatch(
            &service,
            &participant,
            &caller,
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

        let inbox_resp = dispatch(
            &service,
            &participant,
            &caller,
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
    async fn send_accepts_a_compact_string_address_in_place_of_the_tagged_object() {
        let (service, participant, caller) = service_with_caller().await;
        let resp = dispatch(
            &service,
            &participant,
            &caller,
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "m4a_mail_send", "arguments": { "to": "alice", "subject": "hi", "body": "hi" } }
            }),
        )
        .await;
        assert_eq!(resp["result"]["isError"], false, "a compact string address must be accepted: {resp}");
    }

    #[tokio::test]
    async fn status_tool_declares_and_whoami_reflects_it() {
        let (service, participant, caller) = service_with_caller().await;
        let status_resp = dispatch(
            &service,
            &participant,
            &caller,
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {
                    "name": "m4a_mail_status",
                    "arguments": { "working_on": "wiring session identity", "role": "worker", "parent": null }
                }
            }),
        )
        .await;
        assert_eq!(status_resp["result"]["isError"], false, "{status_resp}");
        assert_eq!(status_resp["result"]["structuredContent"]["card"]["declared"]["working_on"], "wiring session identity");
        assert_eq!(status_resp["result"]["structuredContent"]["card"]["declared"]["role"], "worker");

        let whoami_resp = dispatch(
            &service,
            &participant,
            &caller,
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "m4a_mail_whoami", "arguments": {} } }),
        )
        .await;
        assert_eq!(whoami_resp["result"]["isError"], false);
        assert_eq!(whoami_resp["result"]["structuredContent"]["card"]["declared"]["working_on"], "wiring session identity");
    }

    #[tokio::test]
    async fn peers_tool_lists_the_caller_s_own_session_under_its_account() {
        let (service, participant, caller) = service_with_caller().await;
        let resp = dispatch(
            &service,
            &participant,
            &caller,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "m4a_mail_peers", "arguments": {} } }),
        )
        .await;
        let directory: mail4agent_api::Directory = serde_json::from_value(resp["result"]["structuredContent"].clone())
            .expect("structuredContent deserializes into Directory");
        let alice = directory
            .participants
            .iter()
            .find(|entry| entry.id.as_str() == "alice")
            .expect("alice is in the directory");
        assert_eq!(alice.sessions.len(), 1, "alice must show exactly the one session resolved for this test");
    }

    #[tokio::test]
    async fn delete_always_answers_204() {
        let resp = handle_mcp_delete().await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
}
