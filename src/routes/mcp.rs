//! `POST /mcp` / `DELETE /mcp` -- the MCP (Model Context Protocol) door onto
//! the SAME mail surface `/mail/*` serves, built on the shared
//! `mcp_service4agent::mcp` server (`nemo/docs/architecture/nemo-hq-scope-and-agent-surface.md`
//! §4 L5, §5) instead of hand-writing the JSON-RPC protocol here. Every tool
//! below still dispatches into the exact `*_impl` function its HTTP sibling
//! in `routes::mail` already calls -- never a second copy of the mailbox
//! logic (`mail4agent/CLAUDE.md`, "one implementation, two doors").
//!
//! # Caller resolution -- once per HTTP call, via a middleware seam
//!
//! `mcp_service4agent::mcp::McpServer` invokes a tool handler once per
//! `tools/call` item in a JSON-RPC batch, handing it only
//! [`mcp_service4agent::mcp::CallContext`] (headers plus an optional client
//! name) -- it has no notion of this crate's own session identity, which
//! needs the request's `ConnectInfo<SocketAddr>` (`crate::identity`). So
//! the caller is resolved exactly ONCE per `POST /mcp` HTTP call in
//! [`resolve_caller_middleware`], mounted as a `route_layer` INSIDE this
//! server's own router (see [`build`]'s caller in `main.rs`) -- the same
//! "resolved once, not once per batch item" property the previous
//! hand-written door documented. On success the resolved participant and
//! address are encoded (hex of a small JSON blob -- see
//! [`encode_resolved_caller`]) into an internal header every tool handler
//! reads back via [`resolved_caller_from_headers`], so there is no second
//! bearer lookup or a second attestation per batch item. On failure the
//! whole HTTP call is refused right there with the same
//! [`crate::error::ApiError`] response any other `/mail/*` handler would
//! answer -- never a JSON-RPC error, since nothing JSON-RPC-shaped has been
//! parsed yet at that point. `DELETE /mcp` is exempted: this server is
//! stateless, so a session end always answers 204 regardless of whether the
//! caller's session can still be resolved (see
//! [`mcp_service4agent::mcp`]'s own `handle_delete`).
//!
//! # Error shape -- the split that matters most
//!
//! A tool that could not be invoked at all (unknown tool name, arguments
//! that do not deserialise into that tool's own shape) is
//! [`mcp_service4agent::mcp::ToolOutcome::invalid_argument`], a JSON-RPC error
//! for an unknown tool name (handled by `mcp_service4agent::mcp` itself) or an
//! `isError: true` result naming the offending field for a malformed
//! argument. A tool that ran and refused -- `PermissionDenied`,
//! `UnknownParticipant`, `NotAddressedToYou`, any other named
//! [`mail4agent_api::MailError`] -- is a normal
//! [`mcp_service4agent::mcp::ToolOutcome::ok`]-shaped result carrying `isError:
//! true` and the refusal (serialised with its `kind` tag, compact) as
//! `content[0].text`. Getting this backwards makes every business refusal
//! look like a broken server.
//!
//! # Wire-type reuse
//!
//! Every tool's `arguments` deserialises straight into [`mail4agent_api`]'s
//! own request type for that call -- [`SendRequest`], [`InboxRequest`],
//! [`AckRequest`], [`MessageGetRequest`], [`mail4agent_api::SessionDeclared`]
//! -- with no local args struct in between, exactly as before. One
//! exception: `m4a_mail_send`'s `to` argument additionally accepts the
//! compact string form [`mail4agent_api::Address`]'s own `Display`/
//! `FromStr` produce (`"claude"`, `"claude/s-7f3a..."`, `"#room-1"`) in
//! place of the tagged JSON object, normalised to the tagged shape before
//! [`SendRequest`] ever sees it -- see [`normalize_address_argument`].

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use mail4agent_api::{
    AckRequest, Address, InboxRequest, MailError, MessageGetRequest, SendRequest, SessionDeclared,
    INBOX_LIMIT_DEFAULT, INBOX_LIMIT_MAX, INBOX_WAIT_SECS_MAX, REFS_MAX,
};
use mcp_service4agent::mcp::{CallContext, McpServer, Tool, ToolOutcome};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::identity::PeerAddr;
use crate::routes::mail::{
    ack_impl, directory_impl, get_impl, inbox_impl, resolve_caller, send_impl, status_impl, whoami_impl,
};
use crate::service::AuthenticatedParticipant;
use crate::state::AppState;

const SERVER_NAME: &str = "mail4agent";

// ---------------------------------------------------------------------------
// Caller resolution seam -- see this module's own doc comment.
// ---------------------------------------------------------------------------

/// Carries the caller [`resolve_caller_middleware`] already resolved, hex of
/// a compact JSON blob (never a raw header, since a label may contain bytes
/// `axum::http::HeaderValue` refuses -- hex is ASCII-only by construction).
const CALLER_HEADER: &str = "x-mail4agent-mcp-caller";

#[derive(Serialize, Deserialize)]
struct ResolvedCallerWire {
    /// [`Address::Display`]'s own compact form -- round-trips through
    /// [`Address::FromStr`] exactly.
    address: String,
    label: Option<String>,
    operator: bool,
}

fn encode_resolved_caller(participant: &AuthenticatedParticipant, caller: &Address) -> String {
    let wire = ResolvedCallerWire { address: caller.to_string(), label: participant.label.clone(), operator: participant.operator };
    let bytes = serde_json::to_vec(&wire).unwrap_or_default();
    hex::encode(bytes)
}

/// Reads back what [`resolve_caller_middleware`] resolved for this HTTP
/// call. Fails only if the middleware did not run (a wiring mistake, not a
/// caller-triggerable condition) -- named so that mistake is legible in a
/// tool result rather than silently mis-attributing the call.
fn resolved_caller_from_headers(headers: &HeaderMap) -> Result<(AuthenticatedParticipant, Address), ToolOutcome> {
    let raw = headers
        .get(CALLER_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ToolOutcome::error("internal: caller was not resolved before this tool ran"))?;
    let bytes = hex::decode(raw).map_err(|_| ToolOutcome::error("internal: malformed resolved-caller header"))?;
    let wire: ResolvedCallerWire =
        serde_json::from_slice(&bytes).map_err(|_| ToolOutcome::error("internal: malformed resolved-caller payload"))?;
    let address: Address = wire.address.parse().map_err(|_| ToolOutcome::error("internal: malformed resolved-caller address"))?;
    let id = address
        .account()
        .cloned()
        .ok_or_else(|| ToolOutcome::error("internal: resolved caller address names no account"))?;
    Ok((AuthenticatedParticipant { id, label: wire.label, operator: wire.operator }, address))
}

/// `route_layer` mounted on this server's own router (see `main.rs`'s call
/// to [`build`]) -- resolves the caller once per HTTP call and hands the
/// result to every tool handler via [`CALLER_HEADER`]. See this module's
/// own doc comment, "Caller resolution".
pub(crate) async fn resolve_caller_middleware(State(app): State<Arc<AppState>>, peer: PeerAddr, mut req: Request, next: Next) -> Response {
    if req.method() == Method::DELETE {
        return next.run(req).await;
    }
    let (participant, caller) = match resolve_caller(&app, req.headers(), peer).await {
        Ok(resolved) => resolved,
        Err(err) => return err.into_response(),
    };
    let encoded = encode_resolved_caller(&participant, &caller);
    let value = HeaderValue::from_str(&encoded).expect("hex::encode output is ASCII hex digits only, always a valid HeaderValue");
    req.headers_mut().insert(CALLER_HEADER, value);
    next.run(req).await
}

// ---------------------------------------------------------------------------
// Tool result helpers
// ---------------------------------------------------------------------------

/// Renders a `*_impl` outcome as a [`ToolOutcome`]: `Ok` is
/// [`ToolOutcome::ok`] (compact JSON); `Err` -- a named [`MailError`] the
/// tool ran and refused with -- is STILL [`ToolOutcome::ok`]-shaped
/// (`isError: true`, not a JSON-RPC error), carrying the refusal serialised
/// with its `kind` tag. See this module's own doc, "Error shape".
fn tool_result<T: Serialize>(outcome: Result<T, MailError>) -> ToolOutcome {
    match outcome {
        Ok(value) => match serde_json::to_value(&value) {
            Ok(v) => ToolOutcome::ok(v),
            Err(_) => ToolOutcome::error("failed to serialize tool result"),
        },
        Err(err) => {
            let text = serde_json::to_string(&err).unwrap_or_else(|_| err.to_string());
            ToolOutcome::error(text)
        }
    }
}

/// If `args[field]` is a JSON string, parses it as an
/// [`mail4agent_api::Address`] (its own `FromStr`: `"claude"`,
/// `"claude/s-7f3a..."`, `"#room-1"`) and replaces it with the tagged JSON
/// shape [`SendRequest`] actually deserialises. Leaves `args` untouched if
/// the field is absent or already an object.
fn normalize_address_argument(args: &mut Value, field: &str) -> Result<(), ToolOutcome> {
    let Some(object) = args.as_object_mut() else { return Ok(()) };
    let Some(Value::String(raw)) = object.get(field) else { return Ok(()) };
    let address: Address = raw.parse().map_err(|err: MailError| ToolOutcome::invalid_argument(field, err))?;
    let encoded = serde_json::to_value(&address)
        .map_err(|err| ToolOutcome::invalid_argument(field, format!("failed to encode a parsed address: {err}")))?;
    object.insert(field.to_string(), encoded);
    Ok(())
}

// ---------------------------------------------------------------------------
// Schemas -- trimmed to fit `mcp_service4agent::mcp::Budget::WORKSPACE` (no tool
// over 1.5 KB, total tools/list at most 8 KB). Per-argument prose rules a
// schema cannot express are enforced as named refusals in the dispatch
// closures below instead of spelled out here -- an agent learns them on the
// one call that needs it, not on every session (L5).
// ---------------------------------------------------------------------------

fn address_schema() -> Value {
    json!({
        "type": "object",
        "description": "Tagged object, or a compact string: \"name\", \"name/session\", \"#room\".",
        "oneOf": [
            {"type": "object", "required": ["kind", "participant"], "additionalProperties": false,
             "properties": {"kind": {"const": "direct"}, "participant": {"type": "string"}}},
            {"type": "object", "required": ["kind", "participant", "session"], "additionalProperties": false,
             "properties": {"kind": {"const": "session"}, "participant": {"type": "string"}, "session": {"type": "string"}}},
            {"type": "object", "required": ["kind", "room"], "additionalProperties": false,
             "properties": {"kind": {"const": "room"}, "room": {"type": "string"}}}
        ]
    })
}

fn message_ref_schema() -> Value {
    json!({
        "type": "object",
        "required": ["kind", "locator"],
        "additionalProperties": false,
        "properties": {
            "kind": {"type": "string"},
            "locator": {"type": "string", "description": "Opaque; stored and returned verbatim."},
            "digest": {"type": ["string", "null"]}
        }
    })
}

fn tool_mail_send() -> Tool {
    Tool::new(
        "m4a_mail_send",
        "Send a message to a participant or a room. The sender is the caller's own credential; there is no \"from\" field.",
        json!({
            "type": "object",
            "required": ["to", "subject", "body"],
            "additionalProperties": false,
            "properties": {
                "to": address_schema(),
                "subject": {"type": "string"},
                "body": {"type": "string"},
                "reply_to": {"type": ["string", "null"]},
                "correlation": {"type": ["string", "null"]},
                "refs": {"type": "array", "maxItems": REFS_MAX, "items": message_ref_schema()},
                "idempotency_key": {"type": ["string", "null"], "description": "A repeat returns the original send."}
            }
        }),
    )
}

fn tool_mail_inbox() -> Tool {
    Tool::new(
        "m4a_mail_inbox",
        "Page the caller's own inbox: direct mail plus any room it belongs to.",
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "since_unix_ms": {"type": ["integer", "null"], "minimum": 0},
                "limit": {"type": ["integer", "null"], "minimum": 1, "maximum": INBOX_LIMIT_MAX, "description": format!("Default {INBOX_LIMIT_DEFAULT}.")},
                "wait_secs": {"type": ["integer", "null"], "minimum": 0, "maximum": INBOX_WAIT_SECS_MAX,
                    "description": "Long-polls up to this many seconds when the page would otherwise be empty. Pair with since_unix_ms set to the newest message already seen, or an inbox with history answers at once."}
            }
        }),
    )
}

fn tool_mail_ack() -> Tool {
    Tool::new(
        "m4a_mail_ack",
        "Mark one message read by id. Repeating it only updates the timestamp.",
        json!({"type": "object", "required": ["message_id"], "additionalProperties": false, "properties": {"message_id": {"type": "string"}}}),
    )
}

fn tool_mail_get() -> Tool {
    Tool::new(
        "m4a_mail_get",
        "Fetch one message by id. Refuses (not_addressed_to_you) if it exists but was never sent to the caller.",
        json!({"type": "object", "required": ["message_id"], "additionalProperties": false, "properties": {"message_id": {"type": "string"}}}),
    )
}

fn tool_mail_whoami() -> Tool {
    Tool::new(
        "m4a_mail_whoami",
        "The caller's own session address, account label, room memberships and session card. Call first if the session does not know its own address.",
        json!({"type": "object", "additionalProperties": false, "properties": {}}),
    )
}

fn tool_mail_status() -> Tool {
    Tool::new(
        "m4a_mail_status",
        "Declare what this session is working on, its role, and which session spawned it -- the session's own unverified claim. An omitted field is cleared, not left unchanged.",
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "working_on": {"type": ["string", "null"]},
                "role": {"type": ["string", "null"]},
                "parent": {"type": ["string", "null"], "description": "A session id this one says spawned it."}
            }
        }),
    )
}

fn tool_mail_peers() -> Tool {
    Tool::new(
        "m4a_mail_peers",
        "Every registered account with its live sessions, and every room with membership reported relative to the caller.",
        json!({"type": "object", "additionalProperties": false, "properties": {}}),
    )
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Builds the seven-tool MCP server. `main.rs` calls [`McpServer::route_docs`]
/// (borrows) before [`McpServer::into_router`] (consumes), then mounts
/// [`resolve_caller_middleware`] on the returned router -- see this module's
/// own doc comment.
pub fn build() -> McpServer<Arc<AppState>> {
    McpServer::<Arc<AppState>>::new(SERVER_NAME, env!("CARGO_PKG_VERSION"))
        .tool(tool_mail_send(), |state: Arc<AppState>, ctx: CallContext, mut args: Value| async move {
            let (_participant, caller) = match resolved_caller_from_headers(&ctx.headers) {
                Ok(v) => v,
                Err(out) => return out,
            };
            if let Err(out) = normalize_address_argument(&mut args, "to") {
                return out;
            }
            let request: SendRequest = match serde_json::from_value(args) {
                Ok(r) => r,
                Err(e) => return ToolOutcome::invalid_argument("arguments", e),
            };
            tool_result(send_impl(&state.service, caller, request).await)
        })
        .tool(tool_mail_inbox(), |state: Arc<AppState>, ctx: CallContext, args: Value| async move {
            let (_participant, caller) = match resolved_caller_from_headers(&ctx.headers) {
                Ok(v) => v,
                Err(out) => return out,
            };
            let request: InboxRequest = match serde_json::from_value(args) {
                Ok(r) => r,
                Err(e) => return ToolOutcome::invalid_argument("arguments", e),
            };
            tool_result(inbox_impl(&state.service, caller, request).await)
        })
        .tool(tool_mail_ack(), |state: Arc<AppState>, ctx: CallContext, args: Value| async move {
            let (_participant, caller) = match resolved_caller_from_headers(&ctx.headers) {
                Ok(v) => v,
                Err(out) => return out,
            };
            let request: AckRequest = match serde_json::from_value(args) {
                Ok(r) => r,
                Err(e) => return ToolOutcome::invalid_argument("arguments", e),
            };
            tool_result(ack_impl(&state.service, caller, request).await)
        })
        .tool(tool_mail_get(), |state: Arc<AppState>, ctx: CallContext, args: Value| async move {
            let (_participant, caller) = match resolved_caller_from_headers(&ctx.headers) {
                Ok(v) => v,
                Err(out) => return out,
            };
            let request: MessageGetRequest = match serde_json::from_value(args) {
                Ok(r) => r,
                Err(e) => return ToolOutcome::invalid_argument("arguments", e),
            };
            tool_result(get_impl(&state.service, caller, request).await)
        })
        .tool(tool_mail_whoami(), |state: Arc<AppState>, ctx: CallContext, _args: Value| async move {
            let (participant, caller) = match resolved_caller_from_headers(&ctx.headers) {
                Ok(v) => v,
                Err(out) => return out,
            };
            tool_result(whoami_impl(&state.service, participant, caller).await)
        })
        .tool(tool_mail_status(), |state: Arc<AppState>, ctx: CallContext, args: Value| async move {
            let (_participant, caller) = match resolved_caller_from_headers(&ctx.headers) {
                Ok(v) => v,
                Err(out) => return out,
            };
            let request: SessionDeclared = match serde_json::from_value(args) {
                Ok(r) => r,
                Err(e) => return ToolOutcome::invalid_argument("arguments", e),
            };
            tool_result(status_impl(&state.service, caller, request).await)
        })
        .tool(tool_mail_peers(), |state: Arc<AppState>, ctx: CallContext, _args: Value| async move {
            let (_participant, caller) = match resolved_caller_from_headers(&ctx.headers) {
                Ok(v) => v,
                Err(out) => return out,
            };
            tool_result(directory_impl(&state.service, caller).await)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::header::AUTHORIZATION;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::middleware;
    use axum::Router;
    use mail4agent_api::ParticipantId;
    use mail4agent_attest::PeerProcess;
    use mail4agent_core::ParticipantPermissions;
    use mail4agent_store_sqlite::SqliteMailStore;
    use mcp_service4agent::mcp::Budget;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    use crate::identity::ensure_session_from_peer_process;
    use crate::service::MailboxService;

    /// L5's own gate: at most 8 tools, `tools/list` at most 8 KB, no tool
    /// over 1.5 KB.
    #[test]
    fn seven_tools_within_the_workspace_mcp_budget() {
        let server = build();
        if let Err(report) = server.check_budget(Budget::WORKSPACE) {
            panic!("workspace MCP budget exceeded:\n{report}");
        }
    }

    #[test]
    fn tools_list_names_the_seven_tools_in_order() {
        let server = build();
        let tools = server.tools_list_json();
        let names: Vec<&str> = tools["tools"]
            .as_array()
            .expect("tools is an array")
            .iter()
            .map(|t| t["name"].as_str().expect("name is a string"))
            .collect();
        assert_eq!(
            names,
            vec![
                "m4a_mail_send",
                "m4a_mail_inbox",
                "m4a_mail_ack",
                "m4a_mail_get",
                "m4a_mail_whoami",
                "m4a_mail_status",
                "m4a_mail_peers",
            ]
        );
    }

    /// A fresh in-memory mailbox with one registered participant ("alice"),
    /// a real bearer secret for [`test_app_with_middleware`], plus a
    /// resolved caller header ready for [`test_app`] to hand straight to a
    /// tool. Session resolution over a real socket
    /// (`mail4agent_attest::attest`) needs a live OS connection this test
    /// harness never opens -- see `crate::identity`'s own tests for why
    /// that half is exercised there, against a `PeerProcess` directly,
    /// never here.
    async fn service_with_caller() -> (Arc<MailboxService>, String, String) {
        let engine_store = SqliteMailStore::open_in_memory().expect("in-memory store opens and migrates");
        let reader_store = SqliteMailStore::new(engine_store.db());
        let service = Arc::new(MailboxService::new(engine_store, reader_store));

        let id = ParticipantId::new("alice").expect("valid participant id");
        let permissions = ParticipantPermissions { may_send: true, may_read: true, operator: false };
        let secret = service
            .register_participant(id.clone(), Some("alice".to_string()), permissions)
            .await
            .expect("register test participant");

        let peer_process = PeerProcess { pid: 111, started_at_unix_ms: 222, exe: None, command_line: None, cwd: None };
        let address = ensure_session_from_peer_process(&service, id.clone(), &peer_process, 1_000)
            .await
            .expect("test session resolves");
        let participant = AuthenticatedParticipant { id, label: Some("alice".to_string()), operator: false };
        let caller_header = encode_resolved_caller(&participant, &address);

        (service, secret, caller_header)
    }

    /// The router this module's own tool-dispatch tests drive: [`build`]'s
    /// server alone, no [`resolve_caller_middleware`] -- the caller header
    /// is set directly on each request from [`service_with_caller`]'s
    /// already-resolved caller, the same boundary the mailbox's own
    /// `*_impl` functions are tested at everywhere else in this crate.
    /// Real HTTP-level caller resolution (bearer, attestation, tier gating)
    /// is [`test_app_with_middleware`]'s job below.
    async fn test_app() -> (Router<()>, String) {
        let (service, _secret, caller_header) = service_with_caller().await;
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("valid socket address literal");
        let app = Arc::new(AppState { service, bind_addr });
        (build().into_router().with_state(app), caller_header)
    }

    /// The full router INCLUDING [`resolve_caller_middleware`], for the two
    /// tests that exercise that seam itself rather than tool dispatch.
    async fn test_app_with_middleware() -> (Router<()>, String) {
        let (service, secret, _caller_header) = service_with_caller().await;
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("valid socket address literal");
        let app = Arc::new(AppState { service, bind_addr });
        let router = build()
            .into_router()
            .route_layer(middleware::from_fn_with_state(app.clone(), resolve_caller_middleware))
            .with_state(app);
        (router, secret)
    }

    async fn call(router: Router<()>, caller_header: &str, body: Value) -> (StatusCode, Value) {
        let req = HttpRequest::post("/mcp")
            .header(CALLER_HEADER, caller_header)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("test body serialises")))
            .expect("build request");
        let resp = router.oneshot(req).await.expect("router call is infallible");
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("read response body");
        let value = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).expect("response body is JSON") };
        (status, value)
    }

    fn tool_text(resp: &Value) -> Value {
        let text = resp["result"]["content"][0]["text"].as_str().expect("content[0].text is a string");
        serde_json::from_str(text).expect("tool text is compact JSON")
    }

    #[tokio::test]
    async fn an_unauthenticated_call_is_refused_before_json_rpc_is_parsed() {
        let (router, _secret) = test_app_with_middleware().await;
        let req = HttpRequest::post("/mcp")
            .header(AUTHORIZATION, "Bearer not-a-real-token")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})).expect("serialise")))
            .expect("build request");
        let resp = router.oneshot(req).await.expect("router call is infallible");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn tools_list_is_reachable_through_the_real_router() {
        let (router, caller_header) = test_app().await;
        let (status, resp) = call(router, &caller_header, json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["result"]["tools"].as_array().expect("tools is an array").len(), 7);
    }

    #[tokio::test]
    async fn send_then_inbox_round_trips_through_the_same_impl_as_http() {
        let (router, caller_header) = test_app().await;
        let (send_status, send_resp) = call(
            router.clone(),
            &caller_header,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "m4a_mail_send", "arguments": {"to": {"kind": "direct", "participant": "alice"}, "subject": "hi", "body": "hi"}
            }}),
        )
        .await;
        assert_eq!(send_status, StatusCode::OK);
        assert_eq!(send_resp["result"]["isError"], false, "{send_resp}");
        let message_id = tool_text(&send_resp)["message_id"].as_str().expect("send result carries a message_id").to_string();

        let (inbox_status, inbox_resp) = call(
            router,
            &caller_header,
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "m4a_mail_inbox", "arguments": {}}}),
        )
        .await;
        assert_eq!(inbox_status, StatusCode::OK);
        assert_eq!(inbox_resp["result"]["isError"], false, "{inbox_resp}");
        let messages = tool_text(&inbox_resp)["messages"].as_array().expect("messages array").clone();
        assert!(messages.iter().any(|m| m["message_id"] == message_id));
    }

    #[tokio::test]
    async fn send_accepts_a_compact_string_address_in_place_of_the_tagged_object() {
        let (router, caller_header) = test_app().await;
        let (status, resp) = call(
            router,
            &caller_header,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "m4a_mail_send", "arguments": {"to": "alice", "subject": "hi", "body": "hi"}
            }}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["result"]["isError"], false, "a compact string address must be accepted: {resp}");
    }

    #[tokio::test]
    async fn a_business_refusal_comes_back_as_iserror_true_not_a_jsonrpc_error() {
        let (router, caller_header) = test_app().await;
        let (status, resp) = call(
            router,
            &caller_header,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "m4a_mail_get", "arguments": {"message_id": "m4a_000000000000000000000000"}
            }}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(resp.get("error").is_none(), "a business refusal must not be a JSON-RPC error: {resp}");
        assert_eq!(resp["result"]["isError"], true);
        assert_eq!(tool_text(&resp)["kind"], "unknown_message");
    }

    #[tokio::test]
    async fn whoami_reflects_the_resolved_caller() {
        let (router, caller_header) = test_app().await;
        let (status, resp) = call(
            router,
            &caller_header,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "m4a_mail_whoami", "arguments": {}}}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["result"]["isError"], false, "{resp}");
        assert_eq!(tool_text(&resp)["label"], "alice");
    }

    #[tokio::test]
    async fn status_tool_declares_and_whoami_reflects_it() {
        let (router, caller_header) = test_app().await;
        let (status_code, status_resp) = call(
            router.clone(),
            &caller_header,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "m4a_mail_status", "arguments": {"working_on": "wiring session identity", "role": "worker", "parent": null}
            }}),
        )
        .await;
        assert_eq!(status_code, StatusCode::OK);
        assert_eq!(status_resp["result"]["isError"], false, "{status_resp}");
        assert_eq!(tool_text(&status_resp)["card"]["declared"]["working_on"], "wiring session identity");

        let (whoami_code, whoami_resp) = call(
            router,
            &caller_header,
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "m4a_mail_whoami", "arguments": {}}}),
        )
        .await;
        assert_eq!(whoami_code, StatusCode::OK);
        assert_eq!(tool_text(&whoami_resp)["card"]["declared"]["working_on"], "wiring session identity");
    }

    #[tokio::test]
    async fn peers_tool_lists_the_caller_s_own_session_under_its_account() {
        let (router, caller_header) = test_app().await;
        let (status, resp) = call(
            router,
            &caller_header,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "m4a_mail_peers", "arguments": {}}}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let body = tool_text(&resp);
        let participants = body["participants"].as_array().expect("participants array");
        let alice = participants.iter().find(|p| p["id"] == "alice").expect("alice is in the directory");
        assert_eq!(alice["sessions"].as_array().expect("sessions array").len(), 1);
    }

    #[tokio::test]
    async fn delete_always_answers_204_even_without_a_resolvable_session() {
        let (router, _secret) = test_app_with_middleware().await;
        // No `ConnectInfo` extension inserted at all: session resolution
        // would fail outright if `resolve_caller_middleware` ran on
        // DELETE -- this is exactly the case it must skip.
        let req = HttpRequest::delete("/mcp").body(Body::empty()).expect("build request");
        let resp = router.oneshot(req).await.expect("router call is infallible");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
}
