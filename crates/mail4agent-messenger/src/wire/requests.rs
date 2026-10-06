//! [`OutgoingRequest`] / [`HttpResponseDescriptor`] — the data shapes that
//! cross the network boundary, plus one builder per Matrix Client-Server
//! API endpoint this crate needs. Every builder's path template lives as a
//! single `PATH_TEMPLATE` constant scoped to that builder's own function
//! body — greppable (`grep -n PATH_TEMPLATE`), one hit per endpoint, never
//! inlined again at a call site (plan §6.8's note, generalized to every
//! endpoint rather than just the two it called out).

use crate::ids::{EventId, RequestId, RoomId, TxnId, UserId};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Percent-encodes one path segment. Conservative on purpose: only RFC
/// 3986's `unreserved` set (`ALPHA / DIGIT / "-" / "." / "_" / "~"`) is
/// left unescaped; everything else — including Matrix's own sigils (`!`,
/// `$`, `:`, `@`), which RFC 3986's `pchar` grammar would technically
/// permit unescaped in a path segment — is escaped. This removes any
/// ambiguity between "path delimiter" and "literal sigil character" for a
/// router that naively splits on `/`, `:`, or `!`, exactly the ids this
/// crate mints into paths.
pub(crate) fn percent_encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{byte:02X}"));
            }
        }
    }
    out
}

/// Reverses [`percent_encode_segment`]: decodes `%XX` escapes back to their
/// original byte values and interprets the result as UTF-8. Returns `None`
/// for a malformed escape (an incomplete or non-hex `%` sequence) or a
/// decoded byte sequence that is not valid UTF-8. Used by
/// [`crate::store`]'s record-key parser to recover the dynamic components
/// (room/user/session/request ids) this module's builders percent-encode
/// into a storage key.
pub(crate) fn percent_decode_segment(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = segment.get(i + 1..i + 3)?;
                let byte = u8::from_str_radix(hex, 16).ok()?;
                out.push(byte);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Substitutes every `{placeholder}` token in `template` with the
/// percent-encoded form of its paired value.
fn substitute(template: &str, params: &[(&str, &str)]) -> String {
    let mut path = template.to_string();
    for (placeholder, value) in params {
        path = path.replace(placeholder, &percent_encode_segment(value));
    }
    path
}

/// HTTP method for an [`OutgoingRequest`]. The Matrix Client-Server API
/// only ever uses these three verbs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
}

impl HttpMethod {
    /// The method's own uppercase wire form (`"GET"`, `"POST"`, `"PUT"`).
    pub fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What kind of Matrix Client-Server API call an [`OutgoingRequest`] is —
/// a plain tag the core uses to know how to interpret the matching
/// [`HttpResponseDescriptor`] (e.g. "this one's body is a `SyncResponse`").
/// The actual path/query/body are already baked into the `OutgoingRequest`
/// itself; this enum carries no duplicate parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OutgoingRequestKind {
    /// `GET /sync` — long-poll for new events, device-list changes, and
    /// one-time-key counts.
    Sync,
    /// `POST /keys/upload` — publish device identity keys and one-time
    /// keys.
    KeysUpload,
    /// `POST /keys/query` — fetch other users' device keys.
    KeysQuery,
    /// `POST /keys/claim` — claim one-time keys to start new Olm sessions.
    KeysClaim,
    /// `GET /keys/changes` — list users whose device lists changed in a
    /// sync range.
    KeysChanges,
    /// `PUT /sendToDevice/{eventType}/{txnId}` — send one or more
    /// to-device events.
    SendToDevice,
    /// `POST /keys/device_signing/upload` — publish cross-signing keys.
    SigningKeysUpload,
    /// `POST /keys/signatures/upload` — publish cross-signing signatures.
    SignaturesUpload,
    /// `PUT /rooms/{roomId}/send/{eventType}/{txnId}` — send a timeline
    /// event.
    RoomSend,
    /// `PUT /rooms/{roomId}/redact/{eventId}/{txnId}` — redact an event.
    RoomRedact,
    /// `PUT /rooms/{roomId}/state/{eventType}/{stateKey}` — set one piece
    /// of room state.
    RoomState,
    /// `GET /rooms/{roomId}/messages` — paginate a room's timeline.
    RoomMessages,
    /// `GET /rooms/{roomId}/members` — list a room's members.
    RoomMembers,
    /// `POST /createRoom` — create a room.
    CreateRoom,
    /// `POST /rooms/{roomId}/join` — join a room by id.
    JoinRoom,
    /// `POST /rooms/{roomId}/leave` — leave a room.
    LeaveRoom,
    /// `POST /rooms/{roomId}/invite` — invite a user to a room.
    Invite,
    /// `POST /rooms/{roomId}/kick` — remove a user from a room.
    Kick,
    /// `PUT /rooms/{roomId}/typing/{userId}` — set/clear a typing
    /// indicator.
    Typing,
    /// `POST /rooms/{roomId}/receipt/{receiptType}/{eventId}` — send a
    /// read receipt.
    Receipt,
    /// `POST /rooms/{roomId}/read_markers` — set the fully-read marker.
    ReadMarkers,
    /// `PUT /user/{userId}/account_data/{type}` — set global account data.
    AccountData,
    /// `PUT /user/{userId}/rooms/{roomId}/account_data/{type}` — set
    /// room-scoped account data.
    RoomAccountData,
    /// `GET /profile/{userId}` — fetch a user's profile.
    Profile,
    /// `POST /user_directory/search` — search the user directory.
    UserDirectorySearch,
    /// `POST /publicRooms` — search the public-room directory.
    PublicRooms,
    /// `GET /room_keys/version` — fetch the current key backup version.
    BackupVersion,
    /// `GET /room_keys/keys/{roomId}/{sessionId}` — fetch one backed-up
    /// Megolm session.
    BackupKeys,
}

/// One HTTP call the core wants a shell to perform. The core never
/// performs the call itself — see the crate doc's "Contract" section.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OutgoingRequest {
    /// This crate's own correlation id — the shell passes it back
    /// unchanged to [`crate::MessengerError`]-surfacing calls (a later
    /// piece) alongside the response.
    pub id: RequestId,
    /// The HTTP method to use.
    pub method: HttpMethod,
    /// The request path, already percent-encoded and rooted at
    /// `/_matrix/client/v3/...` — ready to append to a homeserver base URL
    /// verbatim.
    pub path: String,
    /// Query-string parameters as `(name, value)` pairs, not yet
    /// percent-encoded (a shell's own HTTP client is expected to encode
    /// query parameters itself, the same way it encodes any other query
    /// string it builds).
    pub query: Vec<(String, String)>,
    /// The JSON request body, if this call has one.
    pub body: Option<serde_json::Value>,
    /// What kind of call this is.
    pub kind: OutgoingRequestKind,
}

/// The inline `/sync` filter every sync request carries: `room.include_leave`,
/// so a room this account left (or was kicked or banned from) arrives in
/// `rooms.leave` -- the server sends that section only when asked.
const SYNC_FILTER: &str = r#"{"room":{"include_leave":true}}"#;

impl OutgoingRequest {
    /// `GET /_matrix/client/v3/sync`. Always carries [`SYNC_FILTER`]: the
    /// server reports a room this account left, or was kicked or banned from,
    /// in `rooms.leave` only when the filter asks for it.
    pub fn sync(id: RequestId, since: Option<&str>, timeout_ms: Option<u64>) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/sync";
        let mut query = vec![("filter".to_string(), SYNC_FILTER.to_string())];
        if let Some(since) = since {
            query.push(("since".to_string(), since.to_string()));
        }
        if let Some(timeout_ms) = timeout_ms {
            query.push(("timeout".to_string(), timeout_ms.to_string()));
        }
        Self {
            id,
            method: HttpMethod::Get,
            path: PATH_TEMPLATE.to_string(),
            query,
            body: None,
            kind: OutgoingRequestKind::Sync,
        }
    }

    /// `POST /_matrix/client/v3/keys/upload`.
    pub fn keys_upload(id: RequestId, body: serde_json::Value) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/keys/upload";
        Self {
            id,
            method: HttpMethod::Post,
            path: PATH_TEMPLATE.to_string(),
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::KeysUpload,
        }
    }

    /// `POST /_matrix/client/v3/keys/query`.
    pub fn keys_query(id: RequestId, body: serde_json::Value) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/keys/query";
        Self {
            id,
            method: HttpMethod::Post,
            path: PATH_TEMPLATE.to_string(),
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::KeysQuery,
        }
    }

    /// `POST /_matrix/client/v3/keys/claim`.
    pub fn keys_claim(id: RequestId, body: serde_json::Value) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/keys/claim";
        Self {
            id,
            method: HttpMethod::Post,
            path: PATH_TEMPLATE.to_string(),
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::KeysClaim,
        }
    }

    /// `GET /_matrix/client/v3/keys/changes`.
    pub fn keys_changes(id: RequestId, from: &str, to: &str) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/keys/changes";
        Self {
            id,
            method: HttpMethod::Get,
            path: PATH_TEMPLATE.to_string(),
            query: vec![("from".to_string(), from.to_string()), ("to".to_string(), to.to_string())],
            body: None,
            kind: OutgoingRequestKind::KeysChanges,
        }
    }

    /// `PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}`.
    pub fn send_to_device(
        id: RequestId,
        event_type: &str,
        txn_id: &TxnId,
        body: serde_json::Value,
    ) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/sendToDevice/{event_type}/{txn_id}";
        let path = substitute(
            PATH_TEMPLATE,
            &[("{event_type}", event_type), ("{txn_id}", txn_id.as_str())],
        );
        Self {
            id,
            method: HttpMethod::Put,
            path,
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::SendToDevice,
        }
    }

    /// `POST /_matrix/client/v3/keys/device_signing/upload`.
    pub fn signing_keys_upload(id: RequestId, body: serde_json::Value) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/keys/device_signing/upload";
        Self {
            id,
            method: HttpMethod::Post,
            path: PATH_TEMPLATE.to_string(),
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::SigningKeysUpload,
        }
    }

    /// `POST /_matrix/client/v3/keys/signatures/upload`.
    pub fn signatures_upload(id: RequestId, body: serde_json::Value) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/keys/signatures/upload";
        Self {
            id,
            method: HttpMethod::Post,
            path: PATH_TEMPLATE.to_string(),
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::SignaturesUpload,
        }
    }

    /// `PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}`.
    pub fn room_send(
        id: RequestId,
        room_id: &RoomId,
        event_type: &str,
        txn_id: &TxnId,
        body: serde_json::Value,
    ) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}";
        let path = substitute(
            PATH_TEMPLATE,
            &[
                ("{room_id}", room_id.as_str()),
                ("{event_type}", event_type),
                ("{txn_id}", txn_id.as_str()),
            ],
        );
        Self {
            id,
            method: HttpMethod::Put,
            path,
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::RoomSend,
        }
    }

    /// `PUT /_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}`.
    pub fn room_redact(
        id: RequestId,
        room_id: &RoomId,
        event_id: &EventId,
        txn_id: &TxnId,
        body: serde_json::Value,
    ) -> Self {
        const PATH_TEMPLATE: &str =
            "/_matrix/client/v3/rooms/{room_id}/redact/{event_id}/{txn_id}";
        let path = substitute(
            PATH_TEMPLATE,
            &[
                ("{room_id}", room_id.as_str()),
                ("{event_id}", event_id.as_str()),
                ("{txn_id}", txn_id.as_str()),
            ],
        );
        Self {
            id,
            method: HttpMethod::Put,
            path,
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::RoomRedact,
        }
    }

    /// `PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}`.
    /// `state_key` may be `""` (the spec's own empty state key), which
    /// percent-encodes to an empty final path segment.
    pub fn room_state(
        id: RequestId,
        room_id: &RoomId,
        event_type: &str,
        state_key: &str,
        body: serde_json::Value,
    ) -> Self {
        const PATH_TEMPLATE: &str =
            "/_matrix/client/v3/rooms/{room_id}/state/{event_type}/{state_key}";
        let path = substitute(
            PATH_TEMPLATE,
            &[
                ("{room_id}", room_id.as_str()),
                ("{event_type}", event_type),
                ("{state_key}", state_key),
            ],
        );
        Self {
            id,
            method: HttpMethod::Put,
            path,
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::RoomState,
        }
    }

    /// `GET /_matrix/client/v3/rooms/{roomId}/messages`.
    pub fn room_messages(
        id: RequestId,
        room_id: &RoomId,
        from: &str,
        dir: &str,
        limit: Option<u32>,
    ) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/rooms/{room_id}/messages";
        let path = substitute(PATH_TEMPLATE, &[("{room_id}", room_id.as_str())]);
        let mut query = vec![("from".to_string(), from.to_string()), ("dir".to_string(), dir.to_string())];
        if let Some(limit) = limit {
            query.push(("limit".to_string(), limit.to_string()));
        }
        Self {
            id,
            method: HttpMethod::Get,
            path,
            query,
            body: None,
            kind: OutgoingRequestKind::RoomMessages,
        }
    }

    /// Latest page, `dir=b`, no `from`. The server starts at the tip.
    /// An encrypted push carries no ciphertext, and a `/sync` token that
    /// has already moved on will not return that event again.
    pub fn room_messages_latest(id: RequestId, room_id: &RoomId, limit: u32) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/rooms/{room_id}/messages";
        let path = substitute(PATH_TEMPLATE, &[("{room_id}", room_id.as_str())]);
        Self {
            id,
            method: HttpMethod::Get,
            path,
            query: vec![
                ("dir".to_string(), "b".to_string()),
                ("limit".to_string(), limit.to_string()),
            ],
            body: None,
            kind: OutgoingRequestKind::RoomMessages,
        }
    }

    /// `GET /_matrix/client/v3/rooms/{roomId}/members`.
    pub fn room_members(id: RequestId, room_id: &RoomId) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/rooms/{room_id}/members";
        let path = substitute(PATH_TEMPLATE, &[("{room_id}", room_id.as_str())]);
        Self {
            id,
            method: HttpMethod::Get,
            path,
            query: Vec::new(),
            body: None,
            kind: OutgoingRequestKind::RoomMembers,
        }
    }

    /// `POST /_matrix/client/v3/createRoom`.
    pub fn create_room(id: RequestId, body: serde_json::Value) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/createRoom";
        Self {
            id,
            method: HttpMethod::Post,
            path: PATH_TEMPLATE.to_string(),
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::CreateRoom,
        }
    }

    /// `POST /_matrix/client/v3/rooms/{roomId}/join`. This crate only ever
    /// joins by room id. It does not speak `/join/{roomIdOrAlias}`.
    pub fn join_room(id: RequestId, room_id: &str) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/rooms/{room_id}/join";
        let path = substitute(PATH_TEMPLATE, &[("{room_id}", room_id)]);
        Self {
            id,
            method: HttpMethod::Post,
            path,
            query: Vec::new(),
            body: None,
            kind: OutgoingRequestKind::JoinRoom,
        }
    }

    /// `POST /_matrix/client/v3/rooms/{roomId}/leave`.
    pub fn leave_room(id: RequestId, room_id: &RoomId) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/rooms/{room_id}/leave";
        let path = substitute(PATH_TEMPLATE, &[("{room_id}", room_id.as_str())]);
        Self {
            id,
            method: HttpMethod::Post,
            path,
            query: Vec::new(),
            body: None,
            kind: OutgoingRequestKind::LeaveRoom,
        }
    }

    /// `POST /_matrix/client/v3/rooms/{roomId}/invite`.
    pub fn invite(id: RequestId, room_id: &RoomId, user_id: &UserId) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/rooms/{room_id}/invite";
        let path = substitute(PATH_TEMPLATE, &[("{room_id}", room_id.as_str())]);
        Self {
            id,
            method: HttpMethod::Post,
            path,
            query: Vec::new(),
            body: Some(serde_json::json!({ "user_id": user_id.as_str() })),
            kind: OutgoingRequestKind::Invite,
        }
    }

    /// `POST /_matrix/client/v3/rooms/{roomId}/kick`.
    pub fn kick(id: RequestId, room_id: &RoomId, user_id: &UserId, reason: Option<&str>) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/rooms/{room_id}/kick";
        let path = substitute(PATH_TEMPLATE, &[("{room_id}", room_id.as_str())]);
        let mut body = serde_json::json!({ "user_id": user_id.as_str() });
        if let Some(reason) = reason {
            body["reason"] = serde_json::Value::String(reason.to_string());
        }
        Self {
            id,
            method: HttpMethod::Post,
            path,
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::Kick,
        }
    }

    /// `PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}`.
    pub fn typing(
        id: RequestId,
        room_id: &RoomId,
        user_id: &UserId,
        typing: bool,
        timeout_ms: Option<u64>,
    ) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/rooms/{room_id}/typing/{user_id}";
        let path = substitute(
            PATH_TEMPLATE,
            &[("{room_id}", room_id.as_str()), ("{user_id}", user_id.as_str())],
        );
        let mut body = serde_json::json!({ "typing": typing });
        if let Some(timeout_ms) = timeout_ms {
            body["timeout"] = serde_json::Value::from(timeout_ms);
        }
        Self {
            id,
            method: HttpMethod::Put,
            path,
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::Typing,
        }
    }

    /// `POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}`.
    pub fn receipt(id: RequestId, room_id: &RoomId, receipt_type: &str, event_id: &EventId) -> Self {
        const PATH_TEMPLATE: &str =
            "/_matrix/client/v3/rooms/{room_id}/receipt/{receipt_type}/{event_id}";
        let path = substitute(
            PATH_TEMPLATE,
            &[
                ("{room_id}", room_id.as_str()),
                ("{receipt_type}", receipt_type),
                ("{event_id}", event_id.as_str()),
            ],
        );
        Self {
            id,
            method: HttpMethod::Post,
            path,
            query: Vec::new(),
            body: Some(serde_json::json!({})),
            kind: OutgoingRequestKind::Receipt,
        }
    }

    /// `POST /_matrix/client/v3/rooms/{roomId}/read_markers`.
    pub fn read_markers(id: RequestId, room_id: &RoomId, body: serde_json::Value) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/rooms/{room_id}/read_markers";
        let path = substitute(PATH_TEMPLATE, &[("{room_id}", room_id.as_str())]);
        Self {
            id,
            method: HttpMethod::Post,
            path,
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::ReadMarkers,
        }
    }

    /// `PUT /_matrix/client/v3/user/{userId}/account_data/{type}`.
    pub fn account_data(
        id: RequestId,
        user_id: &UserId,
        event_type: &str,
        body: serde_json::Value,
    ) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/user/{user_id}/account_data/{event_type}";
        let path = substitute(
            PATH_TEMPLATE,
            &[("{user_id}", user_id.as_str()), ("{event_type}", event_type)],
        );
        Self {
            id,
            method: HttpMethod::Put,
            path,
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::AccountData,
        }
    }

    /// `PUT /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}`.
    pub fn room_account_data(
        id: RequestId,
        user_id: &UserId,
        room_id: &RoomId,
        event_type: &str,
        body: serde_json::Value,
    ) -> Self {
        const PATH_TEMPLATE: &str =
            "/_matrix/client/v3/user/{user_id}/rooms/{room_id}/account_data/{event_type}";
        let path = substitute(
            PATH_TEMPLATE,
            &[
                ("{user_id}", user_id.as_str()),
                ("{room_id}", room_id.as_str()),
                ("{event_type}", event_type),
            ],
        );
        Self {
            id,
            method: HttpMethod::Put,
            path,
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::RoomAccountData,
        }
    }

    /// `GET /_matrix/client/v3/profile/{userId}`.
    pub fn profile(id: RequestId, user_id: &UserId) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/profile/{user_id}";
        let path = substitute(PATH_TEMPLATE, &[("{user_id}", user_id.as_str())]);
        Self {
            id,
            method: HttpMethod::Get,
            path,
            query: Vec::new(),
            body: None,
            kind: OutgoingRequestKind::Profile,
        }
    }

    /// `POST /_matrix/client/v3/user_directory/search`.
    pub fn user_directory_search(id: RequestId, body: serde_json::Value) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/user_directory/search";
        Self {
            id,
            method: HttpMethod::Post,
            path: PATH_TEMPLATE.to_string(),
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::UserDirectorySearch,
        }
    }

    /// `POST /_matrix/client/v3/publicRooms`.
    pub fn public_rooms(id: RequestId, body: serde_json::Value) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/publicRooms";
        Self {
            id,
            method: HttpMethod::Post,
            path: PATH_TEMPLATE.to_string(),
            query: Vec::new(),
            body: Some(body),
            kind: OutgoingRequestKind::PublicRooms,
        }
    }

    /// `GET /_matrix/client/v3/room_keys/version` — the current backup
    /// version. Creating/updating a version is a different endpoint,
    /// deferred to whichever piece implements key backup (plan §5, M9).
    pub fn backup_version(id: RequestId) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/room_keys/version";
        Self {
            id,
            method: HttpMethod::Get,
            path: PATH_TEMPLATE.to_string(),
            query: Vec::new(),
            body: None,
            kind: OutgoingRequestKind::BackupVersion,
        }
    }

    /// `GET /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}` — the
    /// single-session lookup shape the plan's §4.3 UTD-recovery walkthrough
    /// uses. The bulk (`/room_keys/keys`) and per-room
    /// (`/room_keys/keys/{roomId}`) variants are deferred to M9, which owns
    /// key backup end to end (plan §6.8: exact backup paths/queries are
    /// still open pending the sibling server plan).
    pub fn backup_keys(id: RequestId, room_id: &RoomId, session_id: &str, version: &str) -> Self {
        const PATH_TEMPLATE: &str = "/_matrix/client/v3/room_keys/keys/{room_id}/{session_id}";
        let path = substitute(
            PATH_TEMPLATE,
            &[("{room_id}", room_id.as_str()), ("{session_id}", session_id)],
        );
        Self {
            id,
            method: HttpMethod::Get,
            path,
            query: vec![("version".to_string(), version.to_string())],
            body: None,
            kind: OutgoingRequestKind::BackupKeys,
        }
    }
}

/// One HTTP response a shell hands back for a prior [`OutgoingRequest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponseDescriptor {
    /// The HTTP status code.
    pub status: u16,
    /// The raw response body bytes.
    pub body: Vec<u8>,
}

impl HttpResponseDescriptor {
    /// Parses `body` as a Matrix-shaped error response
    /// (`{"errcode": "...", "error": "..."}`), returning
    /// `(errcode, error)` if the body is JSON and carries an `errcode`
    /// string field. `error` defaults to `""` if absent (the spec makes it
    /// optional). Returns `None` for a non-JSON body or a JSON body with
    /// no `errcode` field, regardless of `status` — callers that only want
    /// this on failure responses should check `status` themselves first.
    pub fn matrix_error(&self) -> Option<(String, String)> {
        let value: serde_json::Value = serde_json::from_slice(&self.body).ok()?;
        let errcode = value.get("errcode")?.as_str()?.to_string();
        let error = value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        Some((errcode, error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> RequestId {
        RequestId::next(0)
    }

    #[test]
    fn percent_encode_segment_escapes_matrix_sigils() {
        assert_eq!(percent_encode_segment("!abc:example.org"), "%21abc%3Aexample.org");
        assert_eq!(percent_encode_segment("safe-._~123"), "safe-._~123");
    }

    #[test]
    fn percent_decode_segment_reverses_percent_encode_segment() {
        for raw in ["!abc:example.org", "safe-._~123", "curve/25519+key=", ""] {
            let encoded = percent_encode_segment(raw);
            assert_eq!(percent_decode_segment(&encoded).as_deref(), Some(raw));
        }
    }

    #[test]
    fn percent_decode_segment_rejects_a_malformed_escape() {
        assert_eq!(percent_decode_segment("%2"), None);
        assert_eq!(percent_decode_segment("%zz"), None);
    }

    #[test]
    fn room_send_percent_encodes_the_room_id_in_the_path() {
        let room_id = RoomId::parse("!abc:example.org").expect("valid room id");
        let txn_id = TxnId::new(0);
        let req = OutgoingRequest::room_send(
            id(),
            &room_id,
            "m.room.message",
            &txn_id,
            serde_json::json!({ "body": "hi" }),
        );
        assert_eq!(
            req.path,
            format!(
                "/_matrix/client/v3/rooms/%21abc%3Aexample.org/send/m.room.message/{}",
                txn_id.as_str()
            )
        );
        assert_eq!(req.method, HttpMethod::Put);
        assert_eq!(req.kind, OutgoingRequestKind::RoomSend);
    }

    #[test]
    fn send_to_device_percent_encodes_the_txn_id_in_the_path() {
        let txn_id = TxnId::new(0);
        let req = OutgoingRequest::send_to_device(
            id(),
            "m.room.encrypted",
            &txn_id,
            serde_json::json!({ "messages": {} }),
        );
        assert!(req.path.starts_with("/_matrix/client/v3/sendToDevice/m.room.encrypted/"));
        assert!(!req.path.contains(':'), "txn id's own characters carry no raw ':'");
    }

    #[test]
    fn sync_carries_since_and_timeout_as_query_params_only_when_present() {
        let filter = ("filter".to_string(), SYNC_FILTER.to_string());
        let bare = OutgoingRequest::sync(id(), None, None);
        assert_eq!(bare.query, vec![filter.clone()]);

        let full = OutgoingRequest::sync(id(), Some("s123"), Some(30_000));
        assert_eq!(
            full.query,
            vec![filter, ("since".to_string(), "s123".to_string()), ("timeout".to_string(), "30000".to_string())]
        );
    }

    #[test]
    fn sync_filter_asks_for_left_rooms() {
        let parsed: serde_json::Value = serde_json::from_str(SYNC_FILTER).expect("the filter is JSON");
        assert_eq!(parsed["room"]["include_leave"], serde_json::Value::Bool(true));
    }

    #[test]
    fn outgoing_request_kind_round_trips_serde() {
        for kind in [
            OutgoingRequestKind::Sync,
            OutgoingRequestKind::KeysUpload,
            OutgoingRequestKind::RoomSend,
            OutgoingRequestKind::BackupKeys,
        ] {
            let json = serde_json::to_string(&kind).expect("serialize");
            let back: OutgoingRequestKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn outgoing_request_round_trips_serde() {
        let room_id = RoomId::parse("!abc:example.org").expect("valid room id");
        let req = OutgoingRequest::room_members(id(), &room_id);
        let json = serde_json::to_string(&req).expect("serialize");
        let back: OutgoingRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    fn matrix_error_parses_errcode_and_error() {
        let resp = HttpResponseDescriptor {
            status: 403,
            body: br#"{"errcode":"M_FORBIDDEN","error":"Guest access is forbidden"}"#.to_vec(),
        };
        assert_eq!(
            resp.matrix_error(),
            Some(("M_FORBIDDEN".to_string(), "Guest access is forbidden".to_string()))
        );
    }

    #[test]
    fn matrix_error_defaults_a_missing_error_field_to_empty() {
        let resp = HttpResponseDescriptor {
            status: 429,
            body: br#"{"errcode":"M_LIMIT_EXCEEDED"}"#.to_vec(),
        };
        assert_eq!(resp.matrix_error(), Some(("M_LIMIT_EXCEEDED".to_string(), String::new())));
    }

    #[test]
    fn matrix_error_is_none_for_a_non_json_body() {
        let resp = HttpResponseDescriptor { status: 200, body: b"not json".to_vec() };
        assert_eq!(resp.matrix_error(), None);
    }

    #[test]
    fn matrix_error_is_none_when_errcode_is_absent() {
        let resp = HttpResponseDescriptor {
            status: 200,
            body: br#"{"next_batch":"s1"}"#.to_vec(),
        };
        assert_eq!(resp.matrix_error(), None);
    }
}
