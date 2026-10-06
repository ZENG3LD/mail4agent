//! An in-process, spec-shaped fake Matrix homeserver for
//! `mail4agent-messenger`'s own integration tests. Speaks [`OutgoingRequest`] -> [`HttpResponseDescriptor`]
//! directly -- no HTTP, no async, no sockets -- but every request/response
//! body is the real wire JSON shape the research doc's §3.2/§3.3 describe,
//! so this is a contract test harness every later piece (cross-signing, key
//! backup, ...) can extend rather than a throwaway mock.
//!
//! Two room models coexist on purpose, never touching each other's code
//! path: the original `RoomTimeline`/`pending_room_state`/
//! `pending_room_timeline` triple (test-supplied membership, drain-on-read
//! or queued-until-consumed delivery -- what `e2e_megolm_group.rs`/
//! `e2e_core.rs` still use), and `Room`/`room_cursors` (M13b: a real
//! `/createRoom`, full join/invite/leave/kick, and a per-device
//! since-cursor delta over `/sync` -- what `e2e_send_pipeline.rs` uses).
//! Still out of scope, left for a later piece: cross-signing, key backup.
//! A request of any [`OutgoingRequestKind`] this fake does not implement
//! gets a clean `501` rather than a panic, so extending this file never
//! requires touching every call site that already works.
//!
//! # Test hooks (M13b)
//!
//! [`FakeServer::request_log`] records every dispatched request's own
//! [`OutgoingRequestKind`] in call order, for a test that needs to assert
//! cross-request ordering (e.g. "the room-key share landed before the room
//! event it unblocks"). [`FakeServer::fail_next_room_send`] makes the next
//! `RoomSend` for a given room fail outright (a one-shot fault injection);
//! [`FakeServer::last_rejected_room_send_body`] then lets a test assert a
//! subsequent `MessengerCommand::RetrySend` resent byte-identical content.

use mail4agent_messenger::wire::{HttpResponseDescriptor, Membership, OutgoingRequest, OutgoingRequestKind};
use mail4agent_messenger::{DeviceId, EventId, RoomId, UserId};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// One device's server-side state: its published `device_keys`, its pool
/// of unclaimed regular one-time keys, and its current fallback key.
#[derive(Default, Clone)]
struct DeviceState {
    device_keys: Option<Value>,
    /// `signed_curve25519:{key_id}` -> the signed key object. Regular
    /// one-time keys are exactly-once: [`FakeServer::handle_keys_claim`]
    /// removes an entry the moment it is claimed.
    one_time_keys: BTreeMap<String, Value>,
    /// The current fallback key, if any -- unlike a regular one-time key,
    /// claiming it does not remove it (real Matrix semantics: a fallback
    /// key stays claimable, potentially by more than one claimant, until
    /// the device replaces it with a new upload). `fallback_used` only
    /// tracks whether `device_unused_fallback_key_types` should still
    /// report it as unused.
    fallback: Option<(String, Value)>,
    fallback_used: bool,
}

/// One device's `/sync` to-device mailbox: real Matrix since-token
/// semantics (spec, and this project's own server's P2 piece), not a
/// drain-on-read queue -- a `/sync` response is only ever safe to forget
/// once a LATER request names a `since` at or past it, because the
/// response naming that later `since` is the client's own proof it
/// durably received everything before it. Until then, the exact same
/// events must be redelivered verbatim on a retried `since` (a lost
/// response, a crashed client, ...).
///
/// `base_index` is the global position of `events[0]`; `events` holds
/// every event from `base_index` onward that has not yet been pruned.
/// `/sync`'s own `next_batch` token is always `"s{base_index + events.len()}"`.
#[derive(Default)]
struct SyncMailbox {
    base_index: usize,
    events: Vec<Value>,
}

fn parse_sync_token(token: &str) -> Option<usize> {
    token.strip_prefix('s').and_then(|rest| rest.parse().ok())
}

/// One room's server-stored timeline (`PUT /rooms/{roomId}/send/...`) --
/// the "bare minimum" the Megolm group tests need: append-only, each event
/// gets a server-assigned id, nothing else (no pagination, no state
/// events, no `/sync` room section -- a test reads it back directly via
/// [`FakeServer::room_timeline`]).
#[derive(Default)]
struct RoomTimeline {
    events: Vec<Value>,
    next_event_seq: u64,
}

/// A full room this fake server created and now broadcasts through
/// `/sync` on its own (M13b's send pipeline: `/createRoom`, join/leave/
/// invite/kick, room account data) -- distinct from [`RoomTimeline`]
/// above, which stays exactly as it was for the older, test-supplied-
/// membership Megolm tests (module doc: never touched by this piece).
#[derive(Default)]
struct Room {
    /// Current state, keyed by `(event_type, state_key)` -- the latest
    /// event of each -- and also appended to `state_log` in order, so a
    /// per-device cursor can compute a delta (module doc's own "state/
    /// timeline delta" note: replaying the full ordered log to this
    /// crate's own `RoomState::apply_state_event` produces the same final
    /// state as a snapshot would, since every field is simply overwritten
    /// in order).
    current_state: BTreeMap<(String, String), Value>,
    state_log: Vec<Value>,
    timeline_log: Vec<Value>,
    members: BTreeMap<UserId, Membership>,
    next_event_seq: u64,
}

impl Room {
    fn next_event_id(&mut self) -> String {
        self.next_event_seq += 1;
        format!("$room-evt{}:example.org", self.next_event_seq)
    }

    /// Applies one state event (creating a fresh server-assigned event id),
    /// recording it as both this room's current value for
    /// `(event_type, state_key)` and the next entry in `state_log`.
    fn apply_state(&mut self, event_type: &str, state_key: &str, sender: &UserId, content: Value) {
        let event_id = self.next_event_id();
        let event = serde_json::json!({
            "event_id": event_id,
            "type": event_type,
            "sender": sender.as_str(),
            "origin_server_ts": self.next_event_seq as i64,
            "state_key": state_key,
            "content": content,
        });
        self.current_state.insert((event_type.to_string(), state_key.to_string()), event.clone());
        self.state_log.push(event);
    }

    /// Appends one non-state timeline event (a message, a Megolm
    /// ciphertext, a reaction, a redaction, ...), returning its
    /// server-assigned event id.
    fn append_timeline(&mut self, event_type: &str, sender: &UserId, content: Value) -> String {
        let event_id = self.next_event_id();
        let event = serde_json::json!({
            "event_id": event_id,
            "type": event_type,
            "sender": sender.as_str(),
            "origin_server_ts": self.next_event_seq as i64,
            "content": content,
        });
        self.timeline_log.push(event);
        event_id
    }
}

/// How much of one room's own [`Room::state_log`]/[`Room::timeline_log`]
/// this fake server has already delivered to one `(user, device)`'s
/// `/sync` stream.
#[derive(Default)]
struct RoomSyncCursor {
    state_seen: usize,
    timeline_seen: usize,
}

fn json_response(status: u16, value: &Value) -> HttpResponseDescriptor {
    HttpResponseDescriptor { status, body: serde_json::to_vec(value).expect("a serde_json::Value always serializes") }
}

/// A small, local, test-only percent-decoder for path segments this fake
/// server needs to recover from a request path (currently just a room id
/// out of a `/rooms/{room_id}/send/...` path). `mail4agent_messenger::wire`'s own
/// implementation is crate-private, and this fake server compiles as a
/// separate integration-test crate, so it cannot reuse it.
fn percent_decode_minimal(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&segment[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Extracts `(room_id, event_type)` from
/// `/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}`.
fn parse_room_send_path(path: &str) -> Option<(RoomId, String)> {
    let segments: Vec<&str> = path.split('/').collect();
    let rooms_idx = segments.iter().position(|segment| *segment == "rooms")?;
    let send_idx = segments.iter().position(|segment| *segment == "send")?;
    let room_id_raw = segments.get(rooms_idx + 1)?;
    let event_type = (*segments.get(send_idx + 1)?).to_string();
    let room_id = RoomId::parse(percent_decode_minimal(room_id_raw)).ok()?;
    Some((room_id, event_type))
}

/// Extracts `(room_id, event_id)` from
/// `/_matrix/client/v3/rooms/{room_id}/redact/{event_id}/{txn_id}`.
fn parse_room_redact_path(path: &str) -> Option<(RoomId, EventId)> {
    let segments: Vec<&str> = path.split('/').collect();
    let rooms_idx = segments.iter().position(|segment| *segment == "rooms")?;
    let redact_idx = segments.iter().position(|segment| *segment == "redact")?;
    let room_id = RoomId::parse(percent_decode_minimal(segments.get(rooms_idx + 1)?)).ok()?;
    let event_id = EventId::parse(percent_decode_minimal(segments.get(redact_idx + 1)?)).ok()?;
    Some((room_id, event_id))
}

/// Extracts `room_id` from `/_matrix/client/v3/rooms/{room_id}/...`
/// (leave/invite/kick all share this shape).
fn parse_room_action_path(path: &str) -> Option<RoomId> {
    let segments: Vec<&str> = path.split('/').collect();
    let rooms_idx = segments.iter().position(|segment| *segment == "rooms")?;
    RoomId::parse(percent_decode_minimal(segments.get(rooms_idx + 1)?)).ok()
}

/// Extracts `(room_id, event_type)` from
/// `/_matrix/client/v3/user/{user_id}/rooms/{room_id}/account_data/{event_type}`.
fn parse_room_account_data_path(path: &str) -> Option<(RoomId, String)> {
    let segments: Vec<&str> = path.split('/').collect();
    let rooms_idx = segments.iter().position(|segment| *segment == "rooms")?;
    let room_id = RoomId::parse(percent_decode_minimal(segments.get(rooms_idx + 1)?)).ok()?;
    let event_type = percent_decode_minimal(segments.last()?);
    Some((room_id, event_type))
}

/// Reshapes one full room-state event `Value` into the stripped-preview
/// shape `invite_state.events` carries (`{type, state_key, sender,
/// content}` -- no `event_id`/`origin_server_ts`/`unsigned`).
fn to_stripped_state(event: &Value) -> Value {
    serde_json::json!({
        "type": event["type"],
        "state_key": event["state_key"],
        "sender": event["sender"],
        "content": event["content"],
    })
}

/// An in-process fake homeserver. See the module doc.
#[derive(Default)]
pub struct FakeServer {
    devices: BTreeMap<(UserId, DeviceId), DeviceState>,
    to_device_mailboxes: BTreeMap<(UserId, DeviceId), SyncMailbox>,
    pending_device_list_changes: BTreeMap<(UserId, DeviceId), Vec<UserId>>,
    room_timelines: BTreeMap<RoomId, RoomTimeline>,
    /// Room state events queued for a specific `(user, device)`'s next
    /// `/sync` response, drain-on-read (unlike `to_device_mailboxes`'s own
    /// since-token-aware redelivery -- no test in this crate's own e2e
    /// suite needs a lost/retried `/sync` to re-observe a room state/
    /// timeline event that already landed in an earlier response, so this
    /// stays the simpler of the two shapes on purpose).
    pending_room_state: BTreeMap<(UserId, DeviceId), BTreeMap<RoomId, Vec<Value>>>,
    /// Timeline events queued the same way as `pending_room_state`.
    pending_room_timeline: BTreeMap<(UserId, DeviceId), BTreeMap<RoomId, Vec<Value>>>,

    /// Rooms created through this fake's own `/createRoom` (M13b) --
    /// broadcast automatically via `/sync`, unlike the legacy
    /// `room_timelines`/`pending_room_*` model above (module doc).
    rooms: BTreeMap<RoomId, Room>,
    /// How much of each such room a given `(user, device)` has already
    /// received.
    room_cursors: BTreeMap<(UserId, DeviceId), BTreeMap<RoomId, RoomSyncCursor>>,
    /// This fake's own room-id minting counter.
    room_seq: u64,
    /// Global (non-room) account data, current value per type, per user --
    /// always redelivered in full on every `/sync` for that user (module
    /// doc: simpler than tracking a delta, and harmless since this crate's
    /// own `ingest_sync` folding is idempotent).
    global_account_data: BTreeMap<UserId, BTreeMap<String, Value>>,
    /// Room-scoped account data, same "always redeliver current value"
    /// convention as `global_account_data`.
    room_account_data: BTreeMap<(UserId, RoomId), BTreeMap<String, Value>>,
    /// One room's own `m.receipt` content (`event_id -> receipt_type ->
    /// user_id -> {ts}`), built up by every `POST .../read_markers` this
    /// fake receives for it (a real server's own read-marker endpoint also
    /// broadcasts an `m.read` receipt when `m.read` is present in the
    /// body) -- always redelivered in full on every `/sync` this room
    /// appears in, same convention as `global_account_data`/
    /// `room_account_data` above.
    room_receipts: BTreeMap<RoomId, Value>,

    /// Every request's own [`OutgoingRequestKind`] this fake has ever
    /// dispatched, in call order -- lets a test assert cross-request
    /// ordering directly at this fake (e.g. "the room-key share landed
    /// before the room event it unblocks").
    request_log: Vec<OutgoingRequestKind>,
    /// A one-shot injected failure for the next `RoomSend` this fake
    /// receives for a given room -- a test's own fault-injection hook for a
    /// send-pipeline retry test. Consumed (removed) the moment it fires.
    fault_next_room_send: BTreeMap<RoomId, String>,
    /// The `(path, body)` of the most recent `RoomSend` this fake received,
    /// captured unconditionally (whether it then succeeded or was rejected
    /// via `fault_next_room_send`) -- lets a test assert a retry sent
    /// byte-identical wire content (same `txn_id`, embedded in `path`; same
    /// ciphertext/content, in `body`) as a send this fake had already seen
    /// once before.
    last_room_send: Option<(String, Value)>,
    /// The body of the most recent `RoomSend` this fake REJECTED under the
    /// encrypted-room type rule (plaintext in an encrypted room) — read back
    /// through [`FakeServer::last_rejected_room_send_body`].
    last_rejected_room_send_body: Option<Value>,
}

/// Extracts the `{event_type}` path component from
/// `/_matrix/client/v3/sendToDevice/{event_type}/{txn_id}`. Every event
/// type this crate's own builders ever put there
/// (`percent_encode_segment`'s unreserved set includes `.`) survives
/// unescaped, so a plain path split is enough for this fake.
fn event_type_from_send_to_device_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    let index = segments.iter().position(|segment| *segment == "sendToDevice").expect("a sendToDevice path segment");
    segments[index + 1].to_string()
}

impl FakeServer {
    /// Builds an empty fake server: no users, no devices, nothing queued.
    pub fn new() -> Self {
        Self::default()
    }

    fn device_mut(&mut self, user_id: &UserId, device_id: &DeviceId) -> &mut DeviceState {
        self.devices.entry((user_id.clone(), device_id.clone())).or_default()
    }

    /// Dispatches one [`OutgoingRequest`] as if authenticated as
    /// `(as_user, as_device)` (this fake has no access-token concept --
    /// the caller supplies the authenticated identity directly).
    pub fn dispatch(&mut self, as_user: &UserId, as_device: &DeviceId, request: &OutgoingRequest) -> HttpResponseDescriptor {
        self.request_log.push(request.kind);
        match request.kind {
            OutgoingRequestKind::KeysUpload => self.handle_keys_upload(as_user, as_device, request),
            OutgoingRequestKind::KeysQuery => self.handle_keys_query(request),
            OutgoingRequestKind::KeysClaim => self.handle_keys_claim(request),
            OutgoingRequestKind::SendToDevice => self.handle_send_to_device(as_user, request),
            OutgoingRequestKind::Sync => self.handle_sync(as_user, as_device, request),
            OutgoingRequestKind::RoomSend => self.handle_room_send(as_user, request),
            OutgoingRequestKind::RoomRedact => self.handle_room_redact(as_user, request),
            OutgoingRequestKind::CreateRoom => self.handle_create_room(as_user, request),
            OutgoingRequestKind::JoinRoom => self.handle_join_room(as_user, request),
            OutgoingRequestKind::LeaveRoom => self.handle_leave_room(as_user, request),
            OutgoingRequestKind::Invite => self.handle_invite(as_user, request),
            OutgoingRequestKind::Kick => self.handle_kick(as_user, request),
            OutgoingRequestKind::Typing => json_response(200, &serde_json::json!({})),
            OutgoingRequestKind::ReadMarkers => self.handle_read_markers(as_user, request),
            OutgoingRequestKind::AccountData => self.handle_account_data(as_user, request),
            OutgoingRequestKind::RoomAccountData => self.handle_room_account_data(as_user, request),
            _ => json_response(
                501,
                &serde_json::json!({ "errcode": "M_UNRECOGNIZED", "error": "fake server: unsupported request kind" }),
            ),
        }
    }

    /// Queues a `device_lists.changed` entry for `(for_user, for_device)`'s
    /// next `/sync` -- lets a test drive device-list re-tracking through
    /// the real `/sync` -> `DeviceTracker::on_device_lists` path instead of
    /// poking the store directly.
    pub fn note_device_list_changed(&mut self, for_user: &UserId, for_device: &DeviceId, changed_user: &UserId) {
        self.pending_device_list_changes
            .entry((for_user.clone(), for_device.clone()))
            .or_default()
            .push(changed_user.clone());
    }

    /// Every request kind this fake has dispatched so far, in call order --
    /// lets a test assert cross-request ordering directly at this fake
    /// (module doc's own "request_log" note), e.g. "the room-key share
    /// landed before the room event it unblocks".
    pub fn request_log(&self) -> &[OutgoingRequestKind] {
        &self.request_log
    }

    /// `GET /_matrix/client/v3/account/whoami` -- outside `dispatch`'s own
    /// [`OutgoingRequestKind`] routing: it is not a
    /// [`mail4agent_messenger::wire::OutgoingRequest`] a core minted. This fake has no real access-token concept
    /// (module doc), so it just echoes back whichever identity the caller
    /// names, exactly as a real homeserver would resolve that identity's
    /// own bearer token.
    pub fn whoami(&self, as_user: &UserId, as_device: &DeviceId) -> HttpResponseDescriptor {
        json_response(200, &serde_json::json!({ "user_id": as_user.as_str(), "device_id": as_device.as_str() }))
    }

    /// Makes the NEXT `RoomSend` this fake receives for `room_id` fail with
    /// `errcode` instead of succeeding -- a test's own fault-injection hook
    /// for a send-pipeline retry test (module doc's own
    /// `fault_next_room_send` note). Consumed the moment it fires; a
    /// following `RoomSend` for the same room succeeds normally.
    pub fn fail_next_room_send(&mut self, room_id: RoomId, errcode: &str) {
        self.fault_next_room_send.insert(room_id, errcode.to_string());
    }

    /// The request body of the most recent `RoomSend` this fake rejected
    /// via [`FakeServer::fail_next_room_send`] -- lets a test assert a
    /// subsequent retry sent byte-identical ciphertext/content (module
    /// doc's own `last_rejected_room_send_body` note).
    pub fn last_rejected_room_send_body(&self) -> Option<&Value> {
        self.last_rejected_room_send_body.as_ref()
    }

    /// The `(path, body)` of the most recent `RoomSend` this fake received,
    /// captured unconditionally (module doc's own `last_room_send` note) --
    /// lets a test assert a retry sent byte-identical wire content (same
    /// `txn_id`, embedded in `path`; same ciphertext/content, in `body`) as
    /// an earlier send this fake already saw.
    pub fn last_room_send(&self) -> Option<(&str, &Value)> {
        self.last_room_send.as_ref().map(|(path, body)| (path.as_str(), body))
    }

    /// Corrupts the signature of one of `(user_id, device_id)`'s currently
    /// unclaimed regular one-time keys in place -- simulates a corrupted
    /// upload or an in-flight tamper, for a test that must prove a
    /// mis-signed claimed key is refused rather than trusted.
    pub fn corrupt_one_time_key_signature(&mut self, user_id: &UserId, device_id: &DeviceId) {
        let Some(state) = self.devices.get_mut(&(user_id.clone(), device_id.clone())) else { return };
        let Some((_, value)) = state.one_time_keys.iter_mut().next() else { return };
        corrupt_first_signature(value, user_id);
    }

    /// Queues one `m.room.*` state event for `room_id` into
    /// `(for_user, for_device)`'s next `/sync` response's
    /// `rooms.join.{room_id}.state.events` -- `event` is the full
    /// `{event_id, type, sender, state_key, origin_server_ts, content}`
    /// shape a real state event carries.
    pub fn queue_room_state(&mut self, for_user: &UserId, for_device: &DeviceId, room_id: &RoomId, event: Value) {
        self.pending_room_state
            .entry((for_user.clone(), for_device.clone()))
            .or_default()
            .entry(room_id.clone())
            .or_default()
            .push(event);
    }

    /// Queues one timeline event for `room_id` into
    /// `(for_user, for_device)`'s next `/sync` response's
    /// `rooms.join.{room_id}.timeline.events` -- same event shape as
    /// [`FakeServer::queue_room_state`], minus `state_key`.
    pub fn queue_room_timeline(&mut self, for_user: &UserId, for_device: &DeviceId, room_id: &RoomId, event: Value) {
        self.pending_room_timeline
            .entry((for_user.clone(), for_device.clone()))
            .or_default()
            .entry(room_id.clone())
            .or_default()
            .push(event);
    }

    fn handle_keys_upload(&mut self, as_user: &UserId, as_device: &DeviceId, request: &OutgoingRequest) -> HttpResponseDescriptor {
        let body = request.body.clone().unwrap_or_else(|| Value::Object(Map::new()));
        let mut identity_reset = false;
        {
            let state = self.device_mut(as_user, as_device);
            if let Some(device_keys) = body.get("device_keys") {
                let new_keys = device_keys.get("keys");
                let old_keys = state.device_keys.as_ref().and_then(|v| v.get("keys"));
                match (old_keys, new_keys) {
                    (None, Some(_)) => {
                        // First publish for this device — wake peers.
                        identity_reset = true;
                    }
                    (Some(old), Some(newk)) if old != newk => {
                        // Authenticated identity reset: wipe OTKs/fallback and
                        // wake peers via device_lists.changed (mirrors production).
                        state.one_time_keys.clear();
                        state.fallback = None;
                        state.fallback_used = false;
                        identity_reset = true;
                    }
                    _ => {}
                }
                state.device_keys = Some(device_keys.clone());
            }
            if let Some(one_time_keys) = body.get("one_time_keys").and_then(Value::as_object) {
                for (key_id, value) in one_time_keys {
                    state.one_time_keys.insert(key_id.clone(), value.clone());
                }
            }
            if let Some(fallback_keys) = body.get("fallback_keys").and_then(Value::as_object) {
                if let Some((key_id, value)) = fallback_keys.iter().next() {
                    state.fallback = Some((key_id.clone(), value.clone()));
                    state.fallback_used = false;
                }
            }
        }
        if identity_reset {
            // Notify every other user this fake has a device for — peers in
            // shared rooms learn via the next /sync.
            let peers: Vec<UserId> = self
                .devices
                .keys()
                .map(|(user, _)| user.clone())
                .filter(|user| user != as_user)
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            for peer in peers {
                self.broadcast_device_list_change(&peer, as_user);
            }
        }

        let count = self.device_mut(as_user, as_device).one_time_keys.len() as u64;
        json_response(200, &serde_json::json!({ "one_time_key_counts": { "signed_curve25519": count } }))
    }

    fn handle_keys_query(&self, request: &OutgoingRequest) -> HttpResponseDescriptor {
        let body = request.body.clone().unwrap_or_else(|| Value::Object(Map::new()));
        let requested_users = body.get("device_keys").and_then(Value::as_object).cloned().unwrap_or_default();

        let mut device_keys_out = Map::new();
        for user_key in requested_users.keys() {
            let mut by_device = Map::new();
            for ((user_id, device_id), state) in &self.devices {
                if user_id.as_str() == user_key.as_str() {
                    if let Some(device_keys) = &state.device_keys {
                        by_device.insert(device_id.as_str().to_string(), device_keys.clone());
                    }
                }
            }
            device_keys_out.insert(user_key.clone(), Value::Object(by_device));
        }

        json_response(200, &serde_json::json!({ "device_keys": device_keys_out, "failures": {} }))
    }

    fn handle_keys_claim(&mut self, request: &OutgoingRequest) -> HttpResponseDescriptor {
        let body = request.body.clone().unwrap_or_else(|| Value::Object(Map::new()));
        let requested = body.get("one_time_keys").and_then(Value::as_object).cloned().unwrap_or_default();

        let mut claimed_out = Map::new();
        for (user_str, by_device_value) in &requested {
            let Ok(user_id) = UserId::parse(user_str.clone()) else { continue };
            let Some(by_device) = by_device_value.as_object() else { continue };

            let mut claimed_devices = Map::new();
            for device_str in by_device.keys() {
                let Ok(device_id) = DeviceId::parse(device_str.clone()) else { continue };
                let Some(state) = self.devices.get_mut(&(user_id.clone(), device_id)) else { continue };

                let claimed = if let Some((key_id, value)) = state.one_time_keys.pop_first() {
                    Some((key_id, value))
                } else if let Some((key_id, value)) = &state.fallback {
                    state.fallback_used = true;
                    Some((key_id.clone(), value.clone()))
                } else {
                    None
                };

                if let Some((key_id, value)) = claimed {
                    let mut one = Map::new();
                    one.insert(key_id, value);
                    claimed_devices.insert(device_str.clone(), Value::Object(one));
                }
            }

            if !claimed_devices.is_empty() {
                claimed_out.insert(user_str.clone(), Value::Object(claimed_devices));
            }
        }

        json_response(200, &serde_json::json!({ "one_time_keys": claimed_out }))
    }

    fn handle_send_to_device(&mut self, as_user: &UserId, request: &OutgoingRequest) -> HttpResponseDescriptor {
        let event_type = event_type_from_send_to_device_path(&request.path);
        let body = request.body.clone().unwrap_or_else(|| Value::Object(Map::new()));
        let messages = body.get("messages").and_then(Value::as_object).cloned().unwrap_or_default();

        for (user_str, by_device_value) in &messages {
            let Ok(user_id) = UserId::parse(user_str.clone()) else { continue };
            let Some(by_device) = by_device_value.as_object() else { continue };
            for (device_str, content) in by_device {
                let Ok(device_id) = DeviceId::parse(device_str.clone()) else { continue };
                let event = serde_json::json!({ "sender": as_user.as_str(), "type": event_type, "content": content });
                self.to_device_mailboxes.entry((user_id.clone(), device_id)).or_default().events.push(event);
            }
        }

        json_response(200, &serde_json::json!({}))
    }

    /// `PUT /rooms/{roomId}/send/{eventType}/{txnId}` -- appends `body` to
    /// `room_id`'s server-side timeline under a fresh, server-assigned
    /// event id (module doc's "bare minimum" for the Megolm group tests).
    /// No idempotency-by-`txnId` handling here (unlike the real spec):
    /// none of this crate's own tests retries a room send, so a second
    /// call with the same `txnId` simply appends a second event, matching
    /// this fake's overall "spec-shaped, not spec-complete" scope.
    fn handle_room_send(&mut self, as_user: &UserId, request: &OutgoingRequest) -> HttpResponseDescriptor {
        let Some((room_id, event_type)) = parse_room_send_path(&request.path) else {
            return json_response(
                400,
                &serde_json::json!({ "errcode": "M_UNKNOWN", "error": "fake server: malformed room send path" }),
            );
        };
        let body = request.body.clone().unwrap_or_else(|| Value::Object(Map::new()));
        self.last_room_send = Some((request.path.clone(), body.clone()));

        if let Some(errcode) = self.fault_next_room_send.remove(&room_id) {
            self.last_rejected_room_send_body = Some(body);
            return json_response(400, &serde_json::json!({ "errcode": errcode, "error": "fake server: injected failure" }));
        }

        // A room this fake's own `/createRoom` created broadcasts through
        // the new per-device cursor model; everything else (the older
        // Megolm-group tests' own test-supplied-membership rooms) keeps
        // using the untouched legacy model (module doc).
        if let Some(room) = self.rooms.get_mut(&room_id) {
            let event_id = room.append_timeline(&event_type, as_user, body);
            return json_response(200, &serde_json::json!({ "event_id": event_id }));
        }

        let timeline = self.room_timelines.entry(room_id).or_default();
        timeline.next_event_seq += 1;
        let event_id = format!("$evt{}:example.org", timeline.next_event_seq);
        let event = serde_json::json!({
            "event_id": event_id,
            "type": event_type,
            "sender": as_user.as_str(),
            "origin_server_ts": timeline.next_event_seq as i64,
            "content": body,
        });
        timeline.events.push(event);

        json_response(200, &serde_json::json!({ "event_id": event_id }))
    }

    /// `PUT /rooms/{roomId}/redact/{eventId}/{txnId}` -- appends an
    /// `m.room.redaction` timeline event naming `redacts`/`reason`. Only
    /// implemented for a room created through this fake's own
    /// `/createRoom` (M13b); the legacy Megolm-group tests never redact.
    fn handle_room_redact(&mut self, as_user: &UserId, request: &OutgoingRequest) -> HttpResponseDescriptor {
        let Some((room_id, target)) = parse_room_redact_path(&request.path) else {
            return json_response(
                400,
                &serde_json::json!({ "errcode": "M_UNKNOWN", "error": "fake server: malformed redact path" }),
            );
        };
        let Some(room) = self.rooms.get_mut(&room_id) else {
            return json_response(404, &serde_json::json!({ "errcode": "M_NOT_FOUND", "error": "fake server: unknown room" }));
        };
        let reason = request.body.as_ref().and_then(|body| body.get("reason")).and_then(Value::as_str);
        let mut content = serde_json::json!({ "redacts": target.as_str() });
        if let Some(reason) = reason {
            content["reason"] = Value::String(reason.to_string());
        }
        let event_id = room.append_timeline("m.room.redaction", as_user, content);
        json_response(200, &serde_json::json!({ "event_id": event_id }))
    }

    /// `POST /createRoom` (M13b) -- derives `kind`/power levels from
    /// `visibility`+`is_direct` (server plan §5), injects every bootstrap
    /// state event server-side, and announces mutual device-list awareness
    /// between every member this call adds (this file's own module doc).
    fn handle_create_room(&mut self, as_user: &UserId, request: &OutgoingRequest) -> HttpResponseDescriptor {
        let body = request.body.clone().unwrap_or_else(|| Value::Object(Map::new()));
        let is_direct = body.get("is_direct").and_then(Value::as_bool).unwrap_or(false);
        let visibility = body.get("visibility").and_then(Value::as_str).unwrap_or("private");
        let name = body.get("name").and_then(Value::as_str).map(str::to_string);
        let topic = body.get("topic").and_then(Value::as_str).map(str::to_string);
        let members_can_invite = body.get("members_can_invite").and_then(Value::as_bool).unwrap_or(false);
        let invite: Vec<UserId> = body
            .get("invite")
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_str).filter_map(|s| UserId::parse(s).ok()).collect())
            .unwrap_or_default();

        let is_channel = !is_direct && visibility == "public";
        let encrypted = !is_channel;
        let (events_default, invite_level, join_rule, history_visibility) = if is_direct {
            (0i64, 50i64, "invite", "shared")
        } else if is_channel {
            (50i64, 50i64, "public", "world_readable")
        } else {
            (0i64, if members_can_invite { 0i64 } else { 50i64 }, "invite", "shared")
        };

        self.room_seq += 1;
        let room_id = RoomId::parse(format!("!room{}:example.org", self.room_seq)).expect("well-formed room id");
        let mut room = Room::default();

        room.apply_state("m.room.create", "", as_user, serde_json::json!({ "creator": as_user.as_str(), "room_version": "11" }));
        room.apply_state("m.room.member", as_user.as_str(), as_user, serde_json::json!({ "membership": "join" }));
        room.members.insert(as_user.clone(), Membership::Join);
        for invitee in &invite {
            room.apply_state(
                "m.room.member",
                invitee.as_str(),
                as_user,
                serde_json::json!({ "membership": "invite", "is_direct": is_direct }),
            );
            room.members.insert(invitee.clone(), Membership::Invite);
        }

        let mut users = Map::new();
        users.insert(as_user.as_str().to_string(), Value::from(100));
        room.apply_state(
            "m.room.power_levels",
            "",
            as_user,
            serde_json::json!({
                "ban": 50, "kick": 50, "redact": 50, "state_default": 50,
                "events_default": events_default, "users_default": 0,
                "invite": invite_level, "users": Value::Object(users),
            }),
        );
        room.apply_state("m.room.join_rules", "", as_user, serde_json::json!({ "join_rule": join_rule }));
        room.apply_state(
            "m.room.history_visibility",
            "",
            as_user,
            serde_json::json!({ "history_visibility": history_visibility }),
        );
        if encrypted {
            room.apply_state("m.room.encryption", "", as_user, serde_json::json!({ "algorithm": "m.megolm.v1.aes-sha2" }));
        }
        if let Some(name) = &name {
            room.apply_state("m.room.name", "", as_user, serde_json::json!({ "name": name }));
        }
        if let Some(topic) = &topic {
            room.apply_state("m.room.topic", "", as_user, serde_json::json!({ "topic": topic }));
        }

        self.rooms.insert(room_id.clone(), room);
        self.broadcast_membership_awareness(&room_id, as_user);
        for invitee in &invite {
            self.broadcast_membership_awareness(&room_id, invitee);
        }

        json_response(200, &serde_json::json!({ "room_id": room_id.as_str() }))
    }

    /// `POST /rooms/{roomId}/join` -- this fake never checks a join rule
    /// (module doc: spec-shaped, not spec-complete); joining a room that
    /// does not exist in `self.rooms` is a `404`.
    fn handle_join_room(&mut self, as_user: &UserId, request: &OutgoingRequest) -> HttpResponseDescriptor {
        let Some(room_id) = parse_room_action_path(&request.path) else {
            return json_response(400, &serde_json::json!({ "errcode": "M_UNKNOWN", "error": "fake server: malformed join path" }));
        };
        let Some(room) = self.rooms.get_mut(&room_id) else {
            return json_response(404, &serde_json::json!({ "errcode": "M_NOT_FOUND", "error": "fake server: unknown room" }));
        };
        room.apply_state("m.room.member", as_user.as_str(), as_user, serde_json::json!({ "membership": "join" }));
        room.members.insert(as_user.clone(), Membership::Join);
        self.broadcast_membership_awareness(&room_id, as_user);
        json_response(200, &serde_json::json!({ "room_id": room_id.as_str() }))
    }

    /// `POST /rooms/{roomId}/leave`.
    fn handle_leave_room(&mut self, as_user: &UserId, request: &OutgoingRequest) -> HttpResponseDescriptor {
        let Some(room_id) = parse_room_action_path(&request.path) else {
            return json_response(400, &serde_json::json!({ "errcode": "M_UNKNOWN", "error": "fake server: malformed leave path" }));
        };
        let Some(room) = self.rooms.get_mut(&room_id) else {
            return json_response(404, &serde_json::json!({ "errcode": "M_NOT_FOUND", "error": "fake server: unknown room" }));
        };
        room.apply_state("m.room.member", as_user.as_str(), as_user, serde_json::json!({ "membership": "leave" }));
        room.members.insert(as_user.clone(), Membership::Leave);
        json_response(200, &serde_json::json!({}))
    }

    /// `POST /rooms/{roomId}/invite`.
    fn handle_invite(&mut self, as_user: &UserId, request: &OutgoingRequest) -> HttpResponseDescriptor {
        let Some(room_id) = parse_room_action_path(&request.path) else {
            return json_response(400, &serde_json::json!({ "errcode": "M_UNKNOWN", "error": "fake server: malformed invite path" }));
        };
        let body = request.body.clone().unwrap_or_else(|| Value::Object(Map::new()));
        let Some(user_id) = body.get("user_id").and_then(Value::as_str).and_then(|s| UserId::parse(s).ok()) else {
            return json_response(400, &serde_json::json!({ "errcode": "M_MISSING_PARAM", "error": "fake server: missing user_id" }));
        };
        let Some(room) = self.rooms.get_mut(&room_id) else {
            return json_response(404, &serde_json::json!({ "errcode": "M_NOT_FOUND", "error": "fake server: unknown room" }));
        };
        room.apply_state("m.room.member", user_id.as_str(), as_user, serde_json::json!({ "membership": "invite" }));
        room.members.insert(user_id.clone(), Membership::Invite);
        self.broadcast_membership_awareness(&room_id, &user_id);
        json_response(200, &serde_json::json!({}))
    }

    /// `POST /rooms/{roomId}/kick`.
    fn handle_kick(&mut self, as_user: &UserId, request: &OutgoingRequest) -> HttpResponseDescriptor {
        let Some(room_id) = parse_room_action_path(&request.path) else {
            return json_response(400, &serde_json::json!({ "errcode": "M_UNKNOWN", "error": "fake server: malformed kick path" }));
        };
        let body = request.body.clone().unwrap_or_else(|| Value::Object(Map::new()));
        let Some(user_id) = body.get("user_id").and_then(Value::as_str).and_then(|s| UserId::parse(s).ok()) else {
            return json_response(400, &serde_json::json!({ "errcode": "M_MISSING_PARAM", "error": "fake server: missing user_id" }));
        };
        let reason = body.get("reason").and_then(Value::as_str);
        let Some(room) = self.rooms.get_mut(&room_id) else {
            return json_response(404, &serde_json::json!({ "errcode": "M_NOT_FOUND", "error": "fake server: unknown room" }));
        };
        let mut content = serde_json::json!({ "membership": "leave" });
        if let Some(reason) = reason {
            content["reason"] = Value::String(reason.to_string());
        }
        room.apply_state("m.room.member", user_id.as_str(), as_user, content);
        room.members.insert(user_id.clone(), Membership::Leave);
        json_response(200, &serde_json::json!({}))
    }

    /// `PUT /user/{userId}/account_data/{type}` -- overwrites the current
    /// value in full (module doc: always redelivered whole, no delta
    /// tracking).
    fn handle_account_data(&mut self, as_user: &UserId, request: &OutgoingRequest) -> HttpResponseDescriptor {
        let Some(event_type) = request.path.rsplit('/').next().map(percent_decode_minimal) else {
            return json_response(400, &serde_json::json!({ "errcode": "M_UNKNOWN", "error": "fake server: malformed account_data path" }));
        };
        let body = request.body.clone().unwrap_or_else(|| Value::Object(Map::new()));
        self.global_account_data.entry(as_user.clone()).or_default().insert(event_type, body);
        json_response(200, &serde_json::json!({}))
    }

    /// `POST /rooms/{roomId}/read_markers` -- a real server's own
    /// read-marker endpoint also broadcasts an `m.read` receipt when the
    /// body carries an `m.read` event id (module doc's own
    /// `room_receipts` note); `m.fully_read` itself is not modeled (this
    /// fake never round-trips it, matching every other "spec-shaped, not
    /// spec-complete" endpoint here).
    fn handle_read_markers(&mut self, as_user: &UserId, request: &OutgoingRequest) -> HttpResponseDescriptor {
        let Some(room_id) = parse_room_action_path(&request.path) else {
            return json_response(400, &serde_json::json!({ "errcode": "M_UNKNOWN", "error": "fake server: malformed read_markers path" }));
        };
        let body = request.body.clone().unwrap_or_else(|| Value::Object(Map::new()));
        if let Some(event_id) = body.get("m.read").and_then(Value::as_str).map(str::to_string) {
            let receipts = self.room_receipts.entry(room_id).or_insert_with(|| Value::Object(Map::new()));
            let receipts_obj = receipts.as_object_mut().expect("room_receipts entries are always objects");
            let per_event = receipts_obj.entry(event_id).or_insert_with(|| serde_json::json!({ "m.read": {} }));
            let per_event_obj = per_event.as_object_mut().expect("per-event receipts are always objects");
            let read_map = per_event_obj.entry("m.read".to_string()).or_insert_with(|| Value::Object(Map::new()));
            let read_map_obj = read_map.as_object_mut().expect("m.read is always an object");
            read_map_obj.insert(as_user.as_str().to_string(), serde_json::json!({ "ts": 0 }));
        }
        json_response(200, &serde_json::json!({}))
    }

    /// `PUT /user/{userId}/rooms/{roomId}/account_data/{type}`.
    fn handle_room_account_data(&mut self, as_user: &UserId, request: &OutgoingRequest) -> HttpResponseDescriptor {
        let Some((room_id, event_type)) = parse_room_account_data_path(&request.path) else {
            return json_response(
                400,
                &serde_json::json!({ "errcode": "M_UNKNOWN", "error": "fake server: malformed room account_data path" }),
            );
        };
        let body = request.body.clone().unwrap_or_else(|| Value::Object(Map::new()));
        self.room_account_data.entry((as_user.clone(), room_id)).or_default().insert(event_type, body);
        json_response(200, &serde_json::json!({}))
    }

    /// Announces, both ways, that `user_id` and every OTHER current
    /// join-or-invite member of `room_id` should now track each other's
    /// device lists -- real Matrix's own `device_lists.changed` semantics
    /// for "you now share a room with this user" (module doc; reuses the
    /// existing [`FakeServer::note_device_list_changed`] mechanism a test
    /// can also drive by hand).
    fn broadcast_membership_awareness(&mut self, room_id: &RoomId, user_id: &UserId) {
        let others: Vec<UserId> = self
            .rooms
            .get(room_id)
            .map(|room| {
                room.members
                    .iter()
                    .filter(|(other, membership)| matches!(membership, Membership::Join | Membership::Invite) && *other != user_id)
                    .map(|(other, _)| other.clone())
                    .collect()
            })
            .unwrap_or_default();
        for other in &others {
            self.broadcast_device_list_change(other, user_id);
            self.broadcast_device_list_change(user_id, other);
        }
    }

    /// Queues a `device_lists.changed` entry for `changed_user` on every
    /// device this fake has ever seen published for `for_user` (i.e. every
    /// `(for_user, *)` key in `self.devices`).
    fn broadcast_device_list_change(&mut self, for_user: &UserId, changed_user: &UserId) {
        let devices: Vec<DeviceId> =
            self.devices.keys().filter(|(user, _)| user == for_user).map(|(_, device)| device.clone()).collect();
        for device in devices {
            self.note_device_list_changed(for_user, &device, changed_user);
        }
    }

    /// Every event currently stored in `room_id`'s server-side timeline,
    /// oldest first, in the full `{event_id, type, sender,
    /// origin_server_ts, content}` shape [`FakeServer::handle_room_send`]
    /// stored it under.
    pub fn room_timeline(&self, room_id: &RoomId) -> Vec<Value> {
        self.room_timelines.get(room_id).map(|timeline| timeline.events.clone()).unwrap_or_default()
    }

    fn handle_sync(&mut self, as_user: &UserId, as_device: &DeviceId, request: &OutgoingRequest) -> HttpResponseDescriptor {
        let key = (as_user.clone(), as_device.clone());
        let since_index =
            request.query.iter().find(|(name, _)| name == "since").and_then(|(_, value)| parse_sync_token(value));

        let mailbox = self.to_device_mailboxes.entry(key.clone()).or_default();
        // The client naming `since_index` is its own proof it already
        // durably has everything before that position -- only now is it
        // safe to forget those events. A request that never advances
        // `since` (a lost response, a retry) re-prunes nothing new and so
        // redelivers the exact same remaining events, verbatim.
        if let Some(since_index) = since_index {
            if since_index > mailbox.base_index {
                let drop_count = (since_index - mailbox.base_index).min(mailbox.events.len());
                mailbox.events.drain(0..drop_count);
                mailbox.base_index += drop_count;
            }
        }
        let events = mailbox.events.clone();
        let next_batch_index = mailbox.base_index + mailbox.events.len();

        let changed: Vec<Value> = self
            .pending_device_list_changes
            .remove(&key)
            .unwrap_or_default()
            .into_iter()
            .map(|user_id| Value::String(user_id.as_str().to_string()))
            .collect();

        let (otk_count, fallback_unused) = match self.devices.get(&key) {
            Some(state) => (state.one_time_keys.len() as u64, state.fallback.is_some() && !state.fallback_used),
            None => (0, false),
        };
        let fallback_types: Vec<&str> = if fallback_unused { vec!["signed_curve25519"] } else { Vec::new() };

        let mut rooms_state = self.pending_room_state.remove(&key).unwrap_or_default();
        let mut rooms_timeline = self.pending_room_timeline.remove(&key).unwrap_or_default();
        let mut room_ids: BTreeMap<String, ()> = BTreeMap::new();
        for room_id in rooms_state.keys().chain(rooms_timeline.keys()) {
            room_ids.insert(room_id.as_str().to_string(), ());
        }
        let mut join = Map::new();
        for room_id_str in room_ids.into_keys() {
            let room_id = RoomId::parse(room_id_str).expect("a room id queued by this fake server is well-formed");
            let state_events = rooms_state.remove(&room_id).unwrap_or_default();
            let timeline_events = rooms_timeline.remove(&room_id).unwrap_or_default();
            join.insert(
                room_id.as_str().to_string(),
                serde_json::json!({
                    "state": { "events": state_events },
                    "timeline": { "events": timeline_events },
                }),
            );
        }

        // M13b's own broadcast rooms (`/createRoom` and friends) -- a
        // per-device cursor delta for a joined room, a current-state
        // snapshot (no cursor: harmless to redeliver, module doc) for an
        // invited one.
        let mut invite = Map::new();
        let room_ids_snapshot: Vec<RoomId> = self.rooms.keys().cloned().collect();
        for room_id in room_ids_snapshot {
            let membership = self.rooms.get(&room_id).and_then(|room| room.members.get(as_user)).cloned();
            match membership {
                Some(Membership::Join) => {
                    let room_account_events: Vec<Value> = self
                        .room_account_data
                        .get(&(as_user.clone(), room_id.clone()))
                        .map(|by_type| by_type.iter().map(|(t, c)| serde_json::json!({ "type": t, "content": c })).collect())
                        .unwrap_or_default();
                    // Same "always redeliver the current full value"
                    // convention as `room_account_events` above (module
                    // doc's own `room_receipts` note) -- harmless given
                    // this crate's own idempotent ephemeral folding.
                    let receipt_events: Vec<Value> = self
                        .room_receipts
                        .get(&room_id)
                        .map(|content| vec![serde_json::json!({ "type": "m.receipt", "content": content })])
                        .unwrap_or_default();
                    let cursor =
                        self.room_cursors.entry(key.clone()).or_default().entry(room_id.clone()).or_default();
                    let room = self.rooms.get(&room_id).expect("just matched Some(Join) above");
                    let state_events = room.state_log[cursor.state_seen..].to_vec();
                    let timeline_events = room.timeline_log[cursor.timeline_seen..].to_vec();
                    cursor.state_seen = room.state_log.len();
                    cursor.timeline_seen = room.timeline_log.len();
                    if !state_events.is_empty()
                        || !timeline_events.is_empty()
                        || !room_account_events.is_empty()
                        || !receipt_events.is_empty()
                    {
                        join.insert(
                            room_id.as_str().to_string(),
                            serde_json::json!({
                                "state": { "events": state_events },
                                "timeline": { "events": timeline_events },
                                "account_data": { "events": room_account_events },
                                "ephemeral": { "events": receipt_events },
                            }),
                        );
                    }
                }
                Some(Membership::Invite) => {
                    let room = self.rooms.get(&room_id).expect("just matched Some(Invite) above");
                    let stripped: Vec<Value> = room.current_state.values().map(to_stripped_state).collect();
                    invite.insert(room_id.as_str().to_string(), serde_json::json!({ "invite_state": { "events": stripped } }));
                }
                _ => {}
            }
        }

        let account_data_events: Vec<Value> = self
            .global_account_data
            .get(as_user)
            .map(|by_type| by_type.iter().map(|(t, c)| serde_json::json!({ "type": t, "content": c })).collect())
            .unwrap_or_default();

        json_response(
            200,
            &serde_json::json!({
                "next_batch": format!("s{next_batch_index}"),
                "rooms": { "join": Value::Object(join), "invite": Value::Object(invite) },
                "account_data": { "events": account_data_events },
                "to_device": { "events": events },
                "device_lists": { "changed": changed, "left": [] },
                "device_one_time_keys_count": { "signed_curve25519": otk_count },
                "device_unused_fallback_key_types": fallback_types,
            }),
        )
    }
}

/// Flips the first byte of whatever string sits under
/// `value["signatures"][user_id][<first key>]` -- used only to corrupt an
/// already-signed key object for a test, never for anything this crate
/// actually trusts.
fn corrupt_first_signature(value: &mut Value, user_id: &UserId) {
    let Some(by_user) = value.get_mut("signatures").and_then(|sigs| sigs.get_mut(user_id.as_str())) else { return };
    let Some(by_user_map) = by_user.as_object_mut() else { return };
    let Some(key_id) = by_user_map.keys().next().cloned() else { return };
    let Some(signature) = by_user_map.get(&key_id).and_then(Value::as_str) else { return };
    let mut bytes = signature.as_bytes().to_vec();
    bytes[0] ^= 0xFF;
    by_user_map.insert(key_id, Value::String(mail4agent_vodozemac::base64_encode(bytes)));
}
