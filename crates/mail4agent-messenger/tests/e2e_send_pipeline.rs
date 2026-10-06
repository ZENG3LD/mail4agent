//! End-to-end send-pipeline tests (M13b, part 2) — two or three
//! [`MessengerCore`]s driven through [`FakeServer`]'s own real-room model
//! (`Room`/`room_cursors`, this fake's own module doc), using ONLY the
//! kernel API on every side: [`MessengerCore::dispatch`],
//! [`MessengerCore::releasable_requests`], [`MessengerCore::on_response`],
//! [`MessengerCore::take_flush_batch`]/[`MessengerCore::ack_flush`],
//! [`MessengerCore::timeline`]/[`MessengerCore::room_state`]/etc. Never
//! reaches into `crypto`/`room`/`store` internals for a core under test —
//! `e2e_core.rs`'s own `PeerClient` is the one place in this crate that
//! still drives Olm/Megolm managers directly, and that is scoped to the
//! receive-path piece (M13a) this file does not touch.
//!
//! # Helper shape
//!
//! [`Device`] pairs one simulated client's identity (`user_id`/`device_id`)
//! with its own [`MessengerCore`], so a test reads as a sequence of
//! `alice.dispatch(...)`/`alice.drive_until(...)` calls rather than
//! threading four parameters through every helper call by hand.
//! [`Device::drive_until`] is the one open-ended ("keep ticking till X is
//! true") loop shape in this file — bounded at [`MAX_TICKS`], panicking
//! with the caller-supplied `loop_name` if the condition never becomes true,
//! per this piece's own working-rule ("every drive loop... has an iteration
//! cap that panics naming the loop"). [`Device::drive_n`] is the other
//! shape, used for bootstrap: a fixed, small tick count, already bounded by
//! construction.

#[allow(dead_code)]
mod support;

use mail4agent_messenger::store::InsecurePlainCodecForTests;
use mail4agent_messenger::wire::{Membership, RoomMessageContent, TagContent};
use mail4agent_messenger::{
    CoreConfig, CoreSecrets, CreateRoomKind, DeviceId, EditRecord, Forwarded, ItemContent, Jitter, MessageKind,
    MessengerCommand, MessengerCore, MessengerEvent, OutgoingMessage, OutgoingRequestKind, RecordKey, RoomId,
    SealedRecord, SendState, TimelineItem, TxnId, UserId,
};
use std::collections::BTreeMap;
use support::fake_server::FakeServer;

type TestCore = MessengerCore<InsecurePlainCodecForTests>;

/// Bound on every open-ended ("keep ticking till X") drive loop in this
/// file's own helpers (module doc).
const MAX_TICKS: usize = 60;

struct FixedJitter(f64);

impl Jitter for FixedJitter {
    fn next_unit(&mut self) -> f64 {
        self.0
    }
}

fn core_config(user_id: &UserId, device_id: &DeviceId) -> CoreConfig {
    CoreConfig { user_id: user_id.clone(), device_id: device_id.clone(), server_name: "example.org".to_string() }
}

/// One simulated client: an identity plus its own [`MessengerCore`] — see
/// this file's own module doc.
struct Device {
    user_id: UserId,
    device_id: DeviceId,
    core: TestCore,
}

impl Device {
    fn new(user: &str, device: &str) -> Self {
        let user_id = UserId::parse(format!("@{user}:example.org")).expect("valid user id");
        let device_id = DeviceId::parse(device).expect("valid device id");
        let core = MessengerCore::open(
            Vec::new(),
            InsecurePlainCodecForTests,
            core_config(&user_id, &device_id),
            CoreSecrets::default(),
            0,
            Box::new(FixedJitter(0.0)),
        )
        .expect("open succeeds on a brand-new device");
        Self { user_id, device_id, core }
    }

    fn flush_and_ack(&mut self) {
        while let Some(batch) = self.core.take_flush_batch() {
            self.core.ack_flush(batch.id);
        }
    }

    /// One full shell tick against `server` — see `e2e_core.rs`'s own
    /// `drive_tick` doc for why this calls
    /// [`MessengerCore::releasable_requests`] exactly once and always
    /// drives every request it returns through to a response.
    fn drive_one(&mut self, server: &mut FakeServer, now_ms: i64) -> Vec<MessengerEvent> {
        self.flush_and_ack();
        let requests = self.core.releasable_requests(now_ms);
        let mut events = Vec::new();
        for request in requests {
            let response = server.dispatch(&self.user_id, &self.device_id, &request);
            events.extend(self.core.on_response(request.id.clone(), response, now_ms));
        }
        self.flush_and_ack();
        events
    }

    /// A fixed, small number of ticks — bounded by construction, no
    /// condition to fail on (module doc). Used for bootstrap, where "enough
    /// ticks for `/keys/upload` to land" is a known small constant
    /// (`e2e_core.rs`'s own precedent).
    fn drive_n(&mut self, server: &mut FakeServer, now_ms: i64, n: usize) -> Vec<MessengerEvent> {
        let mut events = Vec::new();
        for _ in 0..n {
            events.extend(self.drive_one(server, now_ms));
        }
        events
    }

    /// Ticks until `condition` holds, capped at [`MAX_TICKS`] — panics
    /// naming `loop_name` if it never does (module doc).
    fn drive_until(
        &mut self,
        server: &mut FakeServer,
        now_ms: i64,
        loop_name: &str,
        mut condition: impl FnMut(&TestCore) -> bool,
    ) -> Vec<MessengerEvent> {
        let mut events = Vec::new();
        for _ in 0..MAX_TICKS {
            events.extend(self.drive_one(server, now_ms));
            if condition(&self.core) {
                return events;
            }
        }
        panic!("{loop_name}: condition not met after {MAX_TICKS} ticks");
    }

    /// This device's own bootstrap: enough ticks for `/keys/upload` to land
    /// on `server` (`e2e_core.rs`'s own "a handful of ticks" precedent).
    fn bootstrap(&mut self, server: &mut FakeServer) {
        self.drive_n(server, 0, 8);
    }
}

/// `true` once `room_id`'s timeline holds an item whose plaintext body is
/// `body` — the non-panicking check every [`Device::drive_until`] predicate
/// waiting on a RECEIVER's own delivery must use instead of [`find_by_body`]
/// (a receiver may not have a `room_id` timeline entry at all yet — no
/// timeline event has arrived for it — until the very message being waited
/// on lands; `find_by_body` panicking on that is correct for a
/// post-condition assertion, but wrong for a predicate that is expected to
/// return `false` on every early tick).
fn has_body(core: &TestCore, room_id: &RoomId, body: &str) -> bool {
    core.timeline(room_id).is_some_and(|timeline| timeline.items().iter().any(|item| item_body(item) == Some(body)))
}

/// The one item in `room_id`'s timeline whose plaintext body is `body` —
/// works for [`mail4agent_messenger::ItemContent::Text`]/`Notice`/`Emote` alike.
/// Panics if `room_id` is unknown or no such item exists — use
/// [`has_body`] instead inside a [`Device::drive_until`] predicate.
fn find_by_body<'a>(core: &'a TestCore, room_id: &RoomId, body: &str) -> &'a TimelineItem {
    core.timeline(room_id)
        .expect("room present")
        .items()
        .iter()
        .find(|item| item_body(item).is_some_and(|b| b == body))
        .unwrap_or_else(|| panic!("no timeline item in {room_id:?} with body {body:?}"))
}

fn item_body(item: &TimelineItem) -> Option<&str> {
    match &item.content {
        ItemContent::Text(inner) | ItemContent::Notice(inner) | ItemContent::Emote(inner) => Some(inner.body.as_str()),
        _ => None,
    }
}

fn text_message(body: &str) -> OutgoingMessage {
    OutgoingMessage { kind: MessageKind::Text, body: body.to_string(), reply_to: None, edit_of: None }
}

fn edit_body(record: &EditRecord) -> Option<&str> {
    match &record.content {
        RoomMessageContent::Text(inner) | RoomMessageContent::Notice(inner) | RoomMessageContent::Emote(inner) => {
            Some(inner.body.as_str())
        }
        RoomMessageContent::Unknown(_) => None,
    }
}

fn is_joined(core: &TestCore, room_id: &RoomId, user_id: &UserId) -> bool {
    core.room_state(room_id).and_then(|state| state.members.get(user_id)).map(|member| &member.membership)
        == Some(&Membership::Join)
}

/// Bootstraps both `a` and `b`, has `a` create a DM inviting `b`, and drives
/// both until `b` has joined — the shared setup every encrypted-DM
/// send-pipeline test in this file starts from. Both devices are bootstrapped
/// BEFORE the room is created so this fake server's own
/// `broadcast_membership_awareness` (fired at `/createRoom`/`/join` time)
/// has an already-registered device to notify on each side (`e2e_core.rs`'s
/// own module doc explains why this ordering matters: a device that does not
/// exist yet cannot be queued a `device_lists.changed` notification).
fn create_dm(a: &mut Device, b: &mut Device, server: &mut FakeServer) -> RoomId {
    a.bootstrap(server);
    b.bootstrap(server);

    a.core.dispatch(MessengerCommand::CreateRoom { kind: CreateRoomKind::Dm { peer: b.user_id.clone() } }, 0).expect("dispatch create_room");
    a.drive_until(server, 0, "create_dm: alice's own room appears", |core| core.room_ids().next().is_some());
    let room_id = a.core.room_ids().next().cloned().expect("room present after drive_until");

    b.drive_until(server, 0, "create_dm: bob sees the invite", |core| core.room_ids().any(|id| id == &room_id));
    b.core.dispatch(MessengerCommand::JoinRoom { room_id: room_id.clone() }, 0).expect("dispatch join_room");
    let b_user_id = b.user_id.clone();
    b.drive_until(server, 0, "create_dm: bob's own join lands", |core| is_joined(core, &room_id, &b_user_id));

    room_id
}

#[test]
fn e2e_two_cores_exchange_messages_in_an_encrypted_dm() {
    let mut server = FakeServer::new();
    let mut alice = Device::new("alice", "ALICE1");
    let mut bob = Device::new("bob", "BOB1");
    let room_id = create_dm(&mut alice, &mut bob, &mut server);
    assert!(alice.core.room_state(&room_id).expect("room present").encryption.is_some(), "a DM is always encrypted");

    alice.core.dispatch(MessengerCommand::SendMessage { room_id: room_id.clone(), message: text_message("hi from alice"), txn_id: None }, 0)
        .expect("dispatch send_message");
    alice.drive_until(&mut server, 0, "alice's send reaches Sent", |core| {
        find_by_body(core, &room_id, "hi from alice").send_state == SendState::Sent
    });
    bob.drive_until(&mut server, 0, "bob receives alice's message", |core| has_body(core, &room_id, "hi from alice"));
    assert_eq!(item_body(find_by_body(&bob.core, &room_id, "hi from alice")), Some("hi from alice"));

    bob.core.dispatch(MessengerCommand::SendMessage { room_id: room_id.clone(), message: text_message("hi from bob"), txn_id: None }, 0)
        .expect("dispatch send_message");
    bob.drive_until(&mut server, 0, "bob's send reaches Sent", |core| {
        find_by_body(core, &room_id, "hi from bob").send_state == SendState::Sent
    });
    alice.drive_until(&mut server, 0, "alice receives bob's message", |core| has_body(core, &room_id, "hi from bob"));
    assert_eq!(item_body(find_by_body(&alice.core, &room_id, "hi from bob")), Some("hi from bob"));
}

#[test]
fn e2e_room_key_is_shared_before_the_message_is_sent() {
    let mut server = FakeServer::new();
    let mut alice = Device::new("alice", "ALICE1");
    let mut bob = Device::new("bob", "BOB1");
    let room_id = create_dm(&mut alice, &mut bob, &mut server);

    alice
        .core
        .dispatch(MessengerCommand::SendMessage { room_id: room_id.clone(), message: text_message("secret"), txn_id: None }, 0)
        .expect("dispatch send_message");
    alice.drive_until(&mut server, 0, "alice's send reaches Sent", |core| {
        find_by_body(core, &room_id, "secret").send_state == SendState::Sent
    });

    let log = server.request_log();
    let share_idx = log
        .iter()
        .position(|kind| *kind == OutgoingRequestKind::SendToDevice)
        .expect("a room-key share happened before the first encrypted send");
    let send_idx =
        log.iter().position(|kind| *kind == OutgoingRequestKind::RoomSend).expect("the room event itself was sent");
    assert!(share_idx < send_idx, "the room-key share must land before the room event it unblocks");
}

#[test]
fn e2e_three_cores_group_kick_excludes_leaver_from_new_messages() {
    let mut server = FakeServer::new();
    let mut alice = Device::new("alice", "ALICE1");
    let mut bob = Device::new("bob", "BOB1");
    let mut carol = Device::new("carol", "CAROL1");
    alice.bootstrap(&mut server);
    bob.bootstrap(&mut server);
    carol.bootstrap(&mut server);

    let kind = CreateRoomKind::Group {
        name: "trio".to_string(),
        invite: vec![bob.user_id.clone(), carol.user_id.clone()],
        members_can_invite: true,
    };
    alice.core.dispatch(MessengerCommand::CreateRoom { kind }, 0).expect("dispatch create_room");
    alice.drive_until(&mut server, 0, "alice's own room appears", |core| core.room_ids().next().is_some());
    let room_id = alice.core.room_ids().next().cloned().expect("room present");

    for member in [&mut bob, &mut carol] {
        member.drive_until(&mut server, 0, "member sees the invite", |core| core.room_ids().any(|id| id == &room_id));
        member.core.dispatch(MessengerCommand::JoinRoom { room_id: room_id.clone() }, 0).expect("dispatch join_room");
        let member_user_id = member.user_id.clone();
        member.drive_until(&mut server, 0, "member's own join lands", |core| is_joined(core, &room_id, &member_user_id));
    }

    alice
        .core
        .dispatch(MessengerCommand::SendMessage { room_id: room_id.clone(), message: text_message("hello all"), txn_id: None }, 0)
        .expect("dispatch send_message");
    alice.drive_until(&mut server, 0, "alice's first send reaches Sent", |core| {
        find_by_body(core, &room_id, "hello all").send_state == SendState::Sent
    });
    bob.drive_until(&mut server, 0, "bob decrypts the first message", |core| has_body(core, &room_id, "hello all"));
    carol.drive_until(&mut server, 0, "carol decrypts the first message", |core| has_body(core, &room_id, "hello all"));

    alice.core.dispatch(MessengerCommand::Kick { room_id: room_id.clone(), user_id: carol.user_id.clone(), reason: None }, 0)
        .expect("dispatch kick");
    let carol_user_id = carol.user_id.clone();
    alice.drive_until(&mut server, 0, "alice observes carol's own leave", |core| {
        core.room_state(&room_id).and_then(|state| state.members.get(&carol_user_id)).map(|member| &member.membership)
            == Some(&Membership::Leave)
    });

    alice
        .core
        .dispatch(MessengerCommand::SendMessage { room_id: room_id.clone(), message: text_message("bye carol"), txn_id: None }, 0)
        .expect("dispatch send_message");
    alice.drive_until(&mut server, 0, "alice's second send reaches Sent", |core| {
        find_by_body(core, &room_id, "bye carol").send_state == SendState::Sent
    });
    bob.drive_until(&mut server, 0, "bob decrypts the second message", |core| has_body(core, &room_id, "bye carol"));

    // Carol never receives it at all: once kicked, this fake server's own
    // `/sync` never again delivers this room's `join`/`invite` section to
    // her (`FakeServer`'s own module doc's `handle_sync` -- a `Leave`
    // membership falls into the match's `_ => {}` arm). A handful of ticks
    // is enough to prove absence without an open-ended wait.
    carol.drive_n(&mut server, 0, 6);
    assert!(
        carol.core.timeline(&room_id).is_none_or(|timeline| !timeline.items().iter().any(|item| item_body(item) == Some("bye carol"))),
        "the kicked member must never receive a message sent after her own kick"
    );
}

#[test]
fn e2e_edit_reply_and_reaction_round_trip() {
    let mut server = FakeServer::new();
    let mut alice = Device::new("alice", "ALICE1");
    let mut bob = Device::new("bob", "BOB1");
    let room_id = create_dm(&mut alice, &mut bob, &mut server);

    alice
        .core
        .dispatch(MessengerCommand::SendMessage { room_id: room_id.clone(), message: text_message("hello"), txn_id: None }, 0)
        .expect("dispatch send_message");
    alice.drive_until(&mut server, 0, "alice's message reaches Sent", |core| {
        find_by_body(core, &room_id, "hello").send_state == SendState::Sent
    });
    let msg1_id = find_by_body(&alice.core, &room_id, "hello").event_id.clone().expect("event id assigned on Sent");
    bob.drive_until(&mut server, 0, "bob receives alice's message", |core| has_body(core, &room_id, "hello"));
    let bob_item_count_before_edit = bob.core.timeline(&room_id).expect("room present").items().len();

    // Edit: alice edits her own message.
    let edit = OutgoingMessage { kind: MessageKind::Text, body: "hello v2".to_string(), reply_to: None, edit_of: Some(msg1_id.clone()) };
    alice.core.dispatch(MessengerCommand::SendMessage { room_id: room_id.clone(), message: edit, txn_id: None }, 0).expect("dispatch edit");
    alice.drive_until(&mut server, 0, "alice's edit reaches Sent", |core| {
        find_by_body(core, &room_id, "hello v2").send_state == SendState::Sent
    });
    let target_id = msg1_id.clone();
    bob.drive_until(&mut server, 0, "bob sees alice's edit", |core| {
        core.timeline(&room_id)
            .and_then(|timeline| timeline.item_by_event_id(&target_id))
            .and_then(|item| item.relations.latest_edit.as_ref())
            .and_then(edit_body)
            == Some("hello v2")
    });
    assert_eq!(
        bob.core.timeline(&room_id).expect("room present").items().len(),
        bob_item_count_before_edit,
        "an edit folds onto its target -- it never becomes its own row"
    );

    // Reply: bob replies to alice's (still-original-bodied) message.
    let reply = OutgoingMessage { kind: MessageKind::Text, body: "replying".to_string(), reply_to: Some(msg1_id.clone()), edit_of: None };
    bob.core.dispatch(MessengerCommand::SendMessage { room_id: room_id.clone(), message: reply, txn_id: None }, 0).expect("dispatch reply");
    bob.drive_until(&mut server, 0, "bob's reply reaches Sent", |core| {
        find_by_body(core, &room_id, "replying").send_state == SendState::Sent
    });
    alice.drive_until(&mut server, 0, "alice receives bob's reply", |core| has_body(core, &room_id, "replying"));
    assert_eq!(find_by_body(&alice.core, &room_id, "replying").relations.reply_to, Some(msg1_id.clone()));

    // Reaction: bob reacts to alice's message.
    bob.core
        .dispatch(MessengerCommand::React { room_id: room_id.clone(), target: msg1_id.clone(), key: "\u{1F44D}".to_string() }, 0)
        .expect("dispatch react");
    // A reaction never gets a local echo (`start_new_send`'s own doc: only
    // a `SendPayload::Message` does), so there is no timeline row to poll
    // for -- a plaintext reaction needs no key pipeline either, so a small
    // fixed tick count is enough to land it on the server.
    bob.drive_n(&mut server, 0, 6);
    let bob_user_id = bob.user_id.clone();
    let target_id = msg1_id.clone();
    alice.drive_until(&mut server, 0, "alice sees bob's reaction", |core| {
        core.timeline(&room_id)
            .and_then(|timeline| timeline.item_by_event_id(&target_id))
            .is_some_and(|item| item.relations.reactions.get("\u{1F44D}").is_some_and(|reactors| reactors.contains(&bob_user_id)))
    });
}

#[test]
fn e2e_channel_is_encrypted_and_members_decrypt() {
    let mut server = FakeServer::new();
    let mut alice = Device::new("alice", "ALICE1");
    let mut bob = Device::new("bob", "BOB1");
    alice.bootstrap(&mut server);
    bob.bootstrap(&mut server);

    let kind = CreateRoomKind::Channel { name: "announcements".to_string(), topic: None };
    alice.core.dispatch(MessengerCommand::CreateRoom { kind }, 0).expect("dispatch create_room");
    alice.drive_until(&mut server, 0, "alice's own channel appears", |core| core.room_ids().next().is_some());
    let room_id = alice.core.room_ids().next().cloned().expect("room present");
    assert!(
        alice.core.room_state(&room_id).expect("room present").encryption.is_some(),
        "public channels are E2E; join_rule alone marks them public"
    );

    // Public channel: join without invite (directory / shared link).
    bob.core.dispatch(MessengerCommand::JoinRoom { room_id: room_id.clone() }, 0).expect("dispatch join_room");
    let bob_user_id = bob.user_id.clone();
    bob.drive_until(&mut server, 0, "bob's own join lands", |core| is_joined(core, &room_id, &bob_user_id));
    // Alice must sync bob's join (and query his devices) before sending so
    // the Megolm room key is shared to him.
    alice.drive_until(&mut server, 0, "alice sees bob joined", |core| is_joined(core, &room_id, &bob_user_id));

    alice
        .core
        .dispatch(MessengerCommand::SendMessage { room_id: room_id.clone(), message: text_message("welcome"), txn_id: None }, 0)
        .expect("dispatch send_message");
    alice.drive_until(&mut server, 0, "alice's send reaches Sent", |core| {
        find_by_body(core, &room_id, "welcome").send_state == SendState::Sent
    });
    bob.drive_until(&mut server, 0, "bob decrypts the channel message", |core| has_body(core, &room_id, "welcome"));

    let item = find_by_body(&bob.core, &room_id, "welcome");
    assert_eq!(item_body(item), Some("welcome"));
}

fn count_typing(server: &FakeServer) -> usize {
    server.request_log().iter().filter(|kind| **kind == OutgoingRequestKind::Typing).count()
}

#[test]
fn e2e_typing_is_debounced() {
    let mut server = FakeServer::new();
    let mut alice = Device::new("alice", "ALICE1");
    let mut bob = Device::new("bob", "BOB1");
    let room_id = create_dm(&mut alice, &mut bob, &mut server);

    // Two `typing: true` asserts inside the debounce window (M13b's own
    // `TYPING_DEBOUNCE_MS` = 4000): the second is a pure no-op inside
    // dispatch itself (never even mints a request), so only one PUT ever
    // reaches the server.
    alice.core.dispatch(MessengerCommand::SetTyping { room_id: room_id.clone(), typing: true }, 0).expect("dispatch typing start");
    alice.core.dispatch(MessengerCommand::SetTyping { room_id: room_id.clone(), typing: true }, 1_000).expect("dispatch debounced re-assert");
    alice.drive_n(&mut server, 1_000, 6);
    assert_eq!(count_typing(&server), 1, "a re-assert inside the debounce window sends nothing new");

    // Past the debounce window: a fresh `true` sends again.
    alice.core.dispatch(MessengerCommand::SetTyping { room_id: room_id.clone(), typing: true }, 5_000).expect("dispatch past debounce");
    alice.drive_n(&mut server, 5_000, 6);
    assert_eq!(count_typing(&server), 2, "a re-assert past the debounce window sends a fresh PUT");

    // A `false` (stop) is never debounced (module doc: "false on send").
    alice.core.dispatch(MessengerCommand::SetTyping { room_id: room_id.clone(), typing: false }, 5_000).expect("dispatch typing stop");
    alice.drive_n(&mut server, 5_000, 6);
    assert_eq!(count_typing(&server), 3, "stopping typing is never debounced");
}

fn room_has_tag(core: &TestCore, room_id: &RoomId, tag: &str) -> bool {
    core.room_account_data(room_id, "m.tag").is_some_and(|value| {
        serde_json::from_value::<TagContent>(value.clone()).is_ok_and(|content| content.tags.contains_key(tag))
    })
}

#[test]
fn e2e_tags_round_trip_as_folders() {
    let mut server = FakeServer::new();
    let mut alice = Device::new("alice", "ALICE1");
    let mut bob = Device::new("bob", "BOB1");
    let room_id = create_dm(&mut alice, &mut bob, &mut server);

    // A tag is `m.tag` room account data -- visible only once it has
    // round-tripped through the server and back via `/sync`, not merely
    // dispatched (this crate keeps no separate "optimistic" tag cache).
    alice
        .core
        .dispatch(MessengerCommand::SetTag { room_id: room_id.clone(), tag: "work".to_string(), order: Some(0.5) }, 0)
        .expect("dispatch set_tag");
    alice.drive_until(&mut server, 0, "alice's own tag round-trips back to her", |core| room_has_tag(core, &room_id, "work"));

    alice.core.dispatch(MessengerCommand::RemoveTag { room_id: room_id.clone(), tag: "work".to_string() }, 0).expect("dispatch remove_tag");
    alice.drive_until(&mut server, 0, "alice's tag removal round-trips back to her", |core| !room_has_tag(core, &room_id, "work"));
}

#[test]
fn e2e_send_failure_marks_failed_and_retry_resends_identical_bytes() {
    let mut server = FakeServer::new();
    let mut alice = Device::new("alice", "ALICE1");
    let mut bob = Device::new("bob", "BOB1");
    let room_id = create_dm(&mut alice, &mut bob, &mut server);

    server.fail_next_room_send(room_id.clone(), "M_UNKNOWN");
    let txn_id = TxnId::new(900_001);
    alice
        .core
        .dispatch(
            MessengerCommand::SendMessage { room_id: room_id.clone(), message: text_message("resend me"), txn_id: Some(txn_id.clone()) },
            0,
        )
        .expect("dispatch send_message");
    alice.drive_until(&mut server, 0, "alice's send fails", |core| core.send_failure_reason(&txn_id) == Some("M_UNKNOWN"));
    assert_eq!(
        find_by_body(&alice.core, &room_id, "resend me").send_state,
        SendState::Failed { reason: "M_UNKNOWN".to_string() }
    );
    let first_body = server.last_rejected_room_send_body().cloned().expect("the failed attempt's own body was captured");

    alice.core.dispatch(MessengerCommand::RetrySend { room_id: room_id.clone(), txn_id: txn_id.clone() }, 0).expect("dispatch retry_send");
    alice.drive_until(&mut server, 0, "alice's retry succeeds", |core| {
        find_by_body(core, &room_id, "resend me").send_state == SendState::Sent
    });

    let (_, retried_body) = server.last_room_send().expect("the retry's own RoomSend was captured");
    assert_eq!(retried_body, &first_body, "a retry resends byte-identical ciphertext -- it never re-encrypts");
}

/// Drives `core` forward, durably persisting every flush batch into
/// `durable` as it goes (`e2e_core.rs`'s own `drive_tick_capturing`
/// pattern), until an [`OutgoingRequest`][mail4agent_messenger::wire::OutgoingRequest]
/// of kind `target_kind` becomes releasable — captured (its own body) and
/// returned WITHOUT ever calling [`MessengerCore::on_response`] for it
/// (every OTHER concurrently-releasable request in the same tick is driven
/// through normally). This is this file's own "simulate a crash after a
/// mutation is durable but before its response arrives" primitive
/// (`e2e_restart_...`'s own scenario) — bounded at [`MAX_TICKS`], panics
/// naming `loop_name` if `target_kind` never becomes releasable.
fn drive_until_pending_capture(
    core: &mut TestCore,
    server: &mut FakeServer,
    identity: (&UserId, &DeviceId),
    now_ms: i64,
    durable: &mut BTreeMap<String, Vec<u8>>,
    target_kind: OutgoingRequestKind,
    loop_name: &str,
) -> serde_json::Value {
    let (user_id, device_id) = identity;
    fn drain_into(core: &mut TestCore, durable: &mut BTreeMap<String, Vec<u8>>) {
        while let Some(batch) = core.take_flush_batch() {
            for record in batch.records {
                durable.insert(record.key.as_str().to_string(), record.bytes);
            }
            for key in batch.deletes {
                durable.remove(key.as_str());
            }
            core.ack_flush(batch.id);
        }
    }
    for _ in 0..MAX_TICKS {
        drain_into(core, durable);
        let requests = core.releasable_requests(now_ms);
        let mut captured = None;
        for request in requests {
            if request.kind == target_kind && captured.is_none() {
                captured = Some(request.body.clone().unwrap_or(serde_json::Value::Null));
                continue;
            }
            let response = server.dispatch(user_id, device_id, &request);
            core.on_response(request.id.clone(), response, now_ms);
        }
        drain_into(core, durable);
        if let Some(body) = captured {
            return body;
        }
    }
    panic!("{loop_name}: condition not met after {MAX_TICKS} ticks");
}

#[test]
fn e2e_restart_between_encrypt_and_send_resends_the_same_ciphertext() {
    let mut server = FakeServer::new();
    let mut alice = Device::new("alice", "ALICE1");
    let mut bob = Device::new("bob", "BOB1");
    let room_id = create_dm(&mut alice, &mut bob, &mut server);

    let mut durable: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let txn_id = TxnId::new(900_002);
    alice
        .core
        .dispatch(
            MessengerCommand::SendMessage { room_id: room_id.clone(), message: text_message("crash me"), txn_id: Some(txn_id.clone()) },
            0,
        )
        .expect("dispatch send_message");
    let original_body = drive_until_pending_capture(
        &mut alice.core,
        &mut server,
        (&alice.user_id, &alice.device_id),
        0,
        &mut durable,
        OutgoingRequestKind::RoomSend,
        "alice's ciphertext is durable before the simulated crash",
    );

    // "Crash": everything alice's core knew that never made it into
    // `durable` (its own in-memory-only "this request is in flight" flag,
    // in particular) is gone the moment this value is dropped.
    let user_id = alice.user_id.clone();
    let device_id = alice.device_id.clone();
    drop(alice);

    let records: Vec<SealedRecord> =
        durable.iter().map(|(key, bytes)| SealedRecord { key: RecordKey::new(key.clone()), bytes: bytes.clone() }).collect();
    let mut restarted = MessengerCore::open(
        records,
        InsecurePlainCodecForTests,
        core_config(&user_id, &device_id),
        CoreSecrets::default(),
        0,
        Box::new(FixedJitter(0.0)),
    )
    .expect("reopen succeeds");

    let resent_body = drive_until_pending_capture(
        &mut restarted,
        &mut server,
        (&user_id, &device_id),
        0,
        &mut durable,
        OutgoingRequestKind::RoomSend,
        "the restarted core re-releases the same pending RoomSend",
    );

    assert_eq!(
        resent_body, original_body,
        "a restart resends byte-identical ciphertext -- the flush-before-send barrier already made it durable before the crash"
    );
}

/// Has `a` create a private group inviting `b`, and drives both until `b` has
/// joined. Returns the group's id (the one room `a` did not know before).
fn create_group(a: &mut Device, b: &mut Device, server: &mut FakeServer, name: &str) -> RoomId {
    let known: Vec<RoomId> = a.core.room_ids().cloned().collect();
    let kind = CreateRoomKind::Group { name: name.to_string(), invite: vec![b.user_id.clone()], members_can_invite: true };
    a.core.dispatch(MessengerCommand::CreateRoom { kind }, 0).expect("dispatch create_room");
    a.drive_until(server, 0, "create_group: alice's own group appears", |core| core.room_ids().any(|id| !known.contains(id)));
    let room_id = a.core.room_ids().find(|id| !known.contains(id)).cloned().expect("the new group is present");

    b.drive_until(server, 0, "create_group: bob sees the invite", |core| core.room_ids().any(|id| id == &room_id));
    b.core.dispatch(MessengerCommand::JoinRoom { room_id: room_id.clone() }, 0).expect("dispatch join_room");
    let b_user_id = b.user_id.clone();
    b.drive_until(server, 0, "create_group: bob's own join lands", |core| is_joined(core, &room_id, &b_user_id));
    room_id
}

#[test]
fn e2e_forward_from_encrypted_dm_into_group_arrives_decrypted_with_hidden_marker() {
    let mut server = FakeServer::new();
    let mut alice = Device::new("alice", "ALICE1");
    let mut bob = Device::new("bob", "BOB1");
    let dm = create_dm(&mut alice, &mut bob, &mut server);
    let group = create_group(&mut alice, &mut bob, &mut server, "trio");
    assert!(alice.core.room_state(&group).expect("group present").encryption.is_some(), "a group is encrypted");

    // Bob says something private to alice in the DM; alice forwards it on.
    bob.core
        .dispatch(MessengerCommand::SendMessage { room_id: dm.clone(), message: text_message("meet at noon"), txn_id: None }, 0)
        .expect("dispatch send_message");
    bob.drive_until(&mut server, 0, "bob's DM message reaches Sent", |core| {
        find_by_body(core, &dm, "meet at noon").send_state == SendState::Sent
    });
    alice.drive_until(&mut server, 0, "alice decrypts bob's DM message", |core| has_body(core, &dm, "meet at noon"));
    let source = find_by_body(&alice.core, &dm, "meet at noon").event_id.clone().expect("a received event has an id");

    alice
        .core
        .dispatch(
            MessengerCommand::Forward { from_room: dm.clone(), event_id: source, to_room: group.clone(), txn_id: None },
            0,
        )
        .expect("dispatch forward");
    alice.drive_until(&mut server, 0, "alice's forward reaches Sent", |core| {
        core.timeline(&group).is_some_and(|timeline| {
            timeline.items().iter().any(|item| item.forwarded == Some(Forwarded::Hidden) && item.send_state == SendState::Sent)
        })
    });

    // The group event on the server is ciphertext only: no text, no marker.
    let (path, body) = server.last_room_send().expect("the forward's own RoomSend was captured");
    assert!(path.contains("/send/m.room.encrypted/"), "a forward into an encrypted room is encrypted: {path}");
    let wire = body.to_string();
    for clear in ["meet at noon", "forwarded"] {
        assert!(!wire.contains(clear), "{clear:?} must not be readable on the wire: {wire}");
    }

    // Bob opens it in the group: the text, marked as forwarded, sent by the
    // forwarder -- and nothing about where it came from.
    bob.drive_until(&mut server, 0, "bob receives the forward in the group", |core| has_body(core, &group, "meet at noon"));
    let item = find_by_body(&bob.core, &group, "meet at noon");
    assert_eq!(item.forwarded, Some(Forwarded::Hidden));
    assert_eq!(item.sender, alice.user_id, "the group sees the forwarder as the sender");
    assert_eq!(item_body(item), Some("meet at noon"));
}

#[test]
fn e2e_forward_from_public_channel_names_the_channel_for_the_recipient() {
    let mut server = FakeServer::new();
    let mut alice = Device::new("alice", "ALICE1");
    let mut bob = Device::new("bob", "BOB1");
    alice.bootstrap(&mut server);
    bob.bootstrap(&mut server);

    let kind = CreateRoomKind::Channel { name: "announcements".to_string(), topic: None };
    alice.core.dispatch(MessengerCommand::CreateRoom { kind }, 0).expect("dispatch create_room");
    alice.drive_until(&mut server, 0, "alice's own channel appears", |core| core.room_ids().next().is_some());
    let channel = alice.core.room_ids().next().cloned().expect("channel present");
    alice
        .core
        .dispatch(MessengerCommand::SendMessage { room_id: channel.clone(), message: text_message("big news"), txn_id: None }, 0)
        .expect("dispatch send_message");
    alice.drive_until(&mut server, 0, "alice's channel post reaches Sent", |core| {
        find_by_body(core, &channel, "big news").send_state == SendState::Sent
    });
    let source = find_by_body(&alice.core, &channel, "big news").event_id.clone().expect("event id assigned on Sent");

    let group = create_group(&mut alice, &mut bob, &mut server, "trio");
    alice
        .core
        .dispatch(
            MessengerCommand::Forward { from_room: channel.clone(), event_id: source, to_room: group.clone(), txn_id: None },
            0,
        )
        .expect("dispatch forward");
    alice.drive_until(&mut server, 0, "alice's forward reaches Sent", |core| {
        find_by_body(core, &group, "big news").send_state == SendState::Sent
    });
    bob.drive_until(&mut server, 0, "bob receives the forward in the group", |core| has_body(core, &group, "big news"));

    let item = find_by_body(&bob.core, &group, "big news");
    assert_eq!(
        item.forwarded,
        Some(Forwarded::Channel { room_id: channel, room_name: "announcements".to_string() }),
        "a public channel's own name is shown, taken from the source room's current state"
    );
    assert_eq!(item.sender, alice.user_id);
}
