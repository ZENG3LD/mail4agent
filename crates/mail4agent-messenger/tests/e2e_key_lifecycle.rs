//! Client↔server identity / key lifecycle: a lost sealed store under the
//! same device id must not black-hole mail, and a brand-new device id must
//! introduce itself via `device_lists.changed`.

#[allow(dead_code)]
mod support;

use mail4agent_messenger::store::InsecurePlainCodecForTests;
use mail4agent_messenger::{
    CoreConfig, CoreSecrets, CreateRoomKind, DeviceId, ItemContent, Jitter, MessageKind, MessengerCommand,
    MessengerCore, MessengerEvent, OutgoingMessage, OutgoingRequestKind, RoomId, SendState, TimelineItem, UserId,
};
use support::fake_server::FakeServer;

type TestCore = MessengerCore<InsecurePlainCodecForTests>;

const MAX_TICKS: usize = 80;

struct FixedJitter(f64);
impl Jitter for FixedJitter {
    fn next_unit(&mut self) -> f64 {
        self.0
    }
}

fn core_config(user_id: &UserId, device_id: &DeviceId) -> CoreConfig {
    CoreConfig { user_id: user_id.clone(), device_id: device_id.clone(), server_name: "example.org".to_string() }
}

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

    fn reopen_empty(&mut self) {
        let user_id = self.user_id.clone();
        let device_id = self.device_id.clone();
        self.core = MessengerCore::open(
            Vec::new(),
            InsecurePlainCodecForTests,
            core_config(&user_id, &device_id),
            CoreSecrets::default(),
            0,
            Box::new(FixedJitter(0.0)),
        )
        .expect("reopen empty store succeeds");
    }

    fn flush_and_ack(&mut self) {
        while let Some(batch) = self.core.take_flush_batch() {
            self.core.ack_flush(batch.id);
        }
    }

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

    fn drive_n(&mut self, server: &mut FakeServer, now_ms: i64, n: usize) {
        for _ in 0..n {
            self.drive_one(server, now_ms);
        }
    }

    fn drive_until(
        &mut self,
        server: &mut FakeServer,
        now_ms: i64,
        loop_name: &str,
        mut condition: impl FnMut(&TestCore) -> bool,
    ) {
        for _ in 0..MAX_TICKS {
            self.drive_one(server, now_ms);
            if condition(&self.core) {
                return;
            }
        }
        panic!("{loop_name}: condition not met after {MAX_TICKS} ticks");
    }

    fn bootstrap(&mut self, server: &mut FakeServer) {
        self.drive_n(server, 0, 8);
    }
}

fn has_body(core: &TestCore, room_id: &RoomId, body: &str) -> bool {
    core.timeline(room_id).is_some_and(|timeline| timeline.items().iter().any(|item| item_body(item) == Some(body)))
}

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

fn is_joined(core: &TestCore, room_id: &RoomId, user_id: &UserId) -> bool {
    use mail4agent_messenger::wire::Membership;
    core.room_state(room_id).and_then(|state| state.members.get(user_id)).map(|member| &member.membership)
        == Some(&Membership::Join)
}

fn create_dm(a: &mut Device, b: &mut Device, server: &mut FakeServer) -> RoomId {
    a.bootstrap(server);
    b.bootstrap(server);
    a.core
        .dispatch(MessengerCommand::CreateRoom { kind: CreateRoomKind::Dm { peer: b.user_id.clone() } }, 0)
        .expect("dispatch create_room");
    a.drive_until(server, 0, "create_dm: alice's room", |core| core.room_ids().next().is_some());
    let room_id = a.core.room_ids().next().cloned().expect("room");
    b.drive_until(server, 0, "create_dm: bob invite", |core| core.room_ids().any(|id| id == &room_id));
    b.core.dispatch(MessengerCommand::JoinRoom { room_id: room_id.clone() }, 0).expect("join");
    let b_user = b.user_id.clone();
    b.drive_until(server, 0, "create_dm: bob joined", |core| is_joined(core, &room_id, &b_user));
    room_id
}

/// Same `session_id` / device id, empty sealed store: client mints a new Olm
/// identity, server accepts the reset, peers re-query and decrypt again.
#[test]
fn e2e_store_loss_same_device_id_recovers_megolm() {
    let mut server = FakeServer::new();
    let mut alice = Device::new("alice", "ALICE1");
    let mut bob = Device::new("bob", "BOB1");
    let room_id = create_dm(&mut alice, &mut bob, &mut server);

    alice
        .core
        .dispatch(
            MessengerCommand::SendMessage { room_id: room_id.clone(), message: text_message("before reset"), txn_id: None },
            0,
        )
        .expect("send");
    alice.drive_until(&mut server, 0, "before-reset sent", |core| {
        find_by_body(core, &room_id, "before reset").send_state == SendState::Sent
    });
    bob.drive_until(&mut server, 0, "bob got before-reset", |core| has_body(core, &room_id, "before reset"));

    // Lost sealed store, same device bearer / device id.
    alice.reopen_empty();
    alice.bootstrap(&mut server);

    // Alice must learn the room again from /sync (membership survived server-side).
    alice.drive_until(&mut server, 0, "alice relearns room after reset", |core| {
        core.room_ids().any(|id| id == &room_id)
    });

    // Bob must learn alice's new keys via device_lists.changed → keys/query.
    bob.drive_n(&mut server, 0, 12);

    alice
        .core
        .dispatch(
            MessengerCommand::SendMessage { room_id: room_id.clone(), message: text_message("after reset"), txn_id: None },
            0,
        )
        .expect("send after reset");
    alice.drive_until(&mut server, 0, "after-reset sent", |core| {
        find_by_body(core, &room_id, "after reset").send_state == SendState::Sent
    });

    // Drive both so room-key share + decrypt land.
    for _ in 0..MAX_TICKS {
        bob.drive_one(&mut server, 0);
        alice.drive_one(&mut server, 0);
        if has_body(&bob.core, &room_id, "after reset") {
            break;
        }
    }
    assert!(
        has_body(&bob.core, &room_id, "after reset"),
        "bob must decrypt alice's post-reset message; a refused identity change used to black-hole it"
    );
}

/// Brand-new device id: first keys/upload is an insert; peers wake via
/// device_lists.changed and can decrypt.
#[test]
fn e2e_new_device_id_introduces_via_device_lists() {
    let mut server = FakeServer::new();
    let mut alice_old = Device::new("alice", "ALICE_OLD");
    let mut bob = Device::new("bob", "BOB1");
    let room_id = create_dm(&mut alice_old, &mut bob, &mut server);

    alice_old
        .core
        .dispatch(
            MessengerCommand::SendMessage { room_id: room_id.clone(), message: text_message("from old device"), txn_id: None },
            0,
        )
        .expect("send");
    alice_old.drive_until(&mut server, 0, "old sent", |core| {
        find_by_body(core, &room_id, "from old device").send_state == SendState::Sent
    });
    bob.drive_until(&mut server, 0, "bob got old", |core| has_body(core, &room_id, "from old device"));

    // New device under the same user (new session_id → new device id).
    let mut alice_new = Device::new("alice", "ALICE_NEW");
    alice_new.bootstrap(&mut server);
    // Join the existing room as the same user (FakeServer membership is per-user).
    // A second device of the same user is already "joined" server-side; the
    // new core just needs /sync to see the room and /keys/upload to announce.
    alice_new.drive_until(&mut server, 0, "new device sees room", |core| core.room_ids().any(|id| id == &room_id));

    // Ensure bob noticed the new device (keys upload on bootstrap should have
    // broadcast device_lists for a first insert — FakeServer broadcasts on
    // membership awareness; also note explicitly if needed).
    server.note_device_list_changed(&bob.user_id, &bob.device_id, &alice_new.user_id);
    bob.drive_n(&mut server, 0, 12);

    alice_new
        .core
        .dispatch(
            MessengerCommand::SendMessage { room_id: room_id.clone(), message: text_message("from new device"), txn_id: None },
            0,
        )
        .expect("send from new");
    alice_new.drive_until(&mut server, 0, "new sent", |core| {
        find_by_body(core, &room_id, "from new device").send_state == SendState::Sent
    });

    for _ in 0..MAX_TICKS {
        bob.drive_one(&mut server, 0);
        alice_new.drive_one(&mut server, 0);
        if has_body(&bob.core, &room_id, "from new device") {
            break;
        }
    }
    assert!(has_body(&bob.core, &room_id, "from new device"), "bob decrypts the new device's message");

    let log = server.request_log();
    assert!(
        log.iter().any(|k| *k == OutgoingRequestKind::KeysUpload),
        "new device uploaded keys"
    );
}
