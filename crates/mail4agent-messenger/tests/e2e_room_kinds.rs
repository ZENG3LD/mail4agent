//! E2E: public / private / DM rooms are all E2E-encrypted; public vs private
//! differs only in join rights (messenger-model).

#[allow(dead_code)]
mod support;

use mail4agent_messenger::store::InsecurePlainCodecForTests;
use mail4agent_messenger::wire::Membership;
use mail4agent_messenger::{
    CoreConfig, CoreSecrets, CreateRoomKind, DeviceId, ItemContent, Jitter, MessageKind, MessengerCommand,
    MessengerCore, MessengerEvent, OutgoingMessage, RoomId, SendState, TimelineItem, UserId,
};
use support::fake_server::FakeServer;

type TestCore = MessengerCore<InsecurePlainCodecForTests>;

const MAX_TICKS: usize = 60;

struct FixedJitter(f64);
impl Jitter for FixedJitter {
    fn next_unit(&mut self) -> f64 {
        self.0
    }
}

fn core_config(user_id: &UserId, device_id: &DeviceId) -> CoreConfig {
    CoreConfig {
        user_id: user_id.clone(),
        device_id: device_id.clone(),
        server_name: "example.org".to_string(),
    }
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
        .expect("open succeeds");
        Self { user_id, device_id, core }
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

    fn drive_until<F>(&mut self, server: &mut FakeServer, now_ms: i64, loop_name: &str, mut pred: F)
    where
        F: FnMut(&TestCore) -> bool,
    {
        for _ in 0..MAX_TICKS {
            if pred(&self.core) {
                return;
            }
            self.drive_one(server, now_ms);
        }
        panic!("{loop_name}: condition never became true within {MAX_TICKS} ticks");
    }

    fn bootstrap(&mut self, server: &mut FakeServer) {
        self.drive_n(server, 0, 8);
    }
}

fn text_message(body: &str) -> OutgoingMessage {
    OutgoingMessage {
        kind: MessageKind::Text,
        body: body.to_string(),
        reply_to: None,
        edit_of: None,
    }
}

fn is_joined(core: &TestCore, room_id: &RoomId, user_id: &UserId) -> bool {
    core.room_state(room_id)
        .and_then(|state| state.members.get(user_id))
        .map(|member| &member.membership)
        == Some(&Membership::Join)
}

fn item_body(item: &TimelineItem) -> Option<&str> {
    match &item.content {
        ItemContent::Text(inner) | ItemContent::Notice(inner) | ItemContent::Emote(inner) => Some(inner.body.as_str()),
        _ => None,
    }
}

fn find_by_body<'a>(core: &'a TestCore, room_id: &RoomId, body: &str) -> &'a TimelineItem {
    core.timeline(room_id)
        .expect("timeline")
        .items()
        .iter()
        .find(|item| item_body(item).is_some_and(|b| b == body))
        .unwrap_or_else(|| panic!("no timeline item with body {body:?}"))
}

fn has_body(core: &TestCore, room_id: &RoomId, body: &str) -> bool {
    core.timeline(room_id)
        .map(|timeline| timeline.items().iter().any(|item| item_body(item).is_some_and(|b| b == body)))
        .unwrap_or(false)
}

fn assert_encrypted(core: &TestCore, room_id: &RoomId, label: &str) {
    assert!(
        core.room_state(room_id).expect("room").encryption.is_some(),
        "{label} must be E2E encrypted"
    );
}

#[test]
fn e2e_public_channel_encrypted_join_without_invite_and_decrypt() {
    let mut server = FakeServer::new();
    let mut alice = Device::new("alice", "ALICE1");
    let mut bob = Device::new("bob", "BOB1");
    alice.bootstrap(&mut server);
    bob.bootstrap(&mut server);

    alice
        .core
        .dispatch(
            MessengerCommand::CreateRoom {
                kind: CreateRoomKind::Channel {
                    name: "town-square".into(),
                    topic: Some("open".into()),
                },
            },
            0,
        )
        .expect("create");
    alice.drive_until(&mut server, 0, "channel appears", |core| core.room_ids().next().is_some());
    let room_id = alice.core.room_ids().next().cloned().expect("room");
    assert_encrypted(&alice.core, &room_id, "public channel");

    bob.core.dispatch(MessengerCommand::JoinRoom { room_id: room_id.clone() }, 0).expect("join");
    let bob_user = bob.user_id.clone();
    bob.drive_until(&mut server, 0, "bob joined public", |core| is_joined(core, &room_id, &bob_user));
    alice.drive_until(&mut server, 0, "alice sees bob joined", |core| is_joined(core, &room_id, &bob_user));

    alice
        .core
        .dispatch(
            MessengerCommand::SendMessage {
                room_id: room_id.clone(),
                message: text_message("hello public"),
                txn_id: None,
            },
            0,
        )
        .expect("send");
    alice.drive_until(&mut server, 0, "sent", |core| {
        find_by_body(core, &room_id, "hello public").send_state == SendState::Sent
    });
    bob.drive_until(&mut server, 0, "bob decrypts", |core| has_body(core, &room_id, "hello public"));
}

#[test]
fn e2e_private_group_encrypted_stranger_cannot_join_invitee_decrypts() {
    let mut server = FakeServer::new();
    let mut alice = Device::new("alice", "ALICE1");
    let mut bob = Device::new("bob", "BOB1");
    let mut carol = Device::new("carol", "CAROL1");
    alice.bootstrap(&mut server);
    bob.bootstrap(&mut server);
    carol.bootstrap(&mut server);

    alice
        .core
        .dispatch(
            MessengerCommand::CreateRoom {
                kind: CreateRoomKind::Group {
                    name: "private".into(),
                    invite: vec![bob.user_id.clone()],
                    members_can_invite: false,
                },
            },
            0,
        )
        .expect("create");
    alice.drive_until(&mut server, 0, "group appears", |core| core.room_ids().next().is_some());
    let room_id = alice.core.room_ids().next().cloned().expect("room");
    assert_encrypted(&alice.core, &room_id, "private group");

    bob.drive_until(&mut server, 0, "bob invite", |core| core.room_ids().any(|id| id == &room_id));
    bob.core.dispatch(MessengerCommand::JoinRoom { room_id: room_id.clone() }, 0).expect("bob join");
    let bob_user = bob.user_id.clone();
    bob.drive_until(&mut server, 0, "bob joined", |core| is_joined(core, &room_id, &bob_user));

    carol.core.dispatch(MessengerCommand::JoinRoom { room_id: room_id.clone() }, 0).expect("dispatch");
    carol.drive_n(&mut server, 0, 12);
    let carol_user = carol.user_id.clone();
    assert!(
        !is_joined(&carol.core, &room_id, &carol_user),
        "stranger must not join a private room without invite"
    );

    alice
        .core
        .dispatch(
            MessengerCommand::SendMessage {
                room_id: room_id.clone(),
                message: text_message("members only"),
                txn_id: None,
            },
            0,
        )
        .expect("send");
    alice.drive_until(&mut server, 0, "sent", |core| {
        find_by_body(core, &room_id, "members only").send_state == SendState::Sent
    });
    bob.drive_until(&mut server, 0, "bob decrypts", |core| has_body(core, &room_id, "members only"));
}

#[test]
fn e2e_dm_is_encrypted_and_peer_decrypts() {
    let mut server = FakeServer::new();
    let mut alice = Device::new("alice", "ALICE1");
    let mut bob = Device::new("bob", "BOB1");
    alice.bootstrap(&mut server);
    bob.bootstrap(&mut server);

    alice
        .core
        .dispatch(
            MessengerCommand::CreateRoom {
                kind: CreateRoomKind::Dm {
                    peer: bob.user_id.clone(),
                },
            },
            0,
        )
        .expect("create");
    alice.drive_until(&mut server, 0, "dm appears", |core| core.room_ids().next().is_some());
    let room_id = alice.core.room_ids().next().cloned().expect("room");
    assert_encrypted(&alice.core, &room_id, "DM");

    bob.drive_until(&mut server, 0, "bob invite", |core| core.room_ids().any(|id| id == &room_id));
    bob.core.dispatch(MessengerCommand::JoinRoom { room_id: room_id.clone() }, 0).expect("join");
    let bob_user = bob.user_id.clone();
    bob.drive_until(&mut server, 0, "bob joined", |core| is_joined(core, &room_id, &bob_user));

    alice
        .core
        .dispatch(
            MessengerCommand::SendMessage {
                room_id: room_id.clone(),
                message: text_message("dm secret"),
                txn_id: None,
            },
            0,
        )
        .expect("send");
    alice.drive_until(&mut server, 0, "sent", |core| {
        find_by_body(core, &room_id, "dm secret").send_state == SendState::Sent
    });
    bob.drive_until(&mut server, 0, "bob decrypts", |core| has_body(core, &room_id, "dm secret"));
}
