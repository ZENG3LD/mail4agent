//! End-to-end Megolm group tests (plan §5, M7) driven through
//! [`support::fake_server::FakeServer`]: `/keys/upload`, `/keys/query`,
//! `/keys/claim`, `/sendToDevice` (room-key sharing over Olm) and
//! `/rooms/{roomId}/send` (the actual Megolm ciphertext). Room membership
//! is supplied directly by each test as plain data (`BTreeSet<UserId>` +
//! `Vec<StoredDevice>`) -- this fake server has no `/createRoom`/`/invite`,
//! matching `tests/support/fake_server.rs`'s own documented scope.

// See `e2e_olm_1to1.rs`'s own `mod support;` for why this allow is here --
// `tests/support` is shared across every integration-test binary in this
// crate, each compiled independently, so a helper this file needs but a
// sibling file's own tests don't (or vice versa) is `dead_code`'s known
// per-binary false positive, not actually unused code.
#[allow(dead_code)]
mod support;

use mail4agent_messenger::wire::{parse_sync_response, RoomEncryptedContent};
use mail4agent_messenger::{
    DeviceId, DeviceTracker, GroupDecryptError, GroupSessionManager, OlmAccountState, OlmSessionManager,
    OutgoingRequest, RequestId, RoomEventPlaintext, RoomId, Store, StoredDevice, TxnId, UserId,
};
use mail4agent_messenger::store::InsecurePlainCodecForTests;
use mail4agent_messenger::wire::events::RoomEncryptionContent;
use serde_json::Value;
use std::collections::BTreeSet;
use support::fake_server::FakeServer;

const MEGOLM_ALGORITHM: &str = "m.megolm.v1.aes-sha2";

fn default_room_encryption() -> RoomEncryptionContent {
    RoomEncryptionContent { algorithm: MEGOLM_ALGORITHM.to_string(), rotation_period_ms: 604_800_000, rotation_period_msgs: 100 }
}

fn response_event_id(response: &mail4agent_messenger::wire::HttpResponseDescriptor) -> String {
    let body: Value = serde_json::from_slice(&response.body).expect("valid JSON body");
    body["event_id"].as_str().expect("event_id present").to_string()
}

/// One simulated device -- same shape as `e2e_olm_1to1.rs`'s own
/// `TestClient`, extended with the Megolm group operations this file's
/// tests need. Each `tests/*.rs` file is its own crate, so this cannot be
/// shared with `e2e_olm_1to1.rs` without a support-module change outside
/// this piece's scope; the small amount of duplication mirrors that
/// file's own self-contained style.
struct TestClient {
    user_id: UserId,
    device_id: DeviceId,
    store: Store<InsecurePlainCodecForTests>,
    account: OlmAccountState,
    request_seq: u64,
    /// This client's own `/sync` `next_batch` token, advanced after every
    /// [`TestClient::sync_and_ingest_room_keys`] call -- without this, a
    /// client that syncs more than once would have the fake server
    /// redeliver every historical to-device event each time (this fake's
    /// own documented since-token semantics), re-decrypting an
    /// already-consumed pre-key message and correctly, but confusingly,
    /// tripping this crate's own Olm replay protection.
    sync_token: Option<String>,
}

impl TestClient {
    fn new(user: &str, device: &str) -> Self {
        let user_id = UserId::parse(format!("@{user}:example.org")).expect("valid user id");
        let device_id = DeviceId::parse(device).expect("valid device id");
        let mut store = Store::new(device_id.clone(), InsecurePlainCodecForTests);
        let account = OlmAccountState::load_or_create(&mut store).expect("create the device's Olm account");
        Self { user_id, device_id, store, account, request_seq: 0, sync_token: None }
    }

    fn next_request_id(&mut self) -> RequestId {
        self.request_seq += 1;
        RequestId::next(self.request_seq)
    }

    fn next_txn_id(&mut self) -> TxnId {
        self.request_seq += 1;
        TxnId::new(self.request_seq)
    }

    fn bootstrap(&mut self, server: &mut FakeServer) {
        self.account.on_sync_counts(&mut self.store, 0, &[]).expect("generate OTKs and a fallback key");
        let request_id = self.next_request_id();
        let Some(request) =
            self.account.keys_upload_request(request_id, &self.user_id, &self.device_id).expect("build the request")
        else {
            return;
        };
        let response = server.dispatch(&self.user_id, &self.device_id, &request);
        assert_eq!(response.status, 200, "keys/upload succeeds");
        self.account.on_keys_upload_response(&mut self.store).expect("mark keys published");
    }

    fn resolve_outdated_devices(&mut self, server: &mut FakeServer) {
        let request_id = self.next_request_id();
        let Some(request) = DeviceTracker::keys_query_request(&self.store, request_id).expect("build the request") else {
            return;
        };
        let response = server.dispatch(&self.user_id, &self.device_id, &request);
        assert_eq!(response.status, 200, "keys/query succeeds");
        DeviceTracker::on_keys_query_response(&mut self.store, &response.body).expect("apply the response");
    }

    fn query_devices(&mut self, server: &mut FakeServer, peer: &UserId) {
        DeviceTracker::on_device_lists(&mut self.store, std::slice::from_ref(peer), &[]).expect("mark peer outdated");
        self.resolve_outdated_devices(server);
    }

    fn devices_of(&self, peer: &UserId) -> Vec<StoredDevice> {
        DeviceTracker::devices_for_user(&self.store, peer).expect("no store error")
    }

    fn claim(&mut self, server: &mut FakeServer, devices: &[&StoredDevice]) {
        let request_id = self.next_request_id();
        let Some(request) = OlmSessionManager::keys_claim_request(request_id, devices) else { return };
        let response = server.dispatch(&self.user_id, &self.device_id, &request);
        assert_eq!(response.status, 200, "keys/claim succeeds");
        OlmSessionManager::on_keys_claim_response(&mut self.store, &self.account, devices, &response.body)
            .expect("apply the response");
    }

    /// Ensures the outbound Megolm session for `room_id` reflects
    /// `member_user_ids`/`known_devices`, Olm-shares the room key with any
    /// new recipients (claiming missing one-time keys first), encrypts
    /// `content`, and sends it. Returns `(rotated, event_id)`.
    #[allow(clippy::too_many_arguments)]
    fn share_and_send(
        &mut self,
        server: &mut FakeServer,
        room_id: &RoomId,
        member_user_ids: &BTreeSet<UserId>,
        known_devices: &[StoredDevice],
        encryption: &RoomEncryptionContent,
        now_ms: i64,
        event_type: &str,
        content: Value,
    ) -> (bool, String) {
        let update = GroupSessionManager::ensure_outbound_session(
            &mut self.store,
            room_id,
            &self.user_id,
            &self.device_id,
            encryption,
            member_user_ids,
            known_devices,
            now_ms,
        )
        .expect("ensure outbound session");

        if let Some(room_key_content) = &update.room_key_content {
            let missing = OlmSessionManager::sessions_missing_for(&self.store, &update.new_recipients).expect("no store error");
            if !missing.is_empty() {
                self.claim(server, &missing);
            }
            for chunk in GroupSessionManager::chunk_recipients_for_send_to_device(&update.new_recipients) {
                let body = GroupSessionManager::build_room_key_send_to_device_body(
                    &mut self.store,
                    &self.account,
                    &self.user_id,
                    &self.device_id,
                    chunk,
                    room_key_content,
                )
                .expect("build the room_key to-device body");
                let request_id = self.next_request_id();
                let txn_id = self.next_txn_id();
                let request = OutgoingRequest::send_to_device(request_id, "m.room.encrypted", &txn_id, body);
                let response = server.dispatch(&self.user_id, &self.device_id, &request);
                assert_eq!(response.status, 200, "sendToDevice(m.room_key) succeeds");
            }
        }

        let sender_curve = self.account.identity_keys().curve25519.to_base64();
        let encrypted = GroupSessionManager::encrypt_event(
            &mut self.store,
            room_id,
            &sender_curve,
            &self.device_id,
            event_type,
            content,
            None,
        )
        .expect("encrypt the room event");
        let wire_content = serde_json::to_value(RoomEncryptedContent::Megolm(encrypted)).expect("serializes");
        let request_id = self.next_request_id();
        let txn_id = self.next_txn_id();
        let request = OutgoingRequest::room_send(request_id, room_id, "m.room.message", &txn_id, wire_content);
        let response = server.dispatch(&self.user_id, &self.device_id, &request);
        assert_eq!(response.status, 200, "room send succeeds");
        (update.rotated, response_event_id(&response))
    }

    /// Syncs once (advancing this client's own `since` token -- see
    /// [`TestClient::sync_token`]'s own doc for why that matters the
    /// moment a client syncs more than once), Olm-decrypts every to-device
    /// event, and feeds any `m.room_key` payloads into
    /// [`GroupSessionManager`].
    fn sync_and_ingest_room_keys(&mut self, server: &mut FakeServer) {
        let request_id = self.next_request_id();
        let request = OutgoingRequest::sync(request_id, self.sync_token.as_deref(), None);
        let response = server.dispatch(&self.user_id, &self.device_id, &request);
        assert_eq!(response.status, 200, "sync succeeds");
        let sync_response = parse_sync_response(&response.body).expect("valid sync response");
        self.sync_token = Some(sync_response.next_batch);

        for event in sync_response.to_device.events {
            if event.event_type != "m.room.encrypted" {
                continue;
            }
            let content: RoomEncryptedContent =
                serde_json::from_value(event.content.clone()).expect("valid m.room.encrypted content");
            let RoomEncryptedContent::Olm(olm_content) = content else { continue };
            let decrypted =
                OlmSessionManager::decrypt_to_device(&mut self.store, &mut self.account, &self.user_id, &event.sender, &olm_content)
                    .expect("decrypt the to-device event");
            GroupSessionManager::accept_room_key_from_to_device(&mut self.store, &decrypted).expect("accept the room key");
        }
    }

    /// Attempts to decrypt every `m.room.encrypted` (Megolm) event
    /// currently in `room_id`'s fake-server timeline, in server order.
    fn decrypt_room_timeline(&mut self, server: &FakeServer, room_id: &RoomId) -> Vec<Result<RoomEventPlaintext, GroupDecryptError>> {
        server
            .room_timeline(room_id)
            .into_iter()
            .filter(|event| event["type"] == "m.room.message")
            .map(|event| {
                let event_id = mail4agent_messenger::EventId::parse(event["event_id"].as_str().expect("event_id present").to_string())
                    .expect("valid event id");
                let origin_server_ts = event["origin_server_ts"].as_i64().expect("origin_server_ts present");
                let sender = UserId::parse(event["sender"].as_str().expect("sender present").to_string()).expect("valid sender");
                let content: RoomEncryptedContent =
                    serde_json::from_value(event["content"].clone()).expect("valid m.room.encrypted content");
                let RoomEncryptedContent::Megolm(megolm_content) = content else {
                    panic!("expected a megolm-encrypted room event, got {content:?}")
                };
                GroupSessionManager::decrypt_event(&mut self.store, room_id, &event_id, origin_server_ts, &sender, &megolm_content)
            })
            .collect()
    }
}

#[test]
fn e2e_three_devices_group_message_after_member_removed_excludes_leaver() {
    let mut server = FakeServer::new();
    let mut alice = TestClient::new("alice", "ALICEDEV");
    let mut bob = TestClient::new("bob", "BOBDEV");
    let mut carol1 = TestClient::new("carol", "CAROLDEV1");
    let mut carol2 = TestClient::new("carol", "CAROLDEV2");
    for client in [&mut alice, &mut bob, &mut carol1, &mut carol2] {
        client.bootstrap(&mut server);
    }

    let alice_user = alice.user_id.clone();
    let bob_user = bob.user_id.clone();
    let carol_user = carol1.user_id.clone();

    alice.query_devices(&mut server, &bob_user);
    alice.query_devices(&mut server, &carol_user);
    bob.query_devices(&mut server, &alice_user);
    carol1.query_devices(&mut server, &alice_user);
    carol2.query_devices(&mut server, &alice_user);

    let room_id = RoomId::parse("!room:example.org").expect("valid room id");
    let encryption = default_room_encryption();
    let mut members: BTreeSet<UserId> = [alice_user.clone(), bob_user.clone(), carol_user.clone()].into_iter().collect();
    let mut known_devices: Vec<StoredDevice> =
        alice.devices_of(&bob_user).into_iter().chain(alice.devices_of(&carol_user)).collect();
    assert_eq!(known_devices.len(), 3, "bob's one device plus carol's two");

    alice.share_and_send(&mut server, &room_id, &members, &known_devices, &encryption, 0, "m.room.message", serde_json::json!({"body": "msg1"}));

    bob.sync_and_ingest_room_keys(&mut server);
    carol1.sync_and_ingest_room_keys(&mut server);
    carol2.sync_and_ingest_room_keys(&mut server);

    assert!(bob.decrypt_room_timeline(&server, &room_id)[0].is_ok(), "bob decrypts message 1");
    assert!(carol1.decrypt_room_timeline(&server, &room_id)[0].is_ok(), "carol device 1 decrypts message 1");
    assert!(carol2.decrypt_room_timeline(&server, &room_id)[0].is_ok(), "carol device 2 decrypts message 1");

    // Carol is removed from the room.
    members.remove(&carol_user);
    known_devices.retain(|device| device.user_id != carol_user);

    let (rotated, _) =
        alice.share_and_send(&mut server, &room_id, &members, &known_devices, &encryption, 0, "m.room.message", serde_json::json!({"body": "msg2"}));
    assert!(rotated, "removing a member forces a fresh outbound session");

    bob.sync_and_ingest_room_keys(&mut server);

    let bob_results = bob.decrypt_room_timeline(&server, &room_id);
    assert_eq!(bob_results.len(), 2);
    assert!(bob_results[1].is_ok(), "bob (still a member) decrypts message 2");

    // Carol's devices never received the post-removal session -- this is
    // a real, structural UTD for her, not a bug.
    let carol1_results = carol1.decrypt_room_timeline(&server, &room_id);
    assert_eq!(carol1_results.len(), 2);
    assert!(carol1_results[0].is_ok(), "carol still has message 1 (forward secrecy is at the session boundary)");
    assert!(
        matches!(carol1_results[1], Err(GroupDecryptError::MissingSession { .. })),
        "got {:?}",
        carol1_results[1]
    );
}

#[test]
fn e2e_invitee_can_read_messages_sent_while_invited() {
    let mut server = FakeServer::new();
    let mut alice = TestClient::new("alice", "ALICEDEV");
    let mut dave = TestClient::new("dave", "DAVEDEV");
    alice.bootstrap(&mut server);
    dave.bootstrap(&mut server);

    let alice_user = alice.user_id.clone();
    let dave_user = dave.user_id.clone();
    alice.query_devices(&mut server, &dave_user);
    dave.query_devices(&mut server, &alice_user);

    let room_id = RoomId::parse("!invite-room:example.org").expect("valid room id");
    let encryption = default_room_encryption();
    // Dave is only INVITED, never joined -- still an eligible recipient
    // per this crate's recipient rule (join OR invite; our rooms use
    // `history_visibility: shared`).
    let members: BTreeSet<UserId> = [alice_user.clone(), dave_user.clone()].into_iter().collect();
    let known_devices = alice.devices_of(&dave_user);

    alice.share_and_send(&mut server, &room_id, &members, &known_devices, &encryption, 0, "m.room.message", serde_json::json!({"body": "welcome"}));
    dave.sync_and_ingest_room_keys(&mut server);

    let results = dave.decrypt_room_timeline(&server, &room_id);
    assert_eq!(results.len(), 1);
    assert!(results[0].is_ok(), "an invitee (not yet joined) can decrypt what was sent while invited");
}

#[test]
fn e2e_new_device_of_member_reads_new_messages_not_old() {
    let mut server = FakeServer::new();
    let mut alice = TestClient::new("alice", "ALICEDEV");
    let mut bob1 = TestClient::new("bob", "BOBDEV1");
    alice.bootstrap(&mut server);
    bob1.bootstrap(&mut server);

    let alice_user = alice.user_id.clone();
    let bob_user = bob1.user_id.clone();
    alice.query_devices(&mut server, &bob_user);
    bob1.query_devices(&mut server, &alice_user);

    let room_id = RoomId::parse("!room:example.org").expect("valid room id");
    let encryption = default_room_encryption();
    let members: BTreeSet<UserId> = [alice_user.clone(), bob_user.clone()].into_iter().collect();

    let known_devices_1 = alice.devices_of(&bob_user);
    alice.share_and_send(&mut server, &room_id, &members, &known_devices_1, &encryption, 0, "m.room.message", serde_json::json!({"body": "old"}));
    bob1.sync_and_ingest_room_keys(&mut server);
    assert!(bob1.decrypt_room_timeline(&server, &room_id)[0].is_ok(), "bob's original device reads the old message");

    // Bob logs in a second device.
    let mut bob2 = TestClient::new("bob", "BOBDEV2");
    bob2.bootstrap(&mut server);
    alice.query_devices(&mut server, &bob_user); // refreshes -- picks up bob's new device
    let known_devices_2 = alice.devices_of(&bob_user);
    assert_eq!(known_devices_2.len(), 2, "alice now knows both of bob's devices");

    let (rotated, _) =
        alice.share_and_send(&mut server, &room_id, &members, &known_devices_2, &encryption, 0, "m.room.message", serde_json::json!({"body": "new"}));
    assert!(!rotated, "a brand-new device of an already-shared member never forces rotation");

    bob2.query_devices(&mut server, &alice_user);
    bob2.sync_and_ingest_room_keys(&mut server);
    let bob2_results = bob2.decrypt_room_timeline(&server, &room_id);
    assert_eq!(bob2_results.len(), 2);
    assert!(
        matches!(bob2_results[0], Err(GroupDecryptError::Vodozemac(_))),
        "bob's new device was shared the session at its CURRENT index, so the old message's lower index is unreachable: {:?}",
        bob2_results[0]
    );
    assert!(bob2_results[1].is_ok(), "but it reads the new message, shared at its current index");
}

#[test]
fn e2e_crash_between_share_and_send_does_not_reuse_an_index() {
    let mut server = FakeServer::new();
    let mut alice = TestClient::new("alice", "ALICEDEV");
    let mut bob = TestClient::new("bob", "BOBDEV");
    alice.bootstrap(&mut server);
    bob.bootstrap(&mut server);

    let alice_user = alice.user_id.clone();
    let bob_user = bob.user_id.clone();
    alice.query_devices(&mut server, &bob_user);
    bob.query_devices(&mut server, &alice_user);

    let room_id = RoomId::parse("!room:example.org").expect("valid room id");
    let encryption = default_room_encryption();
    let members: BTreeSet<UserId> = [alice_user.clone(), bob_user.clone()].into_iter().collect();
    let known_devices = alice.devices_of(&bob_user);

    alice.share_and_send(&mut server, &room_id, &members, &known_devices, &encryption, 0, "m.room.message", serde_json::json!({"body": "first"}));

    // Simulate a crash right after the ratchet advance was persisted (this
    // crate's flush-before-send discipline: `GroupSessionManager::
    // encrypt_event` saves the advanced pickle before returning) --
    // rebuild alice's whole store from exactly what was flushed and acked,
    // discarding the in-memory state the "crashed" process held.
    let batch = alice.store.take_flush_batch().expect("sharing/encrypting dirtied the store");
    alice.store.ack_flush(batch.id);
    let mut reloaded_store =
        Store::load(batch.records, InsecurePlainCodecForTests, alice.device_id.clone()).expect("reload succeeds");
    let reloaded_account = OlmAccountState::load_or_create(&mut reloaded_store).expect("reload reuses the persisted account");
    alice.store = reloaded_store;
    alice.account = reloaded_account;

    // Sending again after the reload must not reuse message index 0.
    alice.share_and_send(&mut server, &room_id, &members, &known_devices, &encryption, 0, "m.room.message", serde_json::json!({"body": "second"}));

    bob.sync_and_ingest_room_keys(&mut server);
    let results = bob.decrypt_room_timeline(&server, &room_id);
    assert_eq!(results.len(), 2);
    let first = results[0].as_ref().expect("message 1 still decrypts");
    assert_eq!(first.content, serde_json::json!({"body": "first"}));
    let second = results[1].as_ref().expect("message 2 (sent after the reload) also decrypts");
    assert_eq!(second.content, serde_json::json!({"body": "second"}));
}
