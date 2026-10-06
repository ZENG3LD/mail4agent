//! End-to-end Olm 1:1 to-device tests (plan §5, M6) driven entirely through
//! [`support::fake_server::FakeServer`] -- no direct poking of internal
//! state that a real shell wouldn't also go through (`/keys/upload`,
//! `/keys/query`, `/keys/claim`, `/sendToDevice`, `/sync`), except where a
//! test's whole point is to forge or corrupt something a real peer never
//! would.

// `tests/support` is shared across every `tests/*.rs` integration-test
// binary in this crate (`e2e_olm_1to1.rs`, `e2e_megolm_group.rs`, and
// future ones), but each such file is compiled as its OWN independent
// crate -- an item `support::fake_server` exports for a SIBLING file's
// own tests (e.g. `room_timeline`, used only by `e2e_megolm_group.rs`) is
// genuinely unreachable from THIS binary's own compilation, even though
// it is exercised by a real, passing test elsewhere in this crate. This
// is `dead_code`'s well-known false positive for a shared, per-binary-
// compiled integration-test helper module, not actually unused code.
#[allow(dead_code)]
mod support;

use mail4agent_messenger::store::InsecurePlainCodecForTests;
use mail4agent_messenger::wire::RoomEncryptedContent;
use mail4agent_messenger::{
    CryptoStore, DecryptedToDevice, DeviceId, DeviceKeyChanged, DeviceTracker, KeysClaimOutcome, KeysQueryOutcome,
    OlmAccountState, OlmDecryptError, OlmSessionManager, OutgoingRequest, RequestId, RoomId, Store, StoredDevice,
    TxnId, UserId,
};
use serde_json::Value;
use support::fake_server::FakeServer;

/// One simulated device: its own identity, its own store, and a private
/// monotonic sequence for minting [`RequestId`]/[`TxnId`] values -- the
/// same shape a real shell (a later piece, M13's `MessengerCore`) would
/// hold per device session, just without the sync-engine plumbing that
/// isn't built yet.
struct TestClient {
    user_id: UserId,
    device_id: DeviceId,
    store: Store<InsecurePlainCodecForTests>,
    account: OlmAccountState,
    request_seq: u64,
}

impl TestClient {
    fn new(user: &str, device: &str) -> Self {
        let user_id = UserId::parse(format!("@{user}:example.org")).expect("valid user id");
        let device_id = DeviceId::parse(device).expect("valid device id");
        let mut store = Store::new(device_id.clone(), InsecurePlainCodecForTests);
        let account = OlmAccountState::load_or_create(&mut store).expect("create the device's Olm account");
        Self { user_id, device_id, store, account, request_seq: 0 }
    }

    fn next_request_id(&mut self) -> RequestId {
        self.request_seq += 1;
        RequestId::next(self.request_seq)
    }

    /// Tops up one-time/fallback keys and publishes everything via
    /// `/keys/upload` -- plan §4.1's "first unlock" sequence, minus the
    /// cross-signing upload (a later piece).
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

    /// This device's own [`StoredDevice`] shape, as a peer would come to
    /// know it via `/keys/query`.
    fn stored_device(&self) -> StoredDevice {
        let identity = self.account.identity_keys();
        StoredDevice {
            user_id: self.user_id.clone(),
            device_id: self.device_id.clone(),
            curve25519: identity.curve25519,
            ed25519: identity.ed25519,
            algorithms: vec!["m.olm.v1.curve25519-aes-sha2".to_string(), "m.megolm.v1.aes-sha2".to_string()],
            display_name: None,
            verified: false,
            blocked: false,
        }
    }

    /// Builds and dispatches a `/keys/query` for every currently-outdated
    /// tracked user, applying the response. `None` if nothing is
    /// outdated.
    fn resolve_outdated_devices(&mut self, server: &mut FakeServer) -> Option<KeysQueryOutcome> {
        let request_id = self.next_request_id();
        let request = DeviceTracker::keys_query_request(&self.store, request_id).expect("build the request")?;
        let response = server.dispatch(&self.user_id, &self.device_id, &request);
        assert_eq!(response.status, 200, "keys/query succeeds");
        Some(DeviceTracker::on_keys_query_response(&mut self.store, &response.body).expect("apply the response"))
    }

    /// Marks `peer` outdated and resolves it via a `/keys/query` round
    /// trip.
    fn query_devices(&mut self, server: &mut FakeServer, peer: &UserId) -> KeysQueryOutcome {
        DeviceTracker::on_device_lists(&mut self.store, std::slice::from_ref(peer), &[]).expect("mark peer outdated");
        self.resolve_outdated_devices(server).expect("peer was just marked outdated")
    }

    /// Performs one `/sync` and applies whatever `device_lists.changed`/
    /// `left` it reports through [`DeviceTracker::on_device_lists`] --
    /// unlike [`TestClient::query_devices`], this exercises the real
    /// `/sync`-reported path rather than marking a user outdated directly.
    fn sync_device_lists(&mut self, server: &mut FakeServer) {
        let request_id = self.next_request_id();
        let request = OutgoingRequest::sync(request_id, None, None);
        let response = server.dispatch(&self.user_id, &self.device_id, &request);
        assert_eq!(response.status, 200, "sync succeeds");
        let sync_response = mail4agent_messenger::wire::parse_sync_response(&response.body).expect("valid sync response");
        DeviceTracker::on_device_lists(
            &mut self.store,
            &sync_response.device_lists.changed,
            &sync_response.device_lists.left,
        )
        .expect("apply device_lists");
    }

    fn devices_of(&self, peer: &UserId) -> Vec<StoredDevice> {
        DeviceTracker::devices_for_user(&self.store, peer).expect("no store error")
    }

    /// Claims one-time keys for `devices` via `/keys/claim`, establishing
    /// an outbound session with each one that succeeds.
    fn claim(&mut self, server: &mut FakeServer, devices: &[&StoredDevice]) -> KeysClaimOutcome {
        let request_id = self.next_request_id();
        let request = OlmSessionManager::keys_claim_request(request_id, devices).expect("devices is non-empty");
        let response = server.dispatch(&self.user_id, &self.device_id, &request);
        assert_eq!(response.status, 200, "keys/claim succeeds");
        OlmSessionManager::on_keys_claim_response(&mut self.store, &self.account, devices, &response.body)
            .expect("apply the response")
    }

    /// Encrypts one to-device event for `target` and sends it via
    /// `/sendToDevice`.
    fn send_to_device(&mut self, server: &mut FakeServer, target: &StoredDevice, event_type: &str, content: Value) {
        let encrypted =
            OlmSessionManager::encrypt_to_device(&mut self.store, &self.account, &self.user_id, &self.device_id, target, event_type, content)
                .expect("encrypt");
        let wire_content = serde_json::to_value(RoomEncryptedContent::Olm(encrypted)).expect("serializes");
        let body = serde_json::json!({
            "messages": { target.user_id.as_str(): { target.device_id.as_str(): wire_content } }
        });
        let request_id = self.next_request_id();
        let seq = self.request_seq;
        let txn_id = TxnId::new(seq);
        let request = OutgoingRequest::send_to_device(request_id, "m.room.encrypted", &txn_id, body);
        let response = server.dispatch(&self.user_id, &self.device_id, &request);
        assert_eq!(response.status, 200, "sendToDevice succeeds");
    }

    /// Syncs once and decrypts every `m.room.encrypted` (Olm) to-device
    /// event the fake server had queued.
    fn sync_and_decrypt(&mut self, server: &mut FakeServer) -> Vec<DecryptedToDevice> {
        let request_id = self.next_request_id();
        let request = OutgoingRequest::sync(request_id, None, None);
        let response = server.dispatch(&self.user_id, &self.device_id, &request);
        assert_eq!(response.status, 200, "sync succeeds");
        let sync_response = mail4agent_messenger::wire::parse_sync_response(&response.body).expect("valid sync response");

        let mut decrypted = Vec::new();
        for event in sync_response.to_device.events {
            if event.event_type != "m.room.encrypted" {
                continue;
            }
            let content: RoomEncryptedContent =
                serde_json::from_value(event.content.clone()).expect("valid m.room.encrypted content");
            if let RoomEncryptedContent::Olm(olm_content) = content {
                let result = OlmSessionManager::decrypt_to_device(
                    &mut self.store,
                    &mut self.account,
                    &self.user_id,
                    &event.sender,
                    &olm_content,
                )
                .expect("decrypt");
                decrypted.push(result);
            }
        }
        decrypted
    }
}

#[test]
fn e2e_two_users_one_device_each_round_trip() {
    let mut server = FakeServer::new();
    let mut alice = TestClient::new("alice", "ALICEDEV");
    let mut bob = TestClient::new("bob", "BOBDEV");

    alice.bootstrap(&mut server);
    bob.bootstrap(&mut server);

    let bob_user = bob.user_id.clone();
    let alice_user = alice.user_id.clone();
    alice.query_devices(&mut server, &bob_user);
    bob.query_devices(&mut server, &alice_user);

    let bob_device = alice.devices_of(&bob_user).into_iter().next().expect("bob's device is known to alice");
    assert_eq!(bob_device, bob.stored_device());
    alice.claim(&mut server, &[&bob_device]);

    alice.send_to_device(&mut server, &bob_device, "m.test", serde_json::json!({ "hello": "bob" }));

    let decrypted = bob.sync_and_decrypt(&mut server);
    assert_eq!(decrypted.len(), 1);
    assert_eq!(decrypted[0].sender, alice_user);
    assert_eq!(decrypted[0].sender_ed25519, alice.account.identity_keys().ed25519);
    assert_eq!(decrypted[0].sender_device_curve25519, alice.account.identity_keys().curve25519);
    assert_eq!(decrypted[0].event_type, "m.test");
    assert_eq!(decrypted[0].content, serde_json::json!({ "hello": "bob" }));

    // The reply direction needs no fresh `/keys/claim`: decrypting alice's
    // pre-key message already established bob's own session with her.
    let alice_device = bob.devices_of(&alice_user).into_iter().next().expect("alice's device is known to bob");
    bob.send_to_device(&mut server, &alice_device, "m.test", serde_json::json!({ "hello": "alice" }));
    let decrypted_back = alice.sync_and_decrypt(&mut server);
    assert_eq!(decrypted_back.len(), 1);
    assert_eq!(decrypted_back[0].sender, bob_user);
    assert_eq!(decrypted_back[0].content, serde_json::json!({ "hello": "alice" }));
}

#[test]
fn e2e_user_with_two_devices() {
    let mut server = FakeServer::new();
    let mut alice = TestClient::new("alice", "ALICEDEV");
    let mut bob1 = TestClient::new("bob", "BOBDEV1");
    let mut bob2 = TestClient::new("bob", "BOBDEV2");

    alice.bootstrap(&mut server);
    bob1.bootstrap(&mut server);
    bob2.bootstrap(&mut server);

    let bob_user = bob1.user_id.clone();
    let alice_user = alice.user_id.clone();
    alice.query_devices(&mut server, &bob_user);
    bob1.query_devices(&mut server, &alice_user);
    bob2.query_devices(&mut server, &alice_user);
    let bob_devices = alice.devices_of(&bob_user);
    assert_eq!(bob_devices.len(), 2, "both of bob's devices are known to alice");

    let refs: Vec<&StoredDevice> = bob_devices.iter().collect();
    let outcome = alice.claim(&mut server, &refs);
    assert_eq!(outcome.established.len(), 2);
    assert!(outcome.refused.is_empty());

    for device in &bob_devices {
        let payload = serde_json::json!({ "to": device.device_id.as_str() });
        alice.send_to_device(&mut server, device, "m.test", payload);
    }

    let decrypted_1 = bob1.sync_and_decrypt(&mut server);
    let decrypted_2 = bob2.sync_and_decrypt(&mut server);
    assert_eq!(decrypted_1.len(), 1);
    assert_eq!(decrypted_2.len(), 1);
    assert_eq!(decrypted_1[0].content, serde_json::json!({ "to": "BOBDEV1" }));
    assert_eq!(decrypted_2[0].content, serde_json::json!({ "to": "BOBDEV2" }));
}

#[test]
fn e2e_otk_consumed_exactly_once() {
    let mut server = FakeServer::new();
    let mut alice = TestClient::new("alice", "ALICEDEV");
    let mut bob = TestClient::new("bob", "BOBDEV");

    // Exactly one regular OTK, no fallback -- isolates the exactly-once
    // guarantee this test is about.
    bob.account
        .on_sync_counts(&mut bob.store, 24, &["signed_curve25519".to_string()])
        .expect("top up to exactly one OTK");
    let request_id = bob.next_request_id();
    let upload = bob
        .account
        .keys_upload_request(request_id, &bob.user_id, &bob.device_id)
        .expect("build the request")
        .expect("something to upload");
    let response = server.dispatch(&bob.user_id, &bob.device_id, &upload);
    assert_eq!(response.status, 200);
    bob.account.on_keys_upload_response(&mut bob.store).expect("mark keys published");

    let bob_user = bob.user_id.clone();
    let bob_device_id = bob.device_id.clone();
    alice.query_devices(&mut server, &bob_user);
    let bob_device = alice.devices_of(&bob_user).into_iter().next().expect("bob is known");

    let first = alice.claim(&mut server, &[&bob_device]);
    assert_eq!(first.established, vec![(bob_user.clone(), bob_device_id.clone())]);

    let second = alice.claim(&mut server, &[&bob_device]);
    assert!(second.established.is_empty(), "the single OTK was already consumed");
    assert!(second.refused.is_empty(), "absent, not refused: nothing was left to claim");

    let sessions =
        alice.store.olm_sessions_for_device(&bob_device.curve25519.to_base64()).expect("no store error");
    assert_eq!(sessions.len(), 1, "the second, empty claim established no new session");
}

#[test]
fn e2e_mis_signed_otk_is_refused() {
    let mut server = FakeServer::new();
    let mut alice = TestClient::new("alice", "ALICEDEV");
    let mut bob = TestClient::new("bob", "BOBDEV");

    alice.bootstrap(&mut server);
    bob.bootstrap(&mut server);
    let bob_user = bob.user_id.clone();
    let bob_device_id = bob.device_id.clone();
    alice.query_devices(&mut server, &bob_user);
    let bob_device = alice.devices_of(&bob_user).into_iter().next().expect("bob is known");

    server.corrupt_one_time_key_signature(&bob_user, &bob_device_id);

    let outcome = alice.claim(&mut server, &[&bob_device]);
    assert!(outcome.established.is_empty(), "a mis-signed OTK must never establish a session");
    assert_eq!(outcome.refused.len(), 1);
    assert_eq!(outcome.refused[0].user_id, bob_user);
    assert_eq!(outcome.refused[0].device_id, bob_device_id);
    assert!(outcome.refused[0].reason.contains("signature"), "reason: {}", outcome.refused[0].reason);

    let sessions =
        alice.store.olm_sessions_for_device(&bob_device.curve25519.to_base64()).expect("no store error");
    assert!(sessions.is_empty(), "no session was established from a refused key");
}

#[test]
fn e2e_device_key_change_is_applied_and_flagged() {
    let mut server = FakeServer::new();
    let mut alice = TestClient::new("alice", "ALICEDEV");
    let mut bob = TestClient::new("bob", "BOBDEV");

    alice.bootstrap(&mut server);
    bob.bootstrap(&mut server);
    let bob_user = bob.user_id.clone();
    let bob_device_id = bob.device_id.clone();

    let first_outcome = alice.query_devices(&mut server, &bob_user);
    assert_eq!(first_outcome.accepted_devices, vec![(bob_user.clone(), bob_device_id.clone())]);
    let original = alice.devices_of(&bob_user).into_iter().next().expect("bob is known");

    // Same device id, new Olm identity — the authenticated store-loss reset
    // the server now accepts. Alice must take the new keys or Megolm to bob
    // stays black-holed under the old curve25519.
    let mut reset_store = Store::new(bob_device_id.clone(), InsecurePlainCodecForTests);
    let reset_account = OlmAccountState::load_or_create(&mut reset_store).expect("fresh reset account");
    let reset_device_keys =
        reset_account.device_keys_json(&bob_user, &bob_device_id).expect("reset self-signs its own keys");
    assert_ne!(reset_account.identity_keys().ed25519, original.ed25519, "reset has different keys");

    let reupload_id = alice.next_request_id();
    let reupload = OutgoingRequest::keys_upload(reupload_id, serde_json::json!({ "device_keys": reset_device_keys }));
    let response = server.dispatch(&bob_user, &bob_device_id, &reupload);
    assert_eq!(response.status, 200);

    server.note_device_list_changed(&alice.user_id, &alice.device_id, &bob_user);
    alice.sync_device_lists(&mut server);
    let second_outcome =
        alice.resolve_outdated_devices(&mut server).expect("bob is outdated after the sync-reported change");
    assert_eq!(
        second_outcome.key_changes,
        vec![DeviceKeyChanged { user_id: bob_user.clone(), device_id: bob_device_id.clone() }]
    );

    let after = alice.devices_of(&bob_user).into_iter().next().expect("still known");
    assert_ne!(after.curve25519, original.curve25519, "new identity keys are applied");
    assert_eq!(after.curve25519, reset_account.identity_keys().curve25519);
    assert!(!after.verified, "verification cleared on key reset");
}

#[test]
fn e2e_payload_with_wrong_recipient_keys_is_rejected() {
    let mut server = FakeServer::new();
    let mut alice = TestClient::new("alice", "ALICEDEV");
    let mut bob = TestClient::new("bob", "BOBDEV");
    let mut mallory = TestClient::new("mallory", "MALDEV");

    alice.bootstrap(&mut server);
    bob.bootstrap(&mut server);
    mallory.bootstrap(&mut server);

    let bob_user = bob.user_id.clone();
    let alice_user = alice.user_id.clone();
    alice.query_devices(&mut server, &bob_user);
    let bob_device = alice.devices_of(&bob_user).into_iter().next().expect("bob is known");
    alice.claim(&mut server, &[&bob_device]);
    // Bob needs to know alice's device for the payload's binding checks to
    // get as far as the `recipient_keys` check this test is about.
    bob.query_devices(&mut server, &alice_user);

    // Forge a plaintext payload with a deliberately WRONG
    // `recipient_keys.ed25519` (mallory's, not bob's), encrypted through
    // alice's real, already-established session with bob.
    let curve_b64 = bob_device.curve25519.to_base64();
    let pickle_bytes = alice
        .store
        .olm_sessions_for_device(&curve_b64)
        .expect("no store error")
        .last()
        .expect("a session with bob exists")
        .clone();
    let pickle: mail4agent_vodozemac::olm::SessionPickle = serde_json::from_slice(&pickle_bytes).expect("valid pickle");
    let mut session = mail4agent_vodozemac::olm::Session::from_pickle(pickle);

    let forged_payload = serde_json::json!({
        "type": "m.test",
        "content": { "malicious": true },
        "sender": alice.user_id.as_str(),
        "sender_device": alice.device_id.as_str(),
        "keys": { "ed25519": alice.account.identity_keys().ed25519.to_base64() },
        "recipient": bob.user_id.as_str(),
        "recipient_keys": { "ed25519": mallory.account.identity_keys().ed25519.to_base64() },
    });
    let olm_message =
        session.encrypt(serde_json::to_vec(&forged_payload).expect("valid JSON")).expect("encrypt the forged payload");
    let info = OlmSessionManager::encode_olm_message(&olm_message);
    let mut ciphertext = std::collections::BTreeMap::new();
    ciphertext.insert(curve_b64, info);
    let forged_content = mail4agent_messenger::wire::OlmEncryptedContent {
        sender_key: alice.account.identity_keys().curve25519.to_base64(),
        ciphertext,
    };

    let result =
        OlmSessionManager::decrypt_to_device(&mut bob.store, &mut bob.account, &bob.user_id, &alice_user, &forged_content);
    assert!(matches!(result, Err(OlmDecryptError::PayloadMismatch(_))), "got {result:?}");
}

#[test]
fn to_device_traffic_never_appears_in_a_room_timeline() {
    let mut server = FakeServer::new();
    let mut alice = TestClient::new("alice", "ALICEDEV");
    let mut bob = TestClient::new("bob", "BOBDEV");
    alice.bootstrap(&mut server);
    bob.bootstrap(&mut server);
    let bob_user = bob.user_id.clone();
    let alice_user = alice.user_id.clone();
    alice.query_devices(&mut server, &bob_user);
    bob.query_devices(&mut server, &alice_user);
    let bob_device = alice.devices_of(&bob_user).into_iter().next().expect("bob known");
    alice.claim(&mut server, &[&bob_device]);
    alice.send_to_device(&mut server, &bob_device, "m.test", serde_json::json!({ "hello": "bob" }));
    bob.sync_and_decrypt(&mut server);

    // `FakeServer::room_timeline` (a room-events getter the Megolm group
    // tests, `e2e_megolm_group.rs`, use to read back `/send`-stored
    // events) must stay empty here -- to-device delivery is a wholly
    // separate channel from any room's timeline, never the other way
    // around.
    let room_id = RoomId::parse("!unused-room:example.org").expect("valid room id");
    assert!(server.room_timeline(&room_id).is_empty(), "to-device traffic must never populate a room's timeline");
}

#[test]
fn to_device_redelivered_when_sync_response_is_lost() {
    let mut server = FakeServer::new();
    let mut alice = TestClient::new("alice", "ALICEDEV");
    let mut bob = TestClient::new("bob", "BOBDEV");

    alice.bootstrap(&mut server);
    bob.bootstrap(&mut server);
    let bob_user = bob.user_id.clone();
    let alice_user = alice.user_id.clone();
    alice.query_devices(&mut server, &bob_user);
    bob.query_devices(&mut server, &alice_user);
    let bob_device = alice.devices_of(&bob_user).into_iter().next().expect("bob known");
    alice.claim(&mut server, &[&bob_device]);
    alice.send_to_device(&mut server, &bob_device, "m.test", serde_json::json!({ "i": 0 }));

    // First sync (since=None): the message is delivered, but bob's
    // response never makes it back to him (dropped connection, crash,
    // ...) -- he never durably advances his own since token.
    let request_id_1 = bob.next_request_id();
    let sync1 = OutgoingRequest::sync(request_id_1, None, None);
    let response1 = server.dispatch(&bob.user_id, &bob.device_id, &sync1);
    let parsed1 = mail4agent_messenger::wire::parse_sync_response(&response1.body).expect("valid sync response");
    assert_eq!(parsed1.to_device.events.len(), 1, "message delivered on the first attempt");

    // Bob retries with the SAME (still-initial) since -- the lost
    // response's message must be redelivered, not gone.
    let request_id_2 = bob.next_request_id();
    let sync2 = OutgoingRequest::sync(request_id_2, None, None);
    let response2 = server.dispatch(&bob.user_id, &bob.device_id, &sync2);
    let parsed2 = mail4agent_messenger::wire::parse_sync_response(&response2.body).expect("valid sync response");
    assert_eq!(parsed2.to_device.events.len(), 1, "the lost response's message is redelivered, not lost");
    assert_eq!(parsed2.next_batch, parsed1.next_batch, "same since in, same next_batch out, deterministically");

    // Only once bob actually advances his since past what he was given
    // does the message stop being redelivered.
    let request_id_3 = bob.next_request_id();
    let sync3 = OutgoingRequest::sync(request_id_3, Some(parsed2.next_batch.as_str()), None);
    let response3 = server.dispatch(&bob.user_id, &bob.device_id, &sync3);
    let parsed3 = mail4agent_messenger::wire::parse_sync_response(&response3.body).expect("valid sync response");
    assert!(parsed3.to_device.events.is_empty(), "an acknowledged message is not redelivered");
}
