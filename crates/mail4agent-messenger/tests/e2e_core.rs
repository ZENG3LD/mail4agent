//! End-to-end [`MessengerCore`] tests (plan §5, M13a) driven entirely
//! through the kernel API -- [`MessengerCore::open`],
//! [`MessengerCore::releasable_requests`], [`MessengerCore::on_response`],
//! [`MessengerCore::take_flush_batch`]/[`MessengerCore::ack_flush`] -- never
//! by reaching into `crypto`/`room`/`store` internals for the core under
//! test. The sending peer in
//! [`e2e_core_receives_and_decrypts_a_megolm_message_sent_by_a_manager_level_peer`]
//! is the one exception the task brief itself calls out: it still drives
//! the managers directly (`crypto::olm_sessions`/`crypto::group_sessions`),
//! exactly like `e2e_megolm_group.rs`'s own `TestClient` already does --
//! this file predates the send pipeline (`MessengerCommand::SendMessage`,
//! M13b) and is kept as-is rather than retrofitted; `e2e_send_pipeline.rs`
//! covers the same scenario, and every other M13b one, with a real
//! [`MessengerCore`] send pipeline on BOTH sides instead.

// See `e2e_olm_1to1.rs`'s own `mod support;` for why this allow is here --
// `tests/support` is shared across every integration-test binary in this
// crate, each compiled independently, so a helper this file needs but a
// sibling file's own tests don't (or vice versa) is `dead_code`'s known
// per-binary false positive, not actually unused code.
#[allow(dead_code)]
mod support;

use mail4agent_messenger::store::InsecurePlainCodecForTests;
use mail4agent_messenger::wire::events::RoomEncryptionContent;
use mail4agent_messenger::wire::RoomEncryptedContent;
use mail4agent_messenger::{
    CoreConfig, CoreSecrets, DeviceId, DeviceTracker, EventId, GroupSessionManager, ItemContent, Jitter,
    MessengerCore, MessengerEvent, OlmAccountState, OlmSessionManager, OutgoingRequest, OutgoingRequestKind,
    RecordKey, RequestId, RoomId, SealedRecord, Store, StoredDevice, TxnId, UserId,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use support::fake_server::FakeServer;

type TestCore = MessengerCore<InsecurePlainCodecForTests>;

struct FixedJitter(f64);

impl Jitter for FixedJitter {
    fn next_unit(&mut self) -> f64 {
        self.0
    }
}

fn core_config(user_id: &UserId, device_id: &DeviceId) -> CoreConfig {
    CoreConfig { user_id: user_id.clone(), device_id: device_id.clone(), server_name: "example.org".to_string() }
}

fn open_core(user_id: &UserId, device_id: &DeviceId) -> TestCore {
    MessengerCore::open(
        Vec::new(),
        InsecurePlainCodecForTests,
        core_config(user_id, device_id),
        CoreSecrets::default(),
        0,
        Box::new(FixedJitter(0.0)),
    )
    .expect("open succeeds on a brand-new device")
}

/// Drains and acks every flush batch a shell would need to persist right
/// now -- the flush-before-send barrier applies to a counter bump just as
/// much as an Olm/Megolm ratchet advance (`crate::core`'s own doc), so this
/// is called both before AND after minting/releasing requests in
/// [`drive_tick`].
fn flush_and_ack(core: &mut TestCore) {
    while let Some(batch) = core.take_flush_batch() {
        core.ack_flush(batch.id);
    }
}

/// One full shell tick: flush whatever is already dirty, then take
/// whatever [`MessengerCore::releasable_requests`] now allows, send each
/// request through `server`, and feed the result back via
/// [`MessengerCore::on_response`]. Returns every [`MessengerEvent`] this
/// tick produced.
///
/// [`MessengerCore::releasable_requests`]'s own doc: a non-empty result
/// must never be discarded (every request it returns is marked in flight
/// as a side effect of being returned, and nothing else will ever release
/// it again). This helper therefore only calls it ONCE per tick and always
/// drives every request it gets back through to a response -- a fresh
/// `/sync` request's own minted counter bump may still need one more flush
/// before it, specifically, becomes releasable, which the NEXT tick's own
/// leading `flush_and_ack` picks up.
fn drive_tick(core: &mut TestCore, server: &mut FakeServer, user_id: &UserId, device_id: &DeviceId, now_ms: i64) -> Vec<MessengerEvent> {
    flush_and_ack(core);
    let requests = core.releasable_requests(now_ms);
    let mut events = Vec::new();
    for request in requests {
        let response = server.dispatch(user_id, device_id, &request);
        events.extend(core.on_response(request.id.clone(), response, now_ms));
    }
    flush_and_ack(core);
    events
}

/// Same as [`drive_tick`], but also mirrors every flushed/acked record
/// into `durable` -- a plain `BTreeMap` standing in for a shell's own
/// on-disk key-value store, so a test can rebuild a fresh
/// [`MessengerCore`] from exactly what would have survived a restart at
/// this point.
fn drive_tick_capturing(
    core: &mut TestCore,
    server: &mut FakeServer,
    user_id: &UserId,
    device_id: &DeviceId,
    now_ms: i64,
    durable: &mut BTreeMap<String, Vec<u8>>,
) -> Vec<MessengerEvent> {
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
    drain_into(core, durable);
    let requests = core.releasable_requests(now_ms);
    let mut events = Vec::new();
    for request in requests {
        let response = server.dispatch(user_id, device_id, &request);
        events.extend(core.on_response(request.id.clone(), response, now_ms));
    }
    drain_into(core, durable);
    events
}

fn text_message_event(event_id: &str, sender: &UserId, ts: i64, body: &str) -> Value {
    serde_json::json!({
        "event_id": event_id,
        "type": "m.room.message",
        "sender": sender.as_str(),
        "origin_server_ts": ts,
        "content": { "msgtype": "m.text", "body": body },
    })
}

fn room_create_event(event_id: &str, sender: &UserId) -> Value {
    serde_json::json!({
        "event_id": event_id,
        "type": "m.room.create",
        "sender": sender.as_str(),
        "origin_server_ts": 1,
        "state_key": "",
        "content": { "creator": sender.as_str() },
    })
}

#[test]
fn e2e_core_initial_sync_then_incremental() {
    let mut server = FakeServer::new();
    let user_id = UserId::parse("@alice:example.org").expect("valid user id");
    let device_id = DeviceId::parse("DEV1").expect("valid device id");
    let room_id = RoomId::parse("!r:example.org").expect("valid room id");

    // Queued BEFORE the core ever syncs -- this is what an initial sync
    // (no `since` token yet) delivers.
    server.queue_room_state(&user_id, &device_id, &room_id, room_create_event("$create:example.org", &user_id));
    server.queue_room_timeline(&user_id, &device_id, &room_id, text_message_event("$1:example.org", &user_id, 1, "hello"));

    let mut core = open_core(&user_id, &device_id);

    // A handful of ticks covers this fresh device's own account bootstrap
    // (`/keys/upload`, driven off the first sync's own OTK counts) plus the
    // initial sync round trip itself.
    let mut initial_events = Vec::new();
    for _ in 0..6 {
        initial_events.extend(drive_tick(&mut core, &mut server, &user_id, &device_id, 0));
    }

    assert!(initial_events.contains(&MessengerEvent::RoomsChanged), "the initial sync's own room join is visible");
    let timeline = core.timeline(&room_id).expect("the room from the initial sync is present");
    assert_eq!(timeline.items().len(), 1, "the initial sync delivered exactly the one pre-queued message");
    assert!(core.room_state(&room_id).expect("room present").create.is_some());

    // Incremental: a second message, queued only now -- after the initial
    // sync already landed.
    server.queue_room_timeline(&user_id, &device_id, &room_id, text_message_event("$2:example.org", &user_id, 2, "world"));
    // Two ticks, regardless of exactly where the bootstrap loop above left
    // `sync_request_id`'s own phase: at most one of the two is a "mint
    // only" tick (nothing yet releasable), the other actually completes
    // the round trip.
    let mut events = drive_tick(&mut core, &mut server, &user_id, &device_id, 1_000);
    events.extend(drive_tick(&mut core, &mut server, &user_id, &device_id, 1_000));

    assert!(
        events.contains(&MessengerEvent::TimelineChanged { room_id: room_id.clone() }),
        "the incremental sync's own new message is visible"
    );
    let timeline = core.timeline(&room_id).expect("room still present");
    assert_eq!(timeline.items().len(), 2, "the incremental sync appended exactly the new message -- no duplicate, no loss");
}

/// One simulated manager-level peer -- same shape as
/// `e2e_megolm_group.rs`'s own `TestClient` (each `tests/*.rs` file is its
/// own crate, so this cannot be shared with that file without a
/// support-module change outside this piece's scope; the small duplication
/// mirrors that file's own self-contained style).
struct PeerClient {
    user_id: UserId,
    device_id: DeviceId,
    store: Store<InsecurePlainCodecForTests>,
    account: OlmAccountState,
    request_seq: u64,
}

impl PeerClient {
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

    fn query_devices(&mut self, server: &mut FakeServer, peer: &UserId) {
        DeviceTracker::on_device_lists(&mut self.store, std::slice::from_ref(peer), &[]).expect("mark peer outdated");
        let request_id = self.next_request_id();
        let Some(request) = DeviceTracker::keys_query_request(&self.store, request_id).expect("build the request") else {
            return;
        };
        let response = server.dispatch(&self.user_id, &self.device_id, &request);
        assert_eq!(response.status, 200, "keys/query succeeds");
        DeviceTracker::on_keys_query_response(&mut self.store, &response.body).expect("apply the response");
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

    /// Shares a fresh Megolm session with `recipients` (claiming a
    /// one-time key from each first) and sends one encrypted room event.
    /// Returns the server-assigned event id.
    #[allow(clippy::too_many_arguments)]
    fn share_and_send(
        &mut self,
        server: &mut FakeServer,
        room_id: &RoomId,
        member_user_ids: &BTreeSet<UserId>,
        known_devices: &[StoredDevice],
        encryption: &RoomEncryptionContent,
        now_ms: i64,
        content: Value,
    ) -> String {
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
            self.claim(server, &update.new_recipients.iter().collect::<Vec<_>>());
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
            "m.room.message",
            content,
            None,
        )
        .expect("encrypt the room event");
        let wire_content = serde_json::to_value(RoomEncryptedContent::Megolm(encrypted)).expect("serializes");
        let request_id = self.next_request_id();
        let txn_id = self.next_txn_id();
        // The WIRE event type is always `m.room.encrypted` (the spec's own
        // encryption-wraps-the-event rule) -- the inner plaintext's own
        // type (`m.room.message`, passed to `encrypt_event` above) is only
        // recoverable after decryption. Our core's own sync ingestion
        // dispatches on THIS outer type to find Megolm ciphertext at all,
        // unlike `e2e_megolm_group.rs`'s own `share_and_send`, which reads
        // the fake server's raw storage directly and never depends on it.
        let request = OutgoingRequest::room_send(request_id, room_id, "m.room.encrypted", &txn_id, wire_content);
        let response = server.dispatch(&self.user_id, &self.device_id, &request);
        assert_eq!(response.status, 200, "room send succeeds");
        let body: Value = serde_json::from_slice(&response.body).expect("valid JSON body");
        body["event_id"].as_str().expect("event_id present").to_string()
    }
}

#[test]
fn e2e_core_receives_and_decrypts_a_megolm_message_sent_by_a_manager_level_peer() {
    let mut server = FakeServer::new();
    let our_user = UserId::parse("@bob:example.org").expect("valid user id");
    let our_device = DeviceId::parse("BOBCORE").expect("valid device id");
    let mut core = open_core(&our_user, &our_device);

    // Enough ticks for this fresh core's own account bootstrap
    // (`/keys/upload`) to land on the fake server, so the peer below can
    // discover our device via `/keys/query`.
    for _ in 0..6 {
        drive_tick(&mut core, &mut server, &our_user, &our_device, 0);
    }

    // The peer is a manager-level client -- the send pipeline
    // (`MessengerCommand::SendMessage`) is M13b, not this piece; see this
    // file's own module doc.
    let mut peer = PeerClient::new("alice", "ALICEDEV");
    peer.bootstrap(&mut server);
    peer.query_devices(&mut server, &our_user);
    let our_devices = peer.devices_of(&our_user);
    assert_eq!(our_devices.len(), 1, "the peer discovered our core's own published device");

    // Our core must already know the peer's own device BEFORE the peer's
    // room key arrives: this crate's own sync ingestion order processes
    // to-device events (1) strictly before `device_lists.changed` (2), so
    // a room key delivered in the very same tick the sender's device list
    // change is first announced would fail `UnknownSenderDevice` -- and,
    // per `crypto::olm_sessions`'s own module doc, a *retry* of that exact
    // pre-key message can never succeed afterwards (Olm's own forward-
    // secrecy guarantee rejects it as a replay the moment the first
    // attempt already established the session). A real client's device
    // lists are essentially always already tracked from an earlier room
    // join/invite by the time a peer first messages it; this test
    // reproduces that ordering explicitly rather than racing it.
    server.note_device_list_changed(&our_user, &our_device, &peer.user_id);
    for _ in 0..3 {
        drive_tick(&mut core, &mut server, &our_user, &our_device, 0);
    }

    let room_id = RoomId::parse("!r:example.org").expect("valid room id");
    let members: BTreeSet<UserId> = [peer.user_id.clone(), our_user.clone()].into_iter().collect();
    let encryption =
        RoomEncryptionContent { algorithm: "m.megolm.v1.aes-sha2".to_string(), rotation_period_ms: 604_800_000, rotation_period_msgs: 100 };
    let event_id = peer.share_and_send(
        &mut server,
        &room_id,
        &members,
        &our_devices,
        &encryption,
        0,
        serde_json::json!({ "msgtype": "m.text", "body": "hi from the peer" }),
    );

    // Bridge the peer's server-stored room event into our core's own next
    // `/sync` mailbox -- this fake server has no real room broadcast (its
    // own documented scope: room membership is supplied directly by a
    // test, never derived from anything this fake tracks itself).
    for event in server.room_timeline(&room_id) {
        server.queue_room_timeline(&our_user, &our_device, &room_id, event);
    }

    // Drive our core through the to-device `m.room_key` delivery
    // (accepted via `GroupSessionManager`, this crate's own sync ingestion
    // order) and the room's own timeline event carrying the Megolm
    // ciphertext.
    for _ in 0..6 {
        drive_tick(&mut core, &mut server, &our_user, &our_device, 0);
    }

    let timeline = core.timeline(&room_id).expect("room joined via sync");
    let item = timeline
        .item_by_event_id(&EventId::parse(event_id).expect("valid event id"))
        .expect("the peer's room event is present");
    match &item.content {
        ItemContent::Text(text) => assert_eq!(text.body, "hi from the peer"),
        other => panic!("expected a decrypted text message, got {other:?}"),
    }
}

#[test]
fn e2e_core_restart_mid_session_resumes_from_records() {
    let mut server = FakeServer::new();
    let user_id = UserId::parse("@alice:example.org").expect("valid user id");
    let device_id = DeviceId::parse("DEV1").expect("valid device id");
    let room_id = RoomId::parse("!r:example.org").expect("valid room id");

    server.queue_room_state(&user_id, &device_id, &room_id, room_create_event("$create:example.org", &user_id));
    server.queue_room_timeline(&user_id, &device_id, &room_id, text_message_event("$1:example.org", &user_id, 1, "before restart"));

    let mut core = open_core(&user_id, &device_id);
    let mut durable: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for _ in 0..6 {
        drive_tick_capturing(&mut core, &mut server, &user_id, &device_id, 0, &mut durable);
    }
    assert_eq!(core.timeline(&room_id).expect("room present").items().len(), 1, "the pre-restart message landed");
    assert!(core.room_state(&room_id).expect("room present").create.is_some());

    // Simulate a restart: rebuild a fresh core from exactly the durable
    // records a shell would have persisted so far (a plain `BTreeMap`
    // standing in for its on-disk store).
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

    // Room STATE survives a restart; timeline CONTENT deliberately does
    // not (re-fetched instead -- `crate::core`'s own doc) -- the room
    // still exists, empty, ready to be re-populated by the next sync/back-
    // page.
    assert!(restarted.room_state(&room_id).expect("room state restored").create.is_some());
    assert_eq!(restarted.timeline(&room_id).expect("room entry restored").items().len(), 0);

    // The first request this restarted core releases must resume with the
    // persisted `since` token, not a fresh/initial sync.
    flush_and_ack(&mut restarted);
    restarted.releasable_requests(0);
    flush_and_ack(&mut restarted);
    let requests = restarted.releasable_requests(0);
    let sync_request = requests.iter().find(|r| r.kind == OutgoingRequestKind::Sync).expect("sync enqueued");
    assert!(
        sync_request.query.iter().any(|(name, _)| name == "since"),
        "resumes with the persisted sync token, not an initial sync"
    );
    let response = server.dispatch(&user_id, &device_id, sync_request);
    let sync_request_id = sync_request.id.clone();
    restarted.on_response(sync_request_id, response, 0);
    flush_and_ack(&mut restarted);

    // An incremental message arriving AFTER the restart lands normally.
    server.queue_room_timeline(&user_id, &device_id, &room_id, text_message_event("$2:example.org", &user_id, 2, "after restart"));
    let mut events = Vec::new();
    for _ in 0..4 {
        events.extend(drive_tick(&mut restarted, &mut server, &user_id, &device_id, 1));
    }
    let timeline = restarted.timeline(&room_id).expect("room still present");
    assert_eq!(
        timeline.items().len(),
        1,
        "only the post-restart message is present -- the pre-restart one was never persisted as timeline content, by design"
    );
    assert!(events.contains(&MessengerEvent::TimelineChanged { room_id: room_id.clone() }));
}
