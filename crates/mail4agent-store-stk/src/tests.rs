//! `SqliteMailStore` exercised directly through [`MailStore`], against an
//! in-memory [`stk_db::Db`]. `mail4agent-core`'s own engine-level
//! properties are proven again, end to end, in `engine_tests.rs`; these
//! tests are about the store's own contract -- what each method persists,
//! and the SQL each read query is built on.

use std::collections::BTreeSet;

use mail4agent_api::{Ack, Address, Message, MessageId, MessageRef, ParticipantId, RoomId};
use mail4agent_core::{InsertMessageOutcome, MailStore, ParticipantRecord, SecretDigest};
use stk_db::{Db, DbConfig, MigrationRunner};

use crate::{migrations, SqliteMailStore};

fn store() -> SqliteMailStore {
    SqliteMailStore::open_in_memory().expect("in-memory store opens and migrates")
}

fn participant(value: &str) -> ParticipantId {
    ParticipantId::new(value).expect("valid participant id")
}

fn room(value: &str) -> RoomId {
    RoomId::new(value).expect("valid room id")
}

fn message_id(byte: u8) -> MessageId {
    let hex = format!("{byte:02x}").repeat(12);
    MessageId::new(format!("m4a_{hex}")).expect("valid message id shape")
}

fn digest(byte: u8) -> SecretDigest {
    [byte; 32]
}

fn participant_record(digest_byte: u8) -> ParticipantRecord {
    ParticipantRecord {
        label: Some("label".to_string()),
        secret_digest: digest(digest_byte),
        may_send: true,
        may_read: true,
        operator: false,
    }
}

fn direct_message(id: MessageId, from: ParticipantId, to: ParticipantId, created_at_unix_ms: u64) -> Message {
    Message {
        message_id: id,
        from,
        to: Address::Direct { participant: to },
        subject: "subject".to_string(),
        body: "body".to_string(),
        reply_to: None,
        correlation: None,
        refs: Vec::new(),
        created_at_unix_ms,
    }
}

fn room_message(id: MessageId, from: ParticipantId, to: RoomId, created_at_unix_ms: u64) -> Message {
    Message {
        message_id: id,
        from,
        to: Address::Room { room: to },
        subject: "subject".to_string(),
        body: "body".to_string(),
        reply_to: None,
        correlation: None,
        refs: Vec::new(),
        created_at_unix_ms,
    }
}

#[test]
fn participant_round_trips_through_register_get_and_deregister() {
    let mut store = store();
    let alice = participant("alice");
    let record = participant_record(1);
    store.register_participant(alice.clone(), record.clone()).expect("registers");

    let fetched = store.get_participant(&alice).expect("get succeeds").expect("participant exists");
    assert_eq!(fetched, record);

    store.deregister_participant(&alice).expect("deregisters");
    assert_eq!(store.get_participant(&alice).expect("get succeeds"), None);
}

#[test]
fn set_participant_secret_digest_replaces_the_digest_and_updates_the_lookup() {
    let mut store = store();
    let alice = participant("alice");
    store.register_participant(alice.clone(), participant_record(1)).expect("registers");

    store.set_participant_secret_digest(&alice, digest(2)).expect("rotates digest");

    assert!(store.find_participant_by_digest(&digest(1)).expect("lookup succeeds").is_none());
    let (found_id, record) =
        store.find_participant_by_digest(&digest(2)).expect("lookup succeeds").expect("found by the new digest");
    assert_eq!(found_id, alice);
    assert_eq!(record.secret_digest, digest(2));
}

#[test]
fn find_participant_by_digest_finds_the_right_one_among_several() {
    let mut store = store();
    let alice = participant("alice");
    let bob = participant("bob");
    let carol = participant("carol");
    store.register_participant(alice.clone(), participant_record(1)).expect("alice registers");
    store.register_participant(bob.clone(), participant_record(2)).expect("bob registers");
    store.register_participant(carol.clone(), participant_record(3)).expect("carol registers");

    let (found_id, record) =
        store.find_participant_by_digest(&digest(2)).expect("lookup succeeds").expect("bob is found by his digest");
    assert_eq!(found_id, bob);
    assert_eq!(record.secret_digest, digest(2));
}

#[test]
fn room_and_membership_round_trip() {
    let mut store = store();
    let alice = participant("alice");
    let bob = participant("bob");
    store.register_participant(alice.clone(), participant_record(1)).expect("alice registers");
    store.register_participant(bob.clone(), participant_record(2)).expect("bob registers");
    let room_id = room("room-1");
    store.create_room(room_id.clone(), 1_000).expect("room is created");

    store.add_room_member(&room_id, alice.clone()).expect("alice joins");
    store.add_room_member(&room_id, bob.clone()).expect("bob joins");
    // Idempotent: adding an existing member is a no-op, not an error.
    store.add_room_member(&room_id, alice.clone()).expect("re-adding alice is a no-op");

    let fetched = store.get_room(&room_id).expect("get succeeds").expect("room exists");
    assert_eq!(fetched.created_at_unix_ms, 1_000);
    assert_eq!(fetched.members, BTreeSet::from([alice.clone(), bob.clone()]));

    assert_eq!(store.rooms_containing(&alice).expect("lookup succeeds"), vec![room_id]);
}

#[test]
fn removed_room_member_no_longer_appears_in_rooms_containing() {
    let mut store = store();
    let alice = participant("alice");
    store.register_participant(alice.clone(), participant_record(1)).expect("alice registers");
    let room_id = room("room-1");
    store.create_room(room_id.clone(), 1_000).expect("room is created");
    store.add_room_member(&room_id, alice.clone()).expect("alice joins");
    assert_eq!(store.rooms_containing(&alice).expect("lookup succeeds"), vec![room_id.clone()]);

    store.remove_room_member(&room_id, &alice).expect("alice leaves");
    // Idempotent: removing a non-member is a no-op, not an error.
    store.remove_room_member(&room_id, &alice).expect("re-removing alice is a no-op");

    assert!(store.rooms_containing(&alice).expect("lookup succeeds").is_empty());
    let fetched = store.get_room(&room_id).expect("get succeeds").expect("room still exists");
    assert!(fetched.members.is_empty());
}

#[test]
fn message_round_trips_through_insert_and_get() {
    let mut store = store();
    let alice = participant("alice");
    let bob = participant("bob");
    let msg = direct_message(message_id(1), alice, bob, 1_000);

    let outcome = store.insert_message(msg.clone(), None).expect("insert succeeds");
    assert_eq!(outcome, InsertMessageOutcome::Inserted);

    let fetched = store.get_message(&msg.message_id).expect("get succeeds").expect("message exists");
    assert_eq!(fetched, msg);
}

#[test]
fn message_round_trip_preserves_refs_reply_to_and_correlation() {
    let mut store = store();
    let alice = participant("alice");
    let bob = participant("bob");
    let mut msg = direct_message(message_id(2), alice, bob, 1_000);
    msg.reply_to = Some(message_id(1));
    msg.correlation = Some("task-42".to_string());
    msg.refs = vec![MessageRef { kind: "note".to_string(), locator: "loc".to_string(), digest: Some("ab".repeat(32)) }];

    store.insert_message(msg.clone(), None).expect("insert succeeds");
    let fetched = store.get_message(&msg.message_id).expect("get succeeds").expect("message exists");
    assert_eq!(fetched, msg);
}

#[test]
fn repeat_idempotency_key_returns_the_original_message_id_and_creates_nothing() {
    let mut store = store();
    let alice = participant("alice");
    let bob = participant("bob");
    let first = direct_message(message_id(1), alice.clone(), bob.clone(), 1_000);
    let second = direct_message(message_id(2), alice.clone(), bob.clone(), 2_000);

    let first_outcome = store
        .insert_message(first.clone(), Some((alice.clone(), "retry-1".to_string())))
        .expect("first insert succeeds");
    assert_eq!(first_outcome, InsertMessageOutcome::Inserted);

    let second_outcome = store
        .insert_message(second.clone(), Some((alice.clone(), "retry-1".to_string())))
        .expect("second insert with the same key succeeds");
    assert_eq!(second_outcome, InsertMessageOutcome::Deduplicated { message_id: first.message_id.clone() });

    assert!(store.get_message(&second.message_id).expect("get succeeds").is_none(), "the retried message was never created");
    assert_eq!(store.direct_messages_since(&bob, 0).expect("read succeeds").len(), 1, "only the first message exists");
}

#[test]
fn direct_messages_since_honours_the_since_bound_and_orders_by_created_at() {
    let mut store = store();
    let alice = participant("alice");
    let bob = participant("bob");
    store.insert_message(direct_message(message_id(1), alice.clone(), bob.clone(), 1_000), None).expect("insert succeeds");
    store.insert_message(direct_message(message_id(2), alice.clone(), bob.clone(), 3_000), None).expect("insert succeeds");
    store.insert_message(direct_message(message_id(3), alice.clone(), bob.clone(), 2_000), None).expect("insert succeeds");

    let page = store.direct_messages_since(&bob, 1_500).expect("read succeeds");
    let ids: Vec<_> = page.iter().map(|message| message.message_id.clone()).collect();
    assert_eq!(ids, vec![message_id(3), message_id(2)], "only messages at/after the bound, oldest first");
}

#[test]
fn room_messages_since_honours_the_since_bound_and_orders_by_created_at() {
    let mut store = store();
    let alice = participant("alice");
    let room_id = room("room-1");
    store.insert_message(room_message(message_id(1), alice.clone(), room_id.clone(), 1_000), None).expect("insert succeeds");
    store.insert_message(room_message(message_id(2), alice.clone(), room_id.clone(), 3_000), None).expect("insert succeeds");
    store.insert_message(room_message(message_id(3), alice.clone(), room_id.clone(), 2_000), None).expect("insert succeeds");

    let page = store.room_messages_since(&room_id, 1_500).expect("read succeeds");
    let ids: Vec<_> = page.iter().map(|message| message.message_id.clone()).collect();
    assert_eq!(ids, vec![message_id(3), message_id(2)], "only messages at/after the bound, oldest first");
}

#[test]
fn ack_round_trips_and_is_idempotent_on_first_write() {
    let mut store = store();
    let alice = participant("alice");
    let bob = participant("bob");
    let msg = direct_message(message_id(1), alice, bob.clone(), 1_000);
    store.insert_message(msg.clone(), None).expect("insert succeeds");

    assert_eq!(store.get_ack(&msg.message_id, &bob).expect("lookup succeeds"), None);

    let first = store
        .record_ack(Ack { message_id: msg.message_id.clone(), reader: bob.clone(), acked_at_unix_ms: 2_000 })
        .expect("first ack succeeds");
    let second = store
        .record_ack(Ack { message_id: msg.message_id.clone(), reader: bob.clone(), acked_at_unix_ms: 9_000 })
        .expect("second ack succeeds");

    assert_eq!(first, second);
    assert_eq!(first.acked_at_unix_ms, 2_000, "the first ack's timestamp wins, not the second's");
    assert_eq!(store.get_ack(&msg.message_id, &bob).expect("lookup succeeds"), Some(first));
}

#[test]
fn ack_is_keyed_by_message_and_reader_independently() {
    let mut store = store();
    let alice = participant("alice");
    let bob = participant("bob");
    let carol = participant("carol");
    let room_id = room("room-1");
    store.create_room(room_id.clone(), 1_000).expect("room is created");
    let msg = room_message(message_id(1), alice, room_id, 1_000);
    store.insert_message(msg.clone(), None).expect("insert succeeds");

    store
        .record_ack(Ack { message_id: msg.message_id.clone(), reader: bob.clone(), acked_at_unix_ms: 2_000 })
        .expect("bob acks");

    assert!(store.get_ack(&msg.message_id, &bob).expect("lookup succeeds").is_some());
    assert!(store.get_ack(&msg.message_id, &carol).expect("lookup succeeds").is_none(), "carol never acked");
}

#[test]
fn list_participants_and_list_rooms_return_the_full_current_set() {
    let mut store = store();
    let alice = participant("alice");
    let bob = participant("bob");
    store.register_participant(alice.clone(), participant_record(1)).expect("alice registers");
    store.register_participant(bob.clone(), participant_record(2)).expect("bob registers");
    let room_id = room("room-1");
    store.create_room(room_id.clone(), 1_000).expect("room is created");
    store.add_room_member(&room_id, alice.clone()).expect("alice joins");

    let participants = store.list_participants().expect("list succeeds");
    let participant_ids: BTreeSet<_> = participants.iter().map(|entry| entry.id.clone()).collect();
    assert_eq!(participant_ids, BTreeSet::from([alice.clone(), bob.clone()]));

    let rooms = store.list_rooms().expect("list succeeds");
    assert_eq!(rooms.len(), 1);
    assert_eq!(rooms[0].id, room_id);
    assert_eq!(rooms[0].members, BTreeSet::from([alice]));
}

#[test]
fn list_participants_stops_naming_a_deregistered_participant() {
    let mut store = store();
    let alice = participant("alice");
    let bob = participant("bob");
    store.register_participant(alice.clone(), participant_record(1)).expect("alice registers");
    store.register_participant(bob.clone(), participant_record(2)).expect("bob registers");

    store.deregister_participant(&bob).expect("bob is deregistered");

    let participant_ids: BTreeSet<_> = store.list_participants().expect("list succeeds").into_iter().map(|entry| entry.id).collect();
    assert_eq!(participant_ids, BTreeSet::from([alice]));
}

#[test]
fn neither_directory_listing_method_ever_carries_a_secret_digest_in_any_form() {
    let mut store = store();
    let alice = participant("alice");
    let bob = participant("bob");
    store.register_participant(alice.clone(), participant_record(0xab)).expect("alice registers");
    store.register_participant(bob.clone(), participant_record(0xcd)).expect("bob registers");
    let room_id = room("room-1");
    store.create_room(room_id.clone(), 1_000).expect("room is created");
    store.add_room_member(&room_id, alice.clone()).expect("alice joins");

    // The exact byte pattern of each digest, as Debug would render it if it
    // ever ended up inside a listed value -- not a substring guess, the
    // literal `[u8; 32]` debug output.
    let digest_ab_debug = format!("{:?}", digest(0xab));
    let digest_cd_debug = format!("{:?}", digest(0xcd));

    let participants_debug = format!("{:?}", store.list_participants().expect("list succeeds"));
    assert!(!participants_debug.contains(&digest_ab_debug), "list_participants leaked alice's secret digest");
    assert!(!participants_debug.contains(&digest_cd_debug), "list_participants leaked bob's secret digest");

    let rooms_debug = format!("{:?}", store.list_rooms().expect("list succeeds"));
    assert!(!rooms_debug.contains(&digest_ab_debug), "list_rooms leaked alice's secret digest");
    assert!(!rooms_debug.contains(&digest_cd_debug), "list_rooms leaked bob's secret digest");
}

#[test]
fn migrations_are_idempotent_when_run_twice_over_the_same_database() {
    let db = Db::open(&DbConfig::in_memory()).expect("in-memory db opens");
    db.run_migrations_blocking(MigrationRunner::new(migrations())).expect("first run applies the schema");
    db.run_migrations_blocking(MigrationRunner::new(migrations())).expect("second run over the same db is a no-op");

    // The schema is still usable afterwards: a second run neither
    // duplicated a table nor left the connection in a broken state.
    let mut mail_store = SqliteMailStore::new(db);
    let alice = participant("alice");
    mail_store.register_participant(alice.clone(), participant_record(1)).expect("store still works after a repeat migration run");
    assert!(mail_store.get_participant(&alice).expect("get succeeds").is_some());
}
