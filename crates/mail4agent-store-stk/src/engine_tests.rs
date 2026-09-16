//! Proves `SqliteMailStore` is interchangeable with
//! `mail4agent_core::InMemoryStore` from `MailboxEngine`'s point of view:
//! the same properties `mail4agent-core`'s own tests
//! (`mail4agent-core/src/tests.rs`) prove against `InMemoryStore` are
//! reproduced here, end to end, against this crate's store instead.

use mail4agent_api::{Address, ParticipantId, RoomId, SendRequest};
use mail4agent_core::{MailboxEngine, ParticipantPermissions};

use crate::SqliteMailStore;

fn engine() -> MailboxEngine<SqliteMailStore> {
    MailboxEngine::new(SqliteMailStore::open_in_memory().expect("in-memory store opens and migrates"))
}

fn permissions(may_send: bool, may_read: bool, operator: bool) -> ParticipantPermissions {
    ParticipantPermissions { may_send, may_read, operator }
}

fn send_request(to: Address) -> SendRequest {
    SendRequest {
        to,
        subject: "subject".to_string(),
        body: "body".to_string(),
        reply_to: None,
        correlation: None,
        refs: Vec::new(),
        idempotency_key: None,
    }
}

#[test]
fn full_mailbox_scenario_matches_in_memory_store_outcomes() {
    let mut engine = engine();

    let alice = ParticipantId::new("alice").expect("valid participant id");
    let bob = ParticipantId::new("bob").expect("valid participant id");
    let room_id = RoomId::new("room-1").expect("valid room id");

    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    engine.create_room(room_id.clone(), 1_000).expect("room is created");
    engine.add_room_member(&room_id, bob.clone()).expect("bob joins the room");

    let direct = engine
        .send(&alice, send_request(Address::Direct { participant: bob.clone() }), 2_000)
        .expect("direct send succeeds");
    let to_room = engine
        .send(&alice, send_request(Address::Room { room: room_id.clone() }), 3_000)
        .expect("room send succeeds");

    // Alice sent both messages but is addressed by neither, so her own
    // inbox is empty -- `participant_cannot_read_anothers_direct_mail`'s
    // property against `InMemoryStore`.
    let alice_inbox = engine.inbox(&alice, 0, 50).expect("alice reads her inbox");
    assert!(alice_inbox.messages.is_empty());

    // Bob reads both the direct message and the room message he belongs
    // to -- `room_member_reads_room_mail_and_non_member_does_not`'s
    // property.
    let bob_inbox = engine.inbox(&bob, 0, 50).expect("bob reads his inbox");
    let bob_ids: std::collections::BTreeSet<_> = bob_inbox.messages.iter().map(|message| message.message_id.clone()).collect();
    assert_eq!(bob_ids, std::collections::BTreeSet::from([direct.message_id.clone(), to_room.message_id.clone()]));
    assert_eq!(bob_inbox.unread, 2);

    // Acking the direct message leaves it in the inbox but drops it from
    // the unread count; a second ack of the same message returns the
    // first ack unchanged -- `ack_is_idempotent`'s property.
    let first_ack = engine.ack(&bob, &direct.message_id, 4_000).expect("bob acks the direct message");
    let second_ack = engine.ack(&bob, &direct.message_id, 9_000).expect("bob acks it again");
    assert_eq!(first_ack, second_ack);
    assert_eq!(first_ack.acked_at_unix_ms, 4_000);

    let bob_inbox_after_ack = engine.inbox(&bob, 0, 50).expect("bob reads his inbox again");
    assert_eq!(bob_inbox_after_ack.messages.len(), 2, "acking does not remove a message from the inbox");
    assert_eq!(bob_inbox_after_ack.unread, 1, "only the room message is still unread");

    // Removing bob from the room drops the room message from his inbox
    // entirely, present-tense, while the direct message he already
    // received stays -- `removed_member_stops_reading_new_room_mail`'s
    // property.
    engine.remove_room_member(&room_id, &bob).expect("bob leaves the room");
    let bob_inbox_after_leaving = engine.inbox(&bob, 0, 50).expect("bob reads his inbox a third time");
    assert_eq!(
        bob_inbox_after_leaving.messages.iter().map(|message| &message.message_id).collect::<Vec<_>>(),
        vec![&direct.message_id]
    );
    assert_eq!(bob_inbox_after_leaving.unread, 0);

    // Reproduces `mail4agent-core`'s own
    // `directory_reports_room_membership_relative_to_the_caller` against
    // this crate's store: alice never joined the room, bob just left it,
    // so neither is reported as a current member even though both are
    // still registered.
    let directory = engine.directory(&alice).expect("alice reads the directory");
    let participant_ids: std::collections::BTreeSet<_> =
        directory.participants.iter().map(|entry| entry.id.clone()).collect();
    assert_eq!(participant_ids, std::collections::BTreeSet::from([alice, bob]));
    let room_entry = directory.rooms.iter().find(|entry| entry.id == room_id).expect("the room is listed");
    assert!(!room_entry.member, "alice never joined this room");
}
