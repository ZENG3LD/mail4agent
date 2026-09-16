//! Engine tests, run against [`InMemoryStore`] only -- this crate does not
//! write SQLite (see the module doc comments on [`crate::MailStore`]).

use mail4agent_api::{Address, MailError, ParticipantId, RoomId, SendRequest};

use crate::{InMemoryStore, MailboxEngine, ParticipantPermissions};

fn participant(value: &str) -> ParticipantId {
    ParticipantId::new(value).expect("valid participant id")
}

fn room(value: &str) -> RoomId {
    RoomId::new(value).expect("valid room id")
}

fn engine() -> MailboxEngine<InMemoryStore> {
    MailboxEngine::new(InMemoryStore::default())
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
fn participant_cannot_read_anothers_direct_mail() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");

    engine.send(&alice, send_request(Address::Direct { participant: bob.clone() }), 1_000).expect("send succeeds");

    let bob_inbox = engine.inbox(&bob, 0, 50).expect("bob reads his inbox");
    assert_eq!(bob_inbox.messages.len(), 1);

    let alice_inbox = engine.inbox(&alice, 0, 50).expect("alice reads her inbox");
    assert!(alice_inbox.messages.is_empty());
}

#[test]
fn room_member_reads_room_mail_and_non_member_does_not() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    let carol = participant("carol");
    let room_id = room("room-1");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    engine.register_participant(carol.clone(), None, permissions(true, true, false)).expect("carol registers");
    engine.create_room(room_id.clone(), 1_000).expect("room is created");
    engine.add_room_member(&room_id, bob.clone()).expect("bob joins the room");

    engine.send(&alice, send_request(Address::Room { room: room_id }), 2_000).expect("room send succeeds");

    let bob_inbox = engine.inbox(&bob, 0, 50).expect("bob reads his inbox");
    assert_eq!(bob_inbox.messages.len(), 1);

    let carol_inbox = engine.inbox(&carol, 0, 50).expect("carol reads her inbox");
    assert!(carol_inbox.messages.is_empty());
}

#[test]
fn removed_member_stops_reading_new_room_mail() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    let room_id = room("room-1");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    engine.create_room(room_id.clone(), 1_000).expect("room is created");
    engine.add_room_member(&room_id, bob.clone()).expect("bob joins the room");

    engine.send(&alice, send_request(Address::Room { room: room_id.clone() }), 2_000).expect("first send succeeds");
    engine.remove_room_member(&room_id, &bob).expect("bob is removed");
    engine.send(&alice, send_request(Address::Room { room: room_id }), 3_000).expect("second send succeeds");

    // Readability is present-tense: `inbox` gates on rooms the reader is
    // *currently* a member of, so removal drops the room's mail entirely,
    // not just what arrives afterwards -- there is no partial history left
    // behind for a former member.
    let bob_inbox = engine.inbox(&bob, 0, 50).expect("bob reads his inbox");
    assert!(bob_inbox.messages.is_empty());
}

#[test]
fn operators_own_inbox_does_not_contain_anothers_direct_mail() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    let operator_id = participant("op");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    engine.register_participant(operator_id.clone(), None, permissions(false, true, true)).expect("operator registers");

    engine.send(&alice, send_request(Address::Direct { participant: bob }), 1_000).expect("direct send succeeds");

    // "An operator may read any address" means any address it names, one at
    // a time (see `inbox_of`) -- not a widened view of its own inbox.
    let operator_inbox = engine.inbox(&operator_id, 0, 50).expect("operator reads its own inbox");
    assert!(operator_inbox.messages.is_empty());
}

#[test]
fn inbox_of_as_an_operator_reads_the_named_targets_mail() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    let operator_id = participant("op");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    engine.register_participant(operator_id.clone(), None, permissions(false, true, true)).expect("operator registers");

    engine.send(&alice, send_request(Address::Direct { participant: bob.clone() }), 1_000).expect("direct send succeeds");

    let page = engine.inbox_of(&operator_id, &bob, 0, 50).expect("operator reads bob's inbox by name");
    assert_eq!(page.messages.len(), 1);
}

#[test]
fn inbox_of_as_a_non_operator_targeting_someone_else_is_refused_by_name() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");

    let err = engine.inbox_of(&alice, &bob, 0, 50).expect_err("must be refused");
    assert_eq!(err, MailError::PermissionDenied { need: "mail:operator".to_string() });
}

#[test]
fn inbox_of_targeting_yourself_works_without_the_operator_bit() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    engine.send(&alice, send_request(Address::Direct { participant: bob.clone() }), 1_000).expect("send succeeds");

    let page = engine.inbox_of(&bob, &bob, 0, 50).expect("bob reads his own inbox via inbox_of");
    assert_eq!(page.messages.len(), 1);
}

#[test]
fn send_without_may_send_is_refused_by_name() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    engine.register_participant(alice.clone(), None, permissions(false, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");

    let err = engine.send(&alice, send_request(Address::Direct { participant: bob }), 1_000).expect_err("must be refused");
    assert_eq!(err, MailError::PermissionDenied { need: "mail:send".to_string() });
}

#[test]
fn send_to_unknown_participant_is_refused_naming_the_id() {
    let mut engine = engine();
    let alice = participant("alice");
    let ghost = participant("ghost");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");

    let err = engine
        .send(&alice, send_request(Address::Direct { participant: ghost.clone() }), 1_000)
        .expect_err("must be refused");
    assert_eq!(err, MailError::UnknownParticipant { participant: ghost });
}

#[test]
fn send_to_unknown_room_is_refused_naming_the_id() {
    let mut engine = engine();
    let alice = participant("alice");
    let ghost_room = room("ghost-room");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");

    let err = engine
        .send(&alice, send_request(Address::Room { room: ghost_room.clone() }), 1_000)
        .expect_err("must be refused");
    assert_eq!(err, MailError::UnknownRoom { room: ghost_room });
}

#[test]
fn same_idempotency_key_returns_original_message_and_creates_nothing() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");

    let mut request = send_request(Address::Direct { participant: bob.clone() });
    request.idempotency_key = Some("retry-1".to_string());

    let first = engine.send(&alice, request.clone(), 1_000).expect("first send succeeds");
    let second = engine.send(&alice, request, 5_000).expect("retry with the same key succeeds");

    assert_eq!(first, second);
    let inbox = engine.inbox(&bob, 0, 50).expect("bob reads his inbox");
    assert_eq!(inbox.messages.len(), 1);
}

#[test]
fn two_identical_sends_without_a_key_create_two_messages() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");

    let request = send_request(Address::Direct { participant: bob.clone() });
    let first = engine.send(&alice, request.clone(), 1_000).expect("first send succeeds");
    let second = engine.send(&alice, request, 1_000).expect("second, otherwise identical send succeeds");

    assert_ne!(first.message_id, second.message_id);
    let inbox = engine.inbox(&bob, 0, 50).expect("bob reads his inbox");
    assert_eq!(inbox.messages.len(), 2);
}

#[test]
fn ack_is_idempotent() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    let sent = engine
        .send(&alice, send_request(Address::Direct { participant: bob.clone() }), 1_000)
        .expect("send succeeds");

    let first_ack = engine.ack(&bob, &sent.message_id, 2_000).expect("first ack succeeds");
    let second_ack = engine.ack(&bob, &sent.message_id, 9_000).expect("second ack succeeds");

    assert_eq!(first_ack, second_ack);
    assert_eq!(first_ack.acked_at_unix_ms, 2_000);
}

#[test]
fn non_readers_ack_is_refused() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    let carol = participant("carol");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    engine.register_participant(carol.clone(), None, permissions(true, true, false)).expect("carol registers");
    let sent = engine.send(&alice, send_request(Address::Direct { participant: bob }), 1_000).expect("send succeeds");

    let err = engine.ack(&carol, &sent.message_id, 2_000).expect_err("must be refused");
    assert_eq!(err, MailError::NotAddressedToYou { message_id: sent.message_id });
}

#[test]
fn inbox_honours_since_unix_ms() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    engine
        .send(&alice, send_request(Address::Direct { participant: bob.clone() }), 1_000)
        .expect("early send succeeds");
    let late = engine
        .send(&alice, send_request(Address::Direct { participant: bob.clone() }), 5_000)
        .expect("late send succeeds");

    let page = engine.inbox(&bob, 2_000, 50).expect("bob reads his inbox");
    assert_eq!(page.messages.len(), 1);
    assert_eq!(page.messages[0].message_id, late.message_id);
}

#[test]
fn inbox_honours_limit() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    for offset in 0..5u64 {
        engine
            .send(&alice, send_request(Address::Direct { participant: bob.clone() }), 1_000 + offset)
            .expect("send succeeds");
    }

    let page = engine.inbox(&bob, 0, 3).expect("bob reads his inbox");
    assert_eq!(page.messages.len(), 3);
    // The limit bounds the page, not the unread count.
    assert_eq!(page.unread, 5);
}

#[test]
fn inbox_orders_by_created_at_then_message_id() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");

    let a = engine
        .send(&alice, send_request(Address::Direct { participant: bob.clone() }), 1_000)
        .expect("send a succeeds");
    let b = engine
        .send(&alice, send_request(Address::Direct { participant: bob.clone() }), 1_000)
        .expect("send b succeeds");
    let c = engine
        .send(&alice, send_request(Address::Direct { participant: bob.clone() }), 500)
        .expect("send c succeeds");

    let page = engine.inbox(&bob, 0, 50).expect("bob reads his inbox");
    let ids: Vec<_> = page.messages.iter().map(|message| message.message_id.clone()).collect();

    // c has the earliest created_at_unix_ms, so it sorts first regardless of id.
    assert_eq!(ids[0], c.message_id);
    // a and b share created_at_unix_ms; among ties, ordering falls back to message_id.
    let mut tied = vec![a.message_id, b.message_id];
    tied.sort();
    assert_eq!(&ids[1..], tied.as_slice());
}

#[test]
fn unread_count_matches_what_inbox_reports() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    let first = engine
        .send(&alice, send_request(Address::Direct { participant: bob.clone() }), 1_000)
        .expect("first send succeeds");
    engine
        .send(&alice, send_request(Address::Direct { participant: bob.clone() }), 2_000)
        .expect("second send succeeds");
    engine.ack(&bob, &first.message_id, 3_000).expect("bob acks the first message");

    let page = engine.inbox(&bob, 0, 50).expect("bob reads his inbox");
    let unread = engine.unread_count_of(&bob, &bob).expect("bob reads his own unread count");

    assert_eq!(page.unread, unread.unread);
    assert_eq!(unread.unread, 1);
}

#[test]
fn a_participants_own_room_message_reaches_its_inbox_but_never_counts_as_unread() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    let crew = room("crew");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    engine.create_room(crew.clone(), 500).expect("room is created");
    engine.add_room_member(&crew, alice.clone()).expect("alice joins");
    engine.add_room_member(&crew, bob.clone()).expect("bob joins");

    engine
        .send(&alice, send_request(Address::Room { room: crew.clone() }), 1_000)
        .expect("alice writes to the room");

    let page = engine.inbox(&alice, 0, 50).expect("alice reads her inbox");

    // She sees what she wrote -- a room is a shared log and its author
    // belongs in it -- but it is not waiting for her.
    assert_eq!(page.messages.len(), 1);
    assert_eq!(page.messages[0].from, alice);
    assert_eq!(page.unread, 0);

    // For the other member it genuinely is unread.
    let bobs = engine.inbox(&bob, 0, 50).expect("bob reads his inbox");
    assert_eq!(bobs.unread, 1);
}

#[test]
fn authenticate_rejects_unknown_secret() {
    let engine = engine();
    let err = engine.authenticate("not-a-real-secret").expect_err("unknown secret must be refused");
    assert_eq!(err, MailError::PermissionDenied { need: "mail:authenticate".to_string() });
}

#[test]
fn authenticate_accepts_registered_participant() {
    let mut engine = engine();
    let alice = participant("alice");
    let secret = engine
        .register_participant(alice.clone(), None, permissions(true, true, false))
        .expect("alice registers");

    let authenticated = engine.authenticate(&secret).expect("a registered secret authenticates");
    assert_eq!(authenticated, alice);
}

#[test]
fn read_without_may_read_permission_is_refused() {
    let mut engine = engine();
    let alice = participant("alice");
    engine.register_participant(alice.clone(), None, permissions(true, false, false)).expect("alice registers");

    let err = engine.inbox(&alice, 0, 50).expect_err("must be refused");
    assert_eq!(err, MailError::PermissionDenied { need: "mail:read".to_string() });
}

#[test]
fn deregistered_participant_can_no_longer_authenticate() {
    let mut engine = engine();
    let alice = participant("alice");
    let secret = engine
        .register_participant(alice.clone(), None, permissions(true, true, false))
        .expect("alice registers");

    engine.deregister_participant(&alice).expect("alice is deregistered");

    let err = engine.authenticate(&secret).expect_err("a deregistered secret must be refused");
    assert_eq!(err, MailError::PermissionDenied { need: "mail:authenticate".to_string() });
}

#[test]
fn rotated_secret_replaces_the_old_one() {
    let mut engine = engine();
    let alice = participant("alice");
    let old_secret = engine
        .register_participant(alice.clone(), None, permissions(true, true, false))
        .expect("alice registers");

    let new_secret = engine.rotate_participant_secret(&alice).expect("alice rotates her secret");

    assert_ne!(old_secret, new_secret);
    engine.authenticate(&old_secret).expect_err("the old secret must no longer authenticate");
    let authenticated = engine.authenticate(&new_secret).expect("the new secret authenticates");
    assert_eq!(authenticated, alice);
}

#[test]
fn revoked_secret_can_no_longer_authenticate_and_nothing_new_is_issued() {
    let mut engine = engine();
    let alice = participant("alice");
    let secret = engine
        .register_participant(alice.clone(), None, permissions(true, true, false))
        .expect("alice registers");

    engine.revoke_participant_secret(&alice).expect("alice's secret is revoked");

    engine.authenticate(&secret).expect_err("the revoked secret must no longer authenticate");
}

#[test]
fn message_get_refuses_unknown_message_by_name() {
    let mut engine = engine();
    let alice = participant("alice");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    let ghost_message = mail4agent_api::MessageId::new("m4a_0123456789abcdef01234567").expect("valid message id shape");

    let err = engine.message_get(&alice, &ghost_message).expect_err("must be refused");
    assert_eq!(err, MailError::UnknownMessage { message_id: ghost_message });
}

#[test]
fn add_room_member_refuses_unknown_room_and_unknown_participant_by_name() {
    let mut engine = engine();
    let alice = participant("alice");
    let ghost_room = room("ghost-room");
    let ghost_participant = participant("ghost");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.create_room(room("room-1"), 1_000).expect("room is created");

    let err = engine.add_room_member(&ghost_room, alice.clone()).expect_err("must be refused");
    assert_eq!(err, MailError::UnknownRoom { room: ghost_room });

    let err = engine.add_room_member(&room("room-1"), ghost_participant.clone()).expect_err("must be refused");
    assert_eq!(err, MailError::UnknownParticipant { participant: ghost_participant });
}
