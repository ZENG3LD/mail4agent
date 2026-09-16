//! Engine tests, run against [`InMemoryStore`] only -- this crate does not
//! write SQLite (see the module doc comments on [`crate::MailStore`]).

use mail4agent_api::{
    Address, MailError, ParticipantId, RoomId, SendRequest, SessionAttested, SessionCard, SessionCorroborated,
    SessionDeclared, SessionId,
};

use crate::{InMemoryStore, MailboxEngine, ParticipantPermissions};

fn participant(value: &str) -> ParticipantId {
    ParticipantId::new(value).expect("valid participant id")
}

fn room(value: &str) -> RoomId {
    RoomId::new(value).expect("valid room id")
}

fn session_id(value: &str) -> SessionId {
    SessionId::new(value).expect("valid session id")
}

/// The account's own address -- shorthand for the overwhelming majority of
/// calls below, which exercise account-level behaviour unchanged by this
/// crate's session support.
fn direct(id: &ParticipantId) -> Address {
    Address::Direct { participant: id.clone() }
}

fn session_address(account: &ParticipantId, session: &SessionId) -> Address {
    Address::Session { participant: account.clone(), session: session.clone() }
}

/// A minimal, otherwise-empty [`SessionCard`], as if freshly attested with
/// no corroborated fields on file yet.
fn bare_card(pid: u32, started_at_unix_ms: u64) -> SessionCard {
    SessionCard {
        attested: SessionAttested { pid, started_at_unix_ms, exe: None },
        corroborated: SessionCorroborated { provider_session_id: None, model: None, cwd: None },
        declared: SessionDeclared::default(),
    }
}

/// A liveness check for tests: nothing this crate builds ever asks a real
/// kernel, so tests supply their own answer.
fn always_alive(_pid: u32, _started_at_unix_ms: u64) -> bool {
    true
}

fn never_alive(_pid: u32, _started_at_unix_ms: u64) -> bool {
    false
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

    engine.send(&direct(&alice), send_request(Address::Direct { participant: bob.clone() }), 1_000).expect("send succeeds");

    let bob_inbox = engine.inbox(&direct(&bob), 0, 50).expect("bob reads his inbox");
    assert_eq!(bob_inbox.messages.len(), 1);

    let alice_inbox = engine.inbox(&direct(&alice), 0, 50).expect("alice reads her inbox");
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

    engine.send(&direct(&alice), send_request(Address::Room { room: room_id }), 2_000).expect("room send succeeds");

    let bob_inbox = engine.inbox(&direct(&bob), 0, 50).expect("bob reads his inbox");
    assert_eq!(bob_inbox.messages.len(), 1);

    let carol_inbox = engine.inbox(&direct(&carol), 0, 50).expect("carol reads her inbox");
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

    engine
        .send(&direct(&alice), send_request(Address::Room { room: room_id.clone() }), 2_000)
        .expect("first send succeeds");
    engine.remove_room_member(&room_id, &bob).expect("bob is removed");
    engine.send(&direct(&alice), send_request(Address::Room { room: room_id }), 3_000).expect("second send succeeds");

    // Readability is present-tense: `inbox` gates on rooms the reader is
    // *currently* a member of, so removal drops the room's mail entirely,
    // not just what arrives afterwards -- there is no partial history left
    // behind for a former member.
    let bob_inbox = engine.inbox(&direct(&bob), 0, 50).expect("bob reads his inbox");
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

    engine.send(&direct(&alice), send_request(Address::Direct { participant: bob }), 1_000).expect("direct send succeeds");

    // "An operator may read any address" means any address it names, one at
    // a time (see `inbox_of`) -- not a widened view of its own inbox.
    let operator_inbox = engine.inbox(&direct(&operator_id), 0, 50).expect("operator reads its own inbox");
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

    engine
        .send(&direct(&alice), send_request(Address::Direct { participant: bob.clone() }), 1_000)
        .expect("direct send succeeds");

    let page = engine.inbox_of(&direct(&operator_id), &direct(&bob), 0, 50).expect("operator reads bob's inbox by name");
    assert_eq!(page.messages.len(), 1);
}

#[test]
fn inbox_of_as_a_non_operator_targeting_someone_else_is_refused_by_name() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");

    let err = engine.inbox_of(&direct(&alice), &direct(&bob), 0, 50).expect_err("must be refused");
    assert_eq!(err, MailError::PermissionDenied { need: "mail:operator".to_string() });
}

#[test]
fn inbox_of_targeting_yourself_works_without_the_operator_bit() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    engine
        .send(&direct(&alice), send_request(Address::Direct { participant: bob.clone() }), 1_000)
        .expect("send succeeds");

    let page = engine.inbox_of(&direct(&bob), &direct(&bob), 0, 50).expect("bob reads his own inbox via inbox_of");
    assert_eq!(page.messages.len(), 1);
}

#[test]
fn send_without_may_send_is_refused_by_name() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    engine.register_participant(alice.clone(), None, permissions(false, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");

    let err = engine
        .send(&direct(&alice), send_request(Address::Direct { participant: bob }), 1_000)
        .expect_err("must be refused");
    assert_eq!(err, MailError::PermissionDenied { need: "mail:send".to_string() });
}

#[test]
fn send_to_unknown_participant_is_refused_naming_the_id() {
    let mut engine = engine();
    let alice = participant("alice");
    let ghost = participant("ghost");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");

    let err = engine
        .send(&direct(&alice), send_request(Address::Direct { participant: ghost.clone() }), 1_000)
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
        .send(&direct(&alice), send_request(Address::Room { room: ghost_room.clone() }), 1_000)
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

    let first = engine.send(&direct(&alice), request.clone(), 1_000).expect("first send succeeds");
    let second = engine.send(&direct(&alice), request, 5_000).expect("retry with the same key succeeds");

    assert_eq!(first, second);
    let inbox = engine.inbox(&direct(&bob), 0, 50).expect("bob reads his inbox");
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
    let first = engine.send(&direct(&alice), request.clone(), 1_000).expect("first send succeeds");
    let second = engine.send(&direct(&alice), request, 1_000).expect("second, otherwise identical send succeeds");

    assert_ne!(first.message_id, second.message_id);
    let inbox = engine.inbox(&direct(&bob), 0, 50).expect("bob reads his inbox");
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
        .send(&direct(&alice), send_request(Address::Direct { participant: bob.clone() }), 1_000)
        .expect("send succeeds");

    let first_ack = engine.ack(&direct(&bob), &sent.message_id, 2_000).expect("first ack succeeds");
    let second_ack = engine.ack(&direct(&bob), &sent.message_id, 9_000).expect("second ack succeeds");

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
    let sent =
        engine.send(&direct(&alice), send_request(Address::Direct { participant: bob }), 1_000).expect("send succeeds");

    let err = engine.ack(&direct(&carol), &sent.message_id, 2_000).expect_err("must be refused");
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
        .send(&direct(&alice), send_request(Address::Direct { participant: bob.clone() }), 1_000)
        .expect("early send succeeds");
    let late = engine
        .send(&direct(&alice), send_request(Address::Direct { participant: bob.clone() }), 5_000)
        .expect("late send succeeds");

    let page = engine.inbox(&direct(&bob), 2_000, 50).expect("bob reads his inbox");
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
            .send(&direct(&alice), send_request(Address::Direct { participant: bob.clone() }), 1_000 + offset)
            .expect("send succeeds");
    }

    let page = engine.inbox(&direct(&bob), 0, 3).expect("bob reads his inbox");
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
        .send(&direct(&alice), send_request(Address::Direct { participant: bob.clone() }), 1_000)
        .expect("send a succeeds");
    let b = engine
        .send(&direct(&alice), send_request(Address::Direct { participant: bob.clone() }), 1_000)
        .expect("send b succeeds");
    let c = engine
        .send(&direct(&alice), send_request(Address::Direct { participant: bob.clone() }), 500)
        .expect("send c succeeds");

    let page = engine.inbox(&direct(&bob), 0, 50).expect("bob reads his inbox");
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
        .send(&direct(&alice), send_request(Address::Direct { participant: bob.clone() }), 1_000)
        .expect("first send succeeds");
    engine
        .send(&direct(&alice), send_request(Address::Direct { participant: bob.clone() }), 2_000)
        .expect("second send succeeds");
    engine.ack(&direct(&bob), &first.message_id, 3_000).expect("bob acks the first message");

    let page = engine.inbox(&direct(&bob), 0, 50).expect("bob reads his inbox");
    let unread = engine.unread_count_of(&direct(&bob), &direct(&bob)).expect("bob reads his own unread count");

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

    engine.send(&direct(&alice), send_request(Address::Room { room: crew.clone() }), 1_000).expect("alice writes to the room");

    let page = engine.inbox(&direct(&alice), 0, 50).expect("alice reads her inbox");

    // She sees what she wrote -- a room is a shared log and its author
    // belongs in it -- but it is not waiting for her.
    assert_eq!(page.messages.len(), 1);
    assert_eq!(page.messages[0].from, direct(&alice));
    assert_eq!(page.unread, 0);

    // For the other member it genuinely is unread.
    let bobs = engine.inbox(&direct(&bob), 0, 50).expect("bob reads his inbox");
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

    let err = engine.inbox(&direct(&alice), 0, 50).expect_err("must be refused");
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

    let err = engine.message_get(&direct(&alice), &ghost_message).expect_err("must be refused");
    assert_eq!(err, MailError::UnknownMessage { message_id: ghost_message });
}

#[test]
fn directory_lists_every_registered_participant_and_room() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    let room_id = room("room-1");
    engine
        .register_participant(alice.clone(), Some("Alice".to_string()), permissions(true, true, false))
        .expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    engine.create_room(room_id.clone(), 1_000).expect("room is created");

    let directory = engine.directory(&direct(&alice), &always_alive).expect("alice reads the directory");

    let participant_ids: std::collections::BTreeSet<_> =
        directory.participants.iter().map(|entry| entry.id.clone()).collect();
    assert_eq!(participant_ids, std::collections::BTreeSet::from([alice.clone(), bob]));
    let alice_entry = directory.participants.iter().find(|entry| entry.id == alice).expect("alice is listed");
    assert_eq!(alice_entry.label, Some("Alice".to_string()));

    let room_ids: std::collections::BTreeSet<_> = directory.rooms.iter().map(|entry| entry.id.clone()).collect();
    assert_eq!(room_ids, std::collections::BTreeSet::from([room_id]));
}

#[test]
fn deregistered_participant_stops_appearing_in_the_directory() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");

    engine.deregister_participant(&bob).expect("bob is deregistered");

    let directory = engine.directory(&direct(&alice), &always_alive).expect("alice reads the directory");
    assert!(directory.participants.iter().all(|entry| entry.id != bob), "a deregistered participant must not be listed");
}

#[test]
fn directory_reports_room_membership_relative_to_the_caller() {
    let mut engine = engine();
    let alice = participant("alice");
    let bob = participant("bob");
    let joined = room("joined");
    let not_joined = room("not-joined");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    engine.create_room(joined.clone(), 1_000).expect("joined room is created");
    engine.create_room(not_joined.clone(), 1_000).expect("not-joined room is created");
    engine.add_room_member(&joined, alice.clone()).expect("alice joins");

    let directory = engine.directory(&direct(&alice), &always_alive).expect("alice reads the directory");

    let joined_entry = directory.rooms.iter().find(|entry| entry.id == joined).expect("joined room is listed");
    assert!(joined_entry.member, "alice must be reported as a member of the room she joined");
    let not_joined_entry = directory.rooms.iter().find(|entry| entry.id == not_joined).expect("not-joined room is listed");
    assert!(!not_joined_entry.member, "alice must not be reported as a member of a room she never joined");
}

#[test]
fn directory_without_may_read_is_refused_by_name() {
    let mut engine = engine();
    let alice = participant("alice");
    engine.register_participant(alice.clone(), None, permissions(true, false, false)).expect("alice registers");

    let err = engine.directory(&direct(&alice), &always_alive).expect_err("must be refused");
    assert_eq!(err, MailError::PermissionDenied { need: "mail:read".to_string() });
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

// -- Sessions
// (`mailbox-service-extraction-and-signed-session-identity-2026-09-16.md`
// §5e: a session is a participant, not a new concept beside one.)

#[test]
fn ensure_session_is_idempotent_and_refreshes_corroborated_fields_without_touching_declared() {
    let mut engine = engine();
    let claude = participant("claude");
    engine.register_participant(claude.clone(), None, permissions(true, true, false)).expect("claude registers");
    let session = session_id("s-7f3a0000");

    let first = engine
        .ensure_session(claude.clone(), session.clone(), bare_card(4242, 1_000), 1_000)
        .expect("first ensure_session registers the session");
    assert_eq!(first, session);
    engine.set_declared(&session, Some("parity work".to_string()), Some("worker".to_string()), None).expect("declares");

    let mut refreshed_card = bare_card(4242, 1_000);
    refreshed_card.corroborated.model = Some(mail4agent_api::Declared::new("opus".to_string()));
    engine
        .ensure_session(claude.clone(), session.clone(), refreshed_card, 2_000)
        .expect("second ensure_session refreshes the same session");

    let directory = engine.directory(&direct(&claude), &always_alive).expect("claude reads the directory");
    let entry = directory.participants.iter().find(|entry| entry.id == claude).expect("claude is listed");
    assert_eq!(entry.sessions.len(), 1, "the same session_id must not create a second entry");
    let session_entry = &entry.sessions[0];
    assert_eq!(session_entry.last_seen_unix_ms, 2_000, "last_seen advances on refresh");
    assert_eq!(
        session_entry.card.corroborated.model.as_ref().map(mail4agent_api::Declared::as_ref),
        Some(&"opus".to_string()),
        "corroborated fields update on refresh"
    );
    assert_eq!(
        session_entry.card.declared.working_on,
        Some("parity work".to_string()),
        "ensure_session must never overwrite what set_declared already wrote"
    );
}

#[test]
fn ensure_session_refuses_a_second_account_for_an_existing_session_id() {
    let mut engine = engine();
    let claude = participant("claude");
    let codex = participant("codex");
    engine.register_participant(claude.clone(), None, permissions(true, true, false)).expect("claude registers");
    engine.register_participant(codex.clone(), None, permissions(true, true, false)).expect("codex registers");
    let session = session_id("s-7f3a0000");
    engine.ensure_session(claude.clone(), session.clone(), bare_card(1, 1), 1_000).expect("first ensure_session succeeds");

    let err = engine
        .ensure_session(codex.clone(), session.clone(), bare_card(1, 1), 2_000)
        .expect_err("a different account for the same session id must be refused");
    assert_eq!(err, MailError::SessionAccountMismatch { session, expected: claude, presented: codex });
}

#[test]
fn set_declared_on_an_unknown_session_is_refused_by_name() {
    let mut engine = engine();
    let session = session_id("s-7f3a0000");
    let err = engine
        .set_declared(&session, Some("work".to_string()), None, None)
        .expect_err("an unensured session must be refused");
    assert_eq!(err, MailError::UnknownSession { session });
}

#[test]
fn a_session_reads_its_own_mail_its_accounts_mail_and_its_accounts_rooms() {
    let mut engine = engine();
    let claude = participant("claude");
    let bob = participant("bob");
    let crew = room("crew");
    engine.register_participant(claude.clone(), None, permissions(true, true, false)).expect("claude registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    engine.create_room(crew.clone(), 500).expect("room is created");
    engine.add_room_member(&crew, claude.clone()).expect("claude's account joins the room");
    let session = session_id("s-7f3a0000");
    engine.ensure_session(claude.clone(), session.clone(), bare_card(1, 1), 1_000).expect("session is ensured");
    let session_addr = session_address(&claude, &session);

    engine
        .send(&direct(&bob), send_request(Address::Session { participant: claude.clone(), session: session.clone() }), 2_000)
        .expect("direct-to-session send succeeds");
    engine
        .send(&direct(&bob), send_request(Address::Direct { participant: claude.clone() }), 3_000)
        .expect("direct-to-account send succeeds");
    engine.send(&direct(&bob), send_request(Address::Room { room: crew }), 4_000).expect("room send succeeds");

    let page = engine.inbox(&session_addr, 0, 50).expect("the session reads its inbox");
    assert_eq!(page.messages.len(), 3, "the session sees its own mail, its account's mail, and its account's room mail");
}

#[test]
fn a_session_scoped_message_is_not_readable_by_the_account_or_a_sibling_session() {
    let mut engine = engine();
    let claude = participant("claude");
    let bob = participant("bob");
    engine.register_participant(claude.clone(), None, permissions(true, true, false)).expect("claude registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    let session_a = session_id("s-aaaaaaaa");
    let session_b = session_id("s-bbbbbbbb");
    engine.ensure_session(claude.clone(), session_a.clone(), bare_card(1, 1), 1_000).expect("session a is ensured");
    engine.ensure_session(claude.clone(), session_b.clone(), bare_card(2, 2), 1_000).expect("session b is ensured");

    engine
        .send(
            &direct(&bob),
            send_request(Address::Session { participant: claude.clone(), session: session_a.clone() }),
            2_000,
        )
        .expect("send to session a succeeds");

    let account_inbox = engine.inbox(&direct(&claude), 0, 50).expect("the account reads its inbox");
    assert!(account_inbox.messages.is_empty(), "session-scoped mail must not leak into the account's own inbox");

    let sibling_inbox =
        engine.inbox(&session_address(&claude, &session_b), 0, 50).expect("session b reads its inbox");
    assert!(sibling_inbox.messages.is_empty(), "session-scoped mail must not leak into a sibling session's inbox");

    let owner_inbox = engine.inbox(&session_address(&claude, &session_a), 0, 50).expect("session a reads its inbox");
    assert_eq!(owner_inbox.messages.len(), 1, "only the named session itself can read mail sent to it");
}

#[test]
fn a_session_can_send_and_its_message_carries_the_sessions_own_address() {
    let mut engine = engine();
    let claude = participant("claude");
    let bob = participant("bob");
    engine.register_participant(claude.clone(), None, permissions(true, true, false)).expect("claude registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    let session = session_id("s-7f3a0000");
    engine.ensure_session(claude.clone(), session.clone(), bare_card(1, 1), 1_000).expect("session is ensured");
    let session_addr = session_address(&claude, &session);

    let response = engine
        .send(&session_addr, send_request(Address::Direct { participant: bob.clone() }), 2_000)
        .expect("the session sends");
    assert_eq!(response.from, session_addr, "a session's own address, not its account's, must be `from`");

    let bobs_inbox = engine.inbox(&direct(&bob), 0, 50).expect("bob reads his inbox");
    assert_eq!(bobs_inbox.messages[0].from, session_addr);
}

#[test]
fn sending_to_an_unensured_session_is_refused_by_name() {
    let mut engine = engine();
    let claude = participant("claude");
    let bob = participant("bob");
    engine.register_participant(claude.clone(), None, permissions(true, true, false)).expect("claude registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    let ghost_session = session_id("s-00000000");

    let err = engine
        .send(&direct(&bob), send_request(Address::Session { participant: claude, session: ghost_session.clone() }), 1_000)
        .expect_err("must be refused");
    assert_eq!(err, MailError::UnknownSession { session: ghost_session });
}

#[test]
fn a_room_address_is_refused_as_a_caller_identity() {
    let mut engine = engine();
    let crew = room("crew");
    engine.create_room(crew.clone(), 500).expect("room is created");

    let err = engine.inbox(&Address::Room { room: crew }, 0, 50).expect_err("a room must never act as a caller");
    assert!(matches!(err, MailError::Malformed { field, .. } if field == "address"));
}

#[test]
fn operator_reads_a_named_sessions_inbox_via_inbox_of() {
    let mut engine = engine();
    let claude = participant("claude");
    let bob = participant("bob");
    let operator_id = participant("op");
    engine.register_participant(claude.clone(), None, permissions(true, true, false)).expect("claude registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");
    engine.register_participant(operator_id.clone(), None, permissions(false, true, true)).expect("operator registers");
    let session = session_id("s-7f3a0000");
    engine.ensure_session(claude.clone(), session.clone(), bare_card(1, 1), 1_000).expect("session is ensured");
    let session_addr = session_address(&claude, &session);

    engine.send(&direct(&bob), send_request(Address::Session { participant: claude, session }), 2_000).expect("send succeeds");

    let page = engine.inbox_of(&direct(&operator_id), &session_addr, 0, 50).expect("operator reads the session by name");
    assert_eq!(page.messages.len(), 1);
}

#[test]
fn directorys_live_flag_comes_from_the_given_liveness_check_not_the_engine_itself() {
    let mut engine = engine();
    let claude = participant("claude");
    engine.register_participant(claude.clone(), None, permissions(true, true, false)).expect("claude registers");
    let session = session_id("s-7f3a0000");
    engine.ensure_session(claude.clone(), session, bare_card(4242, 1_000), 1_000).expect("session is ensured");

    let alive_directory = engine.directory(&direct(&claude), &always_alive).expect("directory with an alive check");
    let alive_entry = alive_directory.participants.iter().find(|entry| entry.id == claude).expect("claude is listed");
    assert!(alive_entry.sessions[0].live, "the given liveness check said alive, so the entry must say alive");

    let dead_directory = engine.directory(&direct(&claude), &never_alive).expect("directory with a dead check");
    let dead_entry = dead_directory.participants.iter().find(|entry| entry.id == claude).expect("claude is listed");
    assert!(!dead_entry.sessions[0].live, "the given liveness check said dead, so the entry must say dead");
}

#[test]
fn set_listener_accepts_a_loopback_url_and_remove_listener_clears_it() {
    let mut engine = engine();
    let alice = participant("alice");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");

    engine.set_listener(&alice, "http://127.0.0.1:9000/hook".to_string()).expect("a loopback url is accepted");
    engine.remove_listener(&alice).expect("removing a listener is not an error");
    // Removing again is still not an error -- idempotent, like every other
    // removal in this engine.
    engine.remove_listener(&alice).expect("removing an already-absent listener is not an error");
}

#[test]
fn set_listener_refuses_a_non_loopback_url_by_name() {
    let mut engine = engine();
    let alice = participant("alice");
    engine.register_participant(alice.clone(), None, permissions(true, true, false)).expect("alice registers");

    let err = engine
        .set_listener(&alice, "http://example.com/hook".to_string())
        .expect_err("a non-loopback url must be refused");
    assert!(matches!(err, MailError::Malformed { field, .. } if field == "url"));

    let err = engine
        .set_listener(&alice, "https://127.0.0.1/hook".to_string())
        .expect_err("https is refused too -- only http is accepted for a loopback listener");
    assert!(matches!(err, MailError::Malformed { field, .. } if field == "url"));

    let err = engine
        .set_listener(&alice, "http://127.0.0.1.evil.example/hook".to_string())
        .expect_err("a host that merely starts with the loopback address must still be refused");
    assert!(matches!(err, MailError::Malformed { field, .. } if field == "url"));

    let err = engine
        .set_listener(&alice, "http://user:pass@127.0.0.1/hook".to_string())
        .expect_err("userinfo in the authority must be refused");
    assert!(matches!(err, MailError::Malformed { field, .. } if field == "url"));
}

#[test]
fn set_listener_refuses_an_unknown_participant_by_name() {
    let mut engine = engine();
    let ghost = participant("ghost");
    let err = engine
        .set_listener(&ghost, "http://127.0.0.1:9000/hook".to_string())
        .expect_err("an unregistered participant must be refused");
    assert!(matches!(err, MailError::UnknownParticipant { participant } if participant == ghost));
}
