//! Proves `SqliteMailStore` is interchangeable with
//! `mail4agent_core::InMemoryStore` from `MailboxEngine`'s point of view:
//! the same properties `mail4agent-core`'s own tests
//! (`mail4agent-core/src/tests.rs`) prove against `InMemoryStore` are
//! reproduced here, end to end, against this crate's store instead.

use mail4agent_api::{
    Address, ParticipantId, RoomId, SendRequest, SessionAttested, SessionCard, SessionCorroborated, SessionDeclared,
    SessionId,
};
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

    let alice_addr = Address::Direct { participant: alice.clone() };
    let bob_addr = Address::Direct { participant: bob.clone() };

    let direct = engine
        .send(&alice_addr, send_request(Address::Direct { participant: bob.clone() }), 2_000)
        .expect("direct send succeeds");
    let to_room = engine
        .send(&alice_addr, send_request(Address::Room { room: room_id.clone() }), 3_000)
        .expect("room send succeeds");

    // Alice sent both messages but is addressed by neither, so her own
    // inbox is empty -- `participant_cannot_read_anothers_direct_mail`'s
    // property against `InMemoryStore`.
    let alice_inbox = engine.inbox(&alice_addr, 0, 50).expect("alice reads her inbox");
    assert!(alice_inbox.messages.is_empty());

    // Bob reads both the direct message and the room message he belongs
    // to -- `room_member_reads_room_mail_and_non_member_does_not`'s
    // property.
    let bob_inbox = engine.inbox(&bob_addr, 0, 50).expect("bob reads his inbox");
    let bob_ids: std::collections::BTreeSet<_> = bob_inbox.messages.iter().map(|message| message.message_id.clone()).collect();
    assert_eq!(bob_ids, std::collections::BTreeSet::from([direct.message_id.clone(), to_room.message_id.clone()]));
    assert_eq!(bob_inbox.unread, 2);

    // Acking the direct message leaves it in the inbox but drops it from
    // the unread count; a second ack of the same message returns the
    // first ack unchanged -- `ack_is_idempotent`'s property.
    let first_ack = engine.ack(&bob_addr, &direct.message_id, 4_000).expect("bob acks the direct message");
    let second_ack = engine.ack(&bob_addr, &direct.message_id, 9_000).expect("bob acks it again");
    assert_eq!(first_ack, second_ack);
    assert_eq!(first_ack.acked_at_unix_ms, 4_000);

    let bob_inbox_after_ack = engine.inbox(&bob_addr, 0, 50).expect("bob reads his inbox again");
    assert_eq!(bob_inbox_after_ack.messages.len(), 2, "acking does not remove a message from the inbox");
    assert_eq!(bob_inbox_after_ack.unread, 1, "only the room message is still unread");

    // Removing bob from the room drops the room message from his inbox
    // entirely, present-tense, while the direct message he already
    // received stays -- `removed_member_stops_reading_new_room_mail`'s
    // property.
    engine.remove_room_member(&room_id, &bob).expect("bob leaves the room");
    let bob_inbox_after_leaving = engine.inbox(&bob_addr, 0, 50).expect("bob reads his inbox a third time");
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
    let directory = engine.directory(&alice_addr, &always_alive).expect("alice reads the directory");
    let participant_ids: std::collections::BTreeSet<_> =
        directory.participants.iter().map(|entry| entry.id.clone()).collect();
    assert_eq!(participant_ids, std::collections::BTreeSet::from([alice, bob]));
    let room_entry = directory.rooms.iter().find(|entry| entry.id == room_id).expect("the room is listed");
    assert!(!room_entry.member, "alice never joined this room");
}

/// A session's full arc against this crate's store: `ensure_session`
/// registers it, a message addressed to the session and a separate one
/// addressed to its account both land in that one session's inbox (see
/// `mail4agent-core`'s own
/// `a_session_reads_its_own_mail_its_accounts_mail_and_its_accounts_rooms`),
/// and the session can ack what it read -- reproduced here end to end
/// against `SqliteMailStore` rather than `InMemoryStore`.
#[test]
fn a_sessions_full_arc_matches_in_memory_store_outcomes() {
    let mut engine = engine();

    let claude = ParticipantId::new("claude").expect("valid participant id");
    let bob = ParticipantId::new("bob").expect("valid participant id");
    engine.register_participant(claude.clone(), None, permissions(true, true, false)).expect("claude registers");
    engine.register_participant(bob.clone(), None, permissions(true, true, false)).expect("bob registers");

    let session = SessionId::new("s-7f3a0000").expect("valid session id");
    engine
        .ensure_session(claude.clone(), session.clone(), bare_card(4242, 1_000), 1_000)
        .expect("the session registers");
    let session_addr = Address::Session { participant: claude.clone(), session: session.clone() };
    let account_addr = Address::Direct { participant: claude.clone() };
    let bob_addr = Address::Direct { participant: bob };

    let to_session = engine
        .send(&bob_addr, send_request(Address::Session { participant: claude.clone(), session: session.clone() }), 2_000)
        .expect("direct-to-session send succeeds");
    let to_account = engine
        .send(&bob_addr, send_request(Address::Direct { participant: claude.clone() }), 3_000)
        .expect("direct-to-account send succeeds");

    let page = engine.inbox(&session_addr, 0, 50).expect("the session reads its inbox");
    let ids: std::collections::BTreeSet<_> = page.messages.iter().map(|message| message.message_id.clone()).collect();
    assert_eq!(
        ids,
        std::collections::BTreeSet::from([to_session.message_id.clone(), to_account.message_id.clone()]),
        "the session's inbox holds both its own mail and its account's"
    );
    assert_eq!(page.unread, 2);

    // The account's own inbox never sees the session-scoped message --
    // mirrors `a_session_scoped_message_is_not_readable_by_the_account_or_a_sibling_session`.
    let account_inbox = engine.inbox(&account_addr, 0, 50).expect("the account reads its inbox");
    assert_eq!(
        account_inbox.messages.iter().map(|message| &message.message_id).collect::<Vec<_>>(),
        vec![&to_account.message_id],
        "session-scoped mail must not leak into the account's own inbox"
    );

    // The session acks the session-scoped message; the account's own
    // unread count is untouched by an ack the session made.
    let ack = engine.ack(&session_addr, &to_session.message_id, 4_000).expect("the session acks its own mail");
    assert_eq!(ack.reader, session_addr);

    let page_after_ack = engine.inbox(&session_addr, 0, 50).expect("the session reads its inbox again");
    assert_eq!(page_after_ack.messages.len(), 2, "acking does not remove a message from the inbox");
    assert_eq!(page_after_ack.unread, 1, "only the still-unacked account mail remains unread");
}
