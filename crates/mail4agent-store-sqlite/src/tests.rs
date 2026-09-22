//! `SqliteMailStore` exercised directly through [`MailStore`], against an
//! in-memory [`crate::db::Db`]. `mail4agent-core`'s own engine-level
//! properties are proven again, end to end, in `engine_tests.rs`; these
//! tests are about the store's own contract -- what each method persists,
//! and the SQL each read query is built on.

use std::collections::BTreeSet;

use mail4agent_api::{
    Ack, Address, Declared, Message, MessageId, MessageRef, ParticipantId, RoomId, SessionAttested, SessionCard,
    SessionCorroborated, SessionDeclared, SessionId,
};
use mail4agent_core::{InsertMessageOutcome, MailStore, ParticipantRecord, SecretDigest, SessionRecord};

use crate::{migrations, Db, DbConfig, MigrationRunner, SqliteMailStore};

fn store() -> SqliteMailStore {
    SqliteMailStore::open_in_memory().expect("in-memory store opens and migrates")
}

fn participant(value: &str) -> ParticipantId {
    ParticipantId::new(value).expect("valid participant id")
}

fn room(value: &str) -> RoomId {
    RoomId::new(value).expect("valid room id")
}

fn session_id(value: &str) -> SessionId {
    SessionId::new(value).expect("valid session id")
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
        listener_url: None,
    }
}

/// The account's own address -- shorthand for the overwhelming majority of
/// calls below, which do not care about session addressing.
fn direct(id: &ParticipantId) -> Address {
    Address::Direct { participant: id.clone() }
}

fn session_address(account: &ParticipantId, session: &SessionId) -> Address {
    Address::Session { participant: account.clone(), session: session.clone() }
}

fn message(id: MessageId, from: Address, to: Address, created_at_unix_ms: u64) -> Message {
    Message {
        message_id: id,
        from,
        to,
        subject: "subject".to_string(),
        body: "body".to_string(),
        reply_to: None,
        correlation: None,
        refs: Vec::new(),
        created_at_unix_ms,
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
fn set_listener_url_persists_and_clears_through_get_participant() {
    let mut store = store();
    let alice = participant("alice");
    store.register_participant(alice.clone(), participant_record(1)).expect("registers");
    assert_eq!(store.get_participant(&alice).expect("get succeeds").expect("exists").listener_url, None);

    store.set_listener_url(&alice, Some("http://127.0.0.1:9000/hook".to_string())).expect("sets the listener url");
    assert_eq!(
        store.get_participant(&alice).expect("get succeeds").expect("exists").listener_url,
        Some("http://127.0.0.1:9000/hook".to_string())
    );

    store.set_listener_url(&alice, None).expect("clears the listener url");
    assert_eq!(store.get_participant(&alice).expect("get succeeds").expect("exists").listener_url, None);
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
    let msg = message(message_id(1), direct(&alice), direct(&bob), 1_000);

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
    let mut msg = message(message_id(2), direct(&alice), direct(&bob), 1_000);
    msg.reply_to = Some(message_id(1));
    msg.correlation = Some("task-42".to_string());
    msg.refs = vec![MessageRef { kind: "note".to_string(), locator: "loc".to_string(), digest: Some("ab".repeat(32)) }];

    store.insert_message(msg.clone(), None).expect("insert succeeds");
    let fetched = store.get_message(&msg.message_id).expect("get succeeds").expect("message exists");
    assert_eq!(fetched, msg);
}

#[test]
fn message_round_trip_preserves_a_session_scoped_from_and_to() {
    let mut store = store();
    let claude = participant("claude");
    let bob = participant("bob");
    let session = session_id("s-7f3a0000");
    let msg = message(message_id(1), session_address(&claude, &session), direct(&bob), 1_000);

    store.insert_message(msg.clone(), None).expect("insert succeeds");
    let fetched = store.get_message(&msg.message_id).expect("get succeeds").expect("message exists");
    assert_eq!(fetched.from, session_address(&claude, &session));
    assert_eq!(fetched, msg);
}

#[test]
fn repeat_idempotency_key_returns_the_original_message_id_and_creates_nothing() {
    let mut store = store();
    let alice = participant("alice");
    let bob = participant("bob");
    let first = message(message_id(1), direct(&alice), direct(&bob), 1_000);
    let second = message(message_id(2), direct(&alice), direct(&bob), 2_000);

    let first_outcome = store
        .insert_message(first.clone(), Some((direct(&alice), "retry-1".to_string())))
        .expect("first insert succeeds");
    assert_eq!(first_outcome, InsertMessageOutcome::Inserted);

    let second_outcome = store
        .insert_message(second.clone(), Some((direct(&alice), "retry-1".to_string())))
        .expect("second insert with the same key succeeds");
    assert_eq!(second_outcome, InsertMessageOutcome::Deduplicated { message_id: first.message_id.clone() });

    assert!(store.get_message(&second.message_id).expect("get succeeds").is_none(), "the retried message was never created");
    assert_eq!(store.messages_to_since(&direct(&bob), 0).expect("read succeeds").len(), 1, "only the first message exists");
}

#[test]
fn idempotency_is_keyed_per_address_so_two_sessions_with_the_same_key_both_create_a_message() {
    let mut store = store();
    let claude = participant("claude");
    let bob = participant("bob");
    let session_a = session_id("s-aaaaaaaa");
    let session_b = session_id("s-bbbbbbbb");
    let to_bob = direct(&bob);

    let first = message(message_id(1), session_address(&claude, &session_a), to_bob.clone(), 1_000);
    let second = message(message_id(2), session_address(&claude, &session_b), to_bob.clone(), 2_000);

    let first_outcome = store
        .insert_message(first.clone(), Some((session_address(&claude, &session_a), "retry-1".to_string())))
        .expect("first insert succeeds");
    assert_eq!(first_outcome, InsertMessageOutcome::Inserted);

    let second_outcome = store
        .insert_message(second.clone(), Some((session_address(&claude, &session_b), "retry-1".to_string())))
        .expect("second insert succeeds");
    assert_eq!(second_outcome, InsertMessageOutcome::Inserted, "a different session's same key is a different message");

    assert_eq!(store.messages_to_since(&to_bob, 0).expect("read succeeds").len(), 2);
}

#[test]
fn messages_to_since_honours_the_since_bound_and_orders_by_created_at() {
    let mut store = store();
    let alice = participant("alice");
    let bob = participant("bob");
    store.insert_message(message(message_id(1), direct(&alice), direct(&bob), 1_000), None).expect("insert succeeds");
    store.insert_message(message(message_id(2), direct(&alice), direct(&bob), 3_000), None).expect("insert succeeds");
    store.insert_message(message(message_id(3), direct(&alice), direct(&bob), 2_000), None).expect("insert succeeds");

    let page = store.messages_to_since(&direct(&bob), 1_500).expect("read succeeds");
    let ids: Vec<_> = page.iter().map(|message| message.message_id.clone()).collect();
    assert_eq!(ids, vec![message_id(3), message_id(2)], "only messages at/after the bound, oldest first");
}

#[test]
fn messages_to_since_distinguishes_an_account_address_from_one_of_its_sessions() {
    let mut store = store();
    let alice = participant("alice");
    let claude = participant("claude");
    let session = session_id("s-7f3a0000");
    let to_account = message(message_id(1), direct(&alice), direct(&claude), 1_000);
    let to_session = message(message_id(2), direct(&alice), session_address(&claude, &session), 1_000);
    store.insert_message(to_account.clone(), None).expect("insert succeeds");
    store.insert_message(to_session.clone(), None).expect("insert succeeds");

    let account_mail = store.messages_to_since(&direct(&claude), 0).expect("read succeeds");
    assert_eq!(
        account_mail.iter().map(|message| message.message_id.clone()).collect::<Vec<_>>(),
        vec![to_account.message_id.clone()]
    );

    let session_mail = store.messages_to_since(&session_address(&claude, &session), 0).expect("read succeeds");
    assert_eq!(
        session_mail.iter().map(|message| message.message_id.clone()).collect::<Vec<_>>(),
        vec![to_session.message_id.clone()]
    );
}

#[test]
fn room_messages_since_honours_the_since_bound_and_orders_by_created_at() {
    let mut store = store();
    let alice = participant("alice");
    let room_id = room("room-1");
    let to_room = Address::Room { room: room_id.clone() };
    store.insert_message(message(message_id(1), direct(&alice), to_room.clone(), 1_000), None).expect("insert succeeds");
    store.insert_message(message(message_id(2), direct(&alice), to_room.clone(), 3_000), None).expect("insert succeeds");
    store.insert_message(message(message_id(3), direct(&alice), to_room.clone(), 2_000), None).expect("insert succeeds");

    let page = store.room_messages_since(&room_id, 1_500).expect("read succeeds");
    let ids: Vec<_> = page.iter().map(|message| message.message_id.clone()).collect();
    assert_eq!(ids, vec![message_id(3), message_id(2)], "only messages at/after the bound, oldest first");
}

#[test]
fn ack_round_trips_and_is_idempotent_on_first_write() {
    let mut store = store();
    let alice = participant("alice");
    let bob = participant("bob");
    let msg = message(message_id(1), direct(&alice), direct(&bob), 1_000);
    store.insert_message(msg.clone(), None).expect("insert succeeds");

    assert_eq!(store.get_ack(&msg.message_id, &direct(&bob)).expect("lookup succeeds"), None);

    let first = store
        .record_ack(Ack { message_id: msg.message_id.clone(), reader: direct(&bob), acked_at_unix_ms: 2_000 })
        .expect("first ack succeeds");
    let second = store
        .record_ack(Ack { message_id: msg.message_id.clone(), reader: direct(&bob), acked_at_unix_ms: 9_000 })
        .expect("second ack succeeds");

    assert_eq!(first, second);
    assert_eq!(first.acked_at_unix_ms, 2_000, "the first ack's timestamp wins, not the second's");
    assert_eq!(store.get_ack(&msg.message_id, &direct(&bob)).expect("lookup succeeds"), Some(first));
}

#[test]
fn ack_is_keyed_by_message_and_reader_independently() {
    let mut store = store();
    let alice = participant("alice");
    let bob = participant("bob");
    let carol = participant("carol");
    let room_id = room("room-1");
    store.create_room(room_id.clone(), 1_000).expect("room is created");
    let msg = message(message_id(1), direct(&alice), Address::Room { room: room_id }, 1_000);
    store.insert_message(msg.clone(), None).expect("insert succeeds");

    store
        .record_ack(Ack { message_id: msg.message_id.clone(), reader: direct(&bob), acked_at_unix_ms: 2_000 })
        .expect("bob acks");

    assert!(store.get_ack(&msg.message_id, &direct(&bob)).expect("lookup succeeds").is_some());
    assert!(store.get_ack(&msg.message_id, &direct(&carol)).expect("lookup succeeds").is_none(), "carol never acked");
}

#[test]
fn an_ack_by_a_session_does_not_count_as_an_ack_by_its_account() {
    let mut store = store();
    let alice = participant("alice");
    let claude = participant("claude");
    let session = session_id("s-7f3a0000");
    let msg = message(message_id(1), direct(&alice), direct(&claude), 1_000);
    store.insert_message(msg.clone(), None).expect("insert succeeds");

    store
        .record_ack(Ack {
            message_id: msg.message_id.clone(),
            reader: session_address(&claude, &session),
            acked_at_unix_ms: 2_000,
        })
        .expect("the session acks");

    assert!(
        store.get_ack(&msg.message_id, &session_address(&claude, &session)).expect("lookup succeeds").is_some(),
        "the session's own ack is on file"
    );
    assert!(
        store.get_ack(&msg.message_id, &direct(&claude)).expect("lookup succeeds").is_none(),
        "a session's ack must not be visible as its account's"
    );
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

// -- Sessions

#[test]
fn session_round_trips_through_get_and_upsert() {
    let mut store = store();
    let claude = participant("claude");
    store.register_participant(claude.clone(), participant_record(1)).expect("claude registers");
    let session = session_id("s-7f3a0000");
    let record = SessionRecord { account: claude.clone(), card: bare_card(4242, 1_000), last_seen_unix_ms: 1_000 };

    assert_eq!(store.get_session(&session).expect("get succeeds"), None);

    store.upsert_session(session.clone(), record.clone()).expect("upsert succeeds");
    let fetched = store.get_session(&session).expect("get succeeds").expect("session exists");
    assert_eq!(fetched, record);
}

#[test]
fn sessions_of_returns_only_that_accounts_sessions() {
    let mut store = store();
    let claude = participant("claude");
    let codex = participant("codex");
    store.register_participant(claude.clone(), participant_record(1)).expect("claude registers");
    store.register_participant(codex.clone(), participant_record(2)).expect("codex registers");
    let claude_session = session_id("s-aaaaaaaa");
    let codex_session = session_id("s-bbbbbbbb");
    store
        .upsert_session(
            claude_session.clone(),
            SessionRecord { account: claude.clone(), card: bare_card(1, 1), last_seen_unix_ms: 1_000 },
        )
        .expect("claude's session registers");
    store
        .upsert_session(
            codex_session.clone(),
            SessionRecord { account: codex.clone(), card: bare_card(2, 2), last_seen_unix_ms: 1_000 },
        )
        .expect("codex's session registers");

    let claude_sessions = store.sessions_of(&claude).expect("lookup succeeds");
    assert_eq!(claude_sessions.len(), 1, "codex's session must not appear under claude");
    assert_eq!(claude_sessions[0].0, claude_session);

    let codex_sessions = store.sessions_of(&codex).expect("lookup succeeds");
    assert_eq!(codex_sessions.len(), 1, "claude's session must not appear under codex");
    assert_eq!(codex_sessions[0].0, codex_session);
}

#[test]
fn upsert_session_refreshes_corroborated_and_last_seen_while_the_caller_carries_declared_forward() {
    let mut store = store();
    let claude = participant("claude");
    store.register_participant(claude.clone(), participant_record(1)).expect("claude registers");
    let session = session_id("s-7f3a0000");

    let mut first_card = bare_card(4242, 1_000);
    first_card.declared.working_on = Some("parity work".to_string());
    store
        .upsert_session(
            session.clone(),
            SessionRecord { account: claude.clone(), card: first_card.clone(), last_seen_unix_ms: 1_000 },
        )
        .expect("first upsert succeeds");

    // Mirrors what `MailboxEngine::ensure_session` does before calling
    // `upsert_session`: carry the existing `declared` group forward
    // untouched while replacing `corroborated` and refreshing
    // `last_seen`. The store itself does no merging (see
    // `MailStore::upsert_session`'s own doc comment) -- this proves it
    // persists exactly what it is handed, field for field.
    let mut refreshed_card = bare_card(4242, 1_000);
    refreshed_card.corroborated.model = Some(Declared::new("opus".to_string()));
    refreshed_card.declared = first_card.declared.clone();
    store
        .upsert_session(session.clone(), SessionRecord { account: claude.clone(), card: refreshed_card, last_seen_unix_ms: 2_000 })
        .expect("second upsert succeeds");

    let fetched = store.get_session(&session).expect("get succeeds").expect("session exists");
    assert_eq!(fetched.last_seen_unix_ms, 2_000, "last_seen advances on refresh");
    assert_eq!(
        fetched.card.declared.working_on,
        Some("parity work".to_string()),
        "declared, carried forward by the caller, survives the refresh"
    );
    assert_eq!(
        fetched.card.corroborated.model.map(Declared::into_inner),
        Some("opus".to_string()),
        "corroborated fields update on refresh"
    );
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

#[test]
fn a_v1_database_survives_the_v2_migration_with_every_v1_row_still_readable() {
    let db = Db::open(&DbConfig::in_memory()).expect("in-memory db opens");
    let all_migrations = migrations();
    assert_eq!(all_migrations.len(), 3, "this test assumes exactly v1, v2 and v3 exist so far");

    // Apply only v1 -- the shape the live mailbox on 18301 is at right now.
    db.run_migrations_blocking(MigrationRunner::new(vec![all_migrations[0].clone()])).expect("v1 alone applies");

    let alice = participant("alice");
    let bob = participant("bob");
    let room_id = room("room-1");
    let msg_id = message_id(1);

    // Insert a participant, a room, a message and an ack directly with SQL,
    // exactly the shape v1's own columns held before this crate's `from`
    // and `to` could ever name a session: `from_participant`/`reader` are
    // plain participant ids, `to_kind = 'direct'`.
    db.write_blocking(|conn| {
        conn.execute(
            "INSERT INTO participants (id, label, secret_digest, may_send, may_read, operator)
             VALUES (?1, NULL, ?2, 1, 1, 0)",
            rusqlite::params![alice.as_str(), vec![1u8; 32]],
        )?;
        conn.execute(
            "INSERT INTO participants (id, label, secret_digest, may_send, may_read, operator)
             VALUES (?1, NULL, ?2, 1, 1, 0)",
            rusqlite::params![bob.as_str(), vec![2u8; 32]],
        )?;
        conn.execute(
            "INSERT INTO rooms (id, created_at_unix_ms) VALUES (?1, 1000)",
            rusqlite::params![room_id.as_str()],
        )?;
        conn.execute(
            "INSERT INTO messages
                (message_id, from_participant, to_kind, to_participant, to_room, created_at_unix_ms, payload)
             VALUES (?1, ?2, 'direct', ?3, NULL, 1000, ?4)",
            rusqlite::params![
                msg_id.as_str(),
                alice.as_str(),
                bob.as_str(),
                r#"{"subject":"hi","body":"hi","reply_to":null,"correlation":null,"refs":[]}"#,
            ],
        )?;
        conn.execute(
            "INSERT INTO acks (message_id, reader, acked_at_unix_ms) VALUES (?1, ?2, 2000)",
            rusqlite::params![msg_id.as_str(), bob.as_str()],
        )?;
        Ok(())
    })
    .expect("v1-shaped rows insert directly");

    // Now bring the database up to the latest schema (v2, then v3).
    db.run_migrations_blocking(MigrationRunner::new(all_migrations))
        .expect("v2 and v3 apply on top of the live v1 data");

    let mut mail_store = SqliteMailStore::new(db);

    let alice_record = mail_store.get_participant(&alice).expect("get succeeds").expect("alice survives the migration");
    assert_eq!(alice_record.secret_digest, [1u8; 32]);
    // v3 adds `listener_url` as a nullable column -- a row written before
    // it existed reads back with no listener on file, not a decode error.
    assert_eq!(alice_record.listener_url, None);
    let bob_record = mail_store.get_participant(&bob).expect("get succeeds").expect("bob survives the migration");
    assert_eq!(bob_record.secret_digest, [2u8; 32]);

    let room_record = mail_store.get_room(&room_id).expect("get succeeds").expect("the room survives the migration");
    assert_eq!(room_record.created_at_unix_ms, 1_000);

    let fetched_message =
        mail_store.get_message(&msg_id).expect("get succeeds").expect("the message survives the migration");
    assert_eq!(fetched_message.from, direct(&alice), "a pre-v2 sender is still read back as a direct account address");
    assert_eq!(fetched_message.to, direct(&bob));
    assert_eq!(fetched_message.subject, "hi");
    assert_eq!(fetched_message.body, "hi");

    let bobs_mail = mail_store.messages_to_since(&direct(&bob), 0).expect("read succeeds");
    assert_eq!(bobs_mail.len(), 1, "the pre-v2 direct message is still found by messages_to_since");
    assert_eq!(bobs_mail[0].message_id, msg_id);

    let ack = mail_store
        .get_ack(&msg_id, &direct(&bob))
        .expect("get succeeds")
        .expect("the pre-v2 ack survives the migration");
    assert_eq!(ack.acked_at_unix_ms, 2_000);

    // The new session-shaped surface is fully usable on this
    // migrated-from-v1 database too, not merely tolerant of the old rows.
    let session = session_id("s-7f3a0000");
    assert_eq!(mail_store.get_session(&session).expect("get succeeds"), None);
    mail_store
        .upsert_session(session.clone(), SessionRecord { account: alice.clone(), card: bare_card(1, 1), last_seen_unix_ms: 5_000 })
        .expect("a session registers on the migrated database");
    assert!(mail_store.get_session(&session).expect("get succeeds").is_some());
}
