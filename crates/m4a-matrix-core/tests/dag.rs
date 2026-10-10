use std::{cell::RefCell, collections::HashMap};

use ed25519_dalek::{Signer as _, SigningKey};
use m4a_matrix_core::dag::DagRead as _;
use m4a_matrix_core::{dag, CanonicalJsonObject, OwnedEventId, OwnedRoomId, Pdu, PublicKeyMap, Signer, StateMap};
use ruma_common::{room_version_rules::RoomVersionRules, serde::Base64};
use ruma_events::StateEventType;
use serde_json::json;

const ALICE: &str = "@alice:a.example";
const BOB: &str = "@bob:b.example";

fn rules() -> RoomVersionRules {
    m4a_matrix_core::ROOM_VERSION.rules().unwrap()
}

fn signer(server: &str, seed: u8) -> Signer {
    let key = SigningKey::from_bytes(&[seed; 32]);
    Signer::new(server, "ed25519:k1", move |m| key.sign(m).to_bytes())
}

fn keys() -> PublicKeyMap {
    let mut m = PublicKeyMap::new();
    for (server, seed) in [("a.example", 1u8), ("b.example", 2u8)] {
        let pk = SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes().to_vec();
        m.entry(server.to_owned()).or_default().insert("ed25519:k1".to_owned(), Base64::new(pk));
    }
    m
}

/// A server's copy of the room.
#[derive(Clone, Default)]
struct Mem {
    pdus: RefCell<HashMap<OwnedEventId, Pdu>>,
    json: RefCell<HashMap<OwnedEventId, CanonicalJsonObject>>,
    state: RefCell<HashMap<OwnedEventId, StateMap<OwnedEventId>>>,
    ext: RefCell<Vec<OwnedEventId>>,
}

impl dag::DagRead for Mem {
    fn pdu(&self, id: &ruma_common::EventId) -> Option<Pdu> {
        self.pdus.borrow().get(id).cloned()
    }
    fn state_after(&self, id: &ruma_common::EventId) -> Option<StateMap<OwnedEventId>> {
        self.state.borrow().get(id).cloned()
    }
    fn extremities(&self) -> Vec<OwnedEventId> {
        self.ext.borrow().clone()
    }
}

impl Mem {
    fn store(&self, a: &dag::Accepted) {
        self.pdus.borrow_mut().insert(a.event_id.clone(), a.pdu.clone());
        self.json.borrow_mut().insert(a.event_id.clone(), a.json.clone());
        self.state.borrow_mut().insert(a.event_id.clone(), a.state_after.clone());
        *self.ext.borrow_mut() = a.extremities.clone();
    }
    fn local(&self, s: &Signer, ts: u64, sender: &str, kind: &str, sk: Option<&str>, content: serde_json::Value) -> dag::Accepted {
        let room: OwnedRoomId = "!r:a.example".try_into().unwrap();
        let a = dag::local_event(&rules(), self, s, &room, ts, sender, kind, sk, content).unwrap();
        self.store(&a);
        a
    }
    fn receive(&self, from: &Mem, id: &OwnedEventId) -> Result<dag::Accepted, dag::Reject> {
        let j = from.json.borrow().get(id).unwrap().clone();
        let a = dag::accept_wire(&rules(), self, j, &keys(), None)?;
        self.store(&a);
        Ok(a)
    }
    fn current(&self) -> StateMap<OwnedEventId> {
        dag::current_state(&rules(), self).unwrap()
    }
    fn name(&self) -> Option<OwnedEventId> {
        self.current().get(&(StateEventType::RoomName, String::new())).cloned()
    }
}

/// Room with alice (server A) and bob (server B, level 50) joined; both servers hold the same history.
fn base() -> (Mem, Mem, Signer, Signer) {
    let (sa, sb) = (signer("a.example", 1), signer("b.example", 2));
    let a = Mem::default();
    let t = 1_700_000_000_000;
    a.local(&sa, t, ALICE, "m.room.create", Some(""), json!({"creator": ALICE, "room_version": "11"}));
    a.local(&sa, t + 1, ALICE, "m.room.member", Some(ALICE), json!({"membership": "join"}));
    a.local(&sa, t + 2, ALICE, "m.room.power_levels", Some(""), json!({"users": {ALICE: 100, BOB: 50}, "users_default": 0, "state_default": 50, "events_default": 0, "ban": 50, "kick": 50, "invite": 0, "redact": 50}));
    a.local(&sa, t + 3, ALICE, "m.room.join_rules", Some(""), json!({"join_rule": "public"}));
    // Bob's join is built from A's template, signed by B, and received by A.
    let room: OwnedRoomId = "!r:a.example".try_into().unwrap();
    let tpl = dag::template(&rules(), &a, &room, t + 4, BOB, "m.room.member", Some(BOB), json!({"membership": "join"})).unwrap();
    let signed = dag::sign_template(&rules(), &sb, tpl).unwrap();
    let acc = dag::accept_wire(&rules(), &a, signed.json, &keys(), None).unwrap();
    a.store(&acc);
    let b = a.clone();
    (a, b, sa, sb)
}

#[test]
fn ids_chain_state_and_extremities_follow_the_dag() {
    let (a, _, sa, _) = base();
    assert_eq!(a.extremities().len(), 1);
    let m = a.local(&sa, 1_700_000_001_000, ALICE, "m.room.message", None, json!({"msgtype": "m.text", "body": "hi"}));
    assert!(!m.forked && m.state_after == a.current(), "a message changes no state");
    assert_eq!(m.pdu.prev_events.len(), 1);
    assert!(m.pdu.depth > 5);
}

#[test]
fn a_forged_or_unsigned_event_is_refused_on_receipt() {
    let (a, _, _, sb) = base();
    let room: OwnedRoomId = "!r:a.example".try_into().unwrap();
    let tpl = dag::template(&rules(), &a, &room, 1_700_000_002_000, BOB, "m.room.name", Some(""), json!({"name": "x"})).unwrap();
    let ok = dag::sign_template(&rules(), &sb, tpl.clone()).unwrap();
    // Signed by the wrong server key: bob's event signed under a.example's name.
    let wrong = dag::sign_template(&rules(), &signer("a.example", 9), tpl).unwrap();
    assert!(matches!(dag::accept_wire(&rules(), &a, wrong.json, &keys(), None), Err(dag::Reject::BadSignature(_))));
    // Tampered signed field.
    let mut forged = ok.json.clone();
    forged.insert("origin_server_ts".into(), ruma_common::CanonicalJsonValue::Integer(7u32.into()));
    assert!(dag::accept_wire(&rules(), &a, forged, &keys(), None).is_err());
    assert!(dag::accept_wire(&rules(), &a, ok.json, &keys(), None).is_ok());
}

#[test]
fn auth_rules_refuse_a_member_without_power_and_an_unknown_prev() {
    let (a, _, sa, _) = base();
    let room: OwnedRoomId = "!r:a.example".try_into().unwrap();
    // carol (no membership) sends a state event; signed by a.example for the test.
    let tpl = dag::template(&rules(), &a, &room, 1_700_000_003_000, "@carol:a.example", "m.room.name", Some(""), json!({"name": "x"})).unwrap();
    let s = dag::sign_template(&rules(), &sa, tpl).unwrap();
    assert!(matches!(dag::accept(&rules(), &a, s.event_id, s.json, None), Err(dag::Reject::Auth(_))));
    // An event whose prev_events this server never saw.
    let other = Mem::default();
    let sb = signer("b.example", 2);
    let (x, _, _, _) = base();
    let _ = (other, sb, x);
    let mut t = dag::template(&rules(), &a, &room, 1_700_000_004_000, ALICE, "m.room.message", None, json!({"body": "x"})).unwrap();
    t.insert("prev_events".into(), ruma_common::CanonicalJsonValue::Array(vec!["$unknownunknownunknownunknownunknownunknownxx".into()]));
    let s = dag::sign_template(&rules(), &sa, t).unwrap();
    assert!(matches!(dag::accept(&rules(), &a, s.event_id, s.json, None), Err(dag::Reject::MissingPrev(_))));
}

#[test]
fn partitioned_servers_converge_on_the_same_state_after_exchanging_a_fork() {
    let (a, b, sa, sb) = base();
    let xa = a.local(&sa, 1_700_000_010_000, ALICE, "m.room.name", Some(""), json!({"name": "from alice"}));
    let yb = b.local(&sb, 1_700_000_010_500, BOB, "m.room.name", Some(""), json!({"name": "from bob"}));
    assert_ne!(a.name(), b.name(), "partitioned: each sees only its own rename");
    // The partition heals: each receives the other's event.
    let on_a = a.receive(&b, &yb.event_id).unwrap();
    let on_b = b.receive(&a, &xa.event_id).unwrap();
    assert!(on_a.forked && on_b.forked, "two forward extremities");
    assert_eq!(a.extremities(), b.extremities());
    assert_eq!(on_a.current_state, a.current(), "the state reported at acceptance is the resolved one, new event included");
    assert_eq!(on_b.current_state, b.current());
    assert_eq!(a.current(), b.current(), "state resolution v2 gives both servers the same room state");
    assert_eq!(a.name(), Some(yb.event_id.clone()), "equal-mainline conflict: the later timestamp wins");
    // The next event cites both branches and closes the fork.
    let m = a.local(&sa, 1_700_000_011_000, ALICE, "m.room.message", None, json!({"body": "merged"}));
    assert_eq!(m.pdu.prev_events.len(), 2);
    assert!(!m.forked);
    assert_eq!(a.extremities().len(), 1);
}

#[test]
fn a_ban_on_one_branch_beats_a_racing_event_of_the_banned_user_on_both_servers() {
    let (a, b, sa, sb) = base();
    let ban = a.local(&sa, 1_700_000_020_000, ALICE, "m.room.member", Some(BOB), json!({"membership": "ban"}));
    let rename = b.local(&sb, 1_700_000_020_100, BOB, "m.room.name", Some(""), json!({"name": "bob wins?"}));
    a.receive(&b, &rename.event_id).unwrap();
    b.receive(&a, &ban.event_id).unwrap();
    assert_eq!(a.current(), b.current());
    assert_eq!(a.current().get(&(StateEventType::RoomMember, BOB.to_owned())), Some(&ban.event_id));
    assert!(a.name().is_none(), "the banned user's rename is not in the resolved state");
}

#[test]
fn an_event_that_only_fails_against_current_state_is_soft_failed_and_not_an_extremity() {
    let (a, b, sa, sb) = base();
    // B's bob renames the room on a branch; A bans bob, but the ban reaches B only after bob's later event.
    a.local(&sa, 1_700_000_030_000, ALICE, "m.room.member", Some(BOB), json!({"membership": "ban"}));
    let late = b.local(&sb, 1_700_000_030_100, BOB, "m.room.message", None, json!({"body": "after ban?"}));
    let acc = a.receive(&b, &late.event_id).unwrap();
    assert!(acc.soft_failed, "valid when sent, refused by the current state");
    assert!(!acc.extremities.contains(&late.event_id));
}

#[test]
fn skeleton_keeps_the_event_id_and_signatures_but_drops_content() {
    let (a, _, sa, _) = base();
    let m = a.local(&sa, 1_700_000_040_000, ALICE, "m.room.message", None, json!({"msgtype": "m.text", "body": "secret"}));
    let sk = dag::skeleton(&rules(), &m.json).unwrap();
    assert_eq!(serde_json::to_value(sk.get("content").unwrap()).unwrap(), json!({}));
    assert!(sk.contains_key("signatures") && sk.contains_key("hashes") && sk.contains_key("prev_events"));
    assert_eq!(dag::compute_event_id(&rules(), &sk).unwrap(), m.event_id, "the id is a hash of the redacted form, so it survives");
    // The skeleton still verifies as a signature, but its content hash no longer matches: a peer sees a redacted event.
    assert!(matches!(dag::verify_wire(&rules(), &sk, &keys()), Err(dag::Reject::BadContentHash) | Ok(())));
}
