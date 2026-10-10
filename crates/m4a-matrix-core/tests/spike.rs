use std::collections::HashMap;

use ed25519_dalek::{Signer as _, SigningKey};
use m4a_matrix_core::{resolve_state, OwnedEventId, OwnedRoomId, Pdu, RoomBuilder, Signer};
use ruma_events::StateEventType;
use serde_json::json;

const SERVER: &str = "a.example";
const ALICE: &str = "@alice:a.example";
const BOB: &str = "@bob:a.example";

fn signer(seed: u8) -> Signer {
    let key = SigningKey::from_bytes(&[seed; 32]);
    Signer::new(SERVER, "ed25519:k1", move |m| key.sign(m).to_bytes())
}

fn room(s: &Signer) -> RoomBuilder<'_> {
    let rid: OwnedRoomId = "!opaque1:a.example".try_into().unwrap();
    let mut r = RoomBuilder::new(rid, s, 1_700_000_000_000).unwrap();
    r.push(ALICE, "m.room.create", Some(""), json!({"creator": ALICE, "room_version": "11"})).unwrap();
    r.push(ALICE, "m.room.member", Some(ALICE), json!({"membership": "join"})).unwrap();
    r.push(ALICE, "m.room.power_levels", Some(""), json!({"users": {ALICE: 100, BOB: 50}, "users_default": 0, "state_default": 50, "events_default": 0, "ban": 50, "kick": 50, "invite": 0, "redact": 50})).unwrap();
    r.push(ALICE, "m.room.join_rules", Some(""), json!({"join_rule": "public"})).unwrap();
    r.push(ALICE, "m.room.history_visibility", Some(""), json!({"history_visibility": "shared"})).unwrap();
    r.push(BOB, "m.room.member", Some(BOB), json!({"membership": "join"})).unwrap();
    r
}

#[test]
fn event_ids_are_the_reference_hash_and_are_deterministic() {
    let s = signer(7);
    let (a, b) = (room(&s), room(&s));
    for (x, y) in a.events().iter().zip(b.events()) {
        assert_eq!(x.event_id, y.event_id, "same content, same key, same id");
        let id = x.event_id.as_str();
        assert!(id.starts_with('$') && id.len() == 44, "$ + 43 chars of unpadded url-safe base64: {id}");
        assert!(!id.contains(['+', '/', '=']));
        assert!(!x.json.contains_key("event_id"), "no event_id on the wire in v11");
        assert!(x.json.contains_key("hashes") && x.json.contains_key("signatures"));
    }
    let ids: std::collections::HashSet<_> = a.events().iter().map(|e| &e.event_id).collect();
    assert_eq!(ids.len(), a.events().len());
}

#[test]
fn auth_events_and_prev_events_are_filled_from_the_room() {
    let s = signer(7);
    let r = room(&s);
    let ev = r.events();
    let get = |i: usize, k: &str| serde_json::to_value(ev[i].json.get(k).unwrap()).unwrap();
    assert_eq!(get(0, "auth_events"), json!([]));
    assert_eq!(get(0, "prev_events"), json!([]));
    // bob's join cites create, power levels and join rules (member join rule), and follows the previous event.
    let bob_auth: Vec<String> = serde_json::from_value(get(5, "auth_events")).unwrap();
    for needed in [&ev[0].event_id, &ev[2].event_id, &ev[3].event_id] {
        assert!(bob_auth.contains(&needed.to_string()), "missing {needed}");
    }
    assert_eq!(get(5, "prev_events"), json!([ev[4].event_id]));
    assert_eq!(get(5, "depth"), json!(6));
}

#[test]
fn signatures_verify_and_a_tampered_event_does_not() {
    let s = signer(7);
    let r = room(&s);
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut pk = std::collections::BTreeMap::new();
    let mut inner = std::collections::BTreeMap::new();
    inner.insert("ed25519:k1".to_owned(), ruma_common::serde::Base64::new(key.verifying_key().to_bytes().to_vec()));
    pk.insert(SERVER.to_owned(), inner);
    let rules = r.rules();
    let ev = &r.events()[3];
    assert_eq!(ruma_signatures::verify_event(&pk, &ev.json, rules).unwrap(), ruma_signatures::Verified::All);
    // A field the signature covers changed: refused.
    let mut forged = ev.json.clone();
    forged.insert("origin_server_ts".into(), ruma_common::CanonicalJsonValue::Integer(5u32.into()));
    assert!(ruma_signatures::verify_event(&pk, &forged, rules).is_err());
    // Content of an event whose content the redaction keeps (history visibility) changed: the signature breaks.
    let mut hv = r.events()[4].json.clone();
    hv.insert("content".into(), ruma_common::CanonicalJsonValue::Object(Default::default()));
    assert!(ruma_signatures::verify_event(&pk, &hv, rules).is_err());
    // Content changed (not covered by the signature, covered by the content hash): only the redacted form verifies.
    let mut r2 = room(&s);
    r2.push(ALICE, "m.room.name", Some(""), json!({"name": "hello"})).unwrap();
    let mut edited = r2.events().last().unwrap().json.clone();
    edited.insert("content".into(), ruma_common::CanonicalJsonValue::Object(Default::default()));
    assert_eq!(ruma_signatures::verify_event(&pk, &edited, rules).unwrap(), ruma_signatures::Verified::Signatures);
}

#[test]
fn the_auth_rules_refuse_what_a_room_would_refuse() {
    let s = signer(7);
    let mut r = room(&s);
    // carol never joined and has no power: she cannot set the name.
    assert!(r.push("@carol:a.example", "m.room.name", Some(""), json!({"name": "x"})).is_err());
    // bob has level 50: he can.
    assert!(r.push(BOB, "m.room.name", Some(""), json!({"name": "bob's"})).is_ok());
}


#[test]
fn state_resolution_applies_a_ban_before_a_racing_event_from_the_banned_user() {
    let s = signer(7);
    // Two replays of the same base, then each branch continues with its own event. The base is
    // deterministic, so both replays have identical event ids.
    let mut a = room(&s);
    let mut b = room(&s);
    assert_eq!(a.events().last().unwrap().event_id, b.events().last().unwrap().event_id);
    // Branch A: alice bans bob. Branch B: bob (level 50, still joined on his branch) renames the room.
    a.push(ALICE, "m.room.member", Some(BOB), json!({"membership": "ban"})).unwrap();
    b.push(BOB, "m.room.name", Some(""), json!({"name": "bob was here"})).unwrap();

    let mut pdus: HashMap<OwnedEventId, Pdu> = a.pdus().clone();
    pdus.extend(b.pdus().clone());
    let rules = a.rules().clone();
    let resolved = resolve_state(&rules, &pdus, &[a.state().clone(), b.state().clone()]).unwrap();
    let bob_member = resolved.get(&(StateEventType::RoomMember, BOB.to_owned())).unwrap();
    let ban_id = a.events().last().unwrap().event_id.clone();
    assert_eq!(bob_member, &ban_id, "the ban wins the member slot");
    // The rename was authorised only against bob's own branch; after resolution bob is banned, so it must not be in the state.
    assert!(resolved.get(&(StateEventType::RoomName, String::new())).is_none(), "a banned user's racing rename is dropped: {resolved:?}");
    // Order of the forks does not matter.
    let swapped = resolve_state(&rules, &pdus, &[b.state().clone(), a.state().clone()]).unwrap();
    assert_eq!(resolved, swapped);
}

#[test]
fn state_resolution_picks_the_later_of_two_equal_power_renames_the_same_way_in_any_order() {
    let s = signer(7);
    let mut a = room(&s);
    let mut b = room(&s);
    a.push(ALICE, "m.room.name", Some(""), json!({"name": "first"})).unwrap();
    b.push(ALICE, "m.room.topic", Some(""), json!({"topic": "other branch"})).unwrap();
    b.push(ALICE, "m.room.name", Some(""), json!({"name": "second"})).unwrap();
    let mut pdus = a.pdus().clone();
    pdus.extend(b.pdus().clone());
    let rules = a.rules().clone();
    let r1 = resolve_state(&rules, &pdus, &[a.state().clone(), b.state().clone()]).unwrap();
    let r2 = resolve_state(&rules, &pdus, &[b.state().clone(), a.state().clone()]).unwrap();
    assert_eq!(r1, r2);
    let name = r1.get(&(StateEventType::RoomName, String::new())).unwrap();
    assert_eq!(name, &b.events().last().unwrap().event_id, "equal power, same mainline: the later timestamp wins");
    assert!(r1.contains_key(&(StateEventType::RoomTopic, String::new())), "the non-conflicting topic is kept");
}
