//! Three real servers, DAG rooms: a gap is filled with get_missing_events, a tampered answer is
//! rejected, and a late joiner catches up the parallel branches that were merged before it came.
//! Partitions and tampering are done by `support_fed::Link` hops between the servers.
#![cfg(feature = "f3-hash-ids")]

#[path = "support_product.rs"]
mod support_product;
#[path = "support/fed.rs"]
mod support_fed;

use std::time::Duration;

use mail4agent_server::federation::enc;
use reqwest::blocking::Client;
use serde_json::json;
use support_fed::{bodies, event_ids, free_port, poll, send, start_node, Link, Srv};

fn ct(tag: &str) -> serde_json::Value {
    json!({"algorithm":"m.megolm.v1.aes-sha2","sender_key":"k","session_id":"s","device_id":"D","ciphertext":format!("ct-{tag}")})
}

fn post(s: &Srv, c: &Client, room: &str, tag: &str) -> String {
    send(s, c, room, "m.room.encrypted", tag, ct(tag))["event_id"].as_str().unwrap().to_string()
}

fn has(s: &Srv, c: &Client, room: &str, tag: &str) -> bool {
    bodies(s, c, room).iter().any(|x| *x == format!("ct-{tag}"))
}

fn join_when_invited(s: &Srv, c: &Client, room: &str) {
    poll("invite arrives", || s.call(c, "GET", "/client/v3/sync?timeout=0", None).1["rooms"]["invite"].get(room).map(|_| ()));
    let (st, v) = s.call(c, "POST", &format!("/client/v3/rooms/{}/join", enc(room)), Some(json!({})));
    assert_eq!(st, 200, "join: {v}");
}

fn members(s: &Srv, c: &Client, room: &str) -> serde_json::Value {
    s.call(c, "GET", &format!("/client/v3/rooms/{}/joined_members", enc(room)), None).1["joined"].clone()
}

#[test]
fn a_gap_is_filled_by_get_missing_events_and_a_tampered_answer_is_rejected() {
    let (pa, pb, pc) = (free_port(), free_port(), free_port());
    let ac = Link::new(pc); // A reaches C through this hop
    let cb = Link::new(pb); // C reaches B through this hop
    let a = start_node("a.example", "alice", pa, &[("b.example", pb), ("c.example", ac.port)]);
    let b = start_node("b.example", "bob", pb, &[("a.example", pa), ("c.example", pc)]);
    let cs = start_node("c.example", "carol", pc, &[("a.example", pa), ("b.example", cb.port)]);
    let c = Client::builder().timeout(Duration::from_secs(10)).build().unwrap();

    let (st, v) = a.call(&c, "POST", "/client/v3/createRoom", Some(json!({"visibility":"private","name":"gap","invite":[b.user, cs.user]})));
    assert_eq!(st, 200, "{v}");
    let room = v["room_id"].as_str().unwrap().to_string();
    join_when_invited(&b, &c, &room);
    join_when_invited(&cs, &c, &room);
    poll("a sees both joined", || (members(&a, &c, &room).get(&b.user).is_some() && members(&a, &c, &room).get(&cs.user).is_some()).then_some(()));

    // A cannot reach C: A's message m1 reaches B only.
    ac.set_up(false);
    let m1 = post(&a, &c, &room, "m1");
    poll("b has m1", || has(&b, &c, &room, "m1").then_some(()));
    std::thread::sleep(Duration::from_millis(1500));
    assert!(!has(&cs, &c, &room, "m1"), "carol has not seen m1");

    // B's m2 cites m1, which C does not hold. C asks B for the gap, but the hop to B alters the
    // answer: the signature/hash no longer match, so C takes neither m1 nor m2.
    cb.set_tamper(true);
    let m2 = post(&b, &c, &room, "m2");
    std::thread::sleep(Duration::from_secs(3));
    assert!(!has(&cs, &c, &room, "m1") && !has(&cs, &c, &room, "m2"), "a tampered get_missing_events answer is rejected");
    assert!(!event_ids(&cs, &c, &room).contains(&m2));

    // An honest answer fills the gap: m3 cites m2, C fetches m2 and m1 from B, verifies them (m1 is
    // signed by A, whose key C looks up itself) and then takes m3.
    cb.set_tamper(false);
    let m3 = post(&b, &c, &room, "m3");
    poll("c has the gap and m3", || (has(&cs, &c, &room, "m1") && has(&cs, &c, &room, "m2") && has(&cs, &c, &room, "m3")).then_some(()));
    let on_c = event_ids(&cs, &c, &room);
    for id in [&m1, &m2, &m3] {
        assert!(on_c.contains(id), "{id} is on c under the same id");
    }

    // The partition heals; A's queued m1 arrives as a duplicate and new events flow again.
    ac.set_up(true);
    let m4 = post(&a, &c, &room, "m4");
    poll("c has m4", || has(&cs, &c, &room, "m4").then_some(()));
    assert!(event_ids(&cs, &c, &room).contains(&m4));
}

#[test]
fn a_late_joiner_catches_up_the_parallel_branches_merged_before_it_came() {
    let (pa, pb, pc) = (free_port(), free_port(), free_port());
    let ab = Link::new(pb);
    let ba = Link::new(pa);
    let a = start_node("a.example", "alice", pa, &[("b.example", ab.port), ("c.example", pc)]);
    let b = start_node("b.example", "bob", pb, &[("a.example", ba.port), ("c.example", pc)]);
    let cs = start_node("c.example", "carol", pc, &[("a.example", pa), ("b.example", pb)]);
    let c = Client::builder().timeout(Duration::from_secs(10)).build().unwrap();

    let (st, v) = a.call(&c, "POST", "/client/v3/createRoom", Some(json!({"visibility":"private","name":"fork","invite":[b.user]})));
    assert_eq!(st, 200, "{v}");
    let room = v["room_id"].as_str().unwrap().to_string();
    join_when_invited(&b, &c, &room);
    poll("a sees bob", || members(&a, &c, &room).get(&b.user).map(|_| ()));

    // Partition: both sides write from the same point, so the DAG forks.
    ab.set_up(false);
    ba.set_up(false);
    let ma = post(&a, &c, &room, "ma");
    let mb = post(&b, &c, &room, "mb");
    std::thread::sleep(Duration::from_millis(1500));
    assert!(!has(&a, &c, &room, "mb") && !has(&b, &c, &room, "ma"));
    ab.set_up(true);
    ba.set_up(true);
    poll("both branches meet on a", || has(&a, &c, &room, "mb").then_some(()));
    poll("both branches meet on b", || has(&b, &c, &room, "ma").then_some(()));
    // The next event cites both branches.
    let merge = post(&a, &c, &room, "merge");
    poll("b has the merge", || has(&b, &c, &room, "merge").then_some(()));

    // Carol comes late: she joins at the merge point and backfills what came before.
    let (st, v) = a.call(&c, "POST", &format!("/client/v3/rooms/{}/invite", enc(&room)), Some(json!({"user_id": cs.user})));
    assert_eq!(st, 200, "{v}");
    join_when_invited(&cs, &c, &room);
    poll("carol has both branches and the merge", || (has(&cs, &c, &room, "ma") && has(&cs, &c, &room, "mb") && has(&cs, &c, &room, "merge")).then_some(()));
    let on_c = event_ids(&cs, &c, &room);
    for id in [&ma, &mb, &merge] {
        assert!(on_c.contains(id), "{id} is on carol under the same id");
    }
}
