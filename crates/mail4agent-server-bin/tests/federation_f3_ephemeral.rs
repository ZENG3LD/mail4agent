//! Typing, read receipts and device-list updates between two servers sharing a hash-id room.
#![cfg(feature = "f3-hash-ids")]

#[path = "support_product.rs"]
mod support_product;
#[path = "support/fed.rs"]
mod support_fed;

use std::time::Duration;

use mail4agent_server::federation::enc;
use reqwest::blocking::Client;
use serde_json::json;
use support_fed::{bodies, free_port, poll, send, start_node};

#[test]
fn typing_receipts_and_device_list_updates_cross_servers() {
    let (pa, pb) = (free_port(), free_port());
    let a = start_node("a.example", "alice", pa, &[("b.example", pb)]);
    let b = start_node("b.example", "bob", pb, &[("a.example", pa)]);
    let c = Client::builder().timeout(Duration::from_secs(10)).build().unwrap();
    let (_, v) = a.call(&c, "POST", "/client/v3/createRoom", Some(json!({"visibility":"private","name":"closed","invite":[b.user]})));
    let room = v["room_id"].as_str().unwrap().to_string();
    poll("invite", || b.call(&c, "GET", "/client/v3/sync?timeout=0", None).1["rooms"]["invite"].get(&room).map(|_| ()));
    assert_eq!(b.call(&c, "POST", &format!("/client/v3/rooms/{}/join", enc(&room)), Some(json!({}))).0, 200);
    poll("joined", || a.call(&c, "GET", &format!("/client/v3/rooms/{}/joined_members", enc(&room)), None).1["joined"].get(&b.user).map(|_| ()));
    let ct = json!({"algorithm":"m.megolm.v1.aes-sha2","sender_key":"k","session_id":"s","device_id":"D","ciphertext":"ct-1"});
    let m1 = send(&a, &c, &room, "m.room.encrypted", "m1", ct)["event_id"].as_str().unwrap().to_string();
    poll("bob has it", || bodies(&b, &c, &room).iter().any(|x| x == "ct-1").then_some(()));

    let mut since = a.call(&c, "GET", "/client/v3/sync?timeout=0", None).1["next_batch"].as_str().unwrap().to_string();
    let mut watch = |what: &str, want: &dyn Fn(&serde_json::Value) -> bool| {
        poll(what, || {
            let (_, s) = a.call(&c, "GET", &format!("/client/v3/sync?timeout=500&since={since}"), None);
            since = s["next_batch"].as_str().unwrap().to_string();
            want(&s).then_some(())
        })
    };

    // Bob types on server b; alice's sync on server a shows it.
    let (st, v) = b.call(&c, "PUT", &format!("/client/v3/rooms/{}/typing/{}", enc(&room), enc(&b.user)), Some(json!({"typing": true, "timeout": 20000})));
    assert_eq!(st, 200, "{v}");
    watch("alice sees bob typing", &|s| s["rooms"]["join"][&room]["ephemeral"]["events"].as_array().is_some_and(|e| e.iter().any(|x| x["type"] == "m.typing" && x["content"]["user_ids"].as_array().is_some_and(|u| u.iter().any(|y| *y == json!(b.user))))));

    // Bob reads alice's message; alice sees his receipt.
    let (st, v) = b.call(&c, "POST", &format!("/client/v3/rooms/{}/receipt/m.read/{}", enc(&room), enc(&m1)), Some(json!({})));
    assert_eq!(st, 200, "{v}");
    watch("alice sees bob's receipt", &|s| s["rooms"]["join"][&room]["ephemeral"]["events"].as_array().is_some_and(|e| e.iter().any(|x| x["type"] == "m.receipt" && x["content"][&m1]["m.read"].get(&b.user).is_some())));

    // Bob publishes new device keys; alice is told his device list changed.
    let dk = json!({"device_keys": {"user_id": b.user, "device_id": b.device, "algorithms": ["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],
        "keys": {format!("curve25519:{}", b.device): "AAAA", format!("ed25519:{}", b.device): "BBBB"}, "signatures": {}}});
    let (st, v) = b.call(&c, "POST", "/client/v3/keys/upload", Some(dk));
    assert_eq!(st, 200, "{v}");
    watch("alice learns bob's device list changed", &|s| s["device_lists"]["changed"].as_array().is_some_and(|l| l.iter().any(|x| *x == json!(b.user))));

    // Presence: bob goes online with a status on server b; alice sees it in sync and by GET,
    // and a stranger's presence is not readable.
    let (st, v) = b.call(&c, "PUT", &format!("/client/v3/presence/{}/status", enc(&b.user)), Some(json!({"presence":"online","status_msg":"in the lab"})));
    assert_eq!(st, 200, "{v}");
    watch("alice sees bob's presence", &|s| s["presence"]["events"].as_array().is_some_and(|e| e.iter().any(|x| x["type"] == "m.presence" && x["sender"] == json!(b.user) && x["content"]["presence"] == "online" && x["content"]["status_msg"] == "in the lab")));
    let (st, v) = a.call(&c, "GET", &format!("/client/v3/presence/{}/status", enc(&b.user)), None);
    assert_eq!((st, v["presence"].as_str(), v["status_msg"].as_str()), (200, Some("online"), Some("in the lab")), "{v}");
    assert_eq!(a.call(&c, "GET", &format!("/client/v3/presence/{}/status", enc("@nobody:b.example")), None).0, 404);
}
