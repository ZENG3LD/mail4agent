//! Client routes beyond the core set, against a real server process behind the example product:
//! aliases, context, search, avatar, OpenID, reports, threads, room upgrade, and the account routes
//! the product owns.

#[path = "support_product.rs"]
mod support_product;
#[path = "support/fed.rs"]
mod support_fed;

use std::time::Duration;

use mail4agent_server::federation::enc;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use support_fed::{free_port, start_node, Srv};

fn call_as(s: &Srv, c: &Client, token: &str, m: &str, p: &str, b: Option<Value>) -> (u16, Value) {
    let mut r = c.request(m.parse().unwrap(), format!("{}{}", s.purl, p)).bearer_auth(token);
    if let Some(b) = b {
        r = r.json(&b);
    }
    let resp = r.send().unwrap();
    (resp.status().as_u16(), resp.json().unwrap_or(Value::Null))
}

#[test]
fn client_routes_for_stock_clients() {
    let a = start_node("a.example", "alice", free_port(), &[]);
    let c = Client::builder().timeout(Duration::from_secs(10)).build().unwrap();
    let pr = support_product::Product { url: a.purl.clone() };
    let bob_tok = support_product::product_user(&pr, "bob");
    let bob = |m: &str, p: &str, b: Option<Value>| call_as(&a, &c, &bob_tok, m, p, b);
    let alice = |m: &str, p: &str, b: Option<Value>| call_as(&a, &c, &a.token, m, p, b);
    let bob_id = bob("GET", "/client/v3/account/whoami", None).1["user_id"].as_str().unwrap().to_string();

    // A channel with a post, a group room with a thread.
    let (_, v) = alice("POST", "/client/v3/createRoom", Some(json!({"name":"general","visibility":"public","topic":"talk"})));
    let chan = v["room_id"].as_str().unwrap().to_string();
    let (st, v) = alice("PUT", &format!("/client/v3/rooms/{}/send/m.room.message/t1", enc(&chan)), Some(json!({"msgtype":"m.text","body":"needle in a haystack"})));
    assert_eq!(st, 200, "{v}");
    let post = v["event_id"].as_str().unwrap().to_string();
    for i in 0..4 {
        alice("PUT", &format!("/client/v3/rooms/{}/send/m.room.message/x{i}", enc(&chan)), Some(json!({"msgtype":"m.text","body":format!("filler {i}")})));
    }

    // aliases: create, resolve, taken, join by alias, list, delete.
    let alias = "#general:a.example";
    let (st, v) = alice("PUT", &format!("/client/v3/directory/room/{}", enc(alias)), Some(json!({"room_id": chan})));
    assert_eq!(st, 200, "{v}");
    assert_eq!(alice("PUT", &format!("/client/v3/directory/room/{}", enc(alias)), Some(json!({"room_id": chan}))).0, 409);
    let (st, v) = bob("GET", &format!("/client/v3/directory/room/{}", enc(alias)), None);
    assert_eq!((st, v["room_id"].as_str()), (200, Some(chan.as_str())));
    let (st, v) = bob("POST", &format!("/client/v3/join/{}", enc(alias)), Some(json!({})));
    assert_eq!((st, v["room_id"].as_str()), (200, Some(chan.as_str())), "{v}");
    assert_eq!(alice("GET", &format!("/client/v3/rooms/{}/aliases", enc(&chan)), None).1["aliases"], json!([alias]));
    assert_eq!(bob("DELETE", &format!("/client/v3/directory/room/{}", enc(alias)), None).0, 403);

    // context around a post, search, report.
    let (st, v) = bob("GET", &format!("/client/v3/rooms/{}/context/{}?limit=4", enc(&chan), enc(&post)), None);
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["event"]["event_id"], post.as_str());
    assert!(!v["events_after"].as_array().unwrap().is_empty() && v["start"].is_string() && v["end"].is_string());
    let (st, v) = bob("POST", "/client/v3/search", Some(json!({"search_categories":{"room_events":{"search_term":"NEEDLE"}}})));
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["search_categories"]["room_events"]["count"], 1);
    assert_eq!(v["search_categories"]["room_events"]["results"][0]["result"]["event_id"], post.as_str());
    assert_eq!(bob("POST", &format!("/client/v3/rooms/{}/report/{}", enc(&chan), enc(&post)), Some(json!({"reason":"spam","score":-100}))).0, 200);

    // profile with an avatar, OpenID.
    let (st, v) = alice("PUT", &format!("/client/v3/profile/{}/avatar_url", enc(&a.user)), Some(json!({"avatar_url":"mxc://a.example/abc"})));
    assert_eq!(st, 200, "{v}");
    let (_, v) = bob("GET", &format!("/client/v3/profile/{}", enc(&a.user)), None);
    assert_eq!(v["avatar_url"], "mxc://a.example/abc");
    assert!(v["displayname"].is_string());
    assert_eq!(bob("GET", &format!("/client/v3/profile/{}/avatar_url", enc(&a.user)), None).1["avatar_url"], "mxc://a.example/abc");
    let (st, v) = alice("POST", &format!("/client/v3/user/{}/openid/request_token", enc(&a.user)), Some(json!({})));
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["token_type"], "Bearer");

    // account routes left to the product.
    // Registration is the product's: a dummy auth stage, then the nick is the username.
    let (st, v) = bob("POST", "/client/v3/register", Some(json!({"username":"carol","password":"long enough pw"})));
    assert_eq!((st, v["flows"][0]["stages"][0].as_str()), (401, Some("m.login.dummy")));
    assert_eq!(bob("GET", "/client/v3/register/available?username=bob", None).0, 400);
    assert_eq!(bob("GET", "/client/v3/register/available?username=carol", None).0, 200);
    let (st, v) = bob("POST", "/client/v3/register", Some(json!({"username":"carol","password":"long enough pw","auth":{"type":"m.login.dummy"}})));
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["user_id"], "@carol:a.example");
    let (st, v) = bob("POST", "/client/v3/login", Some(json!({"type":"m.login.password","identifier":{"type":"m.id.user","user":"carol"},"password":"long enough pw"})));
    assert_eq!((st, v["user_id"].as_str()), (200, Some("@carol:a.example")), "{v}");
    assert_eq!(bob("POST", "/client/v3/account/password", Some(json!({}))).0, 403);
    assert_eq!(bob("GET", "/client/v3/account/3pid", None).1["threepids"], json!([]));

    // threads in a group room.
    let (_, v) = alice("POST", "/client/v3/createRoom", Some(json!({"name":"team","visibility":"private","invite":[bob_id]})));
    let group = v["room_id"].as_str().unwrap().to_string();
    assert_eq!(bob("POST", &format!("/client/v3/rooms/{}/join", enc(&group)), Some(json!({}))).0, 200);
    let ct = |tag: &str, rel: Option<&str>| {
        let mut v = json!({"algorithm":"m.megolm.v1.aes-sha2","sender_key":"k","session_id":"s","device_id":"D","ciphertext":format!("ct-{tag}")});
        if let Some(root) = rel {
            v["m.relates_to"] = json!({"rel_type":"m.thread","event_id":root});
        }
        v
    };
    let (_, v) = alice("PUT", &format!("/client/v3/rooms/{}/send/m.room.encrypted/r1", enc(&group)), Some(ct("root", None)));
    let root = v["event_id"].as_str().unwrap().to_string();
    let (st, v) = bob("PUT", &format!("/client/v3/rooms/{}/send/m.room.encrypted/r2", enc(&group)), Some(ct("reply", Some(&root))));
    assert_eq!(st, 200, "{v}");
    let (st, v) = alice("GET", &format!("/client/v1/rooms/{}/threads", enc(&group)), None);
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["chunk"][0]["event_id"], root.as_str());
    assert_eq!(v["chunk"][0]["unsigned"]["m.relations"]["m.thread"]["count"], 1);

    // upgrade: only the owner, once; the new room names its predecessor, the old one is tombstoned.
    assert_eq!(bob("POST", &format!("/client/v3/rooms/{}/upgrade", enc(&group)), Some(json!({"new_version":"11"}))).0, 403);
    assert_eq!(alice("POST", &format!("/client/v3/rooms/{}/upgrade", enc(&group)), Some(json!({"new_version":"3"}))).0, 400);
    let (st, v) = alice("POST", &format!("/client/v3/rooms/{}/upgrade", enc(&group)), Some(json!({"new_version":"11"})));
    assert_eq!(st, 200, "{v}");
    let new_room = v["replacement_room"].as_str().unwrap().to_string();
    let (_, create) = alice("GET", &format!("/client/v3/rooms/{}/state/m.room.create", enc(&new_room)), None);
    assert_eq!(create["predecessor"]["room_id"], group.as_str());
    let (_, tomb) = alice("GET", &format!("/client/v3/rooms/{}/state/m.room.tombstone", enc(&group)), None);
    assert_eq!(tomb["replacement_room"], new_room.as_str());
    assert_eq!(alice("POST", &format!("/client/v3/rooms/{}/upgrade", enc(&group)), Some(json!({"new_version":"11"}))).0, 403);
    // The channel moves its alias with it.
    let (st, v) = alice("POST", &format!("/client/v3/rooms/{}/upgrade", enc(&chan)), Some(json!({"new_version":"11"})));
    assert_eq!(st, 200, "{v}");
    let (_, r) = bob("GET", &format!("/client/v3/directory/room/{}", enc(alias)), None);
    assert_eq!(r["room_id"], v["replacement_room"], "{r}");
}

#[test]
fn an_alias_resolves_across_servers_and_a_remote_profile_is_fetched() {
    let (pa, pb) = (free_port(), free_port());
    let a = start_node("a.example", "alice", pa, &[("b.example", pb)]);
    let b = start_node("b.example", "bob", pb, &[("a.example", pa)]);
    let c = Client::builder().timeout(Duration::from_secs(10)).build().unwrap();
    let (_, v) = a.call(&c, "POST", "/client/v3/createRoom", Some(json!({"name":"open","visibility":"public"})));
    let room = v["room_id"].as_str().unwrap().to_string();
    let alias = "#open:a.example";
    assert_eq!(a.call(&c, "PUT", &format!("/client/v3/directory/room/{}", enc(alias)), Some(json!({"room_id": room}))).0, 200);
    let (st, v) = b.call(&c, "GET", &format!("/client/v3/directory/room/{}", enc(alias)), None);
    assert_eq!((st, v["room_id"].as_str()), (200, Some(room.as_str())), "{v}");
    assert_eq!(a.call(&c, "PUT", &format!("/client/v3/profile/{}/avatar_url", enc(&a.user)), Some(json!({"avatar_url":"mxc://a.example/x"}))).0, 200);
    let (st, v) = b.call(&c, "GET", &format!("/client/v3/profile/{}", enc(&a.user)), None);
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["avatar_url"], "mxc://a.example/x");
    let (st, v) = b.call(&c, "POST", &format!("/client/v3/join/{}", enc(alias)), Some(json!({})));
    assert_eq!((st, v["room_id"].as_str()), (200, Some(room.as_str())), "join by a remote alias: {v}");
}
