//! Searching across servers: a user directory lookup that reaches the user's own server, and the
//! public room directory of another server (`?server=`), plain and filtered.

#[path = "support_product.rs"]
mod support_product;
#[path = "support/fed.rs"]
mod support_fed;

use std::time::Duration;

use reqwest::blocking::Client;
use serde_json::json;
use support_fed::{free_port, start_node};

#[test]
fn users_and_public_rooms_of_another_server_can_be_searched() {
    let (pa, pb) = (free_port(), free_port());
    let a = start_node("a.example", "alice", pa, &[("b.example", pb)]);
    let b = start_node("b.example", "bob", pb, &[("a.example", pa)]);
    let c = Client::builder().timeout(Duration::from_secs(15)).build().unwrap();

    // Bob has an avatar and a public channel.
    let (st, v) = b.call(&c, "PUT", &format!("/client/v3/profile/{}/avatar_url", mail4agent_server::federation::enc(&b.user)), Some(json!({"avatar_url":"mxc://b.example/pic"})));
    assert_eq!(st, 200, "{v}");
    let (st, v) = b.call(&c, "POST", "/client/v3/createRoom", Some(json!({"visibility":"public","name":"Gardening club","topic":"plants"})));
    assert_eq!(st, 200, "{v}");

    // Alice looks for bob by full user id: found at his own server, with his avatar.
    let (st, v) = a.call(&c, "POST", "/client/v3/user_directory/search", Some(json!({"search_term": b.user})));
    assert_eq!(st, 200, "{v}");
    let hit = &v["results"][0];
    assert_eq!((hit["user_id"].as_str(), hit["avatar_url"].as_str()), (Some(b.user.as_str()), Some("mxc://b.example/pic")), "{v}");
    // A name that does not exist there is just absent.
    let (_, v) = a.call(&c, "POST", "/client/v3/user_directory/search", Some(json!({"search_term": "@nobody:b.example"})));
    assert_eq!(v["results"].as_array().unwrap().len(), 0, "{v}");

    // Alice lists bob's server's public rooms, then filters them.
    let (st, v) = a.call(&c, "GET", "/client/v3/publicRooms?server=b.example", None);
    assert_eq!(st, 200, "{v}");
    assert!(v["chunk"].as_array().unwrap().iter().any(|r| r["name"] == "Gardening club"), "{v}");
    let (_, v) = a.call(&c, "POST", "/client/v3/publicRooms?server=b.example", Some(json!({"filter":{"generic_search_term":"garden"}})));
    assert_eq!(v["chunk"].as_array().unwrap().len(), 1, "{v}");
    let (_, v) = a.call(&c, "POST", "/client/v3/publicRooms?server=b.example", Some(json!({"filter":{"generic_search_term":"zzz"}})));
    assert_eq!(v["chunk"].as_array().unwrap().len(), 0, "{v}");
    // Our own directory does not list it.
    let (_, v) = a.call(&c, "GET", "/client/v3/publicRooms", None);
    assert!(!v["chunk"].as_array().unwrap().iter().any(|r| r["name"] == "Gardening club"));
}
