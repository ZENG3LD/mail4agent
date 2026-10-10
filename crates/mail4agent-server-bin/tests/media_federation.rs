//! Media across two servers: upload on one, download on the other through the authenticated
//! routes (remote fetch over federation, cached), the reserve-then-PUT flow, size limit, thumbnail
//! fallback for opaque bytes, and the config/preview routes.

#[path = "support_product.rs"]
mod support_product;
#[path = "support/fed.rs"]
mod support_fed;

use std::time::Duration;

use reqwest::blocking::Client;
use serde_json::Value;
use support_fed::{free_port, start_node, Srv};

fn upload(s: &Srv, c: &Client, bytes: &[u8]) -> (u16, Value) {
    let r = c.post(format!("{}/media/v3/upload?filename=blob.bin", s.purl)).bearer_auth(&s.token).header("content-type", "application/octet-stream").body(bytes.to_vec()).send().unwrap();
    (r.status().as_u16(), r.json().unwrap_or(Value::Null))
}

fn get(s: &Srv, c: &Client, path: &str) -> (u16, Vec<u8>) {
    let r = c.get(format!("{}{}", s.purl, path)).bearer_auth(&s.token).send().unwrap();
    (r.status().as_u16(), r.bytes().unwrap().to_vec())
}

fn mxc_path(v: &Value) -> String {
    v["content_uri"].as_str().unwrap().strip_prefix("mxc://").unwrap().to_string()
}

#[test]
fn media_moves_between_servers_both_ways_and_respects_limits() {
    std::env::set_var("M4A_MEDIA_MAX_BYTES", "200000");
    let (pa, pb) = (free_port(), free_port());
    let a = start_node("a.example", "alice", pa, &[("b.example", pb)]);
    let b = start_node("b.example", "bob", pb, &[("a.example", pa)]);
    let c = Client::builder().timeout(Duration::from_secs(20)).build().unwrap();

    // Ciphertext-like bytes: never interpreted.
    let blob_a: Vec<u8> = (0..50_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let (st, v) = upload(&a, &c, &blob_a);
    assert_eq!(st, 200, "{v}");
    let path_a = mxc_path(&v);
    assert!(path_a.starts_with("a.example/"));

    // Bob, on server b, downloads alice's file: fetched over federation, then served from cache.
    for _ in 0..2 {
        let (st, got) = get(&b, &c, &format!("/client/v1/media/download/{path_a}"));
        assert_eq!(st, 200);
        assert_eq!(got, blob_a);
    }
    // Thumbnail of non-image bytes falls back to the original.
    let (st, got) = get(&b, &c, &format!("/client/v1/media/thumbnail/{path_a}?width=32&height=32&method=scale"));
    assert_eq!((st, got.len()), (200, blob_a.len()));
    assert_eq!(get(&b, &c, &format!("/client/v1/media/thumbnail/{path_a}?width=0&height=32")).0, 400);

    // And the other way round.
    let blob_b = vec![7u8; 4096];
    let (_, v) = upload(&b, &c, &blob_b);
    let path_b = mxc_path(&v);
    let (st, got) = get(&a, &c, &format!("/client/v1/media/download/{path_b}"));
    assert_eq!((st, got), (200, blob_b));
    assert_eq!(get(&a, &c, "/client/v1/media/download/b.example/doesnotexist").0, 404);
    assert_eq!(get(&a, &c, "/client/v1/media/download/nowhere.example/abc").0, 404);

    // Size limit and config.
    assert_eq!(upload(&a, &c, &vec![1u8; 300_000]).0, 413);
    let (_, cfg) = get(&a, &c, "/client/v1/media/config");
    assert_eq!(serde_json::from_slice::<Value>(&cfg).unwrap()["m.upload.size"], 200000);
    assert_eq!(serde_json::from_slice::<Value>(&get(&a, &c, "/client/v1/media/preview_url?url=https%3A%2F%2Fexample.org").1).unwrap(), serde_json::json!({}));

    // Reserve, then fill: not yet uploaded -> 504; filled -> 200; filling twice -> 409.
    let r: Value = c.post(format!("{}/media/v1/create", a.purl)).bearer_auth(&a.token).send().unwrap().json().unwrap();
    let path_r = mxc_path(&r);
    assert!(r["unused_expires_at"].is_number());
    assert_eq!(get(&a, &c, &format!("/client/v1/media/download/{path_r}")).0, 504);
    let put = |bytes: &[u8]| c.put(format!("{}/media/v3/upload/{path_r}", a.purl)).bearer_auth(&a.token).body(bytes.to_vec()).send().unwrap().status().as_u16();
    assert_eq!(put(b"late bytes"), 200);
    assert_eq!(get(&a, &c, &format!("/client/v1/media/download/{path_r}")), (200, b"late bytes".to_vec()));
    assert_eq!(put(b"again"), 403, "the reservation is spent");

    // Federation media needs a signed request.
    let raw = c.get(format!("{}/_matrix/federation/v1/media/download/xyz", a.addr_url())).send().unwrap();
    assert_eq!(raw.status().as_u16(), 401);
}

trait AddrUrl {
    fn addr_url(&self) -> String;
}
impl AddrUrl for Srv {
    fn addr_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}
