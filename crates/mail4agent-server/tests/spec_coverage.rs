//! Spec coverage probe: every endpoint of the Matrix client-server and server-server APIs that a
//! homeserver is expected to expose (spec v1.19) must answer through a real handler (any status
//! but the router's own 404 `M_UNRECOGNIZED`). A few are deliberately not offered; those are listed
//! with the reason and must answer with the spec's error shape.

use axum::body::{to_bytes, Body};
use axum::http::{header, Request};
use rusqlite::Connection;
use std::sync::Arc;
use tower::ServiceExt;

use mail4agent_server::http::{hash_token, Homeserver};

const TOKEN: &str = "probe-token";

fn hs() -> Arc<Homeserver> {
    let conn = Connection::open_in_memory().unwrap();
    mail4agent_server::store::create_matrix_schema(&conn).unwrap();
    mail4agent_server::keys::create_matrix_keys_schema(&conn).unwrap();
    mail4agent_server::store::ensure_matrix_user(&conn, 1, "alice000000000000000000000000a1", "2026-10-09T00:00:00+00:00").unwrap();
    mail4agent_server::keys::create_device(&conn, 1, mail4agent_server::keys::CredentialKind::Bearer, &hash_token(TOKEN), "2026-10-09T00:00:00+00:00").unwrap();
    let hs = Homeserver::new(conn);
    let _ = hs.federation_enabled.set(());
    Arc::new(hs)
}

async fn probe(state: &Arc<Homeserver>, method: &str, path: &str) -> (u16, serde_json::Value) {
    let req = Request::builder().method(method).uri(path).header(header::AUTHORIZATION, format!("Bearer {TOKEN}")).header(header::CONTENT_TYPE, "application/json").body(Body::from("{}")).unwrap();
    let resp = mail4agent_server::http::router(Arc::clone(state)).oneshot(req).await.unwrap();
    let st = resp.status().as_u16();
    let b = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (st, serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null))
}

const R: &str = "!room:localhost";
const U: &str = "@alice:localhost";

/// (method, path) pairs a homeserver must serve.
fn served() -> Vec<(&'static str, String)> {
    let c = "/client/v3";
    let mut v: Vec<(&'static str, String)> = Vec::new();
    let mut add = |m: &'static str, p: String| v.push((m, p));
    for (m, p) in [
        ("GET", "/client/versions"), ("GET", "/.well-known/matrix/client"), ("GET", "/.well-known/matrix/server"), ("GET", "/.well-known/matrix/support"),
        ("GET", "/client/v3/login"), ("POST", "/client/v3/login"), ("POST", "/client/v1/login/get_token"), ("POST", "/client/v3/refresh"),
        ("POST", "/client/v3/logout"), ("POST", "/client/v3/logout/all"), ("POST", "/client/v3/register"), ("GET", "/client/v3/register/available"),
        ("POST", "/client/v3/register/email/requestToken"), ("POST", "/client/v3/register/msisdn/requestToken"),
        ("GET", "/client/v1/register/m.login.registration_token/validity"),
        ("POST", "/client/v3/account/password"), ("POST", "/client/v3/account/password/email/requestToken"), ("POST", "/client/v3/account/password/msisdn/requestToken"),
        ("POST", "/client/v3/account/deactivate"), ("GET", "/client/v3/account/3pid"), ("POST", "/client/v3/account/3pid/add"), ("POST", "/client/v3/account/3pid/bind"),
        ("POST", "/client/v3/account/3pid/delete"), ("POST", "/client/v3/account/3pid/unbind"), ("POST", "/client/v3/account/3pid/email/requestToken"),
        ("POST", "/client/v3/account/3pid/msisdn/requestToken"), ("GET", "/client/v3/account/whoami"), ("GET", "/client/v3/capabilities"),
        ("GET", "/client/v3/sync"), ("POST", "/client/v3/createRoom"), ("GET", "/client/v3/joined_rooms"), ("GET", "/client/v3/publicRooms"), ("POST", "/client/v3/publicRooms"),
        ("POST", "/client/v3/user_directory/search"), ("POST", "/client/v3/search"), ("GET", "/client/v3/voip/turnServer"),
        ("GET", "/client/v3/devices"), ("POST", "/client/v3/delete_devices"), ("POST", "/client/v3/keys/upload"), ("POST", "/client/v3/keys/query"),
        ("POST", "/client/v3/keys/claim"), ("GET", "/client/v3/keys/changes"), ("POST", "/client/v3/keys/device_signing/upload"), ("POST", "/client/v3/keys/signatures/upload"),
        ("GET", "/client/v3/room_keys/version"), ("POST", "/client/v3/room_keys/version"),
        ("GET", "/client/v3/pushers"), ("POST", "/client/v3/pushers/set"), ("GET", "/client/v3/notifications"), ("GET", "/client/v3/pushrules/"),
        ("GET", "/client/v3/thirdparty/protocols"), ("GET", "/client/v3/thirdparty/protocol/irc"), ("GET", "/client/v3/thirdparty/location/irc"), ("GET", "/client/v3/thirdparty/user/irc"),
        ("GET", "/client/v3/thirdparty/location"), ("GET", "/client/v3/thirdparty/user"),
        ("POST", "/media/v1/create"), ("POST", "/media/v3/upload"), ("GET", "/media/v3/config"), ("GET", "/media/v3/preview_url"), ("GET", "/client/v1/media/config"),
        ("POST", "/client/unstable/org.matrix.simplified_msc3575/sync"),
    ] {
        add(m, p.to_string());
    }
    add("POST", format!("{c}/user/{U}/filter")); add("GET", format!("{c}/user/{U}/filter/1"));
    add("GET", format!("{c}/user/{U}/account_data/m.test")); add("PUT", format!("{c}/user/{U}/account_data/m.test"));
    add("GET", format!("{c}/user/{U}/rooms/{R}/account_data/m.test")); add("PUT", format!("{c}/user/{U}/rooms/{R}/account_data/m.test"));
    add("GET", format!("{c}/user/{U}/rooms/{R}/tags")); add("PUT", format!("{c}/user/{U}/rooms/{R}/tags/u.x")); add("DELETE", format!("{c}/user/{U}/rooms/{R}/tags/u.x"));
    add("POST", format!("{c}/user/{U}/openid/request_token"));
    add("GET", format!("{c}/profile/{U}")); add("GET", format!("{c}/profile/{U}/displayname")); add("PUT", format!("{c}/profile/{U}/displayname"));
    add("GET", format!("{c}/profile/{U}/avatar_url")); add("PUT", format!("{c}/profile/{U}/avatar_url"));
    add("GET", format!("{c}/profile/{U}/m.tz")); add("PUT", format!("{c}/profile/{U}/m.tz")); add("DELETE", format!("{c}/profile/{U}/m.tz"));
    add("GET", format!("{c}/presence/{U}/status")); add("PUT", format!("{c}/presence/{U}/status"));
    add("GET", format!("{c}/devices/D")); add("PUT", format!("{c}/devices/D")); add("DELETE", format!("{c}/devices/D"));
    add("PUT", format!("{c}/sendToDevice/m.test/t1"));
    add("GET", format!("{c}/pushrules/global/override/.m.rule.master")); add("PUT", format!("{c}/pushrules/global/override/x")); add("DELETE", format!("{c}/pushrules/global/override/x"));
    add("GET", format!("{c}/pushrules/global/override/x/enabled")); add("PUT", format!("{c}/pushrules/global/override/x/enabled"));
    add("GET", format!("{c}/pushrules/global/override/x/actions")); add("PUT", format!("{c}/pushrules/global/override/x/actions"));
    add("GET", format!("{c}/room_keys/version/1")); add("PUT", format!("{c}/room_keys/version/1")); add("DELETE", format!("{c}/room_keys/version/1"));
    add("GET", format!("{c}/room_keys/keys")); add("PUT", format!("{c}/room_keys/keys")); add("DELETE", format!("{c}/room_keys/keys"));
    add("GET", format!("{c}/room_keys/keys/{R}")); add("PUT", format!("{c}/room_keys/keys/{R}")); add("DELETE", format!("{c}/room_keys/keys/{R}"));
    add("GET", format!("{c}/room_keys/keys/{R}/S")); add("PUT", format!("{c}/room_keys/keys/{R}/S")); add("DELETE", format!("{c}/room_keys/keys/{R}/S"));
    add("PUT", format!("{c}/directory/room/%23a%3Alocalhost")); add("GET", format!("{c}/directory/room/%23a%3Alocalhost")); add("DELETE", format!("{c}/directory/room/%23a%3Alocalhost"));
    add("GET", format!("{c}/directory/list/room/{R}")); add("PUT", format!("{c}/directory/list/room/{R}"));
    add("PUT", format!("{c}/directory/list/appservice/n/{R}"));
    add("POST", format!("{c}/join/{R}")); add("POST", format!("{c}/knock/{R}"));
    add("GET", format!("{c}/rooms/{R}/aliases"));
    for a in ["invite", "join", "leave", "forget", "kick", "ban", "unban", "report", "upgrade", "read_markers"] {
        add("POST", format!("{c}/rooms/{R}/{a}"));
    }
    add("POST", format!("{c}/rooms/{R}/report/$e")); add("POST", format!("{c}/rooms/{R}/receipt/m.read/$e"));
    add("PUT", format!("{c}/rooms/{R}/typing/{U}")); add("PUT", format!("{c}/rooms/{R}/send/m.test/t1")); add("PUT", format!("{c}/rooms/{R}/redact/$e/t1"));
    add("GET", format!("{c}/rooms/{R}/event/$e")); add("GET", format!("{c}/rooms/{R}/joined_members")); add("GET", format!("{c}/rooms/{R}/members"));
    add("GET", format!("{c}/rooms/{R}/state")); add("GET", format!("{c}/rooms/{R}/state/m.room.name")); add("GET", format!("{c}/rooms/{R}/state/m.room.name/"));
    add("GET", format!("{c}/rooms/{R}/state/m.space.child/!x:localhost")); add("PUT", format!("{c}/rooms/{R}/state/m.space.child/!x:localhost")); add("PUT", format!("{c}/rooms/{R}/state/m.room.name"));
    add("GET", format!("{c}/rooms/{R}/messages")); add("GET", format!("{c}/rooms/{R}/context/$e"));
    add("GET", format!("{c}/rooms/{R}/relations/$e")); add("GET", format!("{c}/rooms/{R}/relations/$e/m.annotation")); add("GET", format!("{c}/rooms/{R}/relations/$e/m.annotation/m.reaction"));
    add("GET", format!("/client/v1/rooms/{R}/timestamp_to_event?ts=1&dir=f"));
    add("GET", format!("/client/v1/rooms/{R}/hierarchy")); add("GET", format!("/client/v1/rooms/{R}/threads")); add("GET", format!("/client/v1/room_summary/{R}"));
    add("GET", format!("/client/v1/rooms/{R}/summary"));
    add("POST", format!("/client/v3/users/{U}/report"));
    add("GET", format!("/client/v3/admin/whois/{U}"));
    // media
    add("GET", "/media/v3/download/localhost/x".into()); add("GET", "/media/v3/download/localhost/x/n".into()); add("GET", "/media/v3/thumbnail/localhost/x?width=8&height=8".into());
    add("PUT", "/media/v3/upload/localhost/x".into());
    add("GET", "/client/v1/media/download/localhost/x".into()); add("GET", "/client/v1/media/download/localhost/x/n".into()); add("GET", "/client/v1/media/thumbnail/localhost/x?width=8&height=8".into());
    add("GET", "/client/v1/media/preview_url".into());
    // federation + keys
    for (m, p) in [
        ("GET", "/key/v2/server"), ("GET", "/key/v2/server/ed25519:a"), ("GET", "/key/v2/query/other.example"), ("GET", "/key/v2/query/other.example/ed25519:a"), ("POST", "/key/v2/query"),
        ("GET", "/federation/v1/version"), ("PUT", "/federation/v1/send/t1"), ("GET", "/federation/v1/publicRooms"), ("POST", "/federation/v1/publicRooms"),
        ("GET", "/federation/v1/query/profile"), ("GET", "/federation/v1/query/directory"), ("GET", "/federation/v1/openid/userinfo"),
        ("POST", "/federation/v1/user/keys/query"), ("POST", "/federation/v1/user/keys/claim"), ("PUT", "/federation/v1/3pid/onbind"),
        ("GET", "/federation/v1/media/download/x"), ("GET", "/federation/v1/media/thumbnail/x?width=8&height=8"),
    ] {
        v.push((m, p.to_string()));
    }
    let f = "/federation/v1";
    let mut add = |m: &'static str, p: String| v.push((m, p));
    add("GET", format!("{f}/user/devices/{U}"));
    for a in ["backfill", "state_ids", "state", "hierarchy", "timestamp_to_event"] {
        add("GET", format!("{f}/{a}/{R}"));
    }
    for a in ["make_join", "make_leave", "make_knock"] {
        add("GET", format!("{f}/{a}/{R}/{U}"));
    }
    add("GET", format!("{f}/event_auth/{R}/$e")); add("GET", format!("{f}/event/$e"));
    add("POST", format!("{f}/get_missing_events/{R}"));
    add("PUT", format!("/federation/v2/send_join/{R}/$e")); add("PUT", format!("/federation/v2/send_leave/{R}/$e")); add("PUT", format!("{f}/send_knock/{R}/$e"));
    add("PUT", format!("/federation/v2/invite/{R}/$e")); add("PUT", format!("{f}/exchange_third_party_invite/{R}"));
    v
}

#[tokio::test]
async fn every_endpoint_of_the_spec_is_served_by_a_handler() {
    let state = hs();
    let mut missing = Vec::new();
    for (m, p) in served() {
        let path = p.clone();
        let (st, body) = probe(&state, m, &path).await;
        if st == 404 && body["errcode"] == "M_UNRECOGNIZED" || st == 405 {
            missing.push(format!("{m} {path} -> {st} {}", body["errcode"]));
        }
    }
    assert!(missing.is_empty(), "endpoints without a handler:\n{}", missing.join("\n"));
}

#[tokio::test]
async fn unknown_paths_and_wrong_methods_answer_with_the_spec_errors() {
    let state = hs();
    let (st, b) = probe(&state, "GET", "/client/v3/definitely/not/a/thing").await;
    assert_eq!((st, b["errcode"].as_str()), (404, Some("M_UNRECOGNIZED")), "{b}");
    // Deliberately not offered: single sign-on and OIDC discovery.
    for p in ["/client/v3/login/sso/redirect", "/client/v3/login/sso/redirect/idp", "/client/v1/auth_metadata", "/federation/v1/query/custom.type"] {
        let (st, b) = probe(&state, "GET", p).await;
        assert_eq!((st, b["errcode"].as_str()), (404, Some("M_UNRECOGNIZED")), "{p}: {b}");
    }
    // A known path with the wrong method: 405 M_UNRECOGNIZED.
    let (st, b) = probe(&state, "DELETE", "/client/v3/sync").await;
    assert_eq!((st, b["errcode"].as_str()), (405, Some("M_UNRECOGNIZED")), "{b}");
}
