//! The engine's HTTP side against a scripted server: the sliding-sync refusal falls back to v3,
//! a forgotten token is refreshed once by the refresher, `.well-known` names the real server, and
//! the spec prefix is dropped unless the server serves it.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use m4a_agent::backend::attached::AttachedBackend;
use m4a_agent::backend::live::Live;
use m4a_agent::backend::matrix::discover_base;
use m4a_agent::engine::HttpExec;
use m4a_agent::{Backend, BackendKind};
use mail4agent_messenger::{HttpMethod, OutgoingRequest, OutgoingRequestKind, RequestId};

type Seen = Arc<Mutex<Vec<String>>>;

/// One request per connection; `script(method, path, authorization) -> (status, body)`.
fn serve(script: impl Fn(&str, &str, &str) -> (u16, String) + Send + 'static) -> (String, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let seen: Seen = Arc::default();
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in l.incoming() {
            let Ok(mut s) = stream else { break };
            let mut buf = vec![0u8; 16384];
            let n = s.read(&mut buf).unwrap_or(0);
            let text = String::from_utf8_lossy(&buf[..n]).to_string();
            let mut lines = text.lines();
            let first = lines.next().unwrap_or("").to_string();
            let mut parts = first.split(' ');
            let (method, path) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
            let auth = text.lines().find(|l| l.to_ascii_lowercase().starts_with("authorization:")).map(|l| l[14..].trim().to_string()).unwrap_or_default();
            log.lock().unwrap().push(format!("{method} {path} {auth}"));
            let (status, body) = script(&method, &path, &auth);
            let _ = write!(s, "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    (url, seen)
}

fn sync_request() -> OutgoingRequest {
    OutgoingRequest { id: RequestId::next(1), method: HttpMethod::Get, path: "/_matrix/client/v3/sync".into(), query: vec![("timeout".into(), "0".into())], body: None, kind: OutgoingRequestKind::Sync }
}

#[test]
fn a_server_that_refuses_sliding_sync_gets_plain_sync_from_then_on() {
    let (url, seen) = serve(|m, p, _| match (m, p) {
        ("GET", "/_matrix/client/versions") => (200, r#"{"versions":["v1.11"],"unstable_features":{"org.matrix.simplified_msc3575":true}}"#.into()),
        ("POST", p) if p.contains("simplified_msc3575") => (404, r#"{"errcode":"M_UNRECOGNIZED","error":"no"}"#.into()),
        ("GET", p) if p.starts_with("/_matrix/client/v3/sync") => (200, r#"{"next_batch":"s1","rooms":{}}"#.into()),
        _ => (404, "{}".into()),
    });
    let backend = AttachedBackend::new(BackendKind::Matrix, &url, "tok").unwrap();
    assert!(backend.uses_sliding_sync(), "advertised, so tried");
    let r = backend.execute(&sync_request()).unwrap();
    assert_eq!(r.status, 200);
    assert!(String::from_utf8_lossy(&r.body).contains("s1"), "the v3 answer came through");
    assert!(!backend.uses_sliding_sync(), "refused, so off");
    backend.execute(&sync_request()).unwrap();
    let log = seen.lock().unwrap().clone();
    assert_eq!(log.iter().filter(|l| l.starts_with("POST")).count(), 1, "sliding was tried once only: {log:?}");
    assert!(log.iter().filter(|l| l.starts_with("GET /_matrix/client/v3/sync")).all(|l| l.ends_with("Bearer tok")));
}

#[test]
fn a_forgotten_token_is_refreshed_once_and_the_request_repeated() {
    let (url, seen) = serve(|_, _, auth| if auth == "Bearer fresh" { (200, r#"{"ok":true}"#.into()) } else { (401, r#"{"errcode":"M_UNKNOWN_TOKEN","error":"gone","soft_logout":true}"#.into()) });
    let live = Live::new(HttpExec::new(&url).unwrap());
    live.set_token("stale");
    let calls = Arc::new(Mutex::new(0));
    let c = Arc::clone(&calls);
    live.set_refresher(Arc::new(move || {
        *c.lock().unwrap() += 1;
        Ok("fresh".to_string())
    }));
    let r = live.execute(&sync_request()).unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(*calls.lock().unwrap(), 1);
    // The new token sticks: the next call needs no refresh.
    assert_eq!(live.execute(&sync_request()).unwrap().status, 200);
    assert_eq!(*calls.lock().unwrap(), 1);
    assert_eq!(seen.lock().unwrap().iter().filter(|l| l.ends_with("Bearer stale")).count(), 1);

    // A refresher that fails leaves the server's answer as it is.
    let (url2, _) = serve(|_, _, _| (401, r#"{"errcode":"M_UNKNOWN_TOKEN","error":"gone"}"#.into()));
    let live2 = Live::new(HttpExec::new(&url2).unwrap());
    live2.set_token("stale");
    live2.set_refresher(Arc::new(|| Err(m4a_agent::AgentError::Refused("no".into()))));
    assert_eq!(live2.execute(&sync_request()).unwrap().status, 401);
}

#[test]
fn well_known_names_the_real_server_and_a_bad_answer_is_ignored() {
    let (real, _) = serve(|_, _, _| (200, "{}".into()));
    let real2 = real.clone();
    let (front, _) = serve(move |_, p, _| if p == "/.well-known/matrix/client" { (200, format!(r#"{{"m.homeserver":{{"base_url":"{real2}/"}}}}"#)) } else { (404, "{}".into()) });
    assert_eq!(discover_base(&front), Some(real));
    let (junk, _) = serve(|_, _, _| (200, r#"{"m.homeserver":{"base_url":"javascript:alert(1)"}}"#.into()));
    assert_eq!(discover_base(&junk), None);
    let (none, _) = serve(|_, _, _| (404, "{}".into()));
    assert_eq!(discover_base(&none), None);
}

#[test]
fn the_spec_prefix_is_dropped_unless_the_server_serves_it() {
    let (spec, seen) = serve(|_, p, _| if p.starts_with("/_matrix/client/versions") { (200, r#"{"versions":[]}"#.into()) } else { (200, r#"{"next_batch":"x"}"#.into()) });
    let b = AttachedBackend::new(BackendKind::Server, &spec, "t").unwrap();
    assert!(b.keep_prefix());
    b.execute(&sync_request()).unwrap();
    assert!(seen.lock().unwrap().iter().any(|l| l.starts_with("GET /_matrix/client/v3/sync")));
    let (own, seen) = serve(|_, p, _| if p.starts_with("/_matrix") { (404, "{}".into()) } else { (200, r#"{"next_batch":"x"}"#.into()) });
    let b = AttachedBackend::new(BackendKind::Server, &own, "t").unwrap();
    assert!(!b.keep_prefix());
    b.execute(&sync_request()).unwrap();
    assert!(seen.lock().unwrap().iter().any(|l| l.starts_with("GET /client/v3/sync")));
}
