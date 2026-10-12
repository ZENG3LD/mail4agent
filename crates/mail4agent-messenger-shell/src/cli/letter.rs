//! `m4a-agent letter deliver`: hand one letter to a session the same way the client daemon
//! does on an inbound room text -- letter hook first (`M4A_LETTER_HOOK`), then the durable inbox. For harness tests and for local senders
//! that already hold the plaintext. Prints `<link> delivered|queued`.

use std::io::Read;
use std::path::PathBuf;

use crate::provider::{self, ProviderSession, SessionKind, WakeLetter, WakeOutcome};
use crate::{ProviderKind, STORE_ROOT_ENV};

fn fail(msg: &str) -> ! {
    eprintln!("m4a-agent letter: {msg}");
    std::process::exit(2)
}

pub fn run(args: Vec<String>) {
    let mut it = args.into_iter();
    if it.next().as_deref() != Some("deliver") {
        fail("usage: m4a-agent letter deliver --provider P --session ID --nick N --from NICK [--event ID] [--root DIR] < body");
    }
    let (mut provider, mut session, mut nick, mut from, mut event, mut root) = (None, None, None, None, None, None);
    while let Some(a) = it.next() {
        let mut v = || it.next().unwrap_or_else(|| fail(&format!("{a} needs a value")));
        match a.as_str() {
            "--provider" => provider = Some(v()),
            "--session" => session = Some(v()),
            "--nick" => nick = Some(v()),
            "--from" => from = Some(v()),
            "--event" => event = Some(v()),
            "--root" => root = Some(v()),
            other => fail(&format!("unknown argument {other}")),
        }
    }
    let provider = ProviderKind::parse(&provider.unwrap_or_else(|| fail("--provider is required"))).unwrap_or_else(|| fail("unknown provider"));
    let session_id = session.unwrap_or_else(|| fail("--session is required"));
    let nick = nick.unwrap_or_else(|| fail("--nick is required"));
    let from = from.unwrap_or_else(|| fail("--from is required"));
    let event = event.unwrap_or_else(|| format!("$local-{}", std::process::id()));
    let root: Option<PathBuf> = root.or_else(|| std::env::var(STORE_ROOT_ENV).ok().filter(|v| !v.is_empty())).map(PathBuf::from);
    let mut body = String::new();
    std::io::stdin().read_to_string(&mut body).unwrap_or_else(|_| fail("stdin is not text"));
    let session = ProviderSession {
        kind: SessionKind::local(provider),
        session_id: session_id.clone(),
        nick,
        cwd: std::env::current_dir().ok(),
        headless: false,
    };
    let mut chain = provider::letter_chain(session.kind, root.as_deref().map(|r| provider::registry::inbox_dir(r, &session_id)));
    let letter = WakeLetter { body: body.trim_end(), from_nick: &from, event_id: &event, room: None };
    match chain.wake(&session, &letter) {
        Ok((id, WakeOutcome::Delivered)) => println!("{id} delivered"),
        Ok((id, _)) => println!("{id} queued"),
        Err(e) => fail(&e.to_string()),
    }
}
