//! `m4a`: mail/Slack-like CLI for agents over the running client's socket.
//!
//!   m4a [--as NICK] [--json] rooms
//!   m4a read <room> [-n 20]          room = !id | #name | nick (DM)
//!   m4a send <room> <text...>        (text '-' reads stdin)
//!   m4a reply <room> <event_id> <text...>
//!   m4a mentions [-n 20]
//!   m4a thread <room> <event_id>
//!   m4a join|leave <room>
//!   m4a create <name> [--channel] [--invite @u:server,...]
//!   m4a invite <room> <user>
//!
//! `--as` defaults to `$M4A_AS`. The client encrypts, decrypts and tracks
//! devices; nothing here touches keys.

use mail4agent_messenger_shell::{load_env_file, send_cmd_via_socket, send_sock_path, CmdRequest, STORE_ROOT_ENV};
use serde_json::{json, Value};
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

fn fail(code: i32, msg: &str) -> ! {
    eprintln!("m4a: {msg}");
    std::process::exit(code);
}

fn hhmm(ts_ms: i64) -> String {
    let secs = ts_ms.div_euclid(1000);
    let day = secs.rem_euclid(86_400);
    format!("{:02}:{:02}", day / 3600, (day % 3600) / 60)
}

fn text_arg(words: &[String]) -> String {
    if words.is_empty() || words == ["-"] {
        let mut text = String::new();
        let _ = std::io::stdin().read_to_string(&mut text);
        text.trim_end_matches('\n').to_string()
    } else {
        words.join(" ")
    }
}

fn print_rows(rows: &[Value], with_room: bool) {
    for row in rows {
        let reply = row["reply_to"].as_str().map(|_| " ↩").unwrap_or("");
        let room = if with_room { format!(" {}", row["room"].as_str().unwrap_or("")) } else { String::new() };
        let body = match row["kind"].as_str() {
            Some("undecryptable") => "[cannot decrypt yet]".to_string(),
            _ => row["body"].as_str().unwrap_or("").to_string(),
        };
        println!(
            "[{}]{} {}{}: {}   ({})",
            hhmm(row["ts"].as_i64().unwrap_or(0)),
            room,
            row["from"].as_str().unwrap_or("?"),
            reply,
            body,
            row["event_id"].as_str().unwrap_or("")
        );
    }
}

fn main() {
    let mut as_nick = std::env::var("M4A_AS").ok().filter(|v| !v.is_empty());
    let mut as_json = false;
    let mut n: Option<u64> = None;
    let mut channel = false;
    let mut invite: Vec<String> = Vec::new();
    let mut pos: Vec<String> = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--as" => as_nick = args.next(),
            "--json" => as_json = true,
            "-n" => n = args.next().and_then(|v| v.parse().ok()),
            "--channel" => channel = true,
            "--invite" => invite = args.next().unwrap_or_default().split(',').map(str::to_string).collect(),
            "-h" | "--help" => {
                println!("usage: m4a [--as NICK] [--json] rooms | read <room> [-n N] | send <room> <text> | reply <room> <event> <text> | mentions | thread <room> <event> | join|leave <room> | create <name> [--channel] [--invite ids] | invite <room> <user>");
                return;
            }
            _ => pos.push(arg),
        }
    }
    let Some(as_nick) = as_nick else { fail(2, "--as NICK (or M4A_AS) is required") };
    if pos.is_empty() {
        fail(2, "command is required (rooms, read, send, reply, mentions, thread, join, leave, create, invite)");
    }
    let sub = pos.remove(0);
    let need = |i: usize, what: &str| -> String {
        pos.get(i).cloned().unwrap_or_else(|| fail(2, &format!("{what} is required")))
    };
    let (cmd, cargs) = match sub.as_str() {
        "rooms" | "ls" => ("rooms.list", json!({})),
        "read" => ("rooms.read", json!({ "room": need(0, "room"), "limit": n.unwrap_or(20) })),
        "send" => ("rooms.send", json!({ "room": need(0, "room"), "text": text_arg(&pos[1.min(pos.len())..]) })),
        "reply" => ("rooms.reply", json!({ "room": need(0, "room"), "event": need(1, "event id"), "text": text_arg(&pos[2.min(pos.len())..]) })),
        "mentions" => ("mentions", json!({ "limit": n.unwrap_or(20) })),
        "thread" => ("threads.read", json!({ "room": need(0, "room"), "event": need(1, "event id") })),
        "join" => ("rooms.join", json!({ "room": need(0, "room") })),
        "leave" => ("rooms.leave", json!({ "room": need(0, "room") })),
        "create" => ("rooms.create", json!({ "name": need(0, "name"), "kind": if channel { "channel" } else { "group" }, "invite": invite })),
        "invite" => ("rooms.invite", json!({ "room": need(0, "room"), "user": need(1, "user") })),
        other => fail(2, &format!("unknown command {other}")),
    };
    load_env_file();
    let get = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());
    let Some(store_root) = get(STORE_ROOT_ENV).map(PathBuf::from) else {
        fail(1, "M4A_STORE_ROOT is not set (environment or env file)");
    };
    let sock = send_sock_path(get, &store_root);
    let request = CmdRequest { cmd: cmd.to_string(), as_nick, args: cargs };
    let reply = send_cmd_via_socket(&sock, &request, Duration::from_secs(90))
        .unwrap_or_else(|_| fail(1, "no running m4a-web-client on the socket (run scripts/m4a-boot.sh)"));
    if !reply.ok {
        fail(1, reply.error.as_deref().unwrap_or("command failed"));
    }
    if as_json {
        println!("{}", serde_json::to_string_pretty(&reply.data).unwrap_or_default());
        return;
    }
    let d = &reply.data;
    match cmd {
        "rooms.list" => {
            for r in d["rooms"].as_array().into_iter().flatten() {
                let last = r["last"]["body"].as_str().unwrap_or("");
                println!(
                    "{} {:<24} {}{}  {}",
                    r["room"].as_str().unwrap_or(""),
                    r["title"].as_str().unwrap_or(""),
                    r["membership"].as_str().unwrap_or(""),
                    if r["encrypted"].as_bool() == Some(true) { " 🔒" } else { "" },
                    last.chars().take(50).collect::<String>()
                );
            }
        }
        "rooms.read" | "threads.read" => {
            if let Some(t) = d["title"].as_str() {
                println!("== {t} ==");
            }
            print_rows(d["messages"].as_array().map(Vec::as_slice).unwrap_or(&[]), false);
        }
        "mentions" => print_rows(d["mentions"].as_array().map(Vec::as_slice).unwrap_or(&[]), true),
        "rooms.send" | "rooms.reply" => println!(
            "sent room={} event={}",
            d["room"].as_str().unwrap_or(""),
            d["event_id"].as_str().unwrap_or("")
        ),
        _ => println!("ok {}", d["room"].as_str().unwrap_or("")),
    }
}
