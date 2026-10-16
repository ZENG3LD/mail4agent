//! `m4a-send --as <nick> --to <nick> <text...>`: a bot answers through its
//! own messenger session.
//!
//! `--as` is the sending bot's own nick (the `to` of the wake it got),
//! `--to` the recipient nick (the wake's `from_nick`). The text is the
//! remaining arguments joined by spaces, or stdin when it is `-` or
//! missing. The running `m4a-web-client` sends it from the `--as` session
//! (encrypted DM, configured homeserver); with no client running this
//! process opens that one session itself. Settings come from the
//! environment and the env file (`M4A_ENV_FILE`, default
//! `~/.config/mail4agent/web-client.env`). Arguments carry no secrets and
//! the output is the room id and event id only.

use crate::{
    load_env_file, send_sock_path, send_via_socket, MachineClient, SendReply, SendRequest,
    MAX_SEND_BYTES, STORE_ROOT_ENV,
};
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

const USAGE: &str =
    "usage: m4a-send --as <your nick> --to <nick> <text...>   (text '-' or none: read stdin)";

fn fail(code: i32, message: &str) -> ! {
    eprintln!("m4a-send: {message}");
    std::process::exit(code);
}

pub fn run(args: Vec<String>) {
    let mut as_nick = None;
    let mut to = None;
    let mut words: Vec<String> = Vec::new();
    let mut args = args.clone().into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--as" => as_nick = args.next(),
            "--to" => to = args.next(),
            "-h" | "--help" => {
                println!("{USAGE}");
                return;
            }
            "--" => words.extend(args.by_ref()),
            _ => words.push(arg),
        }
    }
    let as_nick = as_nick.or_else(|| std::env::var_os(SIGNER_HANDLE_ENV).map(|_| String::new()));
    let (Some(as_nick), Some(to)) = (as_nick, to) else {
        fail(2, USAGE);
    };
    let text = if words.is_empty() || words == ["-"] {
        let mut text = String::new();
        if std::io::stdin().read_to_string(&mut text).is_err() {
            fail(2, "stdin is not text");
        }
        text.trim_end_matches('\n').to_string()
    } else {
        words.join(" ")
    };
    if text.trim().is_empty() {
        fail(2, "text is empty");
    }
    // Delegated mode (m4a_keys::Authority::Delegated): the session holds only a process-bound
    // handle; the node proxy checks this process, the orchestrator keystore signs as the
    // session's own nick and delivers.
    // `--as` is ignored there: the identity comes from the handle, never from arguments.
    #[cfg(unix)]
    if let (Some(handle), Some(sock)) = (std::env::var_os(SIGNER_HANDLE_ENV), std::env::var_os(SIGNER_SOCK_ENV)) {
        match send_via_signer(std::path::Path::new(&sock), &handle.to_string_lossy(), &to, &text) {
            Ok(from) => {
                println!("sent via signer as {from}");
                return;
            }
            Err(e) => fail(1, &format!("signer proxy: {e}")),
        }
    }
    if text.len() > MAX_SEND_BYTES {
        fail(2, &format!("text is longer than {MAX_SEND_BYTES} bytes"));
    }
    load_env_file();
    let get = |key: &str| std::env::var(key).ok().filter(|value| !value.is_empty());
    let Some(store_root) = get(STORE_ROOT_ENV).map(PathBuf::from) else {
        fail(1, "M4A_STORE_ROOT is not set (environment or env file)");
    };
    let request = SendRequest {
        as_nick: as_nick.clone(),
        to: to.clone(),
        text: text.clone(),
        cap: crate::send::session_cap_from_env(),
    };
    let sock = send_sock_path(get, &store_root);
    let reply = match send_via_socket(&sock, &request, Duration::from_secs(180)) {
        Ok(reply) => reply,
        Err(_) => {
            // No client answered: open the one session here.
            let mut client = match MachineClient::from_env_for(&as_nick) {
                Ok(client) => client,
                Err(err) => fail(
                    1,
                    &format!("no running client and opening {as_nick} failed: {err}"),
                ),
            };
            client.send_blocking(&as_nick, &to, &text, Duration::from_secs(120))
        }
    };
    print_reply(&reply);
}

fn print_reply(reply: &SendReply) {
    if reply.ok {
        println!(
            "sent room={} event={}",
            reply.room.as_deref().unwrap_or(""),
            reply.event_id.as_deref().unwrap_or("")
        );
    } else {
        fail(1, reply.error.as_deref().unwrap_or("send failed"));
    }
}

pub const SIGNER_HANDLE_ENV: &str = m4a_keys::env::SESSION_HANDLE;
pub const SIGNER_SOCK_ENV: &str = m4a_keys::env::SIGNER_SOCK;

/// One JSON line to the node's signer proxy: `{handle, op:"send", payload_hex}`; the answer is
/// `{status:"sent", result:{from, message_id, ...}}` or `{status:"refused", reason}`.
#[cfg(unix)]
pub fn send_via_signer(sock: &std::path::Path, handle: &str, to: &str, text: &str) -> Result<String, String> {
    use std::io::{BufRead, Write};
    let subject: String = text.lines().next().unwrap_or("").chars().take(80).collect();
    let letter = serde_json::json!({ "to": to, "subject": subject, "body": text });
    let payload: String = serde_json::to_vec(&letter).map_err(|e| e.to_string())?.iter().map(|b| format!("{b:02x}")).collect();
    let mut req = serde_json::to_vec(&serde_json::json!({ "handle": handle, "op": "send", "payload_hex": payload })).map_err(|e| e.to_string())?;
    req.push(b'\n');
    let mut s = std::os::unix::net::UnixStream::connect(sock).map_err(|e| e.kind().to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();
    s.write_all(&req).map_err(|e| e.kind().to_string())?;
    let mut line = String::new();
    std::io::BufReader::new(s).read_line(&mut line).map_err(|e| e.kind().to_string())?;
    let v: serde_json::Value = serde_json::from_str(&line).map_err(|_| "bad answer".to_string())?;
    match v["status"].as_str() {
        Some("sent") => Ok(v["result"]["from"].as_str().unwrap_or("").to_owned()),
        _ => Err(v["reason"].as_str().unwrap_or("refused").to_owned()),
    }
}
