//! Reply path for a woken bot: `m4a-send --as <nick> --to <nick> <text>`.
//!
//! The running web client ([`crate::MachineClient`]) holds every bot's
//! sealed store, so `m4a-send` does not open that store a second time
//! while it runs: it writes one JSON line to the client's local socket
//! ([`SEND_SOCK_ENV`], default [`DEFAULT_SOCK_NAME`] under the store root,
//! mode 0600) and the client sends the encrypted DM from the `--as`
//! session, through the configured homeserver. With no client running,
//! `m4a-send` opens that one session itself (the store lock keeps the two
//! from overlapping). No URL, key, or bearer is passed in arguments or
//! printed.

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Path of the web client's local send socket.
pub const SEND_SOCK_ENV: &str = "M4A_SEND_SOCK";

/// Socket file name under the store root when [`SEND_SOCK_ENV`] is unset.
pub const DEFAULT_SOCK_NAME: &str = "web-client.sock";

/// Env file with the machine's client settings (`KEY=VALUE` lines), read by
/// `m4a-web-client` and `m4a-send` for every variable the process
/// environment leaves unset. Default `$HOME/.config/mail4agent/web-client.env`.
/// Settings only: homeserver URL, store root, keychain dir, skip list,
/// session-id aliases. Never secrets.
pub const ENV_FILE_ENV: &str = "M4A_ENV_FILE";

/// Longest text one send carries.
pub const MAX_SEND_BYTES: usize = 16 * 1024;

/// One request on the send socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendRequest {
    /// Sending session's nick (the bot running the command).
    #[serde(rename = "as")]
    pub as_nick: String,
    /// Recipient nick.
    pub to: String,
    /// Plaintext; encrypted by the sending session.
    pub text: String,
}

/// The answer to one [`SendRequest`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SendReply {
    /// Whether the text was accepted by the homeserver.
    pub ok: bool,
    /// DM room id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
    /// Matrix event id of the sent text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// Why it failed. No secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SendReply {
    /// A failed reply with `error`.
    pub fn failed(error: impl Into<String>) -> Self {
        Self {
            error: Some(error.into()),
            ..Self::default()
        }
    }
}

/// Socket path: [`SEND_SOCK_ENV`] when set, else [`DEFAULT_SOCK_NAME`]
/// under `store_root`.
pub fn send_sock_path(get: impl FnMut(&str) -> Option<String>, store_root: &Path) -> PathBuf {
    send_sock_path_named(get, store_root, DEFAULT_SOCK_NAME)
}

/// Like [`send_sock_path`], but uses `default_name` under `store_root` when
/// [`SEND_SOCK_ENV`] is unset (node client uses `node-client.sock`).
pub fn send_sock_path_named(
    mut get: impl FnMut(&str) -> Option<String>,
    store_root: &Path,
    default_name: &str,
) -> PathBuf {
    get(SEND_SOCK_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| store_root.join(default_name))
}

/// Sets each `KEY=VALUE` from the env file ([`ENV_FILE_ENV`] or the
/// default web-client path) that the environment does not already have.
/// Blank lines and `#` comments are skipped; surrounding quotes are
/// dropped. Call at the start of `main`, before any thread starts.
/// Returns the file read.
pub fn load_env_file() -> Option<PathBuf> {
    load_env_file_named("web-client.env")
}

/// Like [`load_env_file`], but the default under
/// `$HOME/.config/mail4agent/` is `default_name` (node uses
/// `node-client.env`). [`ENV_FILE_ENV`] still wins when set.
pub fn load_env_file_named(default_name: &str) -> Option<PathBuf> {
    let path = std::env::var(ENV_FILE_ENV)
        .ok()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME").ok().map(|home| {
                PathBuf::from(home).join(".config/mail4agent").join(default_name)
            })
        })?;
    let text = std::fs::read_to_string(&path).ok()?;
    for (key, value) in parse_env_lines(&text) {
        if std::env::var_os(&key).is_none() {
            std::env::set_var(key, value);
        }
    }
    Some(path)
}

fn parse_env_lines(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return None;
            }
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                .unwrap_or(value);
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

/// Sends `request` over the client's socket and waits up to `wait` for
/// the answer. `Err` means no client answered on that socket (missing,
/// refused, or closed early), so the caller may fall back to opening the
/// session itself.
pub fn send_via_socket(
    sock: &Path,
    request: &SendRequest,
    wait: Duration,
) -> std::io::Result<SendReply> {
    let mut stream = UnixStream::connect(sock)?;
    stream.set_read_timeout(Some(wait))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut line = serde_json::to_vec(request)?;
    line.push(b'\n');
    stream.write_all(&line)?;
    stream.flush()?;
    let mut reader = BufReader::new(stream);
    let mut answer = String::new();
    reader.read_line(&mut answer)?;
    if answer.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "client closed the socket without an answer",
        ));
    }
    serde_json::from_str(answer.trim())
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

/// Reads one request line from an accepted socket connection.
pub(crate) fn read_request(stream: &mut UnixStream) -> Result<SendRequest, String> {
    stream
        .set_nonblocking(false)
        .map_err(|err| err.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|err| err.to_string())?;
    let mut buf = Vec::new();
    let mut limited = (&*stream).take((MAX_SEND_BYTES * 2 + 1024) as u64);
    let mut reader = BufReader::new(&mut limited);
    reader
        .read_until(b'\n', &mut buf)
        .map_err(|err| err.to_string())?;
    let request: SendRequest =
        serde_json::from_slice(&buf).map_err(|_| "request is not a send JSON line".to_string())?;
    if request.text.trim().is_empty() {
        return Err("text is empty".to_string());
    }
    if request.text.len() > MAX_SEND_BYTES {
        return Err(format!("text is longer than {MAX_SEND_BYTES} bytes"));
    }
    Ok(request)
}

/// Writes one answer line. Errors are ignored: the sender may have gone.
pub(crate) fn write_reply(stream: &mut UnixStream, reply: &SendReply) {
    if let Ok(mut line) = serde_json::to_vec(reply) {
        line.push(b'\n');
        let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
        let _ = stream.write_all(&line);
        let _ = stream.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_lines_skip_comments_and_strip_quotes() {
        let parsed = parse_env_lines(
            "# c\n\nM4A_A=1\nexport M4A_B=\"two words\"\nM4A_C='x'\nbad line\n=v\n",
        );
        assert_eq!(
            parsed,
            vec![
                ("M4A_A".to_string(), "1".to_string()),
                ("M4A_B".to_string(), "two words".to_string()),
                ("M4A_C".to_string(), "x".to_string()),
            ]
        );
    }

    #[test]
    fn request_uses_as_on_the_wire() {
        let request = SendRequest {
            as_nick: "hostbot".to_string(),
            to: "privet-mir".to_string(),
            text: "hi".to_string(),
        };
        let json = serde_json::to_value(&request).expect("json");
        assert_eq!(json["as"], "hostbot");
        assert_eq!(json["to"], "privet-mir");
    }
}
