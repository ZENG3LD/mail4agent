//! Second courier: one session id, one operator-supplied webhook, one POST.
//!
//! This is not a mailbox listener. `validate_listener_url` stays loopback-only
//! and is not used here. The URL is read from `mail4agent-webhooks.toml` in
//! the Grok home for the session the letter is already addressed to. Room and
//! direct mail never reach this module's POST. Nothing in here is a vendor API.
//!
//! An optional local bearer on that file, or `MAIL4AGENT_WEBHOOK_BEARER` when
//! the file has none, is sent as `Authorization: Bearer <key>` on this one
//! POST. No key keeps the POST without an Authorization header. The key is
//! not a mailbox credential and is not logged.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use mail4agent_api::DeliveryNotification;
use thiserror::Error;

use crate::gate::{screen, screen_session, Screen};

pub const WEBHOOKS_FILE: &str = "mail4agent-webhooks.toml";

/// Process environment read by the binary when the binding file has no bearer.
/// The value stays on the machine. This module does not read it itself.
pub const WEBHOOK_BEARER_ENV: &str = "MAIL4AGENT_WEBHOOK_BEARER";

/// Bound so a pasted URL cannot be an unbounded string. Same order of
/// magnitude as the mailbox listener bound, not the same rule.
const WEBHOOK_URL_MAX_BYTES: usize = 512;

#[derive(Debug, PartialEq, Eq)]
pub enum DeliveryRoute {
    Drop(&'static str),
    /// Existing CLI path. The caller still runs `push_into_session`.
    Leader {
        mail_session: String,
    },
    /// Web path. `url` is the binding for `mail_session` and is not logged.
    Web {
        mail_session: String,
        url: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookBinding {
    pub url: String,
    /// `None` means the file did not configure a key. The caller may still
    /// supply one from the environment. Never an empty string.
    pub bearer: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WebhookError {
    #[error("webhooks-unreadable")]
    Unreadable,
    #[error("webhook-bad-binding")]
    BadBinding,
    #[error("webhook-bad-url")]
    BadUrl,
    /// A bearer was configured and cannot be put in a header. The key is not
    /// included. Missing and blank are not this error.
    #[error("webhook-bad-bearer")]
    BadBearer,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WebPostError {
    /// The POST did not complete. A later doorbell may try once more.
    #[error("webhook-transport")]
    Transport,
    /// The POST was answered once and was not a success. Do not send it again.
    #[error("webhook-status: {0}")]
    Status(u16),
    /// A bearer was passed and cannot be a header value. Nothing was sent.
    /// The key is not included.
    #[error("webhook-bad-bearer")]
    BadBearer,
}

pub fn webhooks_path(grok_home: &Path) -> PathBuf {
    grok_home.join(WEBHOOKS_FILE)
}

/// `webhook` is the URL already resolved for this letter's session, if the
/// operator bound one. A binding wins over the leader pipe so one letter is
/// not delivered twice. No binding leaves the CLI path exactly as it was.
pub fn choose_route(
    note: &DeliveryNotification,
    account: &str,
    webhook: Option<&str>,
    use_leader: bool,
    leader_ready: bool,
) -> DeliveryRoute {
    let mail_session = match screen_session(note, account) {
        Screen::Drop(reason) => return DeliveryRoute::Drop(reason),
        Screen::Proceed { mail_session } => mail_session,
    };
    if let Some(url) = webhook {
        return DeliveryRoute::Web {
            mail_session,
            url: url.to_string(),
        };
    }
    match screen(note, account, use_leader, leader_ready) {
        Screen::Drop(reason) => DeliveryRoute::Drop(reason),
        Screen::Proceed { mail_session } => DeliveryRoute::Leader { mail_session },
    }
}

pub fn webhook_for(
    toml_text: &str,
    session_id: &str,
) -> Result<Option<WebhookBinding>, WebhookError> {
    let map = parse_webhooks(toml_text)?;
    Ok(map.get(session_id).cloned())
}

/// File bearer wins over `from_env`. Blank is unset, not an empty Bearer.
/// A configured token with whitespace or controls is `BadBearer` and must
/// not be sent. When both are unset the POST stays unauthenticated.
pub fn effective_bearer(
    binding: Option<&str>,
    from_env: Option<&str>,
) -> Result<Option<String>, WebhookError> {
    if let Some(raw) = binding {
        return normalize_bearer(raw);
    }
    match from_env {
        Some(raw) => normalize_bearer(raw),
        None => Ok(None),
    }
}

fn normalize_bearer(raw: &str) -> Result<Option<String>, WebhookError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if !bearer_is_header_safe(trimmed) {
        return Err(WebhookError::BadBearer);
    }
    Ok(Some(trimmed.to_string()))
}

fn bearer_is_header_safe(token: &str) -> bool {
    !token.is_empty() && token.is_ascii() && !token.chars().any(|c| c.is_control() || c.is_whitespace())
}

pub fn parse_webhooks(toml_text: &str) -> Result<BTreeMap<String, WebhookBinding>, WebhookError> {
    if toml_text.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    let value: toml::Value = toml_text.parse().map_err(|_| WebhookError::Unreadable)?;
    let Some(root) = value.as_table() else {
        return Err(WebhookError::Unreadable);
    };
    if root.is_empty() {
        return Ok(BTreeMap::new());
    }
    for key in root.keys() {
        if key != "sessions" && key != "bearer" {
            return Err(WebhookError::Unreadable);
        }
    }
    let root_bearer = match root.get("bearer") {
        None => None,
        Some(value) => normalize_bearer(value.as_str().ok_or(WebhookError::BadBinding)?)?,
    };
    let Some(sessions) = root.get("sessions") else {
        return Ok(BTreeMap::new());
    };
    let Some(sessions) = sessions.as_table() else {
        return Err(WebhookError::BadBinding);
    };
    let mut out = BTreeMap::new();
    for (session_id, value) in sessions {
        if session_id.is_empty() {
            return Err(WebhookError::BadBinding);
        }
        let (url, bearer) = match value {
            toml::Value::String(url) => (url.clone(), root_bearer.clone()),
            toml::Value::Table(table) => binding_from_table(table, root_bearer.as_deref())?,
            _ => return Err(WebhookError::BadBinding),
        };
        validate_webhook_url(&url)?;
        out.insert(session_id.clone(), WebhookBinding { url, bearer });
    }
    Ok(out)
}

fn binding_from_table(
    table: &toml::map::Map<String, toml::Value>,
    root_bearer: Option<&str>,
) -> Result<(String, Option<String>), WebhookError> {
    let mut url = None;
    let mut bearer = None;
    let mut saw_bearer = false;
    for (key, value) in table {
        match key.as_str() {
            "url" => {
                let Some(text) = value.as_str() else {
                    return Err(WebhookError::BadBinding);
                };
                url = Some(text.to_string());
            }
            "bearer" => {
                let Some(text) = value.as_str() else {
                    return Err(WebhookError::BadBinding);
                };
                saw_bearer = true;
                bearer = normalize_bearer(text)?;
            }
            _ => return Err(WebhookError::BadBinding),
        }
    }
    let Some(url) = url else {
        return Err(WebhookError::BadBinding);
    };
    // A bearer key on the session, even blank, does not inherit the file one.
    let bearer = if saw_bearer {
        bearer
    } else {
        root_bearer.map(str::to_string)
    };
    Ok((url, bearer))
}

/// Operator-supplied URL for one POST. `http` and `https` only. Loopback is
/// allowed and not required. Userinfo is refused so a secret is not carried
/// in the authority. This function does not call `validate_listener_url`.
pub fn validate_webhook_url(url: &str) -> Result<(), WebhookError> {
    if url.is_empty() || url.len() > WEBHOOK_URL_MAX_BYTES || url.chars().any(char::is_control) {
        return Err(WebhookError::BadUrl);
    }
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or(WebhookError::BadUrl)?;
    if after_scheme.is_empty() {
        return Err(WebhookError::BadUrl);
    }
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || authority.contains(char::is_whitespace) {
        return Err(WebhookError::BadUrl);
    }
    let host = authority
        .rsplit_once(']')
        .map(|(head, _)| head)
        .unwrap_or(authority);
    let host = host
        .strip_prefix('[')
        .unwrap_or_else(|| host.split(':').next().unwrap_or(""));
    if host.is_empty() {
        return Err(WebhookError::BadUrl);
    }
    Ok(())
}

/// Blank stays unset. Anything that cannot be a single header field is refused
/// before the POST, and the token is not copied into the error.
pub fn bearer_token(bearer: Option<&str>) -> Result<Option<&str>, WebPostError> {
    let Some(raw) = bearer else {
        return Ok(None);
    };
    let token = raw.trim();
    if token.is_empty() {
        return Ok(None);
    }
    if !bearer_is_header_safe(token) {
        return Err(WebPostError::BadBearer);
    }
    Ok(Some(token))
}

/// One POST of the letter body. Non-success, including a redirect, is an
/// error. The caller must use a client that does not follow redirects, or a
/// 3xx is still a failure here and the body is not re-sent by this function.
pub async fn post_letter(
    http: &reqwest::Client,
    url: &str,
    letter: &str,
    bearer: Option<&str>,
) -> Result<(), WebPostError> {
    let mut request = http
        .post(url)
        .timeout(Duration::from_secs(10))
        .header(reqwest::header::CONTENT_TYPE, "text/plain; charset=utf-8");
    if let Some(token) = bearer_token(bearer)? {
        request = request.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = request
        .body(letter.to_string())
        .send()
        .await
        .map_err(|_| WebPostError::Transport)?;
    let status = response.status();
    if !status.is_success() {
        return Err(WebPostError::Status(status.as_u16()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail4agent_api::{Address, DeliveryNotification, ParticipantId, SessionId};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    fn note(to: Address) -> DeliveryNotification {
        DeliveryNotification {
            account: ParticipantId::new("acct").unwrap(),
            to,
            message_id: "m4a_0123456789abcdef01234567".parse().unwrap(),
            from: Address::Direct {
                participant: ParticipantId::new("acct").unwrap(),
            },
        }
    }

    fn session_to(id: &str) -> Address {
        Address::Session {
            participant: ParticipantId::new("acct").unwrap(),
            session: SessionId::new(id).unwrap(),
        }
    }

    #[test]
    fn one_session_id_maps_to_one_url_and_loopback_is_not_required() {
        let text = "\
[sessions]
sess-a = \"https://hooks.example/letter\"
sess-b = \"http://127.0.0.1:9/hook\"
";
        let map = parse_webhooks(text).unwrap();
        assert_eq!(
            map.get("sess-a").map(|binding| binding.url.as_str()),
            Some("https://hooks.example/letter")
        );
        assert_eq!(
            map.get("sess-a").and_then(|binding| binding.bearer.clone()),
            None
        );
        assert_eq!(
            webhook_for(text, "sess-a")
                .unwrap()
                .as_ref()
                .map(|binding| binding.url.as_str()),
            Some("https://hooks.example/letter")
        );
        assert_eq!(webhook_for(text, "sess-c").unwrap(), None);
        assert!(parse_webhooks("").unwrap().is_empty());
        assert_eq!(
            parse_webhooks("not toml").unwrap_err(),
            WebhookError::Unreadable
        );
        assert_eq!(
            parse_webhooks("[sessions]\nsess-a = \"ftp://hooks.example/x\"\n").unwrap_err(),
            WebhookError::BadUrl
        );
        assert_eq!(
            parse_webhooks("[sessions]\nsess-a = \"https://user:pw@hooks.example/x\"\n")
                .unwrap_err(),
            WebhookError::BadUrl
        );
        assert_eq!(
            parse_webhooks("[other]\nname = \"x\"\n").unwrap_err(),
            WebhookError::Unreadable
        );
    }

    #[test]
    fn a_bound_session_takes_the_web_path_and_room_still_drops() {
        let session = note(session_to("s-01234567"));
        assert_eq!(
            choose_route(
                &session,
                "acct",
                Some("https://hooks.example/letter"),
                false,
                false
            ),
            DeliveryRoute::Web {
                mail_session: "s-01234567".to_string(),
                url: "https://hooks.example/letter".to_string(),
            }
        );
        assert_eq!(
            choose_route(&session, "acct", None, true, true),
            DeliveryRoute::Leader {
                mail_session: "s-01234567".to_string()
            }
        );
        assert_eq!(
            choose_route(&session, "acct", None, false, true),
            DeliveryRoute::Drop("leader-off")
        );
        let room = note(Address::Room {
            room: "room-a".parse().unwrap(),
        });
        assert_eq!(
            choose_route(
                &room,
                "acct",
                Some("https://hooks.example/letter"),
                true,
                true
            ),
            DeliveryRoute::Drop("not-session")
        );
        let direct = note(Address::Direct {
            participant: ParticipantId::new("acct").unwrap(),
        });
        assert_eq!(
            choose_route(&direct, "acct", None, true, true),
            DeliveryRoute::Drop("not-session")
        );
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap()
    }

    async fn serve(
        status_line: &'static str,
    ) -> (
        String,
        Arc<AtomicUsize>,
        Arc<Mutex<String>>,
        Arc<Mutex<String>>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let body = Arc::new(Mutex::new(String::new()));
        let headers = Arc::new(Mutex::new(String::new()));
        let hits2 = Arc::clone(&hits);
        let body2 = Arc::clone(&body);
        let headers2 = Arc::clone(&headers);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let hits2 = Arc::clone(&hits2);
                let body2 = Arc::clone(&body2);
                let headers2 = Arc::clone(&headers2);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 1024];
                    loop {
                        let n = tokio::io::AsyncReadExt::read(&mut sock, &mut tmp)
                            .await
                            .unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(split) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let header = String::from_utf8_lossy(&buf[..split]).to_string();
                            let have = buf.len() - (split + 4);
                            let need = header
                                .lines()
                                .find_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    if !name.eq_ignore_ascii_case("content-length") {
                                        return None;
                                    }
                                    value.trim().parse::<usize>().ok()
                                })
                                .unwrap_or(0);
                            if have >= need {
                                let letter =
                                    String::from_utf8_lossy(&buf[split + 4..split + 4 + need])
                                        .to_string();
                                hits2.fetch_add(1, Ordering::SeqCst);
                                *body2.lock().unwrap() = letter;
                                *headers2.lock().unwrap() = header;
                                let resp = format!("{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                                let _ =
                                    tokio::io::AsyncWriteExt::write_all(&mut sock, resp.as_bytes())
                                        .await;
                                break;
                            }
                        }
                    }
                });
            }
        });
        (format!("http://127.0.0.1:{port}/hook"), hits, body, headers)
    }

    fn authorization_values(headers: &str) -> Vec<String> {
        headers
            .lines()
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("authorization") {
                    Some(value.trim().to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    #[tokio::test]
    async fn the_letter_is_posted_once() {
        let (url, hits, body, headers) = serve("HTTP/1.1 204 No Content").await;
        let letter = "from: acct\nto: acct/s-01234567\nsubject: hello\nmessage_id: m4a_0123456789abcdef01234567\n\nbody line";
        post_letter(&client(), &url, letter, None).await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(body.lock().unwrap().as_str(), letter);
        assert!(authorization_values(&headers.lock().unwrap()).is_empty());

        let (url, hits, _, _) = serve("HTTP/1.1 500 Nope").await;
        let err = post_letter(&client(), &url, letter, None)
            .await
            .unwrap_err();
        assert_eq!(err, WebPostError::Status(500));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let err_text = err.to_string();
        assert!(!err_text.contains("127.0.0.1"));
        assert!(!err_text.contains(letter));
    }

    #[test]
    fn a_local_bearer_is_read_from_the_binding_and_a_blank_one_is_not_sent() {
        let text = "\
bearer = \"from-root\"

[sessions]
sess-a = \"https://hooks.example/letter\"

[sessions.sess-b]
url = \"http://127.0.0.1:9/hook\"
bearer = \"from-session\"

[sessions.sess-c]
url = \"http://127.0.0.1:9/other\"
bearer = \"  \"
";
        let map = parse_webhooks(text).unwrap();
        assert_eq!(map["sess-a"].bearer.as_deref(), Some("from-root"));
        assert_eq!(map["sess-b"].bearer.as_deref(), Some("from-session"));
        assert_eq!(map["sess-c"].bearer, None);
        assert_eq!(effective_bearer(None, None).unwrap(), None);
        assert_eq!(
            effective_bearer(None, Some("  from-env  "))
                .unwrap()
                .as_deref(),
            Some("from-env")
        );
        assert_eq!(
            effective_bearer(Some("from-file"), Some("from-env"))
                .unwrap()
                .as_deref(),
            Some("from-file")
        );
        assert_eq!(effective_bearer(None, Some("\n")).unwrap(), None);
        assert_eq!(
            effective_bearer(Some("bad token"), None).unwrap_err(),
            WebhookError::BadBearer
        );
        assert_eq!(
            parse_webhooks(
                "bearer = \"bad token\"\n\n[sessions]\nsess-a = \"https://hooks.example/a\"\n"
            )
            .unwrap_err(),
            WebhookError::BadBearer
        );
        let err = effective_bearer(Some("bad token"), None).unwrap_err();
        assert!(!err.to_string().contains("bad token"));
    }

    #[tokio::test]
    async fn the_local_key_is_the_bearer_and_is_not_in_the_tree() {
        let token = ["unit", "test", "webhook", "bearer"].join("-");
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let root = root.canonicalize().unwrap();
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name == "target" || name == ".git" {
                    continue;
                }
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                assert!(
                    !text.contains(&token),
                    "local key appeared in {}",
                    path.display()
                );
            }
        }

        let toml_text = format!(
            "[sessions.sess-a]\nurl = \"https://hooks.example/letter\"\nbearer = \"{token}\"\n"
        );
        let binding = webhook_for(&toml_text, "sess-a").unwrap().unwrap();
        assert_eq!(binding.bearer.as_deref(), Some(token.as_str()));

        let (url, hits, body, headers) = serve("HTTP/1.1 204 No Content").await;
        let letter = "from: acct\nto: acct/s-01234567\nsubject: hello\n\nbody";
        post_letter(&client(), &url, letter, binding.bearer.as_deref())
            .await
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(body.lock().unwrap().as_str(), letter);
        assert_eq!(
            authorization_values(&headers.lock().unwrap()),
            vec![format!("Bearer {token}")]
        );

        let (url, hits, _, _) = serve("HTTP/1.1 204 No Content").await;
        let err = post_letter(&client(), &url, letter, Some("not a header"))
            .await
            .unwrap_err();
        assert_eq!(err, WebPostError::BadBearer);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        assert!(!err.to_string().contains("not a header"));
    }
}
