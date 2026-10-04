//! Second courier: one session id, one operator-supplied webhook, one POST.
//!
//! This is not a mailbox listener. `validate_listener_url` stays loopback-only
//! and is not used here. The URL is read from `mail4agent-webhooks.toml` in
//! the Grok home for the session the letter is already addressed to. Room and
//! direct mail never reach this module's POST. Nothing in here is a vendor API.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use mail4agent_api::DeliveryNotification;
use thiserror::Error;

use crate::gate::{screen, screen_session, Screen};

pub const WEBHOOKS_FILE: &str = "mail4agent-webhooks.toml";

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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WebhookError {
    #[error("webhooks-unreadable")]
    Unreadable,
    #[error("webhook-bad-binding")]
    BadBinding,
    #[error("webhook-bad-url")]
    BadUrl,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WebPostError {
    /// The POST did not complete. A later doorbell may try once more.
    #[error("webhook-transport")]
    Transport,
    /// The POST was answered once and was not a success. Do not send it again.
    #[error("webhook-status: {0}")]
    Status(u16),
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

pub fn webhook_for(toml_text: &str, session_id: &str) -> Result<Option<String>, WebhookError> {
    let map = parse_webhooks(toml_text)?;
    Ok(map.get(session_id).cloned())
}

pub fn parse_webhooks(toml_text: &str) -> Result<BTreeMap<String, String>, WebhookError> {
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
    let Some(sessions) = root.get("sessions") else {
        return Err(WebhookError::Unreadable);
    };
    let Some(sessions) = sessions.as_table() else {
        return Err(WebhookError::BadBinding);
    };
    let mut out = BTreeMap::new();
    for (session_id, value) in sessions {
        if session_id.is_empty() {
            return Err(WebhookError::BadBinding);
        }
        let Some(url) = value.as_str() else {
            return Err(WebhookError::BadBinding);
        };
        validate_webhook_url(url)?;
        out.insert(session_id.clone(), url.to_string());
    }
    Ok(out)
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

/// One POST of the letter body. Non-success, including a redirect, is an
/// error. The caller must use a client that does not follow redirects, or a
/// 3xx is still a failure here and the body is not re-sent by this function.
pub async fn post_letter(
    http: &reqwest::Client,
    url: &str,
    letter: &str,
) -> Result<(), WebPostError> {
    let response = http
        .post(url)
        .timeout(Duration::from_secs(10))
        .header(reqwest::header::CONTENT_TYPE, "text/plain; charset=utf-8")
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
            map.get("sess-a").map(String::as_str),
            Some("https://hooks.example/letter")
        );
        assert_eq!(
            webhook_for(text, "sess-a").unwrap().as_deref(),
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

    async fn serve(status_line: &'static str) -> (String, Arc<AtomicUsize>, Arc<Mutex<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let body = Arc::new(Mutex::new(String::new()));
        let hits2 = Arc::clone(&hits);
        let body2 = Arc::clone(&body);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let hits2 = Arc::clone(&hits2);
                let body2 = Arc::clone(&body2);
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
        (format!("http://127.0.0.1:{port}/hook"), hits, body)
    }

    #[tokio::test]
    async fn the_letter_is_posted_once() {
        let (url, hits, body) = serve("HTTP/1.1 204 No Content").await;
        let letter = "from: acct\nto: acct/s-01234567\nsubject: hello\nmessage_id: m4a_0123456789abcdef01234567\n\nbody line";
        post_letter(&client(), &url, letter).await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(body.lock().unwrap().as_str(), letter);

        let (url, hits, _) = serve("HTTP/1.1 500 Nope").await;
        let err = post_letter(&client(), &url, letter).await.unwrap_err();
        assert_eq!(err, WebPostError::Status(500));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let err_text = err.to_string();
        assert!(!err_text.contains("127.0.0.1"));
        assert!(!err_text.contains(letter));
    }
}
