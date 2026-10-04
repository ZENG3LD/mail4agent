//! Doorbell for the `grok` account. Binds a loopback URL, registers it with
//! the mailbox, and returns as soon as the notification is in hand. The ACP
//! push runs after that, because the mailbox does not retry and its POST
//! budget is a few seconds.
//!
//! Refusals are named and the letter stays in the mailbox. Nothing here
//! starts a Grok process or writes mail.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use clap::Parser;
use mail4agent_api::{DeliveryNotification, Directory, Message, MessageGetRequest};
use mail4agent_grok::{
    choose_route, config_mtime_unix_ms, effective_bearer, grok_home, leader_is_listening,
    leader_socket, locate, parse_active_sessions, post_letter, prompt_text, push_into_session,
    screen_session, use_leader_enabled, webhook_for, webhooks_path, DeliveryRoute, LocateError,
    Screen, WebPostError, WebhookBinding, WEBHOOK_BEARER_ENV,
};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;

const REGISTER_ATTEMPTS: usize = 5;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:18302")]
    bind: SocketAddr,
    #[arg(long, default_value = "http://127.0.0.1:18301")]
    mailbox: String,
    #[arg(long, default_value = "grok")]
    account: String,
}

struct App {
    http: Client,
    mailbox: String,
    account: String,
    key: String,
    grok_home: PathBuf,
    seen: Mutex<std::collections::HashSet<String>>,
}

#[derive(Debug, thiserror::Error)]
enum BootError {
    #[error("bind must be 127.0.0.1 or localhost, got {0}")]
    BindNotLoopback(SocketAddr),
    #[error("grok home did not resolve")]
    NoGrokHome,
    #[error("operator key: {0}")]
    Key(String),
    #[error("bind {0}: {1}")]
    Bind(SocketAddr, std::io::Error),
    #[error("register listener: {0}")]
    Register(String),
    #[error("serve: {0}")]
    Serve(std::io::Error),
}

#[tokio::main]
async fn main() -> Result<(), BootError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    if !args.bind.ip().is_loopback() {
        return Err(BootError::BindNotLoopback(args.bind));
    }
    let listener_url = format!("http://{}/delivery", args.bind);
    let grok_home = grok_home().ok_or(BootError::NoGrokHome)?;
    let key = read_operator_key()?;
    let http = Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| BootError::Register(err.to_string()))?;

    let app = Arc::new(App {
        http: http.clone(),
        mailbox: args.mailbox.clone(),
        account: args.account.clone(),
        key: key.clone(),
        grok_home,
        seen: Mutex::new(std::collections::HashSet::new()),
    });
    let router = Router::new()
        .route("/health", axum::routing::get(|| async { "ok" }))
        .route("/delivery", post(delivery))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .map_err(|err| BootError::Bind(args.bind, err))?;
    register_listener(&http, &args.mailbox, &key, &args.account, &listener_url).await?;
    tracing::info!(url = %listener_url, account = %args.account, "grok listener registered");
    axum::serve(listener, router)
        .await
        .map_err(BootError::Serve)
}

async fn delivery(
    State(app): State<Arc<App>>,
    Json(note): Json<DeliveryNotification>,
) -> StatusCode {
    let message_id = note.message_id.as_str().to_string();
    if !remember(&app, &message_id) {
        tracing::info!(message_id = %message_id, "duplicate doorbell");
        return StatusCode::NO_CONTENT;
    }
    let app = Arc::clone(&app);
    tokio::spawn(async move {
        match deliver(&app, note).await {
            Ok(()) => {}
            Err(Failure::BeforePush(reason)) => {
                forget(&app, &message_id);
                tracing::info!(message_id = %message_id, refusal = %reason, "mail left in the mailbox");
            }
            Err(Failure::AfterPush(reason)) => {
                tracing::warn!(message_id = %message_id, refusal = %reason, "prompt was sent; mail left in the mailbox");
            }
        }
    });
    StatusCode::NO_CONTENT
}

enum Failure {
    BeforePush(String),
    AfterPush(String),
}

async fn deliver(app: &App, note: DeliveryNotification) -> Result<(), Failure> {
    let message_id = note.message_id.as_str().to_string();
    let config_path = app.grok_home.join("config.toml");
    let use_leader = std::fs::read_to_string(&config_path)
        .map(|text| use_leader_enabled(&text))
        .unwrap_or(false);
    let sock = leader_socket(
        &app.grok_home,
        std::env::var_os("GROK_LEADER_SOCKET").as_deref(),
    );
    let leader_ready = use_leader && leader_is_listening(&sock);
    let mail_session = match screen_session(&note, &app.account) {
        Screen::Drop(reason) => return Err(Failure::BeforePush(reason.to_string())),
        Screen::Proceed { mail_session } => mail_session,
    };
    let binding = session_webhook(&app.grok_home, &mail_session)?;
    let webhook_url = binding.as_ref().map(|item| item.url.clone());
    match choose_route(
        &note,
        &app.account,
        webhook_url.as_deref(),
        use_leader,
        leader_ready,
    ) {
        DeliveryRoute::Drop(reason) => return Err(Failure::BeforePush(reason.to_string())),
        DeliveryRoute::Web { mail_session, url } => {
            // File bearer wins. The env var fills in only when the binding has
            // no key. Neither value is logged. No key: POST with no Authorization.
            let from_env = std::env::var(WEBHOOK_BEARER_ENV).ok();
            let bearer = effective_bearer(
                binding.as_ref().and_then(|item| item.bearer.as_deref()),
                from_env.as_deref(),
            )
            .map_err(|err| Failure::BeforePush(err.to_string()))?;
            let text = load_letter(app, &note, &message_id).await?;
            match post_letter(&app.http, &url, &text, bearer.as_deref()).await {
                Ok(()) => {
                    tracing::info!(message_id = %message_id, session = %mail_session, "posted letter to session webhook");
                    return Ok(());
                }
                Err(WebPostError::Transport) => {
                    return Err(Failure::BeforePush(WebPostError::Transport.to_string()))
                }
                Err(err @ WebPostError::BadBearer) => {
                    return Err(Failure::BeforePush(err.to_string()))
                }
                Err(err @ WebPostError::Status(_)) => {
                    return Err(Failure::AfterPush(err.to_string()))
                }
            }
        }
        DeliveryRoute::Leader { .. } => {}
    }

    let directory = post_json::<Directory>(app, "/mail/directory", serde_json::json!({})).await?;
    let index_text = std::fs::read_to_string(app.grok_home.join("active_sessions.json"))
        .map_err(|_| Failure::BeforePush("index-unreadable".to_string()))?;
    let index = parse_active_sessions(&index_text)
        .map_err(|err| Failure::BeforePush(locate_reason(err)))?;
    let config_mtime = config_mtime_unix_ms(&config_path).unwrap_or(0);
    let target = locate(
        &directory,
        &app.account,
        &mail_session,
        &index,
        config_mtime,
    )
    .map_err(|err| Failure::BeforePush(locate_reason(err)))?;

    let text = load_letter(app, &note, &message_id).await?;
    push_into_session(&sock, &target.grok_session_id, &target.cwd, &text)
        .await
        .map_err(|err| Failure::AfterPush(err.to_string()))?;
    tracing::info!(
        message_id = %message_id,
        session = %target.grok_session_id,
        "pushed into grok session"
    );
    Ok(())
}

fn session_webhook(
    grok_home: &std::path::Path,
    session_id: &str,
) -> Result<Option<WebhookBinding>, Failure> {
    let path = webhooks_path(grok_home);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Failure::BeforePush("webhooks-unreadable".to_string())),
    };
    webhook_for(&text, session_id).map_err(|err| Failure::BeforePush(err.to_string()))
}

async fn load_letter(
    app: &App,
    note: &DeliveryNotification,
    message_id: &str,
) -> Result<String, Failure> {
    let request = MessageGetRequest {
        message_id: note.message_id.clone(),
    };
    let body = serde_json::to_value(&request)
        .map_err(|err| Failure::BeforePush(format!("mailbox: {err}")))?;
    let message = post_json::<Message>(app, "/mail/get", body).await?;
    if message.message_id.as_str() != message_id {
        return Err(Failure::BeforePush("message-id-mismatch".to_string()));
    }
    Ok(prompt_text(
        &message.from.to_string(),
        &message.to.to_string(),
        &message.subject,
        message.message_id.as_str(),
        &message.body,
    ))
}

fn locate_reason(err: LocateError) -> String {
    err.to_string()
}

async fn post_json<T: serde::de::DeserializeOwned>(
    app: &App,
    path: &str,
    body: serde_json::Value,
) -> Result<T, Failure> {
    let url = format!("{}{path}", app.mailbox.trim_end_matches('/'));
    let response = app
        .http
        .post(url)
        .header(AUTHORIZATION, format!("Bearer {}", app.key))
        .header(CONTENT_TYPE, "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|err| Failure::BeforePush(format!("mailbox: {err}")))?;
    let status = response.status();
    if !status.is_success() {
        return Err(Failure::BeforePush(format!("mailbox: {path} {status}")));
    }
    response
        .json()
        .await
        .map_err(|err| Failure::BeforePush(format!("mailbox: {err}")))
}

async fn register_listener(
    http: &Client,
    mailbox: &str,
    key: &str,
    account: &str,
    url: &str,
) -> Result<(), BootError> {
    let endpoint = format!("{}/admin/listener", mailbox.trim_end_matches('/'));
    let body = serde_json::json!({ "account": account, "url": url });
    let mut last = String::from("no attempt");
    for attempt in 1..=REGISTER_ATTEMPTS {
        match http
            .post(&endpoint)
            .header(AUTHORIZATION, format!("Bearer {key}"))
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => last = format!("{}", response.status()),
            Err(err) => last = err.to_string(),
        }
        tracing::warn!(attempt, error = %last, "listener registration failed");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(BootError::Register(last))
}

fn read_operator_key() -> Result<String, BootError> {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .ok_or_else(|| BootError::Key("no home directory".to_string()))?;
    let path = PathBuf::from(home)
        .join(".mail4agent")
        .join("operator-key.raw");
    let text = std::fs::read_to_string(&path)
        .map_err(|err| BootError::Key(format!("{}: {err}", path.display())))?;
    let key = text.trim().to_string();
    if key.is_empty() {
        return Err(BootError::Key(format!("{} is empty", path.display())));
    }
    Ok(key)
}

fn remember(app: &App, message_id: &str) -> bool {
    match app.seen.lock() {
        Ok(mut seen) => seen.insert(message_id.to_string()),
        Err(poisoned) => poisoned.into_inner().insert(message_id.to_string()),
    }
}

fn forget(app: &App, message_id: &str) {
    match app.seen.lock() {
        Ok(mut seen) => {
            seen.remove(message_id);
        }
        Err(poisoned) => {
            poisoned.into_inner().remove(message_id);
        }
    }
}

use axum::http::StatusCode;
