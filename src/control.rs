//! Local control channel: `POST /control/{drain,reload,handoff}`.
//!
//! Lets a successor (a newer mail4agent, or a host such as a hatchery node)
//! take this daemon over gracefully instead of killing it. Authentication is
//! owner-only: a random token in a file only the owning user can read
//! (`control.token` next to the database, or `MAIL4AGENT_CONTROL_TOKEN_FILE`).
//! The file is created with mode 0600 on Unix; on Windows it lives in the
//! per-user data directory, whose ACL admits only that user (and SYSTEM /
//! administrators). The path is published in `/health` (not the token).
//!
//! - `drain`: stop accepting new mail (`/mail/send` and the MCP tools answer
//!   503); reads, acks and health keep working. `{"draining": false}` undoes it.
//! - `reload`: re-read the config file and report what changed; nothing is
//!   hot-swapped (the bind and db path need a handoff).
//! - `handoff`: drain, answer 202, then stop serving after `release_after_ms`
//!   so the successor can bind the same address. The process exits by itself.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;

pub const TOKEN_FILE_ENV: &str = "MAIL4AGENT_CONTROL_TOKEN_FILE";
pub const CAPABILITIES: [&str; 3] = ["control.drain", "control.reload", "control.handoff"];
const DEFAULT_RELEASE_AFTER_MS: u64 = 300;
const MAX_RELEASE_AFTER_MS: u64 = 10_000;

pub struct Control {
    token: String,
    token_file: PathBuf,
    draining: AtomicBool,
    stop: tokio::sync::watch::Sender<bool>,
}

impl Control {
    /// Create a fresh token and write it owner-only to `token_file`.
    pub fn create(token_file: PathBuf) -> std::io::Result<(Arc<Self>, tokio::sync::watch::Receiver<bool>)> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
        let token = hex::encode(bytes);
        write_owner_only(&token_file, token.as_bytes())?;
        let (stop, stop_rx) = tokio::sync::watch::channel(false);
        Ok((Arc::new(Self { token, token_file, draining: AtomicBool::new(false), stop }), stop_rx))
    }

    pub fn token_file(&self) -> &Path {
        &self.token_file
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    fn authorized(&self, request: &Request) -> bool {
        let Some(value) = request.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) else {
            return false;
        };
        let Some(given) = value.strip_prefix("Bearer ") else { return false };
        bool::from(given.as_bytes().ct_eq(self.token.as_bytes()))
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        // Only remove the file if it still holds our token (a successor may
        // already have written its own).
        if std::fs::read_to_string(&self.token_file).is_ok_and(|t| t.trim() == self.token) {
            let _ = std::fs::remove_file(&self.token_file);
        }
    }
}

/// Default token file: `control.token` beside the database.
pub fn default_token_file(db_path: &Path) -> PathBuf {
    if let Some(from_env) = std::env::var_os(TOKEN_FILE_ENV).filter(|v| !v.is_empty()) {
        return PathBuf::from(from_env);
    }
    db_path.parent().map_or_else(|| PathBuf::from("control.token"), |dir| dir.join("control.token"))
}

fn write_owner_only(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("token.tmp");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)
}

/// Refuse new mail while draining.
pub async fn drain_gate(State(control): State<Arc<Control>>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let new_mail = path == "/mail/send" || path.starts_with("/mcp");
    if new_mail && control.is_draining() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "draining"}))).into_response();
    }
    next.run(request).await
}

#[derive(Debug, Default, Deserialize)]
pub struct DrainBody {
    pub draining: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub struct HandoffBody {
    pub release_after_ms: Option<u64>,
    pub successor: Option<String>,
}

pub async fn handle(State(control): State<Arc<Control>>, request: Request) -> Response {
    if !control.authorized(&request) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "control token required"}))).into_response();
    }
    let verb = request.uri().path().trim_start_matches("/control/").to_owned();
    let body = axum::body::to_bytes(request.into_body(), 64 * 1024).await.unwrap_or_default();
    match verb.as_str() {
        "drain" => {
            let parsed: DrainBody = serde_json::from_slice(&body).unwrap_or_default();
            let on = parsed.draining.unwrap_or(true);
            control.draining.store(on, Ordering::SeqCst);
            tracing::info!(draining = on, "control: drain");
            Json(json!({"ok": true, "draining": on})).into_response()
        }
        "reload" => match crate::config::Config::load() {
            Ok(config) => {
                tracing::info!("control: reload (config re-read, nothing hot-swapped)");
                Json(json!({"ok": true, "bind": config.bind.to_string(), "applied": [], "needs_handoff_for": ["bind", "db_path"]}))
                    .into_response()
            }
            Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"ok": false, "error": error.to_string()}))).into_response(),
        },
        "handoff" => {
            let parsed: HandoffBody = serde_json::from_slice(&body).unwrap_or_default();
            let after = parsed.release_after_ms.unwrap_or(DEFAULT_RELEASE_AFTER_MS).min(MAX_RELEASE_AFTER_MS);
            control.draining.store(true, Ordering::SeqCst);
            tracing::info!(release_after_ms = after, successor = parsed.successor.as_deref().unwrap_or("-"), "control: handoff accepted");
            let stop = control.stop.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(after)).await;
                let _ = stop.send(true);
            });
            (StatusCode::ACCEPTED, Json(json!({"ok": true, "release_after_ms": after}))).into_response()
        }
        _ => (StatusCode::NOT_FOUND, Json(json!({"error": "unknown control verb"}))).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_file_is_written_and_removed() {
        let dir = std::env::temp_dir().join(format!("m4a-ctl-{}", std::process::id()));
        let path = dir.join("control.token");
        let (control, _rx) = Control::create(path.clone()).unwrap();
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk.len(), 64);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        drop(control);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn default_path_sits_beside_db() {
        if std::env::var_os(TOKEN_FILE_ENV).is_none() {
            assert_eq!(default_token_file(Path::new("/x/y/db.sqlite")), PathBuf::from("/x/y/control.token"));
        }
    }
}
