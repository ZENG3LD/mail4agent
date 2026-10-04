//! One leader connection: register, initialize, `session/load`, `session/prompt`.
//!
//! Notifications are skipped. Reverse requests are not answered, so a
//! permission modal stays with the TUI (first answer wins). The connection
//! is closed when the prompt response arrives. This never spawns `grok`.

use std::path::Path;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{timeout, Instant};

use crate::acp::{
    acp_envelope, acp_request, classify_inbound, disconnect_message, initialize_params, register_message,
    registered_is_ready, server_type, session_load_params, session_prompt_params, Inbound,
};
use crate::frame::{encode_frame, MAX_FRAME_BYTES};
use crate::pipe::PushError;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REGISTER_TIMEOUT: Duration = Duration::from_secs(10);
const READY_TIMEOUT: Duration = Duration::from_secs(15);
const INIT_TIMEOUT: Duration = Duration::from_secs(10);
const LOAD_TIMEOUT: Duration = Duration::from_secs(30);
const PROMPT_TIMEOUT: Duration = Duration::from_secs(15 * 60);

const INIT_ID: i64 = 0;
const LOAD_ID: i64 = 1;
const PROMPT_ID: i64 = 2;

pub async fn push_into_session(sock: &Path, session_id: &str, cwd: &str, text: &str) -> Result<(), PushError> {
    #[cfg(windows)]
    let stream = {
        let pipe = crate::pipe::leader_pipe_os_path(sock);
        timeout(
            CONNECT_TIMEOUT,
            tokio::task::spawn_blocking(move || tokio::net::windows::named_pipe::ClientOptions::new().open(pipe)),
        )
        .await
        .map_err(|_| PushError::LeaderAbsent)?
        .map_err(|_| PushError::LeaderAbsent)?
        .map_err(|_| PushError::LeaderAbsent)?
    };
    #[cfg(not(windows))]
    let stream = {
        timeout(CONNECT_TIMEOUT, tokio::net::UnixStream::connect(sock))
            .await
            .map_err(|_| PushError::LeaderAbsent)?
            .map_err(|_| PushError::LeaderAbsent)?
    };
    finish(stream, session_id, cwd, text).await
}

async fn finish<S>(stream: S, session_id: &str, cwd: &str, text: &str) -> Result<(), PushError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let result = drive(&mut reader, &mut writer, session_id, cwd, text).await;
    let _ = write_value(&mut writer, &disconnect_message()).await;
    result
}

async fn drive<R, W>(reader: &mut R, writer: &mut W, session_id: &str, cwd: &str, text: &str) -> Result<(), PushError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    write_value(writer, &register_message()).await?;
    let registered = read_until(reader, REGISTER_TIMEOUT, |value| registered_is_ready(value).is_some()).await?;
    if !registered_is_ready(&registered).unwrap_or(true) {
        read_until(reader, READY_TIMEOUT, |value| server_type(value) == Some("leader_ready"))
            .await
            .map_err(|_| PushError::LeaderNotReady)?;
    }

    acp_call(
        reader,
        writer,
        INIT_ID,
        "initialize",
        initialize_params(),
        INIT_TIMEOUT,
        PushError::Protocol,
    )
    .await?;
    acp_call(
        reader,
        writer,
        LOAD_ID,
        "session/load",
        session_load_params(session_id, cwd),
        LOAD_TIMEOUT,
        PushError::SessionLoadFailed,
    )
    .await?;
    acp_call(
        reader,
        writer,
        PROMPT_ID,
        "session/prompt",
        session_prompt_params(session_id, text),
        PROMPT_TIMEOUT,
        PushError::PromptFailed,
    )
    .await
}

async fn acp_call<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    id: i64,
    method: &str,
    params: Value,
    limit: Duration,
    fail: F,
) -> Result<(), PushError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: Fn(String) -> PushError,
{
    let payload = acp_request(id, method, params);
    write_value(writer, &acp_envelope(&payload)).await?;
    let deadline = Instant::now() + limit;
    loop {
        let value = read_one(reader, deadline).await?;
        if let Some(err) = terminal(&value) {
            return Err(err);
        }
        if server_type(&value) != Some("acp") {
            continue;
        }
        let Some(inner_text) = value.get("payload").and_then(Value::as_str) else {
            continue;
        };
        let inner: Value = match serde_json::from_str(inner_text) {
            Ok(parsed) => parsed,
            Err(_) => continue,
        };
        match classify_inbound(&inner, id) {
            Inbound::Ignore => continue,
            Inbound::Matched { ok: true, .. } => return Ok(()),
            Inbound::Matched { ok: false, error } => {
                let message = truncate(&error.unwrap_or_else(|| "error".to_string()));
                if message.contains("leader_starting") {
                    return Err(PushError::LeaderNotReady);
                }
                return Err(fail(message));
            }
        }
    }
}

fn terminal(value: &Value) -> Option<PushError> {
    match server_type(value) {
        Some("error") => {
            let message = value.get("message").and_then(Value::as_str).unwrap_or("error");
            Some(PushError::Protocol(truncate(message)))
        }
        Some("shutting_down") | Some("shutdown") => Some(PushError::Protocol("leader-shutdown".to_string())),
        _ => None,
    }
}

async fn read_until<R, F>(reader: &mut R, limit: Duration, pred: F) -> Result<Value, PushError>
where
    R: AsyncRead + Unpin,
    F: Fn(&Value) -> bool,
{
    let deadline = Instant::now() + limit;
    loop {
        let value = read_one(reader, deadline).await?;
        if let Some(err) = terminal(&value) {
            return Err(err);
        }
        if pred(&value) {
            return Ok(value);
        }
    }
}

async fn read_one<R: AsyncRead + Unpin>(reader: &mut R, deadline: Instant) -> Result<Value, PushError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(PushError::Protocol("timeout".to_string()));
    }
    timeout(left, read_value(reader))
        .await
        .map_err(|_| PushError::Protocol("timeout".to_string()))?
}

async fn read_value<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Value, PushError> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|err| PushError::Protocol(err.to_string()))?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(PushError::FrameTooLarge);
    }
    let mut buf = vec![0u8; len as usize];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|err| PushError::Protocol(err.to_string()))?;
    serde_json::from_slice(&buf).map_err(|err| PushError::Protocol(err.to_string()))
}

async fn write_value<W: AsyncWrite + Unpin>(writer: &mut W, value: &Value) -> Result<(), PushError> {
    let bytes = serde_json::to_vec(value).map_err(|err| PushError::Protocol(err.to_string()))?;
    let frame = encode_frame(&bytes).map_err(|_| PushError::FrameTooLarge)?;
    writer
        .write_all(&frame)
        .await
        .map_err(|err| PushError::Protocol(err.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|err| PushError::Protocol(err.to_string()))?;
    Ok(())
}

fn truncate(message: &str) -> String {
    let mut out = String::new();
    for ch in message.chars().take(180) {
        out.push(ch);
    }
    out
}
