//! Join a mailbox session card to a Grok session id.
//!
//! Grok's argv does not carry the session UUID. `active_sessions.json` does:
//! one row per open session, with the process pid. The mailbox card's
//! attested pid is the join key. Two rows on the same pid are matched by
//! cwd, and if that still leaves more than one, the courier refuses.

use std::path::Path;

use mail4agent_api::Directory;
use serde::Deserialize;
use thiserror::Error;

use crate::gate::process_may_use_leader;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveSession {
    pub session_id: String,
    pub pid: u32,
    pub cwd: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub grok_session_id: String,
    pub cwd: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocateError {
    #[error("session-unknown")]
    SessionUnknown,
    #[error("session-dead")]
    SessionDead,
    #[error("process-predates-config")]
    ProcessPredatesConfig,
    #[error("no-process")]
    NoProcess,
    #[error("ambiguous-session")]
    AmbiguousSession,
    #[error("index-unreadable")]
    IndexUnreadable,
}

#[derive(Deserialize)]
struct RawRow {
    session_id: String,
    pid: u32,
    cwd: String,
}

pub fn parse_active_sessions(text: &str) -> Result<Vec<ActiveSession>, LocateError> {
    let rows: Vec<RawRow> = serde_json::from_str(text).map_err(|_| LocateError::IndexUnreadable)?;
    Ok(rows
        .into_iter()
        .filter(|row| !row.session_id.is_empty() && !row.cwd.is_empty())
        .map(|row| ActiveSession { session_id: row.session_id, pid: row.pid, cwd: row.cwd })
        .collect())
}

pub fn locate(
    directory: &Directory,
    account: &str,
    mail_session: &str,
    index: &[ActiveSession],
    config_modified_unix_ms: u64,
) -> Result<Target, LocateError> {
    let participant = directory
        .participants
        .iter()
        .find(|entry| entry.id.as_str() == account)
        .ok_or(LocateError::SessionUnknown)?;
    let session = participant
        .sessions
        .iter()
        .find(|entry| entry.id.as_str() == mail_session)
        .ok_or(LocateError::SessionUnknown)?;
    if !session.live {
        return Err(LocateError::SessionDead);
    }
    if !process_may_use_leader(session.card.attested.started_at_unix_ms, config_modified_unix_ms) {
        return Err(LocateError::ProcessPredatesConfig);
    }
    let cwd_hint = session.card.corroborated.cwd.as_ref().map(|value| value.inner_ref().as_str());
    resolve_pid(index, session.card.attested.pid, cwd_hint)
}

fn resolve_pid(index: &[ActiveSession], pid: u32, cwd_hint: Option<&str>) -> Result<Target, LocateError> {
    let matches: Vec<&ActiveSession> = index.iter().filter(|row| row.pid == pid).collect();
    let chosen: &ActiveSession = match matches.as_slice() {
        [] => return Err(LocateError::NoProcess),
        [one] => one,
        many => {
            let Some(hint) = cwd_hint else {
                return Err(LocateError::AmbiguousSession);
            };
            let by_cwd: Vec<&&ActiveSession> = many.iter().filter(|row| cwd_eq(&row.cwd, hint)).collect();
            match by_cwd.as_slice() {
                [one] => one,
                _ => return Err(LocateError::AmbiguousSession),
            }
        }
    };
    Ok(Target { grok_session_id: chosen.session_id.clone(), cwd: chosen.cwd.clone() })
}

fn cwd_eq(left: &str, right: &str) -> bool {
    norm_cwd(left) == norm_cwd(right)
}

fn norm_cwd(value: &str) -> String {
    let trimmed = value.trim().trim_end_matches(['/', '\\']);
    #[cfg(windows)]
    {
        trimmed.replace('/', "\\").to_lowercase()
    }
    #[cfg(not(windows))]
    {
        trimmed.to_string()
    }
}

pub fn config_mtime_unix_ms(path: &Path) -> Option<u64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let millis = modified.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis();
    u64::try_from(millis).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail4agent_api::Directory;

    fn directory(live: bool, started: u64, cwd: Option<&str>) -> Directory {
        let cwd_json = match cwd {
            Some(value) => serde_json::json!(value),
            None => serde_json::Value::Null,
        };
        serde_json::from_value(serde_json::json!({
            "participants": [{
                "id": "grok",
                "label": null,
                "sessions": [{
                    "id": "s-01234567",
                    "live": live,
                    "last_seen_unix_ms": 10,
                    "card": {
                        "attested": { "pid": 1001, "started_at_unix_ms": started, "exe": "grok.exe" },
                        "corroborated": { "provider_session_id": null, "model": null, "cwd": cwd_json },
                        "declared": { "working_on": null, "role": null, "parent": null }
                    }
                }]
            }],
            "rooms": []
        }))
        .unwrap()
    }

    fn row(pid: u32, session_id: &str, cwd: &str) -> ActiveSession {
        ActiveSession { session_id: session_id.to_string(), pid, cwd: cwd.to_string() }
    }

    #[test]
    fn one_pid_joins_to_that_grok_session() {
        let index = vec![row(1001, "sess-a", r"C:\work\nemo")];
        let target = locate(&directory(true, 20, None), "grok", "s-01234567", &index, 10).unwrap();
        assert_eq!(target.grok_session_id, "sess-a");
        assert_eq!(target.cwd, r"C:\work\nemo");
    }

    #[test]
    fn a_dead_or_older_process_is_not_loaded() {
        let index = vec![row(1001, "sess-a", r"C:\work\nemo")];
        assert_eq!(
            locate(&directory(false, 20, None), "grok", "s-01234567", &index, 10),
            Err(LocateError::SessionDead)
        );
        assert_eq!(
            locate(&directory(true, 5, None), "grok", "s-01234567", &index, 10),
            Err(LocateError::ProcessPredatesConfig)
        );
        assert_eq!(
            locate(&directory(true, 20, None), "grok", "s-ffffffff", &index, 10),
            Err(LocateError::SessionUnknown)
        );
    }

    #[test]
    fn two_rows_need_a_unique_cwd_and_otherwise_refuse() {
        let index = vec![
            row(1001, "aaa", r"C:\work\nemo"),
            row(1001, "bbb", r"C:\work\other"),
        ];
        // `norm_cwd` folds slashes only on Windows. Elsewhere the hint must
        // already equal the row, or two rows stay ambiguous.
        let cwd_hint = if cfg!(windows) { r"C:/work/nemo" } else { r"C:\work\nemo" };
        let target = locate(
            &directory(true, 20, Some(cwd_hint)),
            "grok",
            "s-01234567",
            &index,
            10,
        )
        .unwrap();
        assert_eq!(target.grok_session_id, "aaa");
        assert_eq!(
            locate(&directory(true, 20, None), "grok", "s-01234567", &index, 10),
            Err(LocateError::AmbiguousSession)
        );
        assert_eq!(
            locate(&directory(true, 20, None), "grok", "s-01234567", &[], 10),
            Err(LocateError::NoProcess)
        );
    }

    #[test]
    fn the_index_must_be_an_array_of_rows() {
        assert!(parse_active_sessions("[]").unwrap().is_empty());
        let parsed = parse_active_sessions(
            r#"[{"session_id":"sess-a","pid":7,"cwd":"C:\\work","opened_at":"t"}]"#,
        )
        .unwrap();
        assert_eq!(parsed[0].session_id, "sess-a");
        assert_eq!(parse_active_sessions("{").unwrap_err(), LocateError::IndexUnreadable);
        assert!(parse_active_sessions(r#"[{"session_id":"","pid":1,"cwd":"C:\\x"}]"#).unwrap().is_empty());
    }
}
