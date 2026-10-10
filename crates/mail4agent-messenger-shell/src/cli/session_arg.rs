//! Shared by the owner-facing commands (`wake`, `element-open`): which session is meant, and where
//! its files live. A session is named by `--session <id>` or by `--as <nick>` (looked up in the
//! records of `M4A_SESSIONS_DIR`). The store root is `M4A_STORE_ROOT`.

use std::path::PathBuf;

use crate::machine::{load_session_records, routine_name_for, HostSession, SESSIONS_DIR_ENV};
use crate::{session_store_dir, STORE_ROOT_ENV};

/// Tests of the owner commands set process-wide environment; they run one at a time.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub struct Target {
    pub session_id: String,
    pub nick: Option<String>,
    pub store_root: PathBuf,
    /// The record, when the session was named by `--as` or the record directory is set.
    pub record: Option<HostSession>,
}

impl Target {
    pub fn store_dir(&self) -> PathBuf {
        session_store_dir(&self.store_root, &self.session_id)
    }
}

/// The value of `--flag value` and the arguments left over.
pub fn take_flag(args: &mut Vec<String>, flag: &str) -> Result<Option<String>, String> {
    let Some(i) = args.iter().position(|a| a == flag) else { return Ok(None) };
    if i + 1 >= args.len() {
        return Err(format!("{flag} needs a value"));
    }
    let v = args.remove(i + 1);
    args.remove(i);
    Ok(Some(v))
}

pub fn take_switch(args: &mut Vec<String>, flag: &str) -> bool {
    match args.iter().position(|a| a == flag) {
        Some(i) => {
            args.remove(i);
            true
        }
        None => false,
    }
}

/// Resolves `--session` / `--as` (removing them from `args`).
pub fn resolve(args: &mut Vec<String>) -> Result<Target, String> {
    let session = take_flag(args, "--session")?;
    let nick = take_flag(args, "--as")?;
    let store_root = std::env::var(STORE_ROOT_ENV).ok().filter(|v| !v.is_empty()).map(PathBuf::from).ok_or_else(|| format!("{STORE_ROOT_ENV} is not set"))?;
    let records = std::env::var(SESSIONS_DIR_ENV).ok().filter(|v| !v.is_empty()).and_then(|d| load_session_records(std::path::Path::new(&d)).ok()).unwrap_or_default();
    match (session, nick) {
        (Some(_), Some(_)) => Err("give --session or --as, not both".into()),
        (None, None) => Err("name the session: --as <nick> or --session <id>".into()),
        (Some(id), None) => {
            let record = records.into_iter().find(|r| r.session_id == id);
            let nick = record.as_ref().and_then(routine_name_for);
            Ok(Target { session_id: id, nick, store_root, record })
        }
        (None, Some(n)) => {
            let want = crate::nick::lookup_nick(&n).map_err(|e| e.to_string())?;
            let record = records.into_iter().find(|r| routine_name_for(r).is_some_and(|x| x.eq_ignore_ascii_case(&want))).ok_or_else(|| format!("no session record for {want} in {SESSIONS_DIR_ENV}"))?;
            Ok(Target { session_id: record.session_id.clone(), nick: Some(want), store_root, record: Some(record) })
        }
    }
}
