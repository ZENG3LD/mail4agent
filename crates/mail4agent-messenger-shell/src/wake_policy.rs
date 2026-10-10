//! When a session's wake fires, and what it last did. Two small non-secret files in the session's
//! store directory, written by `m4a-agent wake` and read by the running client at every wake:
//!
//! * `wake.json`: `{"enabled": bool, "mode": "off"|"dm"|"mention"|"all"}`. Default: enabled, `mention`
//!   (a direct message always wakes; a room message wakes only when it addresses the session).
//! * `wake-status.json`: `{"state","source","last_status","last_event_ms"}`; never a URL or a key.
//!
//! The process-wide switch `M4A_WAKE=off` silences every wake of the process whatever the files say.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const WAKE_ENV: &str = "M4A_WAKE";
const POLICY_FILE: &str = "wake.json";
const STATUS_FILE: &str = "wake-status.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WakeMode {
    /// Never.
    Off,
    /// Direct messages only.
    Dm,
    /// Direct messages and room messages that address this session (the default).
    Mention,
    /// Every inbound text.
    All,
}

impl WakeMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "dm" => Some(Self::Dm),
            "mention" | "dm+mention" => Some(Self::Mention),
            "all" => Some(Self::All),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Dm => "dm",
            Self::Mention => "mention",
            Self::All => "all",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakePolicy {
    pub enabled: bool,
    pub mode: WakeMode,
}

impl Default for WakePolicy {
    fn default() -> Self {
        Self { enabled: true, mode: WakeMode::Mention }
    }
}

/// `M4A_WAKE=off` (also `0`, `false`, `no`) in this process.
pub fn globally_off() -> bool {
    std::env::var(WAKE_ENV).is_ok_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "off" | "0" | "false" | "no"))
}

impl WakePolicy {
    /// The stored policy; a missing file is the default, a damaged one is `Off` (a wake that
    /// cannot be understood must not fire).
    pub fn load(dir: &Path) -> Self {
        match std::fs::read_to_string(dir.join(POLICY_FILE)) {
            Ok(t) => serde_json::from_str(&t).unwrap_or(Self { enabled: false, mode: WakeMode::Off }),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        write_atomic(&dir.join(POLICY_FILE), &serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?)
    }

    /// Whether a message wakes the session. `direct`: the room is a one-to-one conversation;
    /// `mentioned`: the text addresses this session.
    pub fn allows(&self, direct: bool, mentioned: bool) -> bool {
        if globally_off() || !self.enabled {
            return false;
        }
        match self.mode {
            WakeMode::Off => false,
            WakeMode::Dm => direct,
            WakeMode::Mention => direct || mentioned,
            WakeMode::All => true,
        }
    }
}

/// Whether `body` addresses the session: `@nick`, the full user id, or `nick:` / `nick,` at the start.
pub fn addresses(body: &str, nick: Option<&str>, user_id: &str) -> bool {
    let lower = body.to_lowercase();
    if lower.contains(&user_id.to_lowercase()) {
        return true;
    }
    let Some(nick) = nick.map(str::to_lowercase).filter(|n| !n.is_empty()) else { return false };
    let at = format!("@{nick}");
    let mut from = 0;
    while let Some(i) = lower[from..].find(&at) {
        let end = from + i + at.len();
        // `@nick` but not `@nickname`.
        if !lower[end..].chars().next().is_some_and(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return true;
        }
        from = end;
    }
    let t = lower.trim_start();
    t.strip_prefix(&nick).is_some_and(|rest| rest.starts_with(':') || rest.starts_with(','))
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakeStatusFile {
    /// `ready` (a wake target is attached), `awaiting` (the routine has no key yet), `failed`, `none`.
    pub state: String,
    /// Where the target came from: `gateway`, `file`, `vault`, `config`.
    pub source: String,
    #[serde(default)]
    pub last_status: Option<u16>,
    #[serde(default)]
    pub last_event_ms: Option<i64>,
}

impl WakeStatusFile {
    pub fn load(dir: &Path) -> Option<Self> {
        serde_json::from_str(&std::fs::read_to_string(dir.join(STATUS_FILE)).ok()?).ok()
    }
    fn save(&self, dir: &Path) {
        if let Ok(b) = serde_json::to_vec_pretty(self) {
            let _ = write_atomic(&dir.join(STATUS_FILE), &b);
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Records how the wake target of a session stands. Best effort; carries no secret.
pub fn note_state(store_dir: &Path, state: &str, source: &str) {
    let mut s = WakeStatusFile::load(store_dir).unwrap_or_default();
    s.state = state.to_string();
    s.source = source.to_string();
    s.save(store_dir);
}

/// Records the answer of the last wake attempt (`None`: no HTTP answer).
pub fn note_attempt(store_dir: &Path, status: Option<u16>) {
    let mut s = WakeStatusFile::load(store_dir).unwrap_or_default();
    if s.state.is_empty() {
        s.state = "ready".into();
    }
    s.last_status = status;
    s.last_event_ms = Some(now_ms());
    s.save(store_dir);
}

fn write_atomic(path: &PathBuf, data: &[u8]) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_wakes_for_dms_and_mentions_only_and_the_switches_win() {
        let d = tempfile::tempdir().unwrap();
        let p = WakePolicy::load(d.path());
        assert_eq!(p, WakePolicy { enabled: true, mode: WakeMode::Mention });
        assert!(p.allows(true, false) && p.allows(false, true) && !p.allows(false, false));
        let mut p = p;
        p.mode = WakeMode::Dm;
        assert!(p.allows(true, false) && !p.allows(false, true));
        p.mode = WakeMode::All;
        assert!(p.allows(false, false));
        p.enabled = false;
        assert!(!p.allows(true, true));
        p.save(d.path()).unwrap();
        assert_eq!(WakePolicy::load(d.path()), p);
        // A damaged file never wakes.
        std::fs::write(d.path().join(POLICY_FILE), "{nope").unwrap();
        assert!(!WakePolicy::load(d.path()).allows(true, true));
        assert_eq!(WakeMode::parse("dm+mention"), Some(WakeMode::Mention));
        assert_eq!(WakeMode::parse("sometimes"), None);
    }

    #[test]
    fn addressing_means_the_nick_or_the_user_id_not_a_longer_name() {
        let me = "@hatcheryweb:example.org";
        assert!(addresses("hey @HatcheryWeb, look", Some("hatcheryweb"), me));
        assert!(addresses("hatcheryweb: do it", Some("hatcheryweb"), me));
        assert!(addresses("cc @hatcheryweb:example.org", Some("hatcheryweb"), me));
        assert!(addresses("see @hatcheryweb.", Some("hatcheryweb"), me));
        assert!(!addresses("@hatcherywebber hi", Some("hatcheryweb"), me));
        assert!(!addresses("nothing here", Some("hatcheryweb"), me));
        assert!(!addresses("", None, me));
    }

    #[test]
    fn the_status_file_holds_state_and_the_last_answer_and_nothing_secret() {
        let d = tempfile::tempdir().unwrap();
        note_state(d.path(), "awaiting", "gateway");
        note_attempt(d.path(), Some(401));
        let s = WakeStatusFile::load(d.path()).unwrap();
        assert_eq!((s.state.as_str(), s.source.as_str(), s.last_status), ("awaiting", "gateway", Some(401)));
        assert!(s.last_event_ms.is_some());
    }
}
