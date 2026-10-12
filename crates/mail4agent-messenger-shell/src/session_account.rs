//! Per-session accounts (owner model): provider = a branch of accounts; session = nick = one key =
//! one role. The environment (local launcher or hatchery node) issues an account per provider
//! session automatically; the server accepts it only with an invite; no session may load another
//! session's key.
//!
//! This module is the client-side registry and binding, first slice:
//! - [`SessionIdentity`] (provider + the provider's own session/thread id) names an account by a
//!   stable [`SessionIdentity::account_ref`]; the provider session id itself is never stored in
//!   clear in file names.
//! - [`AccountRegistry`] (`<base>/.m4a-accounts/registry.json`, 0600, dir 0700) provisions one local
//!   account per identity with a unique nick, tracks its server state (local -> invite pending ->
//!   enrolled), and keeps each account in its own store root ([`AccountRegistry::store_root`]), so
//!   each account has its own vault and the directory can get its own OS owner/ACL.
//! - A per-session capability ([`AccountRegistry::issue_capability`]): random 32 bytes, only its
//!   SHA-256 is stored. The environment injects it into that session's process env only; the
//!   client daemon that holds the vaults requires it before acting for the account
//!   ([`AccountRegistry::authorize`]). Wiring into the send socket / inbox is the next slice.
//!
//! Nothing here holds an invite or a server token.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::provider::ProviderKind;

/// Env var the environment sets in a session's process: its capability (hex).
pub const SESSION_CAP_ENV: &str = "M4A_SESSION_CAP";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    pub provider: ProviderKind,
    /// Provider-native session/thread id.
    pub provider_session_id: String,
}

impl SessionIdentity {
    pub fn new(provider: ProviderKind, provider_session_id: &str) -> Result<Self, AccountError> {
        let id = provider_session_id.trim();
        if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
            return Err(AccountError::BadIdentity);
        }
        Ok(Self { provider, provider_session_id: id.to_string() })
    }

    /// Stable, non-reversible account reference: `<provider>-<16 hex>`.
    pub fn account_ref(&self) -> String {
        let h = Sha256::digest(format!("m4a-session-account/v1\0{}\0{}", self.provider.id(), self.provider_session_id).as_bytes());
        format!("{}-{}", self.provider.id(), hex(&h[..8]))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerState {
    /// Only on this machine (local bus); no server identity yet.
    Local,
    /// The owner/operator was asked for an invite for this nick.
    InvitePending,
    /// Enrolled on the server with this nick (key held by this account's vault).
    Enrolled,
    /// Retired: the nick is never reused for another identity.
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountEntry {
    pub nick: String,
    pub provider: String,
    pub state: ServerState,
    /// SHA-256 (hex) of the session capability; none until issued.
    #[serde(default)]
    pub cap_sha256: Option<String>,
    /// OS user that owns the session (unix uid); when set, the daemon also requires the caller
    /// on the send socket to be this uid (SO_PEERCRED / getpeereid).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_uid: Option<u32>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RegistryFile {
    /// account_ref -> entry
    accounts: BTreeMap<String, AccountEntry>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AccountError {
    #[error("session identity is empty or malformed")]
    BadIdentity,
    #[error("nick is not a valid slug")]
    BadNick,
    #[error("no account for this session")]
    Unknown,
    #[error("capability refused")]
    Refused,
    #[error("session capability missing")]
    Missing,
    #[error("caller is not the session's OS user")]
    WrongCaller,
    #[error("account registry io: {0}")]
    Io(String),
}

pub struct AccountRegistry {
    base: PathBuf,
    file: RegistryFile,
}

impl AccountRegistry {
    pub fn open(base: &Path) -> Result<Self, AccountError> {
        let dir = base.join(".m4a-accounts");
        create_private_dir(&dir)?;
        let path = dir.join("registry.json");
        let file = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| AccountError::Io(e.to_string()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => RegistryFile::default(),
            Err(e) => return Err(AccountError::Io(e.to_string())),
        };
        Ok(Self { base: base.to_path_buf(), file })
    }

    /// Account of `identity`, provisioning a new local one if missing. The nick is
    /// `base_nick` (slugged) or `<provider>-<n>`; never one used by another identity.
    pub fn provision(&mut self, identity: &SessionIdentity, base_nick: Option<&str>) -> Result<AccountEntry, AccountError> {
        let r = identity.account_ref();
        if let Some(e) = self.file.accounts.get(&r) {
            return Ok(e.clone());
        }
        let stem = match base_nick {
            Some(n) => slug(n).ok_or(AccountError::BadNick)?,
            None => identity.provider.id().to_string(),
        };
        let taken = |n: &str| self.file.accounts.values().any(|e| e.nick == n);
        let nick = if base_nick.is_some() && !taken(&stem) {
            stem
        } else {
            (1..).map(|i| format!("{stem}-{i}")).find(|n| !taken(n)).expect("free nick")
        };
        let entry = AccountEntry { nick, provider: identity.provider.id().to_string(), state: ServerState::Local, cap_sha256: None, os_uid: None };
        self.file.accounts.insert(r, entry.clone());
        self.save()?;
        create_private_dir(&self.store_root(identity))?;
        Ok(entry)
    }

    pub fn get(&self, identity: &SessionIdentity) -> Option<&AccountEntry> {
        self.file.accounts.get(&identity.account_ref())
    }

    pub fn set_state(&mut self, identity: &SessionIdentity, state: ServerState) -> Result<(), AccountError> {
        let e = self.file.accounts.get_mut(&identity.account_ref()).ok_or(AccountError::Unknown)?;
        e.state = state;
        self.save()
    }

    /// Store root of this account only (its own vault lives under it).
    pub fn store_root(&self, identity: &SessionIdentity) -> PathBuf {
        self.base.join("accounts").join(identity.account_ref())
    }

    /// New capability for the session (returned once, hex). Replaces any earlier one.
    pub fn issue_capability(&mut self, identity: &SessionIdentity) -> Result<String, AccountError> {
        let e = self.file.accounts.get_mut(&identity.account_ref()).ok_or(AccountError::Unknown)?;
        let raw = m4a_agent::vault::random_bytes(32);
        let cap = hex(&raw);
        e.cap_sha256 = Some(hex(&Sha256::digest(cap.as_bytes())));
        self.save()?;
        Ok(cap)
    }

    /// Ok only when `cap` is this identity's current capability.
    pub fn authorize(&self, identity: &SessionIdentity, cap: &str) -> Result<&AccountEntry, AccountError> {
        let e = self.get(identity).ok_or(AccountError::Unknown)?;
        let want = e.cap_sha256.as_deref().ok_or(AccountError::Refused)?;
        let got = hex(&Sha256::digest(cap.trim().as_bytes()));
        if ct_eq(want, &got) && e.state != ServerState::Retired {
            Ok(e)
        } else {
            Err(AccountError::Refused)
        }
    }

    /// The account that carries `nick` (account_ref, entry).
    pub fn find_by_nick(&self, nick: &str) -> Option<(&str, &AccountEntry)> {
        self.file.accounts.iter().find(|(_, e)| e.nick.eq_ignore_ascii_case(nick.trim())).map(|(r, e)| (r.as_str(), e))
    }

    /// Records the OS user that owns the account (unix uid).
    pub fn set_os_uid(&mut self, identity: &SessionIdentity, uid: Option<u32>) -> Result<(), AccountError> {
        let e = self.file.accounts.get_mut(&identity.account_ref()).ok_or(AccountError::Unknown)?;
        e.os_uid = uid;
        self.save()
    }

    /// The daemon's gate for one request acting as `nick`: Ok only when `cap` is that account's
    /// current capability and (when the account has an OS owner and the caller's uid is known)
    /// the caller is that OS user. A nick that is not a session account (operator/legacy bots
    /// such as the web client's own) passes only when `require` is false.
    pub fn gate(&self, nick: &str, cap: Option<&str>, peer_uid: Option<u32>, require: bool) -> Result<(), AccountError> {
        let Some((_, e)) = self.find_by_nick(nick) else {
            return if require { Err(AccountError::Unknown) } else { Ok(()) };
        };
        if e.state == ServerState::Retired {
            return Err(AccountError::Refused);
        }
        let want = e.cap_sha256.as_deref().ok_or(AccountError::Refused)?;
        let cap = cap.map(str::trim).filter(|c| !c.is_empty()).ok_or(AccountError::Missing)?;
        if !ct_eq(want, &hex(&Sha256::digest(cap.as_bytes()))) {
            return Err(AccountError::Refused);
        }
        match (e.os_uid, peer_uid) {
            (Some(owner), Some(caller)) if owner != caller => Err(AccountError::WrongCaller),
            _ => Ok(()),
        }
    }

    fn save(&self) -> Result<(), AccountError> {
        let dir = self.base.join(".m4a-accounts");
        let tmp = dir.join("registry.json.tmp");
        let bytes = serde_json::to_vec_pretty(&self.file).map_err(|e| AccountError::Io(e.to_string()))?;
        write_private(&tmp, &bytes)?;
        std::fs::rename(&tmp, dir.join("registry.json")).map_err(|e| AccountError::Io(e.to_string()))
    }
}

/// What the environment hands one session at spawn/registration.
pub struct Provisioned {
    pub account_ref: String,
    pub entry: AccountEntry,
    /// This account's own store root (own vault, own key, own server token).
    pub store_root: PathBuf,
    /// Fresh capability, only when one was issued by this call (first time or rotation).
    pub cap: Option<zeroize::Zeroizing<String>>,
}

impl Provisioned {
    /// Env for THAT session's process only: its local login session id (the account ref, so no
    /// two sessions share a login/token), its nick, its own store root and, when issued, its cap.
    pub fn session_env(&self) -> Vec<(&'static str, String)> {
        let mut v = vec![
            ("M4A_SESSION_ID", self.account_ref.clone()),
            ("M4A_NICK", self.entry.nick.clone()),
            ("M4A_BOT_NAME", self.entry.nick.clone()),
            ("M4A_STORE_ROOT", self.store_root.to_string_lossy().into_owned()),
        ];
        if let Some(cap) = &self.cap {
            v.push((SESSION_CAP_ENV, cap.to_string()));
        }
        v
    }
}

/// One call for launchers, `inbox register` and the hatchery node: the account of
/// (provider, session) under `base`, created if missing; a capability is issued when the account
/// has none yet or `rotate` is set. Nothing here prints the capability.
pub fn provision_session(base: &Path, provider: ProviderKind, provider_session_id: &str, nick: Option<&str>, rotate: bool) -> Result<Provisioned, AccountError> {
    let identity = SessionIdentity::new(provider, provider_session_id)?;
    let mut reg = AccountRegistry::open(base)?;
    let mut entry = reg.provision(&identity, nick)?;
    let cap = if rotate || entry.cap_sha256.is_none() {
        let c = reg.issue_capability(&identity)?;
        entry = reg.get(&identity).cloned().ok_or(AccountError::Unknown)?;
        Some(zeroize::Zeroizing::new(c))
    } else {
        None
    };
    Ok(Provisioned { account_ref: identity.account_ref(), store_root: reg.store_root(&identity), entry, cap })
}

/// Appends `KEY=VALUE` lines to an env file the provider reads into that session only
/// (e.g. `CLAUDE_ENV_FILE` of a SessionStart hook). Owner-only on unix.
pub fn append_env_file(path: &Path, pairs: &[(&str, String)]) -> Result<(), AccountError> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(|e| AccountError::Io(e.to_string()))?;
    for (k, v) in pairs {
        if v.contains('\n') {
            return Err(AccountError::Io("newline in env value".into()));
        }
        writeln!(f, "export {k}={v}").map_err(|e| AccountError::Io(e.to_string()))?;
    }
    Ok(())
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn slug(s: &str) -> Option<String> {
    crate::nick::routine_folder_id(s).filter(|n| !n.is_empty() && n.len() <= 64)
}

fn create_private_dir(p: &Path) -> Result<(), AccountError> {
    std::fs::create_dir_all(p).map_err(|e| AccountError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).map_err(|e| AccountError::Io(e.to_string()))?;
    }
    Ok(())
}

fn write_private(p: &Path, b: &[u8]) -> Result<(), AccountError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(p).map_err(|e| AccountError::Io(e.to_string()))?;
        f.write_all(b).map_err(|e| AccountError::Io(e.to_string()))
    }
    #[cfg(not(unix))]
    {
        std::fs::write(p, b).map_err(|e| AccountError::Io(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("m4a-acct-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }
    fn id(p: ProviderKind, s: &str) -> SessionIdentity { SessionIdentity::new(p, s).unwrap() }

    #[test]
    fn one_account_per_session_and_stable_across_reopen() {
        let b = base("stable");
        let mut r = AccountRegistry::open(&b).unwrap();
        let a = r.provision(&id(ProviderKind::Codex, "thread-a"), None).unwrap();
        let again = r.provision(&id(ProviderKind::Codex, "thread-a"), None).unwrap();
        assert_eq!(a, again);
        let other = r.provision(&id(ProviderKind::Codex, "thread-b"), None).unwrap();
        assert_ne!(a.nick, other.nick, "two sessions of one provider get two accounts");
        assert_eq!(AccountRegistry::open(&b).unwrap().get(&id(ProviderKind::Codex, "thread-a")).unwrap().nick, a.nick);
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn nick_is_never_shared_between_identities() {
        let b = base("nick");
        let mut r = AccountRegistry::open(&b).unwrap();
        let x = r.provision(&id(ProviderKind::Codex, "t1"), Some("Home Codex")).unwrap();
        let y = r.provision(&id(ProviderKind::Codex, "t2"), Some("home codex")).unwrap();
        assert_eq!(x.nick, "home-codex");
        assert_eq!(y.nick, "home-codex-1");
        let k = r.provision(&id(ProviderKind::KimiCode, "t1"), None).unwrap();
        assert_ne!(k.nick, x.nick, "same native id under another provider is another account");
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn foreign_capability_is_refused() {
        let b = base("cap");
        let mut r = AccountRegistry::open(&b).unwrap();
        let (a, c) = (id(ProviderKind::ClaudeCode, "s-a"), id(ProviderKind::ClaudeCode, "s-c"));
        r.provision(&a, None).unwrap();
        r.provision(&c, None).unwrap();
        let cap_a = r.issue_capability(&a).unwrap();
        assert!(r.authorize(&a, &cap_a).is_ok());
        assert_eq!(r.authorize(&c, &cap_a).unwrap_err(), AccountError::Refused, "c has no capability yet");
        let cap_c = r.issue_capability(&c).unwrap();
        assert_eq!(r.authorize(&a, &cap_c).unwrap_err(), AccountError::Refused);
        let rotated = r.issue_capability(&a).unwrap();
        assert!(r.authorize(&a, &cap_a).is_err() && r.authorize(&a, &rotated).is_ok());
        r.set_state(&a, ServerState::Retired).unwrap();
        assert!(r.authorize(&a, &rotated).is_err());
        let raw = std::fs::read_to_string(b.join(".m4a-accounts/registry.json")).unwrap();
        assert!(!raw.contains(&rotated) && !raw.contains("s-a"), "no capability or native id in clear");
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn each_account_has_its_own_private_store_root() {
        let b = base("root");
        let mut r = AccountRegistry::open(&b).unwrap();
        let (a, c) = (id(ProviderKind::Grok, "g1"), id(ProviderKind::Grok, "g2"));
        r.provision(&a, None).unwrap();
        r.provision(&c, None).unwrap();
        assert_ne!(r.store_root(&a), r.store_root(&c));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(r.store_root(&a)).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(std::fs::metadata(b.join(".m4a-accounts/registry.json")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn identity_rejects_empty_and_control_chars() {
        assert!(SessionIdentity::new(ProviderKind::Codex, " ").is_err());
        assert!(SessionIdentity::new(ProviderKind::Codex, "a\nb").is_err());
    }

    #[test]
    fn two_sessions_same_provider_get_distinct_accounts_roots_and_logins() {
        let dir = base("s2-two");
        let a = provision_session(&dir, ProviderKind::Codex, "thread-a", Some("codex"), false).unwrap();
        let b = provision_session(&dir, ProviderKind::Codex, "thread-b", Some("codex"), false).unwrap();
        assert_ne!(a.entry.nick, b.entry.nick);
        assert_ne!(a.store_root, b.store_root);
        assert_ne!(a.account_ref, b.account_ref);
        let env_a: Vec<_> = a.session_env().into_iter().map(|(k, _)| k).collect();
        assert!(env_a.contains(&SESSION_CAP_ENV));
        // re-registration does not hand the cap out again
        let a2 = provision_session(&dir, ProviderKind::Codex, "thread-a", Some("codex"), false).unwrap();
        assert!(a2.cap.is_none());
        assert_eq!(a2.entry.nick, a.entry.nick);
    }

    #[test]
    fn gate_refuses_foreign_missing_and_wrong_caller() {
        let dir = base("s2-gate");
        let a = provision_session(&dir, ProviderKind::Codex, "thread-a", None, false).unwrap();
        let b = provision_session(&dir, ProviderKind::Codex, "thread-b", None, false).unwrap();
        let (ca, cb) = (a.cap.unwrap(), b.cap.unwrap());
        let mut reg = AccountRegistry::open(&dir).unwrap();
        assert_eq!(reg.gate(&a.entry.nick, Some(&ca), None, true), Ok(()));
        assert_eq!(reg.gate(&a.entry.nick, Some(&cb), None, true), Err(AccountError::Refused));
        assert_eq!(reg.gate(&a.entry.nick, None, None, false), Err(AccountError::Missing));
        assert_eq!(reg.gate("operator-bot", None, None, false), Ok(()));
        assert_eq!(reg.gate("operator-bot", None, None, true), Err(AccountError::Unknown));
        let ida = SessionIdentity::new(ProviderKind::Codex, "thread-a").unwrap();
        reg.set_os_uid(&ida, Some(1000)).unwrap();
        assert_eq!(reg.gate(&a.entry.nick, Some(&ca), Some(1001), true), Err(AccountError::WrongCaller));
        assert_eq!(reg.gate(&a.entry.nick, Some(&ca), Some(1000), true), Ok(()));
        reg.set_state(&ida, ServerState::Retired).unwrap();
        assert_eq!(reg.gate(&a.entry.nick, Some(&ca), Some(1000), true), Err(AccountError::Refused));
    }

    #[test]
    fn env_file_is_private_and_rejects_newlines() {
        let dir = base("s2-env");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("env");
        append_env_file(&p, &[("M4A_NICK", "x".into())]).unwrap();
        assert!(append_env_file(&p, &[("M4A_NICK", "x\ny".into())]).is_err());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "export M4A_NICK=x\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
