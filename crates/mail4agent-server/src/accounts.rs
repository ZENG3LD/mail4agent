//! Accounts, external identities, nicks and the localpart freeze.
//!
//! An account is a person-shaped identity of this instance. Its login key is
//! `(source, subject)` in `external_identities`; a foreign name is never
//! copied into the nick. The mxid localpart is the lowercase nick at first
//! contact with the messenger and never moves afterwards. Remote federated
//! users are NOT accounts: they stay negative-id proxy rows in `matrix_users`.
//!
//! All functions take explicit `now_ms` so tests inject the clock.

use rand::thread_rng;
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::account_source::Asserted;
use crate::error::MatrixError;
use crate::keys::CredentialKind;
use crate::nick_policy::{generate_placeholder, validate_nick, NickLists};

pub const DEFAULT_COOLDOWN_MS: i64 = 30 * 24 * 3600 * 1000;

/// Deployment knobs for nick handling.
#[derive(Debug, Clone)]
pub struct AccountsConfig {
    pub lists: NickLists,
    pub cooldown_ms: i64,
}

impl Default for AccountsConfig {
    fn default() -> Self {
        Self { lists: NickLists::default(), cooldown_ms: DEFAULT_COOLDOWN_MS }
    }
}

impl AccountsConfig {
    /// `M4A_NICK_LISTS` (file) and `M4A_NICK_COOLDOWN_DAYS` (default 30).
    pub fn from_env() -> Result<Self, String> {
        let days: i64 = match std::env::var("M4A_NICK_COOLDOWN_DAYS") {
            Ok(v) => v.parse().map_err(|_| "M4A_NICK_COOLDOWN_DAYS must be an integer".to_string())?,
            Err(_) => 30,
        };
        Ok(Self { lists: NickLists::from_env()?, cooldown_ms: days * 24 * 3600 * 1000 })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// Same integer as `matrix_users.user_id` once the account has made contact.
    pub id: i64,
    pub nick: String,
    pub nick_is_placeholder: bool,
    pub nick_changes: i64,
    pub nick_changed_at: Option<i64>,
    pub localpart: String,
    pub localpart_frozen: bool,
    pub first_contact_ms: Option<i64>,
    pub status: String,
}

pub fn create_accounts_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS accounts (
            id                  INTEGER PRIMARY KEY,
            nick                TEXT NOT NULL,
            nick_ci             TEXT NOT NULL UNIQUE,
            nick_is_placeholder INTEGER NOT NULL,
            nick_changes        INTEGER NOT NULL DEFAULT 0,
            nick_changed_at     INTEGER,
            localpart           TEXT NOT NULL UNIQUE,
            localpart_frozen    INTEGER NOT NULL DEFAULT 0,
            first_contact_ms    INTEGER,
            status              TEXT NOT NULL DEFAULT 'active',
            created_ms          INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS external_identities (
            source     TEXT NOT NULL,
            subject    TEXT NOT NULL,
            account_id INTEGER NOT NULL REFERENCES accounts(id),
            created_ms INTEGER NOT NULL,
            PRIMARY KEY (source, subject)
        );
        CREATE INDEX IF NOT EXISTS idx_external_identities_account ON external_identities(account_id);
        CREATE TABLE IF NOT EXISTS reserved_localparts (
            localpart TEXT PRIMARY KEY,
            reason    TEXT,
            since_ms  INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS account_events_seen (
            event_id TEXT PRIMARY KEY,
            at_ms    INTEGER NOT NULL
        );
        "#,
    )
}

const COLS: &str = "id, nick, nick_is_placeholder, nick_changes, nick_changed_at, localpart, localpart_frozen, first_contact_ms, status";

fn from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Account> {
    Ok(Account {
        id: r.get(0)?,
        nick: r.get(1)?,
        nick_is_placeholder: r.get::<_, i64>(2)? != 0,
        nick_changes: r.get(3)?,
        nick_changed_at: r.get(4)?,
        localpart: r.get(5)?,
        localpart_frozen: r.get::<_, i64>(6)? != 0,
        first_contact_ms: r.get(7)?,
        status: r.get(8)?,
    })
}

pub fn account_by_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<Account>> {
    conn.query_row(&format!("SELECT {COLS} FROM accounts WHERE id = ?1"), params![id], from_row).optional()
}

pub fn account_by_nick(conn: &Connection, nick: &str) -> rusqlite::Result<Option<Account>> {
    conn.query_row(&format!("SELECT {COLS} FROM accounts WHERE nick_ci = ?1"), params![nick.to_ascii_lowercase()], from_row)
        .optional()
}

pub fn account_by_identity(conn: &Connection, source: &str, subject: &str) -> rusqlite::Result<Option<Account>> {
    conn.query_row(
        &format!(
            "SELECT {COLS} FROM accounts WHERE id = (SELECT account_id FROM external_identities WHERE source = ?1 AND subject = ?2)"
        ),
        params![source, subject],
        from_row,
    )
    .optional()
}

/// Is `lower` unavailable as a nick or localpart for anyone but `except_id`?
/// Covers live nicks, every account localpart (frozen or not), tombstones,
/// localparts already used by Matrix users, and the server-reserved prefix.
pub fn name_taken(conn: &Connection, lower: &str, except_id: i64) -> rusqlite::Result<bool> {
    if crate::store::is_reserved_localpart(lower) {
        return Ok(true);
    }
    let q = |sql: &str, p: &[&dyn rusqlite::ToSql]| -> rusqlite::Result<bool> {
        Ok(conn.query_row(sql, p, |_| Ok(())).optional()?.is_some())
    };
    Ok(q("SELECT 1 FROM accounts WHERE id != ?2 AND (nick_ci = ?1 OR localpart = ?1)", &[&lower, &except_id])?
        || q("SELECT 1 FROM reserved_localparts WHERE localpart = ?1", &[&lower])?
        || q(
            "SELECT 1 FROM matrix_users WHERE mxid = ?1 AND user_id != ?2",
            &[&crate::store::mxid_for_public_id(lower), &except_id],
        )?)
}

fn next_id(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT MAX((SELECT COALESCE(MAX(id), 0) FROM accounts), (SELECT COALESCE(MAX(user_id), 0) FROM matrix_users)) + 1",
        [],
        |r| r.get(0),
    )
}

fn insert_account(tx: &Transaction<'_>, nick: &str, placeholder: bool, now_ms: i64) -> Result<Account, MatrixError> {
    let id = next_id(tx)?;
    let lower = nick.to_ascii_lowercase();
    tx.execute(
        "INSERT INTO accounts (id, nick, nick_ci, nick_is_placeholder, localpart, created_ms) VALUES (?1, ?2, ?3, ?4, ?3, ?5)",
        params![id, nick, lower, placeholder as i64, now_ms],
    )?;
    Ok(account_by_id(tx, id)?.ok_or_else(MatrixError::internal)?)
}

fn link_identity(tx: &Transaction<'_>, source: &str, subject: &str, id: i64, now_ms: i64) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO external_identities (source, subject, account_id, created_ms) VALUES (?1, ?2, ?3, ?4)",
        params![source, subject, id, now_ms],
    )?;
    Ok(())
}

/// `devices.credential_ref` for a source's credential.
pub fn credential_key(source: &str, cred_ref: &str) -> String {
    format!("{source}|{cred_ref}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub account: Account,
    pub created: bool,
}

/// Map an asserted identity to an account, creating one when needed.
/// Order: `(source, subject)`; credential continuity; issuer nick; create.
pub fn resolve_account(conn: &mut Connection, a: &Asserted, cfg: &AccountsConfig, now_ms: i64) -> Result<Resolved, MatrixError> {
    let tx = conn.transaction()?;
    let mut found = account_by_identity(&tx, &a.source, &a.subject)?;
    if found.is_none() && !a.cred_ref.is_empty() {
        let key = credential_key(&a.source, &a.cred_ref);
        if let Some(dev) = crate::keys::device_for_credential(&tx, CredentialKind::Web, &key)? {
            found = account_by_id(&tx, dev.user_id)?;
        }
    }
    if found.is_none() {
        if let Some(nick) = &a.nick {
            if let Some(acc) = account_by_nick(&tx, nick)? {
                let same_source: bool = tx
                    .query_row(
                        "SELECT 1 FROM external_identities WHERE account_id = ?1 AND source = ?2",
                        params![acc.id, a.source],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                if !same_source {
                    // A nick owned by someone else's door/local account is never adopted.
                    return Err(MatrixError::nick_conflict());
                }
                found = Some(acc);
            }
        }
    }
    let (account, created) = match found {
        Some(acc) => {
            if acc.status != "active" {
                return Err(MatrixError::forbidden("account is not active"));
            }
            link_identity(&tx, &a.source, &a.subject, acc.id, now_ms)?;
            (acc, false)
        }
        None => {
            let acc = match &a.nick {
                Some(nick) => {
                    validate_nick(nick, &cfg.lists)?;
                    if name_taken(&tx, &nick.to_ascii_lowercase(), 0)? {
                        return Err(MatrixError::nick_conflict());
                    }
                    insert_account(&tx, nick, a.placeholder, now_ms)?
                }
                None => {
                    let nick = generate_placeholder(&mut thread_rng(), &cfg.lists, |c| !name_taken(&tx, c, 0).unwrap_or(true))?;
                    insert_account(&tx, &nick, true, now_ms)?
                }
            };
            link_identity(&tx, &a.source, &a.subject, acc.id, now_ms)?;
            (acc, true)
        }
    };
    // Issuer owns the nick: follow its rename softly (a collision keeps the old nick).
    let account = match &a.nick {
        Some(nick) if *nick != account.nick => match issuer_rename(&tx, account.id, nick, a.placeholder, cfg) {
            Ok(acc) => acc,
            Err(e) => {
                tracing::warn!(account = account.id, "issuer rename not applied: {}", e.errcode);
                account
            }
        },
        _ => account,
    };
    tx.commit()?;
    Ok(Resolved { account, created })
}

/// Make sure the account has its Matrix user and freeze the localpart. One
/// transaction, idempotent. Returns the mxid.
pub fn first_contact(conn: &mut Connection, account_id: i64, now_ms: i64) -> Result<String, MatrixError> {
    let tx = conn.transaction()?;
    let acc = account_by_id(&tx, account_id)?.ok_or_else(|| MatrixError::not_found("unknown account"))?;
    if acc.localpart_frozen {
        let mxid = crate::store::mxid_of(&tx, account_id)?.ok_or_else(MatrixError::internal)?;
        return Ok(mxid);
    }
    let mxid = crate::store::ensure_matrix_user(&tx, account_id, &acc.localpart, &chrono::Utc::now().to_rfc3339())?;
    tx.execute(
        "UPDATE accounts SET localpart_frozen = 1, first_contact_ms = ?2 WHERE id = ?1",
        params![account_id, now_ms],
    )?;
    tx.commit()?;
    Ok(mxid)
}

/// True when the account's nick is owned by an issuer (we only receive its changes).
pub fn is_issuer_account(conn: &Connection, account_id: i64) -> rusqlite::Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM external_identities WHERE account_id = ?1 AND source LIKE 'issuer:%'",
            params![account_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Self-service nick change (door and local accounts). See the identity design.
pub fn set_nick(conn: &mut Connection, account_id: i64, new: &str, cfg: &AccountsConfig, now_ms: i64) -> Result<Account, MatrixError> {
    validate_nick(new, &cfg.lists)?;
    let tx = conn.transaction()?;
    let acc = account_by_id(&tx, account_id)?.ok_or_else(|| MatrixError::not_found("unknown account"))?;
    if acc.status != "active" {
        return Err(MatrixError::forbidden("account is not active"));
    }
    if is_issuer_account(&tx, account_id)? {
        return Err(MatrixError::forbidden("the nick of this account is managed by its issuer"));
    }
    let lower = new.to_ascii_lowercase();
    if lower == acc.nick.to_ascii_lowercase() {
        // Case-only change: always allowed, no cooldown, no counter.
        tx.execute("UPDATE accounts SET nick = ?2 WHERE id = ?1", params![account_id, new])?;
        tx.commit()?;
        return account_by_id(conn, account_id)?.ok_or_else(MatrixError::internal);
    }
    if name_taken(&tx, &lower, account_id)? {
        return Err(MatrixError::nick_taken());
    }
    if acc.nick_changes > 0 {
        let since = now_ms - acc.nick_changed_at.unwrap_or(0);
        if since < cfg.cooldown_ms {
            return Err(MatrixError::nick_cooldown((cfg.cooldown_ms - since) as u64));
        }
    }
    if acc.localpart_frozen {
        tx.execute(
            "UPDATE accounts SET nick = ?2, nick_ci = ?3, nick_is_placeholder = 0, nick_changes = nick_changes + 1, nick_changed_at = ?4 WHERE id = ?1",
            params![account_id, new, lower, now_ms],
        )?;
    } else {
        tx.execute(
            "UPDATE accounts SET nick = ?2, nick_ci = ?3, localpart = ?3, nick_is_placeholder = 0, nick_changes = nick_changes + 1, nick_changed_at = ?4 WHERE id = ?1",
            params![account_id, new, lower, now_ms],
        )?;
    }
    tx.commit()?;
    account_by_id(conn, account_id)?.ok_or_else(MatrixError::internal)
}

/// Apply an issuer-owned nick. No cooldown; a collision is `nick_conflict`.
fn issuer_rename(tx: &Transaction<'_>, account_id: i64, new: &str, placeholder: bool, cfg: &AccountsConfig) -> Result<Account, MatrixError> {
    validate_nick(new, &cfg.lists)?;
    let acc = account_by_id(tx, account_id)?.ok_or_else(|| MatrixError::not_found("unknown account"))?;
    let lower = new.to_ascii_lowercase();
    if lower != acc.nick.to_ascii_lowercase() && name_taken(tx, &lower, account_id)? {
        return Err(MatrixError::nick_conflict());
    }
    if acc.localpart_frozen {
        tx.execute(
            "UPDATE accounts SET nick = ?2, nick_ci = ?3, nick_is_placeholder = ?4 WHERE id = ?1",
            params![account_id, new, lower, placeholder as i64],
        )?;
    } else {
        tx.execute(
            "UPDATE accounts SET nick = ?2, nick_ci = ?3, localpart = ?3, nick_is_placeholder = ?4 WHERE id = ?1",
            params![account_id, new, lower, placeholder as i64],
        )?;
    }
    account_by_id(tx, account_id)?.ok_or_else(MatrixError::internal)
}

/// Lifecycle event `nick.changed{old,new}` from an issuer.
pub fn apply_nick_changed(conn: &mut Connection, source: &str, old: &str, new: &str, cfg: &AccountsConfig) -> Result<bool, MatrixError> {
    let tx = conn.transaction()?;
    let Some(acc) = account_by_nick(&tx, old)? else { return Ok(false) };
    let owned: bool = tx
        .query_row(
            "SELECT 1 FROM external_identities WHERE account_id = ?1 AND source = ?2",
            params![acc.id, source],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !owned {
        return Err(MatrixError::forbidden("account does not belong to this source"));
    }
    issuer_rename(&tx, acc.id, new, false, cfg)?;
    tx.commit()?;
    Ok(true)
}

/// Delete an account: frees login keys and devices, tombstones a frozen localpart.
pub fn delete_account(conn: &mut Connection, account_id: i64, now_ms: i64) -> Result<bool, MatrixError> {
    let Some(acc) = account_by_id(conn, account_id)? else { return Ok(false) };
    if acc.status == "deleted" {
        return Ok(false);
    }
    for d in crate::keys::list_devices(conn, account_id)? {
        crate::keys::delete_device(conn, account_id, &d.device_id, &chrono::Utc::now().to_rfc3339())?;
    }
    let tx = conn.transaction()?;
    if acc.localpart_frozen {
        tx.execute(
            "INSERT OR IGNORE INTO reserved_localparts (localpart, reason, since_ms) VALUES (?1, 'account deleted', ?2)",
            params![acc.localpart, now_ms],
        )?;
        tx.execute(
            "UPDATE accounts SET status = 'deleted', nick_ci = 'deleted:' || id WHERE id = ?1",
            params![account_id],
        )?;
    } else {
        tx.execute(
            "UPDATE accounts SET status = 'deleted', nick_ci = 'deleted:' || id, localpart = 'deleted:' || id WHERE id = ?1",
            params![account_id],
        )?;
    }
    tx.execute("DELETE FROM external_identities WHERE account_id = ?1", params![account_id])?;
    tx.commit()?;
    Ok(true)
}

/// Lifecycle event `account.deleted{nick}` from an issuer.
pub fn apply_account_deleted(conn: &mut Connection, source: &str, nick: &str, now_ms: i64) -> Result<bool, MatrixError> {
    let Some(acc) = account_by_nick(conn, nick)? else { return Ok(false) };
    let owned: bool = conn
        .query_row(
            "SELECT 1 FROM external_identities WHERE account_id = ?1 AND source = ?2",
            params![acc.id, source],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !owned {
        return Err(MatrixError::forbidden("account does not belong to this source"));
    }
    delete_account(conn, acc.id, now_ms)
}

/// Lifecycle event `credential.revoked{cred_ref}`: removes the device. Returns the user id so the caller can wake sync.
pub fn apply_credential_revoked(conn: &mut Connection, source: &str, cred_ref: &str) -> Result<Option<i64>, MatrixError> {
    let key = credential_key(source, cred_ref);
    let hit = crate::keys::delete_device_by_credential(conn, CredentialKind::Web, &key, &chrono::Utc::now().to_rfc3339())?;
    Ok(hit.map(|(u, _)| u))
}

/// The device of this credential, minted on first use.
pub fn device_for_assertion(conn: &Connection, account_id: i64, a: &Asserted) -> Result<String, MatrixError> {
    let key = credential_key(&a.source, &a.cred_ref);
    if let Some(d) = crate::keys::device_for_credential(conn, CredentialKind::Web, &key)? {
        if d.user_id != account_id {
            return Err(MatrixError::forbidden("credential belongs to another account"));
        }
        return Ok(d.device_id);
    }
    Ok(crate::keys::create_device(conn, account_id, CredentialKind::Web, &key, &chrono::Utc::now().to_rfc3339())?)
}

/// Current nick for an account that has made contact, used for display labels.
pub fn nick_of_user(conn: &Connection, user_id: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT nick FROM accounts WHERE id = ?1 AND status = 'active'", params![user_id], |r| r.get(0)).optional()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::create_matrix_schema;

    const DAY: i64 = 24 * 3600 * 1000;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "foreign_keys", "ON").unwrap();
        create_matrix_schema(&c).unwrap();
        crate::keys::create_matrix_keys_schema(&c).unwrap();
        c
    }
    fn door(subject: &str, cred: &str) -> Asserted {
        Asserted { source: "matrix".into(), subject: subject.into(), nick: None, placeholder: true, authenticated: true, paid: false, cred_ref: cred.into(), expires_ms: 0 }
    }
    fn issuer(nick: &str, cred: &str, placeholder: bool) -> Asserted {
        Asserted { source: "issuer:t".into(), subject: nick.into(), nick: Some(nick.into()), placeholder, authenticated: true, paid: false, cred_ref: cred.into(), expires_ms: 0 }
    }
    fn mk(c: &mut Connection, s: &str) -> Account {
        resolve_account(c, &door(s, ""), &AccountsConfig::default(), 1).unwrap().account
    }

    #[test]
    fn door_login_creates_placeholder_once_and_is_stable() {
        let mut c = db();
        let r = resolve_account(&mut c, &door("@x:other.example", "c1"), &AccountsConfig::default(), 10).unwrap();
        assert!(r.created && r.account.nick_is_placeholder && r.account.nick.len() == 8);
        assert_eq!(r.account.localpart, r.account.nick);
        assert!(!r.account.localpart_frozen && r.account.nick_changes == 0);
        let again = resolve_account(&mut c, &door("@x:other.example", "c1"), &AccountsConfig::default(), 20).unwrap();
        assert!(!again.created);
        assert_eq!(again.account.id, r.account.id);
        assert_ne!(mk(&mut c, "@x:another.example").id, r.account.id, "same localpart elsewhere = other account");
    }

    #[test]
    fn foreign_name_is_never_copied_and_no_account_for_remote_users() {
        let mut c = db();
        let a = mk(&mut c, "@alice:other.example");
        assert!(!a.nick.contains("alice"));
        crate::fed_rooms::ensure_remote_user(&c, "@bob:other.example", "t").unwrap();
        let n: i64 = c.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "remote federated user creates no account");
        let u: i64 = c.query_row("SELECT user_id FROM matrix_users WHERE mxid='@bob:other.example'", [], |r| r.get(0)).unwrap();
        assert!(u < 0);
    }

    #[test]
    fn freeze_at_first_contact_and_set_nick_before_and_after() {
        let mut c = db();
        let cfg = AccountsConfig::default();
        let a = mk(&mut c, "s1");
        let old = a.nick.clone();
        let b = set_nick(&mut c, a.id, "Bob", &cfg, 5 * DAY).unwrap();
        assert_eq!((b.localpart.as_str(), b.nick.as_str(), b.nick_changes, b.nick_is_placeholder), ("bob", "Bob", 1, false));
        assert!(!name_taken(&c, &old, 0).unwrap(), "old placeholder freed before contact");
        let mxid = first_contact(&mut c, a.id, 6 * DAY).unwrap();
        assert_eq!(mxid, "@bob:example.org");
        assert_eq!(first_contact(&mut c, a.id, 7 * DAY).unwrap(), mxid, "idempotent");
        let e = set_nick(&mut c, a.id, "Robert", &cfg, 6 * DAY).unwrap_err();
        assert_eq!(e.errcode, "M4A_NICK_COOLDOWN");
        assert_eq!(e.retry_after_ms, Some(29 * DAY as u64));
        let r = set_nick(&mut c, a.id, "Robert", &cfg, 36 * DAY).unwrap();
        assert_eq!((r.localpart.as_str(), r.nick.as_str(), r.nick_changes), ("bob", "Robert", 2));
        assert!(name_taken(&c, "bob", 0).unwrap(), "frozen localpart stays reserved");
        assert!(!name_taken(&c, "robert", a.id).unwrap());
    }

    #[test]
    fn first_change_is_free_and_case_only_is_free() {
        let mut c = db();
        let cfg = AccountsConfig::default();
        let a = mk(&mut c, "s1");
        set_nick(&mut c, a.id, "carol", &cfg, 1).unwrap();
        let e = set_nick(&mut c, a.id, "caroline", &cfg, 2).unwrap_err();
        assert_eq!(e.errcode, "M4A_NICK_COOLDOWN");
        let r = set_nick(&mut c, a.id, "Carol", &cfg, 3).unwrap();
        assert_eq!((r.nick.as_str(), r.nick_changes), ("Carol", 1));
        let ok = set_nick(&mut c, a.id, "caroline", &cfg, 1 + 30 * DAY).unwrap();
        assert_eq!(ok.nick_changes, 2);
    }

    #[test]
    fn collisions_rows_2_3_9_14_15() {
        let mut c = db();
        let cfg = AccountsConfig::default();
        let a = mk(&mut c, "s1");
        let b = mk(&mut c, "s2");
        set_nick(&mut c, a.id, "dave", &cfg, 1).unwrap();
        first_contact(&mut c, a.id, 2).unwrap();
        assert_eq!(set_nick(&mut c, b.id, "DAVE", &cfg, 1).unwrap_err().errcode, "M4A_NICK_TAKEN");
        set_nick(&mut c, a.id, "david", &cfg, 2 + 31 * DAY).unwrap();
        assert_eq!(set_nick(&mut c, b.id, "dave", &cfg, 1).unwrap_err().errcode, "M4A_NICK_TAKEN", "frozen localpart of another");
        // issuer asserting a nick equal to a frozen localpart
        let e = resolve_account(&mut c, &issuer("dave", "k1", false), &cfg, 1).unwrap_err();
        assert_eq!(e.errcode, "M4A_NICK_CONFLICT");
        // an existing matrix user (agent) localpart is also protected
        crate::store::ensure_matrix_user(&c, 900, "agentx", "t").unwrap();
        assert_eq!(set_nick(&mut c, b.id, "agentx", &cfg, 1).unwrap_err().errcode, "M4A_NICK_TAKEN");
    }

    #[test]
    fn grammar_and_lists_are_enforced_on_set_nick_and_issuer_create() {
        let mut c = db();
        let cfg = AccountsConfig { lists: NickLists::parse("root"), ..Default::default() };
        let a = mk(&mut c, "s1");
        for bad in ["a:b", "ab", "bob.com", "root"] {
            assert_eq!(set_nick(&mut c, a.id, bad, &cfg, 1).unwrap_err().errcode, "M4A_INVALID_NICK", "{bad}");
        }
        assert_eq!(resolve_account(&mut c, &issuer("root", "k", false), &cfg, 1).unwrap_err().errcode, "M4A_INVALID_NICK");
    }

    #[test]
    fn issuer_accounts_create_heal_rename_and_refuse_self_service() {
        let mut c = db();
        let cfg = AccountsConfig::default();
        let r = resolve_account(&mut c, &issuer("erin", "k1", false), &cfg, 1).unwrap();
        assert!(r.created && !r.account.nick_is_placeholder && r.account.localpart == "erin");
        assert_eq!(set_nick(&mut c, r.account.id, "other", &cfg, 1).unwrap_err().errcode, "M_FORBIDDEN");
        // device continuity: credential known, nick renamed upstream -> same account, nick follows
        device_for_assertion(&c, r.account.id, &issuer("erin", "k1", false)).unwrap();
        first_contact(&mut c, r.account.id, 2).unwrap();
        let healed = resolve_account(&mut c, &issuer("erin2", "k1", false), &cfg, 3).unwrap();
        assert!(!healed.created);
        assert_eq!((healed.account.id, healed.account.nick.as_str(), healed.account.localpart.as_str()), (r.account.id, "erin2", "erin"));
        // a rename colliding with another account is refused on the event path
        let other = resolve_account(&mut c, &issuer("frank", "k2", false), &cfg, 4).unwrap().account;
        assert_ne!(other.id, r.account.id);
        // event path reports the conflict
        let e = apply_nick_changed(&mut c, "issuer:t", "erin2", "frank", &cfg).unwrap_err();
        assert_eq!(e.errcode, "M4A_NICK_CONFLICT");
        assert!(apply_nick_changed(&mut c, "issuer:t", "erin2", "erin3", &cfg).unwrap());
        assert!(!apply_nick_changed(&mut c, "issuer:t", "nobody", "xyz", &cfg).unwrap());
    }

    #[test]
    fn issuer_nick_of_a_door_account_is_not_adopted() {
        let mut c = db();
        let cfg = AccountsConfig::default();
        let a = mk(&mut c, "s1");
        set_nick(&mut c, a.id, "gina", &cfg, 1).unwrap();
        assert_eq!(resolve_account(&mut c, &issuer("gina", "k", false), &cfg, 1).unwrap_err().errcode, "M4A_NICK_CONFLICT");
    }

    #[test]
    fn delete_tombstones_frozen_localpart_and_revoke_removes_device() {
        let mut c = db();
        let cfg = AccountsConfig::default();
        let r = resolve_account(&mut c, &issuer("hank", "k1", false), &cfg, 1).unwrap();
        let id = r.account.id;
        first_contact(&mut c, id, 2).unwrap();
        device_for_assertion(&c, id, &issuer("hank", "k1", false)).unwrap();
        assert_eq!(apply_credential_revoked(&mut c, "issuer:t", "k1").unwrap(), Some(id));
        assert_eq!(apply_credential_revoked(&mut c, "issuer:t", "k1").unwrap(), None);
        assert!(apply_account_deleted(&mut c, "issuer:t", "hank", 3).unwrap());
        assert!(!apply_account_deleted(&mut c, "issuer:t", "hank", 3).unwrap());
        assert!(name_taken(&c, "hank", 0).unwrap(), "frozen localpart never reissued");
        assert_eq!(resolve_account(&mut c, &issuer("hank", "k9", false), &cfg, 4).unwrap_err().errcode, "M4A_NICK_CONFLICT");
        // a door account that was never in contact frees everything
        let d = mk(&mut c, "s9");
        let nick = d.nick.clone();
        delete_account(&mut c, d.id, 5).unwrap();
        assert!(!name_taken(&c, &nick, 0).unwrap());
        let back = mk(&mut c, "s9");
        assert_ne!(back.id, d.id);
    }

    #[test]
    fn concurrent_style_double_login_finds_the_winner() {
        let mut c = db();
        let a = mk(&mut c, "same");
        let b = mk(&mut c, "same");
        assert_eq!(a.id, b.id);
        let n: i64 = c.query_row("SELECT COUNT(*) FROM external_identities", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn account_ids_do_not_collide_with_existing_matrix_users() {
        let mut c = db();
        crate::store::ensure_matrix_user(&c, 41, "legacyuser", "t").unwrap();
        assert!(mk(&mut c, "s1").id >= 42);
    }
}
