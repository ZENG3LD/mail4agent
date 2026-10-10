//! Nick + domain identities of this messenger server.
//!
//! The server keeps no user database: it knows a nick, the Matrix localpart
//! derived from it (lowercase nick at FIRST CONTACT, frozen from then on), the
//! first-contact time, and the devices of the credentials a product vouches
//! for. Who a person is, how they log in and which nick rules apply are the
//! product server's business; the product tells this server by signed
//! assertion ([`m4a_seam`]) and by lifecycle events.
//!
//! Remote federated users are NOT identities: they stay negative-id proxy rows
//! in `matrix_users`.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::MatrixError;
use crate::keys::CredentialKind;

/// Longest nick the server will turn into a localpart.
pub const NICK_MAX: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Same integer as `matrix_users.user_id`.
    pub id: i64,
    pub nick: String,
    pub localpart: String,
    pub first_contact_ms: i64,
}

pub fn create_identities_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS identities (
            id               INTEGER PRIMARY KEY,
            nick             TEXT NOT NULL,
            nick_ci          TEXT NOT NULL UNIQUE,
            localpart        TEXT NOT NULL UNIQUE,
            first_contact_ms INTEGER NOT NULL
        );
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

/// The only nick check the server makes itself: the nick must be a legal,
/// predictable Matrix localpart. Product nick rules are the product's.
pub fn legal_localpart(nick: &str) -> Result<(), MatrixError> {
    let ok = !nick.is_empty()
        && nick.len() <= NICK_MAX
        && nick.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '='));
    if ok {
        Ok(())
    } else {
        Err(MatrixError::invalid_nick("nick must be 1-64 of A-Z a-z 0-9 _ - . ="))
    }
}

const COLS: &str = "id, nick, localpart, first_contact_ms";

fn from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Identity> {
    Ok(Identity { id: r.get(0)?, nick: r.get(1)?, localpart: r.get(2)?, first_contact_ms: r.get(3)? })
}

pub fn identity_by_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<Identity>> {
    conn.query_row(&format!("SELECT {COLS} FROM identities WHERE id = ?1"), params![id], from_row).optional()
}

pub fn identity_by_nick(conn: &Connection, nick: &str) -> rusqlite::Result<Option<Identity>> {
    conn.query_row(&format!("SELECT {COLS} FROM identities WHERE nick_ci = ?1"), params![nick.to_ascii_lowercase()], from_row).optional()
}

/// Is `lower` unavailable as a nick or localpart for anyone but `except_id`?
pub fn name_taken(conn: &Connection, lower: &str, except_id: i64) -> rusqlite::Result<bool> {
    if crate::store::is_reserved_localpart(lower) {
        return Ok(true);
    }
    let q = |sql: &str, p: &[&dyn rusqlite::ToSql]| -> rusqlite::Result<bool> { Ok(conn.query_row(sql, p, |_| Ok(())).optional()?.is_some()) };
    Ok(q("SELECT 1 FROM identities WHERE id != ?2 AND (nick_ci = ?1 OR localpart = ?1)", &[&lower, &except_id])?
        || q("SELECT 1 FROM reserved_localparts WHERE localpart = ?1", &[&lower])?
        || q("SELECT 1 FROM matrix_users WHERE mxid = ?1 AND user_id != ?2", &[&crate::store::mxid_for_public_id(lower), &except_id])?)
}

fn next_id(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT MAX((SELECT COALESCE(MAX(id), 0) FROM identities), (SELECT COALESCE(MAX(user_id), 0) FROM matrix_users)) + 1",
        [],
        |r| r.get(0),
    )
}

/// What a valid assertion resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub identity: Identity,
    pub device_id: String,
    pub created: bool,
}

/// Resolve a verified assertion: find the identity by nick, else by the
/// credential's device (the product renamed the nick; follow it softly), else
/// create it. Creation IS first contact: the Matrix user is made and the
/// localpart frozen in the same transaction. Then the credential's device.
pub fn resolve_assertion(conn: &mut Connection, nick: &str, cred_ref: &str, now_ms: i64) -> Result<Resolved, MatrixError> {
    let tx = conn.transaction()?;
    let mut found = identity_by_nick(&tx, nick)?;
    if found.is_none() {
        if let Some(dev) = crate::keys::device_for_credential(&tx, CredentialKind::Web, cred_ref)? {
            found = identity_by_id(&tx, dev.user_id)?;
            if let Some(idn) = &found {
                // The product renamed this person: follow if the new nick is free.
                match rename_in(&tx, idn.id, nick) {
                    Ok(()) => found = identity_by_id(&tx, idn.id)?,
                    Err(e) => tracing::warn!(identity = idn.id, "rename by assertion not applied: {}", e.errcode),
                }
            }
        }
    }
    let (identity, created) = match found {
        Some(i) => {
            if i.nick != nick && i.nick.eq_ignore_ascii_case(nick) {
                tx.execute("UPDATE identities SET nick = ?2 WHERE id = ?1", params![i.id, nick])?;
            }
            (identity_by_id(&tx, i.id)?.ok_or_else(MatrixError::internal)?, false)
        }
        None => {
            legal_localpart(nick)?;
            let lower = nick.to_ascii_lowercase();
            if name_taken(&tx, &lower, 0)? {
                return Err(MatrixError::nick_conflict());
            }
            let id = next_id(&tx)?;
            crate::store::ensure_matrix_user(&tx, id, &lower, &chrono::Utc::now().to_rfc3339())?;
            tx.execute(
                "INSERT INTO identities (id, nick, nick_ci, localpart, first_contact_ms) VALUES (?1, ?2, ?3, ?3, ?4)",
                params![id, nick, lower, now_ms],
            )?;
            (identity_by_id(&tx, id)?.ok_or_else(MatrixError::internal)?, true)
        }
    };
    let device_id = match crate::keys::device_for_credential(&tx, CredentialKind::Web, cred_ref)? {
        Some(d) if d.user_id == identity.id => d.device_id,
        Some(_) => return Err(MatrixError::forbidden("credential belongs to another identity")),
        None => crate::keys::create_device(&tx, identity.id, CredentialKind::Web, cred_ref, &chrono::Utc::now().to_rfc3339())?,
    };
    tx.commit()?;
    Ok(Resolved { identity, device_id, created })
}

/// Change the nick (display) of an identity; the localpart never moves.
fn rename_in(conn: &Connection, id: i64, new: &str) -> Result<(), MatrixError> {
    legal_localpart(new)?;
    let lower = new.to_ascii_lowercase();
    if name_taken(conn, &lower, id)? {
        return Err(MatrixError::nick_conflict());
    }
    conn.execute("UPDATE identities SET nick = ?2, nick_ci = ?3 WHERE id = ?1", params![id, new, lower])?;
    Ok(())
}

/// Event `nick.changed{old,new}`. `Ok(Some(id))` when applied.
pub fn apply_nick_changed(conn: &mut Connection, old: &str, new: &str) -> Result<Option<i64>, MatrixError> {
    let tx = conn.transaction()?;
    let Some(idn) = identity_by_nick(&tx, old)? else { return Ok(None) };
    rename_in(&tx, idn.id, new)?;
    tx.commit()?;
    Ok(Some(idn.id))
}

/// Event `account.deleted{nick}`: devices gone, localpart tombstoned forever,
/// the nick string freed. Returns whether an identity was retired.
pub fn apply_account_deleted(conn: &mut Connection, nick: &str, now_ms: i64) -> Result<bool, MatrixError> {
    let Some(idn) = identity_by_nick(conn, nick)? else { return Ok(false) };
    for d in crate::keys::list_devices(conn, idn.id)? {
        crate::keys::delete_device(conn, idn.id, &d.device_id, &chrono::Utc::now().to_rfc3339())?;
    }
    let tx = conn.transaction()?;
    tx.execute("INSERT OR IGNORE INTO reserved_localparts (localpart, reason, since_ms) VALUES (?1, 'identity retired', ?2)", params![idn.localpart, now_ms])?;
    tx.execute("DELETE FROM identities WHERE id = ?1", params![idn.id])?;
    tx.commit()?;
    Ok(true)
}

/// Event `credential.revoked{cred_ref}`: the device is removed. Returns the user id to wake.
pub fn apply_credential_revoked(conn: &mut Connection, cred_ref: &str) -> Result<Option<i64>, MatrixError> {
    let hit = crate::keys::delete_device_by_credential(conn, CredentialKind::Web, cred_ref, &chrono::Utc::now().to_rfc3339())?;
    Ok(hit.map(|(u, _)| u))
}

/// What a reconcile pass changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcileOutcome {
    pub devices_removed: usize,
    pub identities_retired: usize,
    pub wake: Vec<i64>,
    /// Users whose push connections must be dropped (device removed or identity retired).
    pub closed: Vec<i64>,
}

/// Apply the product's snapshot of live credentials. Devices of a listed nick whose
/// credential is not in its list are removed; with `complete`, identities whose nick is not
/// listed at all are retired exactly as `account.deleted` would.
pub fn reconcile(conn: &mut Connection, snap: &m4a_seam::Reconcile, now_ms: i64) -> Result<ReconcileOutcome, MatrixError> {
    let mut out = ReconcileOutcome::default();
    let mut listed = std::collections::HashSet::new();
    for live in &snap.nicks {
        listed.insert(live.nick.to_ascii_lowercase());
        let Some(idn) = identity_by_nick(conn, &live.nick)? else { continue };
        for d in crate::keys::list_devices(conn, idn.id)? {
            if d.credential_kind == CredentialKind::Web && !live.creds.iter().any(|c| *c == d.credential_ref) {
                crate::keys::delete_device(conn, idn.id, &d.device_id, &chrono::Utc::now().to_rfc3339())?;
                out.devices_removed += 1;
                if !out.wake.contains(&idn.id) {
                    out.wake.push(idn.id);
                    out.closed.push(idn.id);
                }
            }
        }
    }
    if snap.complete {
        let all: Vec<String> = {
            let mut st = conn.prepare("SELECT nick FROM identities")?;
            let rows = st.query_map([], |r| r.get::<_, String>(0))?;
            rows.collect::<Result<_, _>>()?
        };
        for nick in all.into_iter().filter(|n| !listed.contains(&n.to_ascii_lowercase())) {
            let id = identity_by_nick(conn, &nick)?.map(|i| i.id);
            if apply_account_deleted(conn, &nick, now_ms)? {
                out.closed.extend(id);
                out.identities_retired += 1;
            }
        }
    }
    Ok(out)
}

/// Current nick of an identity, for display labels.
pub fn nick_of_user(conn: &Connection, user_id: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT nick FROM identities WHERE id = ?1", params![user_id], |r| r.get(0)).optional()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::create_matrix_schema;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "foreign_keys", "ON").unwrap();
        create_matrix_schema(&c).unwrap();
        crate::keys::create_matrix_keys_schema(&c).unwrap();
        c
    }

    #[test]
    fn first_assertion_is_first_contact_and_freezes_the_localpart() {
        let mut c = db();
        let r = resolve_assertion(&mut c, "Carol", "c1", 10).unwrap();
        assert!(r.created);
        assert_eq!((r.identity.nick.as_str(), r.identity.localpart.as_str()), ("Carol", "carol"));
        assert_eq!(crate::store::mxid_of(&c, r.identity.id).unwrap().as_deref(), Some("@carol:example.org"));
        let again = resolve_assertion(&mut c, "carol", "c1", 20).unwrap();
        assert!(!again.created);
        assert_eq!(again.identity.id, r.identity.id);
        assert_eq!(again.device_id, r.device_id);
        assert_eq!(again.identity.nick, "carol", "case-only change follows");
        let other = resolve_assertion(&mut c, "dave", "c2", 30).unwrap();
        assert_ne!(other.device_id, r.device_id);
    }

    #[test]
    fn rename_by_assertion_and_by_event_keep_the_localpart() {
        let mut c = db();
        let r = resolve_assertion(&mut c, "erin", "k1", 1).unwrap();
        let healed = resolve_assertion(&mut c, "erin2", "k1", 2).unwrap();
        assert!(!healed.created);
        assert_eq!((healed.identity.id, healed.identity.nick.as_str(), healed.identity.localpart.as_str()), (r.identity.id, "erin2", "erin"));
        resolve_assertion(&mut c, "frank", "k2", 3).unwrap();
        assert_eq!(apply_nick_changed(&mut c, "erin2", "frank").unwrap_err().errcode, "M4A_NICK_CONFLICT");
        assert_eq!(apply_nick_changed(&mut c, "erin2", "erin3").unwrap(), Some(r.identity.id));
        assert_eq!(apply_nick_changed(&mut c, "nobody", "xyz").unwrap(), None);
        assert!(name_taken(&c, "erin", 0).unwrap(), "frozen localpart stays reserved to others");
        assert!(!name_taken(&c, "erin2", 0).unwrap(), "old nick string is free");
    }

    #[test]
    fn collisions_and_legality() {
        let mut c = db();
        resolve_assertion(&mut c, "gina", "k1", 1).unwrap();
        // another credential asserting an existing nick is the same identity (the product owns uniqueness)
        assert!(!resolve_assertion(&mut c, "GINA", "k9", 2).unwrap().created);
        // a nick equal to an existing matrix user's localpart is refused
        crate::store::ensure_matrix_user(&c, 900, "agentx", "t").unwrap();
        assert_eq!(resolve_assertion(&mut c, "agentx", "k3", 3).unwrap_err().errcode, "M4A_NICK_CONFLICT");
        for bad in ["a:b", "a b", "a/b", "", &"x".repeat(65)] {
            assert_eq!(resolve_assertion(&mut c, bad, "k4", 4).unwrap_err().errcode, "M4A_INVALID_NICK", "{bad:?}");
        }
        let n: i64 = c.query_row("SELECT COUNT(*) FROM identities", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn revoke_and_delete_retire_devices_and_tombstone_the_localpart() {
        let mut c = db();
        let r = resolve_assertion(&mut c, "hank", "k1", 1).unwrap();
        assert_eq!(apply_credential_revoked(&mut c, "k1").unwrap(), Some(r.identity.id));
        assert_eq!(apply_credential_revoked(&mut c, "k1").unwrap(), None);
        resolve_assertion(&mut c, "hank", "k5", 2).unwrap();
        assert!(apply_account_deleted(&mut c, "hank", 3).unwrap());
        assert!(!apply_account_deleted(&mut c, "hank", 3).unwrap());
        assert!(name_taken(&c, "hank", 0).unwrap(), "retired localpart is never reissued");
        assert_eq!(resolve_assertion(&mut c, "hank", "k6", 4).unwrap_err().errcode, "M4A_NICK_CONFLICT");
        assert!(crate::keys::list_devices(&c, r.identity.id).unwrap().is_empty());
    }

    #[test]
    fn remote_users_are_not_identities_and_ids_do_not_collide() {
        let mut c = db();
        crate::fed_rooms::ensure_remote_user(&c, "@bob:other.example", "t").unwrap();
        crate::store::ensure_matrix_user(&c, 41, "legacyuser", "t").unwrap();
        let r = resolve_assertion(&mut c, "ivy", "k1", 1).unwrap();
        assert!(r.identity.id >= 42);
        let n: i64 = c.query_row("SELECT COUNT(*) FROM identities", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }
}
