//! Nick stored on `messenger_sessions`. The HTTP layer stamps member display
//! names from [`effective_label`] and refuses create/invite when
//! [`require_nick`] fails. [`set_nick`] writes that session row. There is no
//! reserved-nick list, no cooldown, and no billing. `matrix_users.nick` is
//! not the source of truth.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::MatrixError;

/// A client session. The nick is this row. `device_id` is only a mark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessengerSession {
    pub session_id: String,
    pub user_id: i64,
    pub device_id: String,
    pub nick: String,
}

pub fn normalize_nick(nick: &str) -> Result<String, MatrixError> {
    let nick = nick.trim();
    if nick.is_empty()
        || nick.len() > 32
        || !nick
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(MatrixError::invalid_param(
            "nick must be 1..=32 of [A-Za-z0-9_-]",
        ));
    }
    Ok(nick.to_string())
}

/// Placeholder row [`set_nick`] uses when a client has not registered yet.
/// Register adopts it. Clients cannot choose this id.
pub(crate) fn legacy_session_id(user_id: i64) -> String {
    format!("legacy-user-{user_id}")
}

pub(crate) fn session_by_id(
    conn: &Connection,
    session_id: &str,
) -> Result<Option<MessengerSession>, MatrixError> {
    let found = conn
        .query_row(
            "SELECT session_id, user_id, device_id, nick FROM messenger_sessions WHERE session_id = ?1",
            params![session_id],
            |row| {
                Ok(MessengerSession {
                    session_id: row.get(0)?,
                    user_id: row.get(1)?,
                    device_id: row.get(2)?,
                    nick: row.get(3)?,
                })
            },
        )
        .optional()?;
    Ok(found)
}

/// True when some other session already has this nick, case-insensitively.
pub(crate) fn nick_taken(
    conn: &Connection,
    nick: &str,
    except_session_id: Option<&str>,
) -> Result<bool, MatrixError> {
    let except = except_session_id.unwrap_or("");
    let taken = conn
        .query_row(
            "SELECT 1 FROM messenger_sessions WHERE LOWER(nick) = LOWER(?1) AND session_id != ?2",
            params![nick, except],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(taken)
}

/// Insert the client session, or adopt the placeholder [`set_nick`] left
/// behind for this user. The placeholder's nick is replaced.
pub(crate) fn save_session(
    conn: &Connection,
    session_id: &str,
    user_id: i64,
    device_id: &str,
    nick: &str,
    replace_legacy: bool,
) -> Result<(), MatrixError> {
    if replace_legacy {
        let legacy = legacy_session_id(user_id);
        let updated = conn.execute(
            "UPDATE messenger_sessions
             SET session_id = ?1, device_id = ?2, nick = ?3
             WHERE session_id = ?4 AND user_id = ?5",
            params![session_id, device_id, nick, legacy, user_id],
        )?;
        if updated > 0 {
            return Ok(());
        }
    }
    conn.execute(
        "INSERT INTO messenger_sessions (session_id, user_id, device_id, nick) VALUES (?1, ?2, ?3, ?4)",
        params![session_id, user_id, device_id, nick],
    )?;
    Ok(())
}

pub fn set_nick(conn: &Connection, user_id: i64, nick: &str) -> Result<(), MatrixError> {
    let nick = normalize_nick(nick)?;
    let user_exists: bool = conn
        .query_row(
            "SELECT 1 FROM matrix_users WHERE user_id = ?1",
            params![user_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !user_exists {
        return Err(MatrixError::not_found("unknown user"));
    }
    let current: Option<String> = conn
        .query_row(
            "SELECT session_id FROM messenger_sessions WHERE user_id = ?1 ORDER BY rowid LIMIT 1",
            params![user_id],
            |row| row.get(0),
        )
        .optional()?;
    if nick_taken(conn, &nick, current.as_deref())? {
        return Err(MatrixError::invalid_param("nick is taken"));
    }
    if let Some(session_id) = current {
        conn.execute(
            "UPDATE messenger_sessions SET nick = ?1 WHERE session_id = ?2",
            params![nick, session_id],
        )?;
    } else {
        let session_id = legacy_session_id(user_id);
        conn.execute(
            "INSERT INTO messenger_sessions (session_id, user_id, device_id, nick) VALUES (?1, ?2, '', ?3)",
            params![session_id, user_id, nick],
        )?;
    }
    Ok(())
}

pub fn user_nick(conn: &Connection, user_id: i64) -> rusqlite::Result<Option<String>> {
    let nick: Option<String> = conn
        .query_row(
            "SELECT nick FROM messenger_sessions
             WHERE user_id = ?1 AND nick != ''
             ORDER BY rowid LIMIT 1",
            params![user_id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(n) = nick.filter(|n| !n.is_empty()) {
        return Ok(Some(n));
    }
    crate::identities::nick_of_user(conn, user_id)
}

/// Earliest session nick when one is set, otherwise the mxid localpart.
pub fn effective_label(conn: &Connection, user_id: i64) -> rusqlite::Result<String> {
    if let Some(nick) = user_nick(conn, user_id)? {
        return Ok(nick);
    }
    let mxid: String = conn.query_row(
        "SELECT mxid FROM matrix_users WHERE user_id = ?1",
        params![user_id],
        |row| row.get(0),
    )?;
    Ok(crate::store::public_id_from_mxid(&mxid)
        .unwrap_or("")
        .to_string())
}

pub fn require_nick(
    conn: &Connection,
    user_id: i64,
    missing: &'static str,
) -> Result<String, MatrixError> {
    match user_nick(conn, user_id)? {
        Some(nick) => Ok(nick),
        None => Err(MatrixError::forbidden(missing)),
    }
}

pub struct NickHit {
    pub mxid: String,
    pub nick: String,
}

/// Case-insensitive substring search over session nicks. `limited` is true
/// when more than `limit` rows matched.
pub fn search_nicks(
    conn: &Connection,
    term: &str,
    limit: usize,
) -> rusqlite::Result<(Vec<NickHit>, bool)> {
    let escaped = term
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let pattern = format!("%{escaped}%");
    let mut stmt = conn.prepare(
        "SELECT mxid, nick FROM (
             SELECT u.mxid AS mxid, s.nick AS nick
             FROM messenger_sessions s JOIN matrix_users u ON u.user_id = s.user_id
             WHERE s.nick != ''
             UNION
             SELECT u.mxid, i.nick
             FROM identities i JOIN matrix_users u ON u.user_id = i.id
         )
         WHERE LOWER(nick) LIKE LOWER(?1) ESCAPE '\\'
         ORDER BY LOWER(nick)
         LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![pattern, (limit as i64) + 1], |row| {
        Ok(NickHit {
            mxid: row.get(0)?,
            nick: row.get(1)?,
        })
    })?;
    let mut hits = Vec::new();
    for row in rows {
        hits.push(row?);
    }
    let limited = hits.len() > limit;
    hits.truncate(limit);
    Ok((hits, limited))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{create_matrix_schema, ensure_matrix_user};

    const T0: &str = "2026-10-05T00:00:00+00:00";

    fn conn() -> Connection {
        let conn = Connection::open_in_memory().expect("memory");
        create_matrix_schema(&conn).expect("schema");
        conn
    }

    #[test]
    fn set_nick_is_unique_and_gates_an_empty_user() {
        let conn = conn();
        ensure_matrix_user(&conn, 1, "alice000000000000000000000000a1", T0).expect("alice");
        ensure_matrix_user(&conn, 2, "bob0000000000000000000000000b02", T0).expect("bob");
        assert!(require_nick(&conn, 1, "choose a nick before creating a room").is_err());
        set_nick(&conn, 1, "alice_nick").expect("set");
        assert_eq!(effective_label(&conn, 1).expect("label"), "alice_nick");
        let on_session: String = conn
            .query_row(
                "SELECT nick FROM messenger_sessions WHERE user_id = 1",
                [],
                |row| row.get(0),
            )
            .expect("session nick");
        assert_eq!(on_session, "alice_nick");
        let column: Option<String> = conn
            .query_row(
                "SELECT nick FROM matrix_users WHERE user_id = 1",
                [],
                |row| row.get(0),
            )
            .expect("column");
        assert!(column.is_none());
        assert!(set_nick(&conn, 2, "Alice_Nick").is_err());
        assert!(set_nick(&conn, 1, "bad nick").is_err());
    }
}
