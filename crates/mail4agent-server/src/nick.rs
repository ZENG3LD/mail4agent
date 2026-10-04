//! Nick stored on `matrix_users`. The HTTP layer stamps member display names
//! from [`effective_label`] and refuses create/invite when [`require_nick`]
//! fails. The websession sets the nick with [`set_nick`]. There is no
//! reserved-nick list, no cooldown, and no billing grant.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::MatrixError;

pub fn set_nick(conn: &Connection, user_id: i64, nick: &str) -> Result<(), MatrixError> {
    let nick = nick.trim();
    if nick.is_empty()
        || nick.len() > 32
        || !nick.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(MatrixError::invalid_param("nick must be 1..=32 of [A-Za-z0-9_]"));
    }
    let taken: bool = conn
        .query_row(
            "SELECT 1 FROM matrix_users WHERE LOWER(nick) = LOWER(?1) AND user_id != ?2",
            params![nick, user_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if taken {
        return Err(MatrixError::invalid_param("nick is taken"));
    }
    let updated = conn.execute(
        "UPDATE matrix_users SET nick = ?1 WHERE user_id = ?2",
        params![nick, user_id],
    )?;
    if updated == 0 {
        return Err(MatrixError::not_found("unknown user"));
    }
    Ok(())
}

pub fn user_nick(conn: &Connection, user_id: i64) -> rusqlite::Result<Option<String>> {
    let nick: Option<String> = conn
        .query_row("SELECT nick FROM matrix_users WHERE user_id = ?1", params![user_id], |row| row.get(0))
        .optional()?
        .flatten();
    Ok(nick.filter(|n| !n.is_empty()))
}

/// Nick when one is set, otherwise the mxid localpart.
pub fn effective_label(conn: &Connection, user_id: i64) -> rusqlite::Result<String> {
    let (nick, mxid): (Option<String>, String) = conn.query_row(
        "SELECT nick, mxid FROM matrix_users WHERE user_id = ?1",
        params![user_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if let Some(nick) = nick.filter(|n| !n.is_empty()) {
        return Ok(nick);
    }
    Ok(crate::store::public_id_from_mxid(&mxid).unwrap_or("").to_string())
}

pub fn require_nick(conn: &Connection, user_id: i64, missing: &'static str) -> Result<String, MatrixError> {
    match user_nick(conn, user_id)? {
        Some(nick) => Ok(nick),
        None => Err(MatrixError::forbidden(missing)),
    }
}

pub struct NickHit {
    pub mxid: String,
    pub nick: String,
}

/// Case-insensitive substring search. `limited` is true when more than
/// `limit` rows matched.
pub fn search_nicks(conn: &Connection, term: &str, limit: usize) -> rusqlite::Result<(Vec<NickHit>, bool)> {
    let escaped = term.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
    let pattern = format!("%{escaped}%");
    let mut stmt = conn.prepare(
        "SELECT mxid, nick FROM matrix_users
         WHERE nick IS NOT NULL AND LOWER(nick) LIKE LOWER(?1) ESCAPE '\\'
         ORDER BY LOWER(nick)
         LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![pattern, (limit as i64) + 1], |row| {
        Ok(NickHit { mxid: row.get(0)?, nick: row.get(1)? })
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
        assert!(set_nick(&conn, 2, "Alice_Nick").is_err());
        assert!(set_nick(&conn, 1, "bad nick").is_err());
    }
}
