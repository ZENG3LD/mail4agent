//! One-shot: open homeserver SQLCipher DB with M4A_DB_KEY_HEX and print
//! schema + nick/session inventory. Does not print bearer tokens or key material.
use std::env;
use mail4agent_server::store::open_messenger_db;

fn main() {
    let path = env::args().nth(1).expect("usage: dump_db <db-path>");
    let key = env::var("M4A_DB_KEY_HEX").expect("M4A_DB_KEY_HEX required");
    let db = open_messenger_db(&path, &key).unwrap_or_else(|e| {
        eprintln!("OPEN_FAILED: {e}");
        std::process::exit(2);
    });
    db.read_blocking(|conn| {
        dump(conn);
        Ok(())
    })
    .expect("dump");
}

fn dump(conn: &rusqlite::Connection) {
    println!("OPEN_OK");

    println!("=== sqlite_master ===");
    let mut stmt = conn
        .prepare("SELECT type, name FROM sqlite_master ORDER BY type, name")
        .unwrap();
    for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).unwrap() {
        let (t, n) = row.unwrap();
        println!("{t}\t{n}");
    }
    let tables = [
        "matrix_users",
        "messenger_sessions",
        "devices",
        "rooms",
        "room_members",
        "events",
        "to_device_messages",
        "device_keys",
        "one_time_keys",
        "stream_counter",
    ];
    for t in tables {
        let n: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0))
            .unwrap_or(-1);
        println!("COUNT {t}={n}");
    }
    println!("=== matrix_users ===");
    let mut stmt = conn
        .prepare("SELECT * FROM matrix_users")
        .unwrap();
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    println!("cols: {}", cols.join(", "));
    let mut rows = stmt.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let mut parts = Vec::new();
        for i in 0..cols.len() {
            let v: rusqlite::types::Value = row.get(i).unwrap();
            let s = match v {
                rusqlite::types::Value::Null => "NULL".into(),
                rusqlite::types::Value::Integer(i) => i.to_string(),
                rusqlite::types::Value::Real(f) => f.to_string(),
                rusqlite::types::Value::Text(t) => {
                    if cols[i].contains("token") || cols[i].contains("secret") || cols[i].contains("key") {
                        format!("<redacted len={}>", t.len())
                    } else {
                        t
                    }
                }
                rusqlite::types::Value::Blob(b) => format!("<blob {}b>", b.len()),
            };
            parts.push(format!("{}={}", cols[i], s));
        }
        println!("{}", parts.join(" | "));
    }
    println!("=== messenger_sessions ===");
    let mut stmt = conn.prepare("SELECT * FROM messenger_sessions").unwrap();
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    println!("cols: {}", cols.join(", "));
    let mut rows = stmt.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let mut parts = Vec::new();
        for i in 0..cols.len() {
            let v: rusqlite::types::Value = row.get(i).unwrap();
            let s = match v {
                rusqlite::types::Value::Null => "NULL".into(),
                rusqlite::types::Value::Integer(i) => i.to_string(),
                rusqlite::types::Value::Real(f) => f.to_string(),
                rusqlite::types::Value::Text(t) => {
                    if cols[i].contains("token") || cols[i].contains("secret") || cols[i].contains("hash") {
                        format!("<redacted len={}>", t.len())
                    } else {
                        t
                    }
                }
                rusqlite::types::Value::Blob(b) => format!("<blob {}b>", b.len()),
            };
            parts.push(format!("{}={}", cols[i], s));
        }
        println!("{}", parts.join(" | "));
    }
    println!("=== devices (device_id, user_id only) ===");
    let mut stmt = conn
        .prepare("SELECT user_id, device_id FROM devices ORDER BY user_id, device_id")
        .unwrap();
    for row in stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .unwrap()
    {
        let (u, d) = row.unwrap();
        println!("{u}\t{d}");
    }
    println!("=== rooms ===");
    let stmt = conn.prepare("SELECT room_id, room_version, is_direct FROM rooms").unwrap_or_else(|_| {
        conn.prepare("SELECT room_id FROM rooms").unwrap()
    });
    // fallback handled below via raw
    drop(stmt);
    let mut stmt = conn.prepare("SELECT * FROM rooms").unwrap();
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    println!("cols: {}", cols.join(", "));
    let mut rows = stmt.query([]).unwrap();
    let mut n = 0;
    while let Some(row) = rows.next().unwrap() {
        n += 1;
        if n > 40 {
            println!("... truncated");
            break;
        }
        let mut parts = Vec::new();
        for i in 0..cols.len() {
            let v: rusqlite::types::Value = row.get(i).unwrap();
            let s = match v {
                rusqlite::types::Value::Null => "NULL".into(),
                rusqlite::types::Value::Integer(i) => i.to_string(),
                rusqlite::types::Value::Real(f) => f.to_string(),
                rusqlite::types::Value::Text(t) => {
                    if t.len() > 120 { format!("{}…", &t[..120]) } else { t }
                }
                rusqlite::types::Value::Blob(b) => format!("<blob {}b>", b.len()),
            };
            parts.push(format!("{}={}", cols[i], s));
        }
        println!("{}", parts.join(" | "));
    }
}
