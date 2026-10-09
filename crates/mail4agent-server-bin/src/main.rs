//! Loopback process for the messenger homeserver library.
//!
//! Sets the homeserver name once, opens a SQLCipher database under `/tmp`
//! with [`mail4agent_server::store::init_messenger_db`], mounts
//! [`mail4agent_server::http::router`], and accepts connections on
//! `127.0.0.1` only. The raw key is `M4A_DB_KEY_HEX` (even-length hex) from
//! the environment. It is not stored in the repo and not printed.
//!
//! Optional single-user bootstrap, all three variables together:
//! `M4A_BOOTSTRAP_PUBLIC_ID`, `M4A_BOOTSTRAP_NICK`, `M4A_BOOTSTRAP_TOKEN`.
//! The token is a bearer. Only [`mail4agent_server::http::hash_token`] is
//! written. There is no password, KDF, or vault.

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use mail4agent_server::http::{hash_token, router, Homeserver};
use mail4agent_server::keys::{self, CredentialKind};
use mail4agent_server::nick;
use mail4agent_server::store::{self, init_messenger_db};
use rusqlite::Connection;
use tokio::net::TcpListener;

const DEFAULT_BIND: &str = "127.0.0.1:8741";
const DEFAULT_DB: &str = "/tmp/mail4agent-server-bin.db";
const DEFAULT_SERVER_NAME: &str = "localhost";

struct Bootstrap {
    public_id: String,
    nick: String,
    token: String,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("mail4agent-server-bin: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut bind_raw = DEFAULT_BIND.to_string();
    let mut db_raw = DEFAULT_DB.to_string();
    let mut server_name = DEFAULT_SERVER_NAME.to_string();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => {
                bind_raw = args
                    .next()
                    .ok_or_else(|| "--bind needs 127.0.0.1:port".to_string())?;
            }
            "--db" => {
                db_raw = args
                    .next()
                    .ok_or_else(|| "--db needs an absolute path under /tmp".to_string())?;
            }
            "--server-name" => {
                server_name = args
                    .next()
                    .ok_or_else(|| "--server-name needs a hostname".to_string())?;
            }
            "--help" | "-h" => {
                println!(
                    "usage: mail4agent-server-bin [--bind 127.0.0.1:8741] [--db /tmp/mail4agent-server-bin.db] [--server-name localhost]\n\
                     required env: M4A_DB_KEY_HEX (even-length hex, not printed)\n\
                     optional bootstrap, all three or none: M4A_BOOTSTRAP_PUBLIC_ID M4A_BOOTSTRAP_NICK M4A_BOOTSTRAP_TOKEN"
                );
                return Ok(());
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }

    let bind = parse_loopback(&bind_raw)?;
    let db_path = db_under_tmp(Path::new(&db_raw))?;
    let key_hex =
        env::var("M4A_DB_KEY_HEX").map_err(|_| "M4A_DB_KEY_HEX is required".to_string())?;
    validate_key_hex(&key_hex)?;
    let bootstrap = read_bootstrap()?;

    let mut conn = open_messenger(&server_name, &db_path, &key_hex)?;
    if let Ok(names) = env::var("M4A_LOCAL_NAMES") {
        mail4agent_server::store::set_local_aliases(names.split(',').map(str::to_string));
    }
    run_boot_migrations(&mut conn)?;
    if let Some(boot) = &bootstrap {
        seed_user(&conn, boot)?;
        eprintln!("bootstrapped one local user");
    }
    let hs = Arc::new(Homeserver::new(conn));
    if let Ok(url) = env::var("M4A_PUBLIC_BASE_URL") {
        let _ = hs.public_base_url.set(url.trim_end_matches('/').to_string());
    }
    if let Ok(target) = env::var("M4A_FEDERATION_DELEGATE") {
        let _ = hs.federation_delegate.set(target);
    }
    spawn_retention(Arc::clone(&hs));
    let app = router(hs);

    let runtime = tokio::runtime::Runtime::new().map_err(|err| format!("runtime: {err}"))?;
    runtime.block_on(serve(bind, app))
}


fn run_boot_migrations(conn: &mut Connection) -> Result<(), String> {
    use mail4agent_server::rooms::{drop_legacy_dm_scaffold_if_empty, migrate_plaintext_rooms_to_encrypted};
    let now = Utc::now().to_rfc3339();
    let origin_ts = Utc::now().timestamp_millis();
    let n = migrate_plaintext_rooms_to_encrypted(conn, &now, origin_ts).map_err(|e| format!("{e:?}"))?;
    if n > 0 {
        eprintln!("migrated {n} plaintext room(s) to encrypted");
    }
    match drop_legacy_dm_scaffold_if_empty(conn) {
        Ok(true) => eprintln!("dropped empty legacy_dm_message_map"),
        Ok(false) => {}
        Err(err) => eprintln!("legacy_dm drop skipped: {err:?}"),
    }
    Ok(())
}

fn open_messenger(server_name: &str, db_path: &Path, key_hex: &str) -> Result<Connection, String> {
    store::set_matrix_server_name(server_name).map_err(|err| err.to_string())?;
    let path = db_path
        .to_str()
        .ok_or_else(|| "db path is not utf-8".to_string())?;
    init_messenger_db(path, key_hex).map_err(|err| format!("open db: {err}"))
}

async fn serve(bind: SocketAddr, app: axum::Router) -> Result<(), String> {
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|err| format!("bind {bind}: {err}"))?;
    let local = listener
        .local_addr()
        .map_err(|err| format!("local addr: {err}"))?;
    if !is_loopback(local) {
        return Err(format!("refusing to serve on {local}"));
    }
    println!("listening {local}");
    axum::serve(listener, app)
        .await
        .map_err(|err| format!("serve: {err}"))
}

fn is_loopback(addr: SocketAddr) -> bool {
    matches!(addr.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST)
}

fn parse_loopback(raw: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = raw
        .parse()
        .map_err(|_| format!("bind must be 127.0.0.1:port, got {raw}"))?;
    if !is_loopback(addr) {
        return Err("refusing non-loopback bind; only 127.0.0.1 is allowed".into());
    }
    Ok(addr)
}

fn db_under_tmp(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("db path must be an absolute path under /tmp".into());
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("db path must not contain ..".into());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| "db path needs a parent directory".to_string())?;
    let canon = parent
        .canonicalize()
        .map_err(|err| format!("db parent: {err}"))?;
    // Default root is /tmp; a durable deployment sets M4A_DB_ROOT to one absolute
    // directory (for example the systemd StateDirectory) and the DB must live there.
    let root = match env::var("M4A_DB_ROOT") {
        Ok(r) if Path::new(&r).is_absolute() && !r.contains("..") => PathBuf::from(r),
        Ok(_) => return Err("M4A_DB_ROOT must be an absolute path without ..".into()),
        Err(_) => PathBuf::from("/tmp"),
    };
    let root = root.canonicalize().map_err(|err| format!("db root: {err}"))?;
    if canon != root && !canon.starts_with(&root) {
        return Err(format!("db path must stay under {}", root.display()));
    }
    Ok(path.to_path_buf())
}

fn validate_key_hex(raw: &str) -> Result<(), String> {
    if raw.len() < 2 || raw.len() % 2 != 0 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("M4A_DB_KEY_HEX must be even-length hex".into());
    }
    Ok(())
}

fn read_bootstrap() -> Result<Option<Bootstrap>, String> {
    let public_id = env::var("M4A_BOOTSTRAP_PUBLIC_ID").ok();
    let nick_value = env::var("M4A_BOOTSTRAP_NICK").ok();
    let token = env::var("M4A_BOOTSTRAP_TOKEN").ok();
    match (public_id, nick_value, token) {
        (None, None, None) => Ok(None),
        (Some(public_id), Some(nick), Some(token)) => {
            if public_id.is_empty() || nick.is_empty() || token.is_empty() {
                return Err("bootstrap public id, nick, and token must be non-empty".into());
            }
            Ok(Some(Bootstrap {
                public_id,
                nick,
                token,
            }))
        }
        _ => Err(
            "set all of M4A_BOOTSTRAP_PUBLIC_ID, M4A_BOOTSTRAP_NICK, M4A_BOOTSTRAP_TOKEN, or none"
                .into(),
        ),
    }
}

fn seed_user(conn: &Connection, boot: &Bootstrap) -> Result<(), String> {
    let now = Utc::now().to_rfc3339();
    const USER_ID: i64 = 1;
    store::ensure_matrix_user(conn, USER_ID, &boot.public_id, &now)
        .map_err(|err| format!("user: {err:?}"))?;
    nick::set_nick(conn, USER_ID, &boot.nick).map_err(|err| format!("nick: {err:?}"))?;
    let hash = hash_token(&boot.token);
    match keys::device_for_credential(conn, CredentialKind::Bearer, &hash)
        .map_err(|err| format!("device lookup: {err}"))?
    {
        Some(device) if device.user_id == USER_ID => Ok(()),
        Some(_) => Err("bootstrap token already belongs to another user".into()),
        None => {
            keys::create_device(conn, USER_ID, CredentialKind::Bearer, &hash, &now)
                .map_err(|err| format!("device: {err}"))?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn random_key_hex() -> String {
        let mut bytes = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .expect("urandom")
            .read_exact(&mut bytes)
            .expect("urandom read");
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    struct TempDb(PathBuf);

    impl Drop for TempDb {
        fn drop(&mut self) {
            let path = self.0.display().to_string();
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(format!("{path}-wal"));
            let _ = std::fs::remove_file(format!("{path}-shm"));
        }
    }

    #[test]
    fn refuses_a_public_bind() {
        let err = parse_loopback("0.0.0.0:8741").unwrap_err();
        assert!(err.contains("127.0.0.1"), "{err}");
        assert!(parse_loopback("127.0.0.1:8741").is_ok());
    }

    #[tokio::test]
    async fn sync_on_loopback_returns_next_batch() {
        let db = TempDb(PathBuf::from(format!(
            "/tmp/mail4agent-server-bin-test-{}.db",
            std::process::id()
        )));
        let conn = open_messenger("localhost", &db.0, &random_key_hex()).expect("open");
        let token = "fake-sync-token";
        seed_user(
            &conn,
            &Bootstrap {
                public_id: "syncuser".to_string(),
                nick: "sync_user".to_string(),
                token: token.to_string(),
            },
        )
        .expect("seed");
        let app = router(Arc::new(Homeserver::new(conn)));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        assert!(is_loopback(addr), "{addr}");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let request = format!(
            "GET /client/v3/sync?timeout=0 HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.expect("write");
        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut buf),
        )
        .await
        .expect("sync timed out")
        .expect("read");
        let body = String::from_utf8_lossy(&buf);
        println!("listening {addr}");
        println!("sync {body}");
        assert!(body.contains("HTTP/1.1 200"), "{body}");
        assert!(body.contains("\"next_batch\""), "{body}");
    }
}


/// Delivery-window retention: delete events every live device acked, TTL as a
/// safety net. `M4A_RETENTION=off` disables; `M4A_EVENT_TTL_DAYS` (default 14).
fn spawn_retention(hs: Arc<Homeserver>) {
    use mail4agent_server::retention::{purge_delivered_events, RetentionPolicy};
    if env::var("M4A_RETENTION").map(|v| v.eq_ignore_ascii_case("off")).unwrap_or(false) {
        eprintln!("retention: disabled");
        return;
    }
    let mut policy = RetentionPolicy::default();
    if let Some(days) = env::var("M4A_EVENT_TTL_DAYS").ok().and_then(|v| v.parse::<i64>().ok()).filter(|d| *d > 0) {
        policy.ttl_ms = days * 86_400_000;
    }
    eprintln!("retention: on, ttl {} days", policy.ttl_ms / 86_400_000);
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(600));
        let now_ms = Utc::now().timestamp_millis();
        let mut conn = hs.conn.lock().unwrap_or_else(|e| e.into_inner());
        match purge_delivered_events(&mut conn, now_ms, &policy) {
            Ok(0) => {}
            Ok(n) => eprintln!("retention: removed {n} delivered event(s)"),
            Err(err) => eprintln!("retention: skipped: {err}"),
        }
    });
}
