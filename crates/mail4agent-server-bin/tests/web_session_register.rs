//! Two Grok Bot web sessions register themselves on loopback and one finds
//! the other by the nick derived from the bot display name. Neither is
//! handed the other's bearer or a routine URL.

use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mail4agent_messenger_shell::{session_store_dir, OpenedStore, SessionConfig};

struct StopServer(Option<Child>);

impl Drop for StopServer {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct TempDb {
    dir: PathBuf,
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let db = self.dir.join("messenger.db");
        let path = db.display().to_string();
        let _ = std::fs::remove_file(&db);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn random_key_hex() -> String {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .expect("urandom")
        .read_exact(&mut bytes)
        .expect("urandom read");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn server_bin() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_mail4agent_server_bin") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    let exe = std::env::current_exe().expect("test executable");
    let mut path = exe
        .parent()
        .and_then(|dir| dir.parent())
        .expect("target profile dir")
        .to_path_buf();
    path.push("mail4agent-server-bin");
    assert!(path.is_file(), "mail4agent-server-bin was not built");
    path
}

fn wait_until_accepts(addr: &str) {
    let start = Instant::now();
    loop {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        if start.elapsed() > Duration::from_secs(15) {
            panic!("server did not accept {addr}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn bearer_is_absent(dir: &std::path::Path, secret: &str) -> bool {
    if secret.is_empty() || !dir.exists() {
        return false;
    }
    let needle = secret.as_bytes();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = match std::fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(_) => return false,
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                return false;
            };
            if bytes.windows(needle.len()).any(|window| window == needle) {
                return false;
            }
        }
    }
    true
}

#[test]
fn two_web_sessions_register_and_one_finds_the_other_by_nick() {
    let temp = TempDb {
        dir: PathBuf::from(format!(
            "/tmp/mail4agent-web-reg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis()
        )),
    };
    std::fs::create_dir_all(&temp.dir).expect("tmpdir");
    let db = temp.dir.join("messenger.db");
    let key_hex = random_key_hex();
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
    let port = probe.local_addr().expect("addr").port();
    drop(probe);
    let addr = format!("127.0.0.1:{port}");
    let base = format!("http://{addr}");

    let child = Command::new(server_bin())
        .args([
            "--bind",
            &addr,
            "--db",
            db.to_str().expect("utf-8"),
            "--server-name",
            "localhost",
        ])
        .env("M4A_DB_KEY_HEX", &key_hex)
        .env_remove("M4A_BOOTSTRAP_PUBLIC_ID")
        .env_remove("M4A_BOOTSTRAP_NICK")
        .env_remove("M4A_BOOTSTRAP_TOKEN")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");
    let mut server = StopServer(Some(child));
    wait_until_accepts(&addr);

    let root = temp.dir.join("stores");
    std::fs::create_dir_all(&root).expect("store root");
    let hostbot_cfg = SessionConfig::new(&base, "Hostbot", "web-hostbot", &root, None)
        .expect("hostbot config");
    let chief_cfg = SessionConfig::new(&base, "Привет мир", "web-chief", &root, None)
        .expect("chief config");
    assert_eq!(hostbot_cfg.nick(), "hostbot");
    assert_eq!(chief_cfg.nick(), "privet_mir");
    assert_ne!(chief_cfg.nick(), "nachshtab");
    let hostbot_dir = hostbot_cfg.store_dir();
    let chief_dir = chief_cfg.store_dir();
    assert_eq!(hostbot_dir, session_store_dir(&root, "web-hostbot"));
    assert_eq!(chief_dir, session_store_dir(&root, "web-chief"));
    assert_ne!(hostbot_dir, chief_dir);

    let mut hostbot = OpenedStore::connect(&hostbot_cfg).expect("hostbot connect");
    let mut chief = OpenedStore::connect(&chief_cfg).expect("chief connect");
    assert_eq!(hostbot.nick(), Some("hostbot"));
    assert_eq!(chief.nick(), Some("privet_mir"));
    assert!(
        bearer_is_absent(&hostbot_dir, hostbot.device_bearer()),
        "hostbot bearer was written under the store"
    );
    assert!(
        bearer_is_absent(&chief_dir, chief.device_bearer()),
        "chief bearer was written under the store"
    );

    let found = hostbot
        .find_nick("Привет мир", 3_000)
        .expect("hostbot finds the chief by display name");
    assert_eq!(found.nick, "privet_mir");
    assert_eq!(found.user_id, "@privet_mir:localhost");
    let found = chief
        .find_nick("hostbot", 4_000)
        .expect("chief finds hostbot by nick");
    assert_eq!(found.nick, "hostbot");
    assert_eq!(found.user_id, "@hostbot:localhost");

    let hostbot_bearer = hostbot.device_bearer().to_string();
    drop(hostbot);
    drop(chief);
    assert!(
        OpenedStore::connect(&hostbot_cfg).is_err(),
        "reopen without the keychain bearer must fail"
    );
    let mut hostbot = OpenedStore::connect(
        &SessionConfig::new(
            &base,
            "Hostbot",
            "web-hostbot",
            &root,
            Some(hostbot_bearer),
        )
        .expect("reopen config"),
    )
    .expect("same session reopens");
    assert_eq!(hostbot.nick(), Some("hostbot"));
    let found = hostbot
        .find_nick("privet_mir", 5_000)
        .expect("reopened session still finds the chief by nick");
    assert_eq!(found.user_id, "@privet_mir:localhost");
    assert!(bearer_is_absent(&hostbot_dir, hostbot.device_bearer()));

    if let Some(child) = server.0.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    server.0 = None;
}
