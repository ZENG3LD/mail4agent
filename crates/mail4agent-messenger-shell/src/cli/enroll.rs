//! `m4a-agent enroll`: enroll one identity from the process environment, then exit.
//!
//! Required: `M4A_PRODUCT_URL` (or `M4A_HOMESERVER_URL`), `M4A_SESSION_ID`,
//! `M4A_STORE_ROOT`. Optional `M4A_BOT_NAME` (the name the nick is asked from). The one-time invite is `M4A_PRODUCT_INVITE`, and only
//! until this identity is enrolled. `M4A_TIER` is `server` (the default) or
//! `matrix`. This command does not read an agents directory, a gateway file,
//! or an env file. It prints the nick.

use crate::OpenedStore;

pub fn run(args: Vec<String>) {
    if !args.is_empty() {
        eprintln!("usage: m4a-agent enroll");
        std::process::exit(64);
    }
    match OpenedStore::connect_from_env() {
        Ok(store) => {
            println!("enrolled nick={}", store.nick().unwrap_or("(unknown)"));
            // A per-session account (its own store root under the accounts base) is now enrolled.
            if let Some(root) = std::env::var_os(crate::STORE_ROOT_ENV).map(std::path::PathBuf::from) {
                if let Err(err) = crate::session_account::mark_enrolled(&root) {
                    eprintln!("enroll: account state not updated: {err}");
                }
            }
        }
        Err(err) => {
            eprintln!("enroll failed: {err}");
            std::process::exit(1);
        }
    }
}
