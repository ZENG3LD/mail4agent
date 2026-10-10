//! `m4a-agent enroll`: enroll one identity from the process environment, then exit.
//!
//! Required: `M4A_PRODUCT_URL` (or `M4A_HOMESERVER_URL`), `M4A_SESSION_ID`,
//! `M4A_STORE_ROOT`. The one-time invite is `M4A_PRODUCT_INVITE`, and only
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
        }
        Err(err) => {
            eprintln!("enroll failed: {err}");
            std::process::exit(1);
        }
    }
}
