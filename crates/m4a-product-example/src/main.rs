//! Example product server. Configuration is environment only:
//!
//! * `M4A_PRODUCT_BIND` (default `127.0.0.1:8080`), `M4A_PRODUCT_DB` (required, SQLCipher file path),
//!   `M4A_PRODUCT_DB_KEY_HEX` (required: even-length hex, at least 32 characters; never logged)
//! * `M4A_PRODUCT_EDGE_URL` (required: messenger edge on the private link)
//! * `M4A_ASSERTION_SECRET` (required, >= 16 chars; must equal the core's), optional
//!   `M4A_ASSERTION_HEADER`, `M4A_EVENT_SIG_HEADER`
//! * `M4A_PRODUCT_OUTBOX_DB` (event queue file, default the product database; `M4A_PRODUCT_OUTBOX_DB_KEY_HEX` its key, default the product key), `M4A_PRODUCT_RECONCILE=off` (skip the startup snapshot), `M4A_PRODUCT_ANON_READ=on`
//! * `M4A_LINK_TOKEN` (optional barrier token presented to the edge/core; must equal theirs)
//! * `M4A_PRODUCT_ADMIN_TOKEN` (optional; enables `/product/v1/admin/*`)
//! * `M4A_PRODUCT_TIERS` (`free=0,paid=1`), `M4A_PRODUCT_NICK_LISTS`, `M4A_PRODUCT_NICK_COOLDOWN_DAYS`
//! * `M4A_PRODUCT_LOGIN_MATRIX=1` with `M4A_PRODUCT_LOCAL_NAMES` (comma list of own server names)
//!   and optional `M4A_PRODUCT_PEER_OVERRIDE` (`name=base,...`): Matrix-address door.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use m4a_product_example::{router, ProductApp, SqliteStore};
use m4a_product_kit::dbkey::DbKey;
use m4a_product_kit::door::LoginDoor;
use m4a_product_kit::nick_rules::NickRules;
use m4a_product_kit::tiers::TierTable;
use m4a_product_kit::{send_reconcile, EdgeLink, EventPublisher, SqliteOutbox, UserService};

fn req(name: &str) -> Result<String, String> {
    env::var(name).ok().filter(|v| !v.is_empty()).ok_or_else(|| format!("{name} is required"))
}

fn opt(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

async fn run() -> Result<(), String> {
    let bind = opt("M4A_PRODUCT_BIND").unwrap_or_else(|| "127.0.0.1:8080".into());
    let secret = req("M4A_ASSERTION_SECRET")?;
    if secret.len() < 16 {
        return Err("M4A_ASSERTION_SECRET must be at least 16 characters".into());
    }
    let db_path = req("M4A_PRODUCT_DB")?;
    let db_key = DbKey::from_env("M4A_PRODUCT_DB_KEY_HEX")?;
    let store = Arc::new(SqliteStore::open_path(&db_path, &db_key).map_err(|e| format!("M4A_PRODUCT_DB (wrong key or not an encrypted database?): {e}"))?);
    let link = EdgeLink::new(&req("M4A_PRODUCT_EDGE_URL")?, secret.into_bytes(), opt("M4A_ASSERTION_HEADER")).with_link_token(opt("M4A_LINK_TOKEN"));
    // Durable queue: events survive a restart of this process (own file, or the product database file).
    let outbox = Arc::new(SqliteOutbox::open(&opt("M4A_PRODUCT_OUTBOX_DB").unwrap_or(db_path.clone()), &match opt("M4A_PRODUCT_OUTBOX_DB_KEY_HEX") { Some(_) => DbKey::from_env("M4A_PRODUCT_OUTBOX_DB_KEY_HEX")?, None => db_key.clone() }).map_err(|e| format!("event outbox: {e}"))?);
    let events = EventPublisher::spawn_with(link.clone(), opt("M4A_EVENT_SIG_HEADER"), Duration::from_secs(1), outbox);
    let mut doors: Vec<Arc<dyn LoginDoor>> = Vec::new();
    #[cfg(feature = "matrix-address-door")]
    if matches!(env::var("M4A_PRODUCT_LOGIN_MATRIX").as_deref(), Ok("1") | Ok("true")) {
        use m4a_product_kit::door::{HttpUserinfo, MatrixAddressDoor};
        let names: Vec<String> = opt("M4A_PRODUCT_LOCAL_NAMES").unwrap_or_default().split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        if names.is_empty() {
            return Err("M4A_PRODUCT_LOGIN_MATRIX needs M4A_PRODUCT_LOCAL_NAMES (own server names, refused as subjects)".into());
        }
        let ui = HttpUserinfo::new().with_overrides(&opt("M4A_PRODUCT_PEER_OVERRIDE").unwrap_or_default());
        doors.push(Arc::new(MatrixAddressDoor::new(Arc::new(ui), names)));
    }
    let app = Arc::new(ProductApp {
        users: UserService::new(store, NickRules::from_env()?, TierTable::from_env()?),
        link,
        events,
        admin_token: opt("M4A_PRODUCT_ADMIN_TOKEN").unwrap_or_default(),
        doors,
        anon_read: opt("M4A_PRODUCT_ANON_READ").is_some_and(|v| v.eq_ignore_ascii_case("on")),
    });
    // Startup reconciliation: tell the messenger which credentials are live, so revocations and
    // deletions it missed (outbox lost, messenger restored from a backup) are applied.
    if !opt("M4A_PRODUCT_RECONCILE").is_some_and(|v| v.eq_ignore_ascii_case("off")) {
        let (app, link, hdr) = (Arc::clone(&app), app.link.clone(), opt("M4A_EVENT_SIG_HEADER"));
        tokio::spawn(async move {
            match app.users.reconcile_snapshots(2000) {
                Ok(snaps) => {
                    for snap in snaps {
                        if let Err(e) = send_reconcile(&link, hdr.clone(), &snap, Duration::from_secs(1), 12).await {
                            tracing::error!(error = %e, "startup reconcile failed");
                            return;
                        }
                    }
                    tracing::info!("startup reconcile delivered");
                }
                Err(e) => tracing::error!(error = ?e, "startup reconcile: cannot read credentials"),
            }
        });
    }
    let listener = tokio::net::TcpListener::bind(&bind).await.map_err(|e| format!("bind {bind}: {e}"))?;
    eprintln!("m4a-product-example listening on {bind}");
    axum::serve(listener, router(app)).with_graceful_shutdown(async { let _ = tokio::signal::ctrl_c().await; }).await.map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("m4a-product-example: {e}");
        std::process::exit(2);
    }
}
