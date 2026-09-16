//! mail4agent daemon entrypoint.
//!
//! Boot sequence, deliberately split across two phases:
//!
//! 1. **Outside any tokio runtime** (plain `fn main`): load config, open
//!    the sqlite [`stk::Db`], and run this crate's schema migrations via
//!    [`stk::Db::run_migrations_blocking`] -- the crate contract's own
//!    words for why: "the daemon is outside the runtime at that point, so
//!    `run_migrations_blocking` is the correct one" (`mail4agent/CLAUDE.md`,
//!    "Wire it with `Server::builder()`"). Doing this before a runtime
//!    exists at all, rather than relying on `try_lock()`'s non-panicking
//!    behaviour inside an already-running one, keeps that discipline
//!    literal rather than load-bearing on an implementation detail of
//!    `tokio::sync::Mutex`.
//! 2. **Inside a manually-built tokio runtime**: bootstrap the first
//!    operator participant if none exists yet, then hand everything to
//!    `stk::Server::builder()`.
//!
//! The engine and its store stay synchronous throughout (see `service.rs`
//! for the async facade every handler goes through instead of touching
//! either directly -- `mail4agent/CLAUDE.md`, "The engine is synchronous;
//! the daemon is not").

mod auth;
mod bootstrap;
mod config;
mod dto;
mod error;
mod routes;
mod service;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::{delete, post};
use config::{Config, ConfigError};
use service::MailboxService;
use stk::{AuthChain, Server, TokenTier};

#[derive(Debug, thiserror::Error)]
enum MainError {
    #[error("config: {0}")]
    Config(#[from] ConfigError),
    #[error("database: {0}")]
    Db(#[from] stk::DbError),
    #[error("build tokio runtime: {0}")]
    Runtime(std::io::Error),
    #[error("bootstrap: {0}")]
    Bootstrap(#[from] bootstrap::BootstrapError),
    #[error("build server: {0}")]
    Build(#[from] stk::BuildError),
    #[error("run server: {0}")]
    Run(#[from] stk::RunError),
}

fn main() -> Result<(), MainError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::load()?;
    let db_path = config.resolve_db_path()?;
    tracing::info!(db = %db_path.display(), bind = %config.bind, "mail4agent starting");

    let db_config = stk::DbConfig::new(db_path);
    let db = stk::Db::open(&db_config)?;
    db.run_migrations_blocking(stk::MigrationRunner::new(mail4agent_store_stk::migrations()))?;

    // Two handles over the SAME connection -- see `service.rs`'s module
    // doc comment for why the facade needs both.
    let engine_store = mail4agent_store_stk::SqliteMailStore::new(db.clone());
    let reader_store = mail4agent_store_stk::SqliteMailStore::new(db);
    let service = Arc::new(MailboxService::new(engine_store, reader_store));

    let runtime = tokio::runtime::Runtime::new().map_err(MainError::Runtime)?;
    runtime.block_on(serve(service, config.bind))
}

async fn serve(service: Arc<MailboxService>, bind: SocketAddr) -> Result<(), MainError> {
    bootstrap::ensure_bootstrap_operator(&service).await?;

    let mailbox_auth = auth::MailboxAuth::new(service.clone());

    let server = Server::builder()
        .name("mail4agent")
        .with_service_kind("http_api")
        .with_version(env!("CARGO_PKG_VERSION"))
        .bind(bind.to_string())
        .with_auth_chain(AuthChain::new().layer(mailbox_auth))
        .post_tier(
            "/mail/send",
            post(routes::mail::send).with_state(service.clone()),
            TokenTier::Authenticated,
        )
        .post_tier(
            "/mail/inbox",
            post(routes::mail::inbox).with_state(service.clone()),
            TokenTier::Authenticated,
        )
        .post_tier(
            "/mail/ack",
            post(routes::mail::ack).with_state(service.clone()),
            TokenTier::Authenticated,
        )
        .post_tier(
            "/mail/get",
            post(routes::mail::get).with_state(service.clone()),
            TokenTier::Authenticated,
        )
        .post_tier(
            "/mail/unread",
            post(routes::mail::unread).with_state(service.clone()),
            TokenTier::Authenticated,
        )
        .post_tier(
            "/mail/whoami",
            post(routes::mail::whoami).with_state(service.clone()),
            TokenTier::Authenticated,
        )
        .post_tier(
            "/mail/directory",
            post(routes::mail::directory).with_state(service.clone()),
            TokenTier::Authenticated,
        )
        // MCP door onto the same mail surface -- `mail4agent/CLAUDE.md`,
        // "one implementation, two doors". Same tier as `/mail/*`: an
        // operator calling a mail tool is just a participant.
        .post_tier(
            "/mcp",
            post(routes::mcp::handle_mcp_post).with_state(service.clone()),
            TokenTier::Authenticated,
        )
        .delete_tier("/mcp", delete(routes::mcp::handle_mcp_delete), TokenTier::Authenticated)
        .post_tier(
            "/admin/participant",
            post(routes::admin::register_participant).with_state(service.clone()),
            TokenTier::Admin,
        )
        .post_tier(
            "/admin/participant/rotate",
            post(routes::admin::rotate_participant).with_state(service.clone()),
            TokenTier::Admin,
        )
        .post_tier(
            "/admin/participant/remove",
            post(routes::admin::remove_participant).with_state(service.clone()),
            TokenTier::Admin,
        )
        .post_tier(
            "/admin/room",
            post(routes::admin::create_room).with_state(service.clone()),
            TokenTier::Admin,
        )
        .post_tier(
            "/admin/room/member/add",
            post(routes::admin::add_room_member).with_state(service.clone()),
            TokenTier::Admin,
        )
        .post_tier(
            "/admin/room/member/remove",
            post(routes::admin::remove_room_member).with_state(service.clone()),
            TokenTier::Admin,
        )
        // `GET /health` is the framework's own built-in route (always
        // mounted; a user route at the same path would panic the router at
        // build time on the overlapping method). `.with_detail_health()`
        // is the closest available fit to the crate contract's requested
        // `{"status":"ok","version":<crate version>}`: stk's shape is
        // `{"ok":true,"service":...,"version":...,"uptime_s":...,
        // "dependencies":[],"background_tasks":[]}` -- `ok` rather than
        // `status`, but it is the version-carrying health shape every
        // other stk daemon in this workspace already answers with. See
        // the handoff note on this exact mismatch.
        .with_detail_health()
        .with_manifest_auto()
        .with_request_id()
        .with_shutdown_timeout(Duration::from_secs(30))
        .build()
        .await?;

    server.run().await?;
    Ok(())
}
