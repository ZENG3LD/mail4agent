//! mail4agent daemon entrypoint.
//!
//! Boot sequence, deliberately split across two phases:
//!
//! 1. **Outside any tokio runtime** (plain `fn main`): load config, open
//!    the sqlite [`mail4agent_store_sqlite::Db`], and run this crate's
//!    schema migrations via [`mail4agent_store_sqlite::Db::run_migrations_blocking`]
//!    -- the daemon is outside the runtime at that point, so the blocking
//!    entry point is the correct one, rather than relying on `try_lock()`'s
//!    non-panicking behaviour inside an already-running one.
//! 2. **Inside a manually-built tokio runtime**: bootstrap the first
//!    operator participant if none exists yet, then serve.
//!
//! The engine and its store stay synchronous throughout (see `service.rs`
//! for the async facade every handler goes through instead of touching
//! either directly -- `mail4agent/CLAUDE.md`, "The engine is synchronous;
//! the daemon is not"). Every `/mail/*` and `/mcp` handler additionally
//! resolves which SESSION of the authenticated account is calling, from
//! the connection itself (`src/identity.rs`) -- that resolution needs this
//! server's own bound address, which is why `serve` builds one
//! [`AppState`] shared by every route rather than handing each route a
//! bare `Arc<MailboxService>`.
//!
//! Serves via `into_make_service_with_connect_info::<SocketAddr>()`, never
//! plain `into_make_service()` -- the latter never inserts a
//! `ConnectInfo<SocketAddr>` extension, which is exactly the fact
//! `src/identity.rs`'s whole session-resolution mechanism depends on.

mod auth;
mod bootstrap;
mod config;
mod dto;
mod error;
mod health;
mod identity;
mod request_id;
mod routes;
mod service;
mod shutdown;
mod state;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::middleware;
use axum::routing::{get, post};
use axum::Router;

use config::{Config, ConfigError};
use mail4agent_store_sqlite::{migrations, Db, DbConfig, DbError, MigrationRunner, SqliteMailStore};
use service::MailboxService;
use state::AppState;

#[derive(Debug, thiserror::Error)]
enum MainError {
    #[error("config: {0}")]
    Config(#[from] ConfigError),
    #[error("database: {0}")]
    Db(#[from] DbError),
    #[error("build tokio runtime: {0}")]
    Runtime(std::io::Error),
    #[error("bootstrap: {0}")]
    Bootstrap(#[from] bootstrap::BootstrapError),
    #[error("bind {0}: {1}")]
    Bind(SocketAddr, std::io::Error),
    #[error("serve: {0}")]
    Serve(std::io::Error),
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

    let db_config = DbConfig::new(db_path);
    let db = Db::open(&db_config)?;
    db.run_migrations_blocking(MigrationRunner::new(migrations()))?;

    // Two handles over the SAME connection -- see `service.rs`'s module
    // doc comment for why the facade needs both.
    let engine_store = SqliteMailStore::new(db.clone());
    let reader_store = SqliteMailStore::new(db);
    let service = Arc::new(MailboxService::new(engine_store, reader_store));

    let runtime = tokio::runtime::Runtime::new().map_err(MainError::Runtime)?;
    runtime.block_on(serve(service, config.bind))
}

async fn serve(service: Arc<MailboxService>, bind: SocketAddr) -> Result<(), MainError> {
    bootstrap::ensure_bootstrap_operator(&service).await?;

    let app = Arc::new(AppState { service: service.clone(), bind_addr: bind });

    // `/mail/*` and `/mcp` -- every one of these derives the caller from
    // the presented credential; none of them accepts a sender.
    let authenticated_guard =
        auth::TierGuard { service: service.clone(), required: auth::Tier::Authenticated };
    let authenticated_router = Router::new()
        .route("/mail/send", post(routes::mail::send))
        .route("/mail/inbox", post(routes::mail::inbox))
        .route("/mail/ack", post(routes::mail::ack))
        .route("/mail/get", post(routes::mail::get))
        .route("/mail/unread", post(routes::mail::unread))
        .route("/mail/whoami", post(routes::mail::whoami))
        .route("/mail/status", post(routes::mail::status))
        .route("/mail/directory", post(routes::mail::directory))
        // MCP door onto the same mail surface -- `mail4agent/CLAUDE.md`,
        // "one implementation, two doors". Same tier as `/mail/*`: an
        // operator calling a mail tool is just a participant.
        .route("/mcp", post(routes::mcp::handle_mcp_post).delete(routes::mcp::handle_mcp_delete))
        .route_layer(middleware::from_fn_with_state(authenticated_guard, auth::require_tier))
        .with_state(app.clone());

    // `/admin/*` -- the operator-only registry surface.
    let admin_guard = auth::TierGuard { service: service.clone(), required: auth::Tier::Admin };
    let admin_router = Router::new()
        .route("/admin/participant", post(routes::admin::register_participant))
        .route("/admin/participant/rotate", post(routes::admin::rotate_participant))
        .route("/admin/participant/remove", post(routes::admin::remove_participant))
        .route("/admin/room", post(routes::admin::create_room))
        .route("/admin/room/member/add", post(routes::admin::add_room_member))
        .route("/admin/room/member/remove", post(routes::admin::remove_room_member))
        .route("/admin/listener", post(routes::admin::set_listener))
        .route("/admin/listener/remove", post(routes::admin::remove_listener))
        .route_layer(middleware::from_fn_with_state(admin_guard, auth::require_tier))
        .with_state(app.clone());

    // `GET /health` -- the only route without authentication, mounted
    // outside every gated router entirely.
    let health_state = Arc::new(health::HealthState::new("mail4agent", env!("CARGO_PKG_VERSION")));
    let health_router = Router::new().route(
        "/health",
        get(move || {
            let health_state = health_state.clone();
            async move { health::handle(health_state).await }
        }),
    );

    let router = Router::new()
        .merge(authenticated_router)
        .merge(admin_router)
        .merge(health_router)
        .layer(middleware::from_fn(request_id::request_id_layer));

    let listener = tokio::net::TcpListener::bind(bind).await.map_err(|e| MainError::Bind(bind, e))?;
    tracing::info!(addr = %bind, "mail4agent listening");

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let serve_handle = tokio::spawn(async move {
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.changed().await;
            })
            .await
    });

    shutdown::graceful_shutdown_signal().await;
    tracing::info!("shutdown signal received");
    let _ = shutdown_tx.send(true);

    match tokio::time::timeout(Duration::from_secs(30), serve_handle).await {
        Ok(Ok(Ok(()))) => tracing::info!("mail4agent stopped"),
        Ok(Ok(Err(err))) => return Err(MainError::Serve(err)),
        Ok(Err(join_err)) => tracing::error!(error = %join_err, "serve task panicked"),
        Err(_) => tracing::warn!("shutdown drain exceeded 30s -- exiting anyway"),
    }
    Ok(())
}
