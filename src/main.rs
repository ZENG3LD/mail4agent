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
mod registration;
mod request_id;
mod routes;
mod service;
mod shutdown;
mod state;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::middleware;
use axum::Router;
use nemo_service::register;
use nemo_service::router::{DocRouter, RouteDoc};

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

    // `GET /health` -- the only route without authentication.
    let health_state = Arc::new(health::HealthState::new("mail4agent", env!("CARGO_PKG_VERSION")));
    let (health_router, health_endpoints) = DocRouter::<Arc<AppState>>::new()
        .get(
            "/health",
            move || {
                let health_state = health_state.clone();
                async move { health::handle(health_state).await }
            },
            RouteDoc::new(
                "Liveness, service name, version and uptime: {\"ok\":true,\"service\":\"mail4agent\",\"version\":...,\"started_at\":...,\"uptime_secs\":...,\"dependencies\":[],\"background_tasks\":[]}. The watchdog only reads the status code.",
            )
            .public(),
        )
        .into_parts();

    // `/mail/*` -- every one of these derives the caller from the
    // presented credential; none of them accepts a sender.
    let (mail_router, mail_endpoints) = DocRouter::<Arc<AppState>>::new()
        .post(
            "/mail/send",
            routes::mail::send,
            RouteDoc::bearer("Send a message to a participant or a room. The sender is derived from the credential and cannot be supplied. Returns the new message id and the sender's own address."),
        )
        .post(
            "/mail/inbox",
            routes::mail::inbox,
            RouteDoc::bearer("Read messages addressed to the caller directly, plus messages to rooms the caller currently belongs to. Takes since_unix_ms and limit, plus wait_secs: long-polls (clamped to 60s, never refused for asking longer) when the inbox would otherwise answer empty, returning an empty page rather than an error on expiry."),
        )
        .post("/mail/ack", routes::mail::ack, RouteDoc::bearer("Acknowledge one message the caller may read. Idempotent per (message, reader)."))
        .post("/mail/get", routes::mail::get, RouteDoc::bearer("Read one message by id, if the caller may read it."))
        .post(
            "/mail/unread",
            routes::mail::unread,
            RouteDoc::bearer("Unread count for the caller, or for another participant when the caller is an operator."),
        )
        .post(
            "/mail/whoami",
            routes::mail::whoami,
            RouteDoc::bearer("The caller's own SESSION address (resolved from the connection, never declared), its account's label, room memberships, and its own card -- attested (kernel), corroborated (its own command line) and declared (its own claims) kept apart."),
        )
        .post(
            "/mail/status",
            routes::mail::status,
            RouteDoc::bearer("The session declares what it is working on, its role, and which session spawned it. The only writer of that group; recorded as the session's own claim, never verified."),
        )
        .post(
            "/mail/directory",
            routes::mail::directory,
            RouteDoc::bearer("Every registered account (id, label) with its live sessions nested under it (card, whether it is live), and every room the mailbox tracks (id, whether the caller is a member). Never returns a secret digest."),
        )
        .into_parts();

    // MCP door onto the same mail surface -- `mail4agent/CLAUDE.md`, "one
    // implementation, two doors". Same tier as `/mail/*`: an operator
    // calling a mail tool is just a participant. `resolve_caller_middleware`
    // is mounted INSIDE this router (see `routes::mcp`'s own doc comment)
    // so `auth::require_tier`, applied below to the merged authenticated
    // router, still runs first on every call.
    let mcp_server = routes::mcp::build();
    let mcp_endpoints = mcp_server.route_docs();
    let mcp_router: Router<Arc<AppState>> = mcp_server
        .into_router()
        .route_layer(middleware::from_fn_with_state(app.clone(), routes::mcp::resolve_caller_middleware));

    let authenticated_guard =
        auth::TierGuard { service: service.clone(), required: auth::Tier::Authenticated };
    let authenticated_router: Router<Arc<AppState>> = mail_router
        .merge(mcp_router)
        .route_layer(middleware::from_fn_with_state(authenticated_guard, auth::require_tier));

    // `/admin/*` -- the operator-only registry surface.
    let (admin_router, admin_endpoints) = DocRouter::<Arc<AppState>>::new()
        .post(
            "/admin/participant",
            routes::admin::register_participant,
            RouteDoc::bearer("Register a participant and return its secret ONCE. Only the digest is kept. Operator only."),
        )
        .post(
            "/admin/participant/rotate",
            routes::admin::rotate_participant,
            RouteDoc::bearer("Issue a new secret for a participant and invalidate the old one. Operator only."),
        )
        .post(
            "/admin/participant/remove",
            routes::admin::remove_participant,
            RouteDoc::bearer("Deregister a participant. Its messages are kept; it can no longer authenticate. Operator only."),
        )
        .post("/admin/room", routes::admin::create_room, RouteDoc::bearer("Create a room. Operator only."))
        .post(
            "/admin/room/member/add",
            routes::admin::add_room_member,
            RouteDoc::bearer("Add a participant to a room, which is what grants it read access to that room. Operator only."),
        )
        .post(
            "/admin/room/member/remove",
            routes::admin::remove_room_member,
            RouteDoc::bearer("Remove a participant from a room. It stops reading that room from then on. Operator only."),
        )
        .post(
            "/admin/listener",
            routes::admin::set_listener,
            RouteDoc::bearer("Register (or replace) the URL the mailbox POSTs a delivery notification to when mail arrives for an account or any of its sessions. Loopback only. Never carries the subject or body. Best-effort. Operator only."),
        )
        .post(
            "/admin/listener/remove",
            routes::admin::remove_listener,
            RouteDoc::bearer("Remove an account's registered delivery listener, if any. Idempotent. Operator only."),
        )
        .into_parts();
    let admin_guard = auth::TierGuard { service: service.clone(), required: auth::Tier::Admin };
    let admin_router: Router<Arc<AppState>> =
        admin_router.route_layer(middleware::from_fn_with_state(admin_guard, auth::require_tier));

    let mut endpoints = health_endpoints;
    endpoints.extend(mail_endpoints);
    endpoints.extend(mcp_endpoints);
    endpoints.extend(admin_endpoints);

    let router = health_router
        .merge(authenticated_router)
        .merge(admin_router)
        .with_state(app.clone())
        .layer(middleware::from_fn(request_id::request_id_layer));

    let listener = tokio::net::TcpListener::bind(bind).await.map_err(|e| MainError::Bind(bind, e))?;
    tracing::info!(addr = %bind, "mail4agent listening");

    // Self-registration (`nemo-service/CLAUDE.md`'s contract: this can
    // never fail or delay startup) -- fire-and-forget, once the socket is
    // live.
    let _reassert = register::spawn(registration::service_manifest(endpoints, bind.port()), register::DEFAULT_REASSERT_INTERVAL);

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
