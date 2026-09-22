//! [`graceful_shutdown_signal`] -- resolves on Ctrl-C / SIGTERM / SIGINT.
//!
//! - Unix: SIGINT or SIGTERM.
//! - Windows (and any other non-unix target): `tokio::signal::ctrl_c()`.
//!
//! `src/main.rs` awaits this, then gives the running server up to 30
//! seconds to drain in-flight requests before it stops waiting -- the same
//! graceful-shutdown budget an internal build framework's own server
//! builder gave every daemon before this crate's open-sourcing dropped it.

/// Resolve when the OS asks the process to terminate.
#[cfg(unix)]
pub async fn graceful_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("install SIGTERM handler failed ({e}); falling back to Ctrl-C only");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    let mut int = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("install SIGINT handler failed ({e}); falling back to Ctrl-C only");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = term.recv() => tracing::info!("shutdown signal: SIGTERM"),
        _ = int.recv() => tracing::info!("shutdown signal: SIGINT"),
    }
}

#[cfg(not(unix))]
pub async fn graceful_shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => tracing::info!("shutdown signal: Ctrl-C"),
        Err(e) => tracing::warn!("ctrl_c install failed: {e}"),
    }
}
