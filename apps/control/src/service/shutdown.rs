//! Process-wide shutdown signalling for the control plane.
//!
//! Nothing handled SIGTERM, so `systemctl restart`, a rolling upgrade or the OOM
//! killer cut the process off mid-request. `axum::serve` has
//! `with_graceful_shutdown` for exactly this; it just was never wired up.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A shutdown flag tasks can share.
#[derive(Clone, Default)]
pub struct Shutdown {
    signalled: Arc<AtomicBool>,
}

impl Shutdown {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark shutdown started. Idempotent.
    pub fn trigger(&self) {
        self.signalled.store(true, Ordering::SeqCst);
    }

    pub fn is_signalled(&self) -> bool {
        self.signalled.load(Ordering::SeqCst)
    }

    /// Resolve once shutdown has been triggered.
    pub async fn wait(&self) {
        while !self.is_signalled() {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
}

/// Resolve when the OS asks this process to stop (SIGTERM or SIGINT).
///
/// On platforms without Unix signals this waits for Ctrl-C. If the handler cannot
/// be installed the future never resolves rather than panicking: a process that
/// runs without a clean shutdown path is still better than one that refuses to
/// start.
pub async fn wait_async() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) {
            (Ok(mut term), Ok(mut int)) => {
                tokio::select! {
                    _ = term.recv() => tracing::info!("SIGTERM received; shutting down"),
                    _ = int.recv() => tracing::info!("SIGINT received; shutting down"),
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                tracing::warn!(error = %e, "cannot install signal handler; shutdown disabled");
                std::future::pending::<()>().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        match tokio::signal::ctrl_c().await {
            Ok(()) => tracing::info!("shutdown requested"),
            Err(e) => {
                tracing::warn!(error = %e, "cannot install Ctrl-C handler; shutdown disabled");
                std::future::pending::<()>().await;
            }
        }
    }
}
