//! Process-wide shutdown signalling.
//!
//! Nothing handled SIGTERM, so `systemctl restart`, a rolling upgrade or the OOM
//! killer cut the edge off mid-response: a streaming body truncated against its own
//! `Content-Length`, the access log writer's queued records lost, and flight locks
//! left to expire. This gives the process a signal to act on.
//!
//! Pingora's listener runs on its own runtime in a spawned thread and has no
//! cooperative stop, so the shutdown path here is "stop flushing and exit" rather
//! than a full drain. That is still the difference between losing the tail of the log
//! and keeping it.

/// Resolve when the OS asks this process to stop (SIGTERM or SIGINT).
///
/// On platforms without Unix signals this waits for Ctrl-C. If the handler cannot be
/// installed the future never resolves rather than panicking: running without a
/// clean shutdown is better than refusing to start.
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
