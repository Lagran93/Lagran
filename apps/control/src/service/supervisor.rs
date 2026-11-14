//! Restart supervision for long-running background loops.
//!
//! A bare `tokio::spawn` whose future panics disappears without a trace: the
//! process keeps serving, but alerts stop firing or certificates stop renewing
//! for the rest of its lifetime. Supervision awaits the task handle and starts a
//! fresh instance on both panic and unexpected exit.

use std::future::Future;
use std::time::Duration;

/// Run `build` forever, restarting with a short backoff after a panic or exit.
pub fn supervise<F, Fut>(name: &'static str, build: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            let handle = tokio::spawn(build());
            match handle.await {
                Ok(()) => tracing::warn!(task = name, "background task exited; restarting"),
                Err(error) => {
                    tracing::error!(task = name, %error, "background task failed; restarting")
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

/// Supervise a task that returns a `JoinHandle` (the older `spawn` shape).
pub fn supervise_handle<F>(name: &'static str, build: F)
where
    F: Fn() -> tokio::task::JoinHandle<()> + Send + 'static,
{
    supervise(name, move || {
        let handle = build();
        async move {
            match handle.await {
                Ok(()) => tracing::warn!(task = name, "background task exited; restarting"),
                Err(error) => {
                    tracing::error!(task = name, %error, "background task failed; restarting")
                }
            }
            // The supervisor restarts after `build`'s future completes; this
            // await is the task itself, so return its completion to the loop.
        }
    });
}
