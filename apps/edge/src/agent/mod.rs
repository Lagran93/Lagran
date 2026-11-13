//! Background agents: heartbeat, config sync, metrics
pub mod access_report;

pub mod cc_sync;
pub mod cert_sync;
pub mod config_sync;
pub mod control_client;
pub mod metrics_report;
pub mod origin_health;
pub mod waf_report;

pub use control_client::ControlClient;

use crate::config::EdgeConfig;
use serde::Deserialize;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Whether this node is allowed to serve traffic. Updated from the heartbeat
/// response so an admin can drain a node from the console.
#[derive(Clone)]
pub struct NodeControl {
    serving: Arc<AtomicBool>,
}

impl NodeControl {
    pub fn new() -> Self {
        Self {
            serving: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn is_serving(&self) -> bool {
        // `Acquire` pairs with the `Release` in `set_serving`.
        //
        // Today the flag carries no payload, so `Relaxed` would still be correct —
        // the ordering exists so that a request thread which observes
        // `serving == false` is guaranteed to see whatever the setter did before
        // flipping it (cache clears, connection teardown). Cheap insurance against a
        // future change that looks obviously safe at the call site.
        self.serving.load(Ordering::Acquire)
    }

    /// Returns true when the state actually changed.
    pub fn set_serving(&self, enabled: bool) -> bool {
        let previous = self.serving.swap(enabled, Ordering::Release);
        previous != enabled
    }
}

impl Default for NodeControl {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize)]
struct HeartbeatReply {
    #[serde(default)]
    accepted: bool,
    #[serde(default)]
    message: String,
    /// Whether this node may serve traffic.
    ///
    /// Absent means "no answer", not "yes". The field used to default to `true`,
    /// so a response that omitted it — an older control plane, a proxy that
    /// stripped it, a changed serialisation — silently re-enabled a node an
    /// administrator had drained. The control plane always sends this field, so
    /// failing closed costs nothing when everything is healthy and stops a
    /// drained node from resuming on its own.
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    status: String,
}

/// Serving state to apply from a heartbeat: only an accepted reply may change
/// it. A rejected reply (database error, unknown node) says nothing about the
/// administrator's intent and must not re-enable a drained node.
fn serving_update(reply: &HeartbeatReply) -> Option<bool> {
    reply.accepted.then_some(reply.enabled)
}

/// Run a background task, restarting it if its future panics.
///
/// A bare `tokio::spawn` that panics disappears silently: the edge keeps
/// serving with whatever configuration it had at startup, heartbeats continue
/// from their own task, and the node looks healthy while new domains and WAF
/// rules never take effect. Supervision turns that into a logged, retried
/// condition instead.
pub fn spawn_supervised<F, Fut>(name: &'static str, build: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut restarts: u64 = 0;
        loop {
            // The inner task is spawned so a panic is caught as a JoinError
            // rather than unwinding this supervisor as well.
            match tokio::spawn(build()).await {
                Ok(()) => return,
                Err(e) => {
                    restarts = restarts.saturating_add(1);
                    let backoff = std::time::Duration::from_secs((5 * restarts).min(60));
                    if e.is_panic() {
                        tracing::error!(
                            task = name,
                            restarts,
                            "background task panicked; restarting"
                        );
                    } else {
                        tracing::warn!(
                            task = name,
                            restarts,
                            "background task was cancelled; restarting"
                        );
                    }
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    });
}

pub fn spawn_heartbeat(config: EdgeConfig, control: ControlClient, node_control: NodeControl) {
    // Supervised: heartbeats are how the control plane decides a node is alive.
    // A silent panic would leave the node serving traffic while the console
    // eventually marks it offline.
    spawn_supervised("heartbeat", move || {
        let config = config.clone();
        let control = control.clone();
        let node_control = node_control.clone();
        async move {
            let interval = Duration::from_secs(config.heartbeat_interval_secs.max(5));
            tracing::info!(
                target = %control.endpoint("/api/v1/nodes/heartbeat"),
                node_id = %config.node_id,
                version = crate::version::VERSION,
                "heartbeat agent started"
            );

            loop {
                let body = json!({
                    "node_id": config.node_id,
                    "region": config.region,
                    "ip": config.listen_addr,
                    "agent_url": config.agent_url,
                    "public_ip": config.public_ip,
                    "version": crate::version::VERSION,
                    "cpu_usage": cpu_usage().await,
                    "memory_usage": memory_usage().await,
                });
                match control
                    .post_json_for::<_, HeartbeatReply>("/api/v1/nodes/heartbeat", &body)
                    .await
                {
                    Ok(reply) => {
                        match serving_update(&reply) {
                            None => {
                                // Rejected heartbeats (database error, unknown
                                // node) must not change the serving state.
                                tracing::warn!(message = %reply.message, "heartbeat rejected");
                            }
                            Some(enabled) => {
                                if node_control.set_serving(enabled) {
                                    if enabled {
                                        tracing::info!(
                                            status = %reply.status,
                                            "node enabled by control plane; serving traffic"
                                        );
                                    } else {
                                        tracing::warn!(
                                            status = %reply.status,
                                            "node disabled by control plane; returning 503 until re-enabled"
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "heartbeat failed"),
                }
                tokio::time::sleep(interval).await;
            }
        }
    });
}

/// Read `/proc` without blocking the async worker.
///
/// These were `std::fs::read_to_string` inside the heartbeat task. The files are
/// tiny and already in the page cache so it was harmless in practice, but a
/// synchronous read on an async thread parks a worker for however long the
/// filesystem takes — and the whole point of the heartbeat is to stay responsive.
async fn cpu_usage() -> Option<f64> {
    let load = tokio::fs::read_to_string("/proc/loadavg").await.ok()?;
    let first = load.split_whitespace().next()?.parse::<f64>().ok()?;
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1) as f64;
    Some((((first / cpus) * 100.0 * 10.0).round() / 10.0).clamp(0.0, 100.0))
}

async fn memory_usage() -> Option<f64> {
    let text = tokio::fs::read_to_string("/proc/meminfo").await.ok()?;
    let mut total = 0f64;
    let mut available = 0f64;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = rest.split_whitespace().next()?.parse().ok()?;
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available = rest.split_whitespace().next()?.parse().ok()?;
        }
    }
    if total <= 0.0 {
        return None;
    }
    Some(((((total - available) / total) * 100.0 * 10.0).round() / 10.0).clamp(0.0, 100.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(accepted: bool, enabled: bool) -> HeartbeatReply {
        HeartbeatReply {
            accepted,
            message: String::new(),
            enabled,
            status: String::new(),
        }
    }

    #[test]
    fn rejected_heartbeat_never_changes_serving_state() {
        assert_eq!(serving_update(&reply(false, true)), None);
        assert_eq!(serving_update(&reply(false, false)), None);
        assert_eq!(serving_update(&reply(true, true)), Some(true));
        assert_eq!(serving_update(&reply(true, false)), Some(false));
    }
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    /// A panicking background task must be restarted, not silently lost.
    ///
    /// With a bare `tokio::spawn` the panic only surfaced as a dropped JoinHandle
    /// and the loop disappeared; the edge then kept serving its startup config
    /// while heartbeats continued, so the node looked healthy.
    #[tokio::test]
    async fn supervised_task_restarts_after_panic() {
        let runs = Arc::new(AtomicU64::new(0));
        let counter = runs.clone();
        spawn_supervised("test-panic", move || {
            let counter = counter.clone();
            async move {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    panic!("first run panics");
                }
                // Second run returns normally, which stops the supervisor.
            }
        });

        // The supervisor sleeps 5s before restarting; allow for that.
        for _ in 0..100 {
            if runs.load(Ordering::SeqCst) >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(
            runs.load(Ordering::SeqCst),
            2,
            "task should run again after panicking"
        );
    }

    /// A task that completes normally must not be restarted.
    #[tokio::test]
    async fn supervised_task_completing_does_not_restart() {
        let runs = Arc::new(AtomicU64::new(0));
        let counter = runs.clone();
        spawn_supervised("test-complete", move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "a finished task must not be re-run"
        );
    }
    /// A heartbeat reply that omits `enabled` must not re-enable a node.
    ///
    /// The field used to default to `true`, so a response without it — an older
    /// control plane, or a proxy that dropped it — resumed traffic on a node an
    /// administrator had drained.
    #[test]
    fn heartbeat_reply_without_enabled_fails_closed() {
        let minimal: HeartbeatReply =
            serde_json::from_str(r#"{"accepted":true,"message":"ok","status":"online"}"#)
                .expect("parse minimal reply");
        assert!(
            !minimal.enabled,
            "a missing `enabled` must not mean \"serve traffic\""
        );
    }

    /// An explicit value is honoured in both directions.
    #[test]
    fn heartbeat_reply_honours_explicit_enabled() {
        let on: HeartbeatReply = serde_json::from_str(r#"{"enabled":true}"#).expect("parse");
        assert!(on.enabled);
        let off: HeartbeatReply = serde_json::from_str(r#"{"enabled":false}"#).expect("parse");
        assert!(!off.enabled);
    }
}
