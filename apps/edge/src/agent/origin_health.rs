//! Periodic origin health probes + report to control.
//!
//! State flips only after consecutive successes/failures (hysteresis) to avoid
//! flapping between primary and backup on a single transient error.

use crate::agent::ControlClient;
use crate::config::registry::DomainRegistry;
use crate::origin::OriginClient;
use axum::http::{header, HeaderMap, HeaderValue};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::task::JoinSet;

#[derive(Clone, Debug)]
struct HealthState {
    healthy: bool,
    consecutive_ok: u32,
    consecutive_fail: u32,
    last_error: String,
    last_latency_ms: u32,
}

impl Default for HealthState {
    fn default() -> Self {
        Self {
            healthy: true, // unknown starts optimistic
            consecutive_ok: 0,
            consecutive_fail: 0,
            last_error: String::new(),
            last_latency_ms: 0,
        }
    }
}

#[derive(Clone)]
pub struct OriginHealthMap {
    inner: Arc<RwLock<HashMap<String, HealthState>>>,
    fail_threshold: u32,
    recover_threshold: u32,
}

impl OriginHealthMap {
    pub fn new() -> Self {
        Self::with_thresholds(
            env_u32("ORIGIN_HEALTH_FAIL_THRESHOLD", 3).clamp(1, 20),
            env_u32("ORIGIN_HEALTH_RECOVER_THRESHOLD", 2).clamp(1, 20),
        )
    }

    pub fn with_thresholds(fail_threshold: u32, recover_threshold: u32) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            fail_threshold,
            recover_threshold,
        }
    }

    pub async fn is_origin_healthy(&self, domain: &str, origin_url: &str) -> bool {
        let map = self.inner.read().await;
        let key = origin_key(domain, origin_url);
        if let Some(state) = map.get(&key) {
            return state.healthy;
        }
        // Compatibility with snapshots/reports that only had a domain key.
        map.get(&domain.to_lowercase())
            .map(|s| s.healthy)
            .unwrap_or(true)
    }

    pub async fn record_origin(
        &self,
        domain: &str,
        origin_url: &str,
        ok: bool,
        latency_ms: u32,
        err: &str,
    ) -> bool {
        self.record(&origin_key(domain, origin_url), ok, latency_ms, err)
            .await
    }

    /// Record a probe result; returns the (possibly updated) healthy flag.
    pub async fn record(&self, domain: &str, ok: bool, latency_ms: u32, err: &str) -> bool {
        let key = domain.to_lowercase();
        let mut map = self.inner.write().await;
        let state = map.entry(key).or_default();
        state.last_latency_ms = latency_ms;
        if ok {
            state.consecutive_ok = state.consecutive_ok.saturating_add(1);
            state.consecutive_fail = 0;
            state.last_error.clear();
            if !state.healthy && state.consecutive_ok >= self.recover_threshold {
                state.healthy = true;
                tracing::info!(
                    domain,
                    ok_streak = state.consecutive_ok,
                    "origin marked healthy again"
                );
            }
        } else {
            state.consecutive_fail = state.consecutive_fail.saturating_add(1);
            state.consecutive_ok = 0;
            state.last_error = err.to_string();
            if state.healthy && state.consecutive_fail >= self.fail_threshold {
                state.healthy = false;
                tracing::warn!(
                    domain,
                    fail_streak = state.consecutive_fail,
                    error = %err,
                    "origin marked unhealthy"
                );
            }
        }
        state.healthy
    }

    /// Mark an origin unhealthy immediately after a hard connectivity failure
    /// observed on the request path (connect error, connect timeout, TLS
    /// handshake timeout).
    ///
    /// [`OriginHealthMap::record`] deliberately applies hysteresis because it
    /// is fed by scheduled probes. On the request path that hysteresis is
    /// expensive: a dead origin keeps being selected and every fetch waits out
    /// the connect timeout. Flipping the flag now routes subsequent requests to
    /// the next origin; the periodic prober still restores the state after
    /// `recover_threshold` successes, and `origin_order` falls back to the full
    /// pool when nothing is healthy, so capacity is never lost.
    pub async fn record_origin_failure(&self, domain: &str, origin_url: &str, err: &str) {
        let key = origin_key(domain, origin_url);
        let mut map = self.inner.write().await;
        let state = map.entry(key).or_default();
        state.consecutive_fail = self.fail_threshold.max(1);
        state.consecutive_ok = 0;
        state.last_error = err.to_string();
        if state.healthy {
            state.healthy = false;
            tracing::warn!(
                domain,
                origin = origin_url,
                error = %err,
                "origin marked unhealthy after a request-path failure"
            );
        }
    }

    /// Force state (e.g. admin override).
    pub async fn set(&self, domain: &str, healthy: bool) {
        let mut map = self.inner.write().await;
        let state = map.entry(domain.to_lowercase()).or_default();
        state.healthy = healthy;
        state.consecutive_ok = if healthy { self.recover_threshold } else { 0 };
        state.consecutive_fail = if healthy { 0 } else { self.fail_threshold };
    }
}

impl Default for OriginHealthMap {
    fn default() -> Self {
        Self::new()
    }
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

pub fn origin_key(domain: &str, origin_url: &str) -> String {
    format!(
        "{}|{}",
        domain.to_lowercase(),
        origin_url.trim_end_matches('/').to_lowercase()
    )
}

/// Drain probe results and post them to the control plane.
///
/// Runs as its own task so the probe round never waits on the control plane. A
/// failure is logged at `warn` with a running count: it used to be a `debug!`, so a
/// control plane that was refusing reports left the health table stale while the
/// logs showed nothing, and the `origin_unhealthy` alert — which reads that table —
/// could not fire for an origin that was actually down.
async fn reporter_loop(
    control: &ControlClient,
    reports: &mut tokio::sync::mpsc::Receiver<serde_json::Value>,
    dropped: &std::sync::atomic::AtomicU64,
) {
    let mut failures: u64 = 0;
    while let Some(body) = reports.recv().await {
        match control
            .post_json("/api/v1/origin-health/report", &body)
            .await
        {
            Ok(()) => {
                if failures > 0 {
                    tracing::info!(failures, "origin health reporting recovered");
                    failures = 0;
                }
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                // Log the first failure and then every 100th, so a control plane
                // outage does not flood the log at one line per target per round.
                if failures == 1 || failures % 100 == 0 {
                    tracing::warn!(
                        error = %e,
                        failures,
                        queued_dropped = dropped.load(Ordering::Relaxed),
                        "origin health report failed; the control plane's health table is not being updated"
                    );
                }
            }
        }
    }
}

pub fn spawn_origin_health(
    control: ControlClient,
    registry: DomainRegistry,
    origin: OriginClient,
    health_map: OriginHealthMap,
) {
    let interval =
        Duration::from_secs(env_u32("ORIGIN_HEALTH_INTERVAL_SECS", 30).clamp(5, 300) as u64);
    let probe_timeout =
        Duration::from_secs(env_u32("ORIGIN_HEALTH_TIMEOUT_SECS", 5).clamp(1, 120) as u64);
    let concurrency = env_u32("ORIGIN_HEALTH_CONCURRENCY", 16).clamp(1, 256) as usize;

    // Probe results go to the reporter through a bounded queue, so a slow control
    // plane cannot stretch a probe round. The bound is generous enough to hold a
    // whole round of small JSON objects without dropping.
    let (reports_tx, reports_rx) = tokio::sync::mpsc::channel::<serde_json::Value>(4096);
    let dropped_reports = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    {
        let control = control.clone();
        let dropped_reports = dropped_reports.clone();
        // `spawn_supervised` takes an `Fn` because it may rebuild the future on
        // restart, and the receiver cannot be rebuilt. The reporter holds no shared
        // state that a panic could corrupt — a panic there just ends reporting until
        // the process restarts — so it is spawned once rather than supervised.
        let mut reports_rx = reports_rx;
        tokio::spawn(async move {
            reporter_loop(&control, &mut reports_rx, &dropped_reports).await;
        });
    }
    let reports = reports_tx;

    // Supervised: a panic here would silently stop health probing, so dead
    // origins would keep receiving traffic.
    crate::agent::spawn_supervised("origin-health", move || {
        let control = control.clone();
        let registry = registry.clone();
        let origin = origin.clone();
        let health_map = health_map.clone();
        let reports = reports.clone();
        let dropped_reports = dropped_reports.clone();
        async move {
            tracing::info!(
                url = %control.endpoint("/api/v1/origin-health/report"),
                ?interval,
                ?probe_timeout,
                concurrency,
                fail_threshold = health_map.fail_threshold,
                recover_threshold = health_map.recover_threshold,
                "origin health probe started"
            );

            // Fixed-rate ticks with `Skip`: a round that overruns does not queue up
            // the missed ones and then burst. The old `sleep(interval)` at the end of
            // the loop measured the interval from the end of the work, so a slow round
            // pushed the next probe even further out.
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;

            loop {
                let mut targets = Vec::new();
                for entry in registry.snapshot().await {
                    let origins: Vec<(String, Option<String>, Option<String>)> =
                        if entry.origins.is_empty() {
                            vec![(entry.origin_url.clone(), None, None)]
                        } else {
                            entry
                                .origins
                                .iter()
                                .filter(|o| o.enabled)
                                .map(|o| (o.url.clone(), o.host_header.clone(), o.sni.clone()))
                                .collect()
                        };
                    for (url, host, sni) in origins {
                        let mut headers = HeaderMap::new();
                        if let Some(host) = host.as_deref() {
                            if let Ok(value) = HeaderValue::from_str(host) {
                                headers.insert(header::HOST, value);
                            }
                        }
                        crate::security::origin_auth::apply(
                            &mut headers,
                            &entry.origin_auth_header,
                            &entry.origin_auth_value,
                        );
                        targets.push((entry.domain.clone(), url, headers, sni));
                    }
                }

                let origin = origin.clone();
                let health_map = health_map.clone();
                let reports = reports.clone();
                let dropped_reports = dropped_reports.clone();
                run_limited(targets, concurrency, move |(domain, url, headers, sni)| {
                    let origin = origin.clone();
                    let health_map = health_map.clone();
                    let reports = reports.clone();
                    let dropped_reports = dropped_reports.clone();
                    async move {
                        let start = Instant::now();
                        let result = tokio::time::timeout(
                            probe_timeout,
                            origin.fetch_from_with_sni(&url, "/", &headers, sni.as_deref()),
                        )
                        .await;
                        let latency = start.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
                        let (ok, err) = match result {
                            Ok(Ok((status, _, _))) => {
                                let ok = status.as_u16() < 500;
                                (
                                    ok,
                                    if ok {
                                        String::new()
                                    } else {
                                        format!("HTTP {status}")
                                    },
                                )
                            }
                            Ok(Err(e)) => (false, e.to_string()),
                            Err(_) => (
                                false,
                                format!(
                                    "health probe timed out after {}s",
                                    probe_timeout.as_secs()
                                ),
                            ),
                        };
                        let healthy = health_map
                            .record_origin(&domain, &url, ok, latency, &err)
                            .await;
                        // Hand the report to the reporter task instead of sending it
                        // here. Posting from the probe task meant a slow control plane
                        // (up to the 15 s request timeout) was paid per target, inside
                        // the round: 1000 targets at concurrency 16 came to ~63 batches
                        // of probe+post, so a "30 second" interval could stretch past
                        // twenty minutes and the health table would lag reality by that
                        // long. `try_send` keeps a stalled reporter from blocking the
                        // probe — the report is dropped and counted, which is visible,
                        // unlike the silent `debug!` it replaced.
                        let body = json!({
                            "domain_name": domain,
                            "origin_url": url,
                            "healthy": healthy,
                            "latency_ms": latency,
                            "error": err,
                        });
                        if reports.try_send(body).is_err() {
                            dropped_reports.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
                .await;
                ticker.tick().await;
            }
        }
    });
}

async fn run_limited<I, F, Fut>(items: Vec<I>, limit: usize, run: F)
where
    I: Send + 'static,
    F: Fn(I) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut pending: VecDeque<_> = items.into();
    let mut tasks = JoinSet::new();
    let limit = limit.max(1);

    while !pending.is_empty() || !tasks.is_empty() {
        while tasks.len() < limit {
            let Some(item) = pending.pop_front() else {
                break;
            };
            let run = run.clone();
            tasks.spawn(async move { run(item).await });
        }
        if let Some(Err(error)) = tasks.join_next().await {
            tracing::warn!(%error, "origin health probe task failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{run_limited, OriginHealthMap};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// A request-path connectivity failure must bypass probe hysteresis: one
    /// dead origin otherwise keeps being selected and every fetch waits out the
    /// connect timeout. The scheduled prober still has to restore it.
    #[tokio::test]
    async fn request_path_failure_flips_origin_immediately() {
        let map = OriginHealthMap::with_thresholds(3, 2);
        let domain = "a.test";
        let origin = "https://origin.test";
        assert!(map.is_origin_healthy(domain, origin).await);

        map.record_origin_failure(domain, origin, "connect timeout")
            .await;
        assert!(
            !map.is_origin_healthy(domain, origin).await,
            "a hard failure must mark the origin unhealthy at once"
        );
        assert!(
            map.is_origin_healthy(domain, "https://backup.test").await,
            "other origins of the same domain must be unaffected"
        );

        // Recovery still needs `recover_threshold` probe successes.
        map.record_origin(domain, origin, true, 1, "").await;
        assert!(!map.is_origin_healthy(domain, origin).await);
        map.record_origin(domain, origin, true, 1, "").await;
        assert!(map.is_origin_healthy(domain, origin).await);
    }

    #[tokio::test]
    async fn probe_tasks_run_concurrently_with_a_fixed_limit() {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let active_task = active.clone();
        let maximum_task = maximum.clone();

        run_limited((0..12).collect(), 3, move |_| {
            let active = active_task.clone();
            let maximum = maximum_task.clone();
            async move {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                active.fetch_sub(1, Ordering::SeqCst);
            }
        })
        .await;

        assert_eq!(maximum.load(Ordering::SeqCst), 3);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
    /// A stalled reporter must not block probing.
    ///
    /// Reports used to be posted inline from the probe task, so the control
    /// plane's 15 s request timeout was paid per target inside the round: 1000
    /// targets at concurrency 16 is ~63 batches of probe+post, which stretched a
    /// "30 second" interval past twenty minutes. The queue decouples them; when it
    /// is full the report is dropped and counted rather than blocking.
    #[tokio::test]
    async fn a_full_report_queue_drops_instead_of_blocking() {
        // Capacity 1, never drained: this is the worst case for the probe path.
        let (tx, _rx) = tokio::sync::mpsc::channel::<serde_json::Value>(1);
        assert!(tx.try_send(serde_json::json!({"n": 1})).is_ok());

        let started = std::time::Instant::now();
        let second = tx.try_send(serde_json::json!({"n": 2}));
        assert!(
            second.is_err(),
            "a full queue must report failure, not wait"
        );
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "try_send must return immediately"
        );
    }

    /// A drained queue accepts reports again, so a recovered control plane catches up.
    #[tokio::test]
    async fn a_drained_queue_accepts_reports_again() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<serde_json::Value>(2);
        assert!(tx.try_send(serde_json::json!({"n": 1})).is_ok());
        assert!(tx.try_send(serde_json::json!({"n": 2})).is_ok());
        assert!(tx.try_send(serde_json::json!({"n": 3})).is_err());

        assert_eq!(rx.recv().await.unwrap()["n"], 1);
        assert!(tx.try_send(serde_json::json!({"n": 4})).is_ok());
    }
}
