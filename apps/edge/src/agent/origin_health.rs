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

    pub async fn is_healthy(&self, domain: &str) -> bool {
        self.inner
            .read()
            .await
            .get(&domain.to_lowercase())
            .map(|s| s.healthy)
            .unwrap_or(true)
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
    tokio::spawn(async move {
        tracing::info!(
            url = %control.endpoint("/api/v1/origin-health/report"),
            ?interval,
            ?probe_timeout,
            concurrency,
            fail_threshold = health_map.fail_threshold,
            recover_threshold = health_map.recover_threshold,
            "origin health probe started"
        );

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
            let control = control.clone();
            run_limited(targets, concurrency, move |(domain, url, headers, sni)| {
                let origin = origin.clone();
                let health_map = health_map.clone();
                let control = control.clone();
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
                            format!("health probe timed out after {}s", probe_timeout.as_secs()),
                        ),
                    };
                    let healthy = health_map
                        .record_origin(&domain, &url, ok, latency, &err)
                        .await;
                    let body = json!({
                        "domain_name": domain,
                        "origin_url": url,
                        "healthy": healthy,
                        "latency_ms": latency,
                        "error": err,
                    });
                    if let Err(e) = control
                        .post_json("/api/v1/origin-health/report", &body)
                        .await
                    {
                        tracing::debug!(error = %e, "origin health report failed");
                    }
                }
            })
            .await;
            tokio::time::sleep(interval).await;
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
    use super::run_limited;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

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
}
