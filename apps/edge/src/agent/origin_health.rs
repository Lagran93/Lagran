//! Periodic origin health probes + report to control.
//!
//! State flips only after consecutive successes/failures (hysteresis) to avoid
//! flapping between primary and backup on a single transient error.

use crate::agent::ControlClient;
use crate::config::registry::DomainRegistry;
use crate::origin::OriginClient;
use axum::http::HeaderMap;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

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
    let interval = Duration::from_secs(
        env_u32("ORIGIN_HEALTH_INTERVAL_SECS", 30).clamp(5, 300) as u64,
    );
    tokio::spawn(async move {
        tracing::info!(
            url = %control.endpoint("/api/v1/origin-health/report"),
            ?interval,
            fail_threshold = health_map.fail_threshold,
            recover_threshold = health_map.recover_threshold,
            "origin health probe started"
        );

        loop {
            for entry in registry.snapshot().await {
                let targets: Vec<String> = if entry.origins.is_empty() {
                    vec![entry.origin_url.clone()]
                } else {
                    entry
                        .origins
                        .iter()
                        .filter(|o| o.enabled)
                        .map(|o| o.url.clone())
                        .collect()
                };
                for url in targets {
                    let start = Instant::now();
                    let result = origin.fetch_from(&url, "/", &HeaderMap::new()).await;
                    let latency = start.elapsed().as_millis() as u32;
                    let (ok, err) = match result {
                        Ok((status, _, _)) => {
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
                        Err(e) => (false, e.to_string()),
                    };
                    let healthy = health_map
                        .record_origin(&entry.domain, &url, ok, latency, &err)
                        .await;

                    let body = json!({
                        "domain_name": entry.domain,
                        "origin_url": url,
                        "healthy": healthy,
                        "latency_ms": latency,
                        "error": err,
                    });
                    let _ = control
                        .post_json("/api/v1/origin-health/report", &body)
                        .await;
                }
            }
            tokio::time::sleep(interval).await;
        }
    });
}
