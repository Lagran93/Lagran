//! Periodic origin health probes + report to control

use crate::agent::ControlClient;
use crate::config::registry::DomainRegistry;
use crate::origin::OriginClient;
use axum::http::HeaderMap;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Clone, Default)]
pub struct OriginHealthMap {
    inner: Arc<RwLock<HashMap<String, bool>>>,
}

impl OriginHealthMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn set(&self, domain: &str, healthy: bool) {
        self.inner.write().await.insert(domain.to_lowercase(), healthy);
    }

    pub async fn is_healthy(&self, domain: &str) -> bool {
        self.inner
            .read()
            .await
            .get(&domain.to_lowercase())
            .copied()
            .unwrap_or(true) // unknown = assume healthy
    }
}

pub fn spawn_origin_health(
    control: ControlClient,
    registry: DomainRegistry,
    origin: OriginClient,
    health_map: OriginHealthMap,
) {
    tokio::spawn(async move {
        tracing::info!(url = %control.endpoint("/api/v1/origin-health/report"), "origin health probe started");

        loop {
            // Snapshot the registry once instead of one lock per domain.
            for entry in registry.snapshot().await {
                let start = Instant::now();
                let result = origin
                    .fetch_from(&entry.origin_url, "/", &HeaderMap::new())
                    .await;
                let latency = start.elapsed().as_millis() as u32;
                let (healthy, err) = match result {
                    Ok((status, _, _)) => {
                        let ok = status.as_u16() < 500;
                        (ok, if ok { String::new() } else { format!("HTTP {status}") })
                    }
                    Err(e) => (false, e.to_string()),
                };
                health_map.set(&entry.domain, healthy).await;
                let body = json!({
                    "domain_name": entry.domain,
                    "origin_url": entry.origin_url,
                    "healthy": healthy,
                    "latency_ms": latency,
                    "error": err,
                });
                let _ = control.post_json("/api/v1/origin-health/report", &body).await;
                if !healthy {
                    tracing::warn!(domain = %entry.domain, %err, latency_ms = latency, "origin unhealthy");
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}
