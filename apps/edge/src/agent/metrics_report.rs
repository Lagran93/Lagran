//! Flush per-domain counters to control plane

use crate::agent::ControlClient;
use crate::config::EdgeConfig;
use crate::metrics::EdgeMetrics;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

pub fn spawn_metrics_report(config: EdgeConfig, control: ControlClient, metrics: Arc<EdgeMetrics>) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(15);
        tracing::info!(url = %control.endpoint("/api/v1/metrics/report"), "metrics reporter started (per-domain)");

        loop {
            tokio::time::sleep(interval).await;
            let snaps = metrics.take_snapshots().await;
            if snaps.is_empty() {
                continue;
            }
            for s in snaps {
                // Prefer real host from traffic; fallback EDGE_DOMAIN only if unknown
                let domain = if s.domain == "(unknown)" && !config.domain.is_empty() {
                    config.domain.clone()
                } else {
                    s.domain.clone()
                };
                let body = json!({
                    "node_id": config.node_id,
                    "domain": domain,
                    "requests": s.requests,
                    "cache_hits": s.cache_hits,
                    "cache_misses": s.cache_misses,
                    "bytes_sent": s.bytes_sent,
                });
                if let Err(e) = control.post_json("/api/v1/metrics/report", &body).await {
                    tracing::warn!(error = %e, domain = %domain, "metrics report failed");
                } else {
                    tracing::debug!(
                        domain = %domain,
                        requests = s.requests,
                        hits = s.cache_hits,
                        "metrics reported"
                    );
                }
            }
        }
    });
}
