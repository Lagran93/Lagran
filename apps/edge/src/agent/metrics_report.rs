//! Flush per-domain counters to control plane

use crate::agent::ControlClient;
use crate::config::EdgeConfig;
use crate::metrics::EdgeMetrics;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

pub fn spawn_metrics_report(config: EdgeConfig, control: ControlClient, metrics: Arc<EdgeMetrics>) {
    // Supervised: a panic here would silently stop metrics reporting.
    crate::agent::spawn_supervised("metrics-report", move || {
        let config = config.clone();
        let control = control.clone();
        let metrics = metrics.clone();
        async move {
            let interval = Duration::from_secs(15);
            tracing::info!(
                url = %control.endpoint("/api/v1/metrics/report/batch"),
                "metrics reporter started (batched)"
            );

            loop {
                tokio::time::sleep(interval).await;
                // Two-phase: read without resetting, report, and only subtract what
                // the control plane acknowledged. `take_snapshots` cleared the
                // counters before the report was attempted, so a failure dropped the
                // batch outright — the hit-ratio charts showed gaps, and the
                // `cache_hit_ratio` alert returns early when `requests <= 0`, so a
                // real problem could hide behind "no data".
                let snaps = metrics.take_snapshots_peek();
                if snaps.is_empty() {
                    continue;
                }
                let snaps_len = snaps.len();
                // Keep the snapshot for `subtract_reported`; the batch below consumes
                // a cloned view for JSON construction.
                let items: Vec<_> = snaps
                    .iter()
                    .map(|s| {
                        // Prefer real host from traffic; fallback EDGE_DOMAIN only if unknown.
                        let domain = if s.domain == "(unknown)" && !config.domain.is_empty() {
                            config.domain.clone()
                        } else {
                            s.domain.clone()
                        };
                        json!({
                            "node_id": config.node_id,
                            "domain": domain,
                            "requests": s.requests,
                            "cache_hits": s.cache_hits,
                            "cache_misses": s.cache_misses,
                            "bytes_sent": s.bytes_sent,
                        })
                    })
                    .collect();
                let body = json!({ "items": items });
                if let Err(e) = control
                    .post_json("/api/v1/metrics/report/batch", &body)
                    .await
                {
                    // Counters keep their values, so the next round sends the same
                    // totals plus whatever arrived in between. Nothing is lost; the
                    // only cost of an outage is a later, larger batch.
                    tracing::warn!(error = %e, domains = snaps_len, "metrics batch report failed; counters retained for the next round");
                } else {
                    metrics.subtract_reported(&snaps);
                    tracing::debug!(
                        domains = body["items"].as_array().map(Vec::len).unwrap_or(0),
                        "metrics batch reported"
                    );
                }
            }
        }
    });
}
