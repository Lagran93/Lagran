//! Flush per-domain counters to control plane

use crate::config::EdgeConfig;
use crate::metrics::EdgeMetrics;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

pub fn spawn_metrics_report(config: EdgeConfig, metrics: Arc<EdgeMetrics>) {
    tokio::spawn(async move {
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        let url = format!(
            "{}/api/v1/metrics/report",
            config.control_url.trim_end_matches('/')
        );
        let interval = Duration::from_secs(15);
        tracing::info!(%url, "metrics reporter started (per-domain)");

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
                if let Err(e) = post_json(&client, &url, &body, &config.agent_token).await {
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

async fn post_json(
    client: &Client<HttpConnector, Full<Bytes>>,
    url: &str,
    body: &serde_json::Value,
    token: &str,
) -> Result<(), String> {
    let bytes = Bytes::from(serde_json::to_vec(body).map_err(|e| e.to_string())?);
    let req = Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/json")
        .header("x-lagran-agent-token", token)
        .body(Full::new(bytes))
        .map_err(|e| e.to_string())?;
    let resp = client.request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let _ = resp.into_body().collect().await;
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    Ok(())
}
