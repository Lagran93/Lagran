//! Periodic origin health probes + report to control

use crate::config::registry::DomainRegistry;
use crate::config::EdgeConfig;
use crate::origin::OriginClient;
use axum::http::HeaderMap;
use bytes::Bytes;
use http_body_util::Full;
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

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
    config: EdgeConfig,
    registry: DomainRegistry,
    origin: OriginClient,
    health_map: OriginHealthMap,
) {
    tokio::spawn(async move {
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        connector.set_connect_timeout(Some(Duration::from_secs(3)));
        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        let report_url = format!(
            "{}/api/v1/origin-health/report",
            config.control_url.trim_end_matches('/')
        );
        tracing::info!("origin health probe started");

        loop {
            // probe each domain in registry
            // DomainRegistry doesn't expose list - add method
            let names = registry.list_domains().await;
            for name in names {
                if let Some(entry) = registry.get(&name).await {
                    let start = Instant::now();
                    let probe_path = "/";
                    let result = origin
                        .fetch_from(&entry.origin_url, probe_path, &HeaderMap::new())
                        .await;
                    let latency = start.elapsed().as_millis() as u32;
                    let (healthy, err) = match result {
                        Ok((status, _, _)) => {
                            let ok = status.as_u16() < 500;
                            (ok, if ok { String::new() } else { format!("HTTP {status}") })
                        }
                        Err(e) => (false, e.to_string()),
                    };
                    health_map.set(&name, healthy).await;
                    let body = json!({
                        "domain_name": name,
                        "origin_url": entry.origin_url,
                        "healthy": healthy,
                        "latency_ms": latency,
                        "error": err,
                    });
                    let _ = post_json(&client, &report_url, &body, &config.agent_token).await;
                    if !healthy {
                        tracing::warn!(domain = %name, %err, latency_ms = latency, "origin unhealthy");
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
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
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    Ok(())
}
