//! Pull origin + cache rules from control plane

use crate::cache::policy::{CacheRule, RuleSet};
use crate::config::EdgeConfig;
use crate::origin::OriginClient;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct OriginCfg {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleCfg {
    pub path_pattern: String,
    pub ttl_seconds: u64,
    pub priority: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DomainConfig {
    pub domain: String,
    pub origin: OriginCfg,
    pub rules: Vec<RuleCfg>,
    pub version: String,
}

pub fn spawn_config_sync(config: EdgeConfig, origin: OriginClient, rules: RuleSet) {
    let domain = config.domain.clone();
    if domain.is_empty() {
        tracing::info!("EDGE_DOMAIN not set; using ORIGIN_URL + default TTL only");
        return;
    }
    tokio::spawn(async move {
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        let url = format!(
            "{}/api/v1/config/{}",
            config.control_url.trim_end_matches('/'),
            domain
        );
        tracing::info!(%url, "config+rules sync started");

        loop {
            match fetch_config(&client, &url).await {
                Ok(cfg) => {
                    let origin_url = format!(
                        "{}://{}:{}",
                        cfg.origin.protocol, cfg.origin.host, cfg.origin.port
                    );
                    tracing::info!(origin_url = %origin_url, "set origin url");
                    origin.set_base_url(origin_url).await;
                    let mapped: Vec<CacheRule> = cfg
                        .rules
                        .into_iter()
                        .map(|r| CacheRule {
                            path_pattern: r.path_pattern,
                            ttl_seconds: r.ttl_seconds,
                            priority: r.priority,
                        })
                        .collect();
                    tracing::info!(count = mapped.len(), version = %cfg.version, "rules updated");
                    rules.replace(mapped).await;
                }
                Err(e) => tracing::warn!(error = %e, domain = %domain, "config sync failed"),
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}

async fn fetch_config(
    client: &Client<HttpConnector, Full<Bytes>>,
    url: &str,
) -> Result<DomainConfig, String> {
    let req = Request::builder()
        .method("GET")
        .uri(url)
        .body(Full::new(Bytes::new()))
        .map_err(|e| e.to_string())?;
    let resp = client.request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    if !status.is_success() {
        return Err(format!(
            "HTTP {}: {}",
            status,
            String::from_utf8_lossy(&body)
        ));
    }
    serde_json::from_slice(&body).map_err(|e| e.to_string())
}
