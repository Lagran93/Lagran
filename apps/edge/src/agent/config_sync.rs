//! Sync all accelerated domains + rules from control plane

use crate::cache::policy::{CacheRule, RuleSet};
use crate::config::registry::{DomainEntry, DomainRegistry};
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
struct OriginCfg {
    host: String,
    port: u16,
    protocol: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RuleCfg {
    path_pattern: String,
    ttl_seconds: u64,
    priority: i32,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    swr_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct DomainCfg {
    domain: String,
    origin: OriginCfg,
    rules: Vec<RuleCfg>,
    #[serde(default)]
    #[allow(dead_code)]
    status: String,
    #[serde(default)]
    rate_limit_rps: u32,
    #[serde(default)]
    rate_limit_burst: u32,
    #[serde(default)]
    ignore_query_string: bool,
    #[serde(default)]
    cors_origins: String,
    #[serde(default)]
    hotlink_allow_referers: String,
    #[serde(default)]
    origin_timeout_ms: u32,
    #[serde(default)]
    custom_headers: String,
    #[serde(default)]
    backup_origin: Option<OriginCfg>,
    version: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AllConfig {
    domains: Vec<DomainCfg>,
    version: String,
}

pub fn spawn_config_sync(
    config: EdgeConfig,
    origin: OriginClient,
    rules: RuleSet,
    registry: DomainRegistry,
) {
    tokio::spawn(async move {
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        let url = format!(
            "{}/api/v1/config",
            config.control_url.trim_end_matches('/')
        );
        tracing::info!(%url, "domain registry sync started");

        let mut last_version = String::new();
        loop {
            match fetch_all(&client, &url).await {
                Ok(cfg) => {
                    if cfg.version != last_version {
                        let mut entries = Vec::new();
                        let mut global_rules = Vec::new();
                        for d in cfg.domains {
                            let origin_url = format!(
                                "{}://{}:{}",
                                d.origin.protocol, d.origin.host, d.origin.port
                            );
                            let mapped: Vec<CacheRule> = d
                                .rules
                                .iter()
                                .map(|r| CacheRule {
                                    path_pattern: r.path_pattern.clone(),
                                    ttl_seconds: r.ttl_seconds,
                                    priority: r.priority,
                                    action: r.action.clone().unwrap_or_else(|| "cache".into()),
                                    swr_seconds: r.swr_seconds.unwrap_or(0),
                                })
                                .collect();
                            global_rules.extend(mapped.clone());
                            entries.push(DomainEntry {
                                domain: d.domain.clone(),
                                origin_url: origin_url.clone(),
                                rules: mapped,
                                version: d.version,
                                rate_limit_rps: d.rate_limit_rps,
                                rate_limit_burst: d.rate_limit_burst,
                                ignore_query_string: d.ignore_query_string,
                                cors_origins: d.cors_origins.clone(),
                                hotlink_allow_referers: d.hotlink_allow_referers.clone(),
                                origin_timeout_ms: if d.origin_timeout_ms == 0 { 10000 } else { d.origin_timeout_ms },
                                custom_headers: d.custom_headers.clone(),
                                backup_origin_url: d.backup_origin.as_ref().map(|o| {
                                    format!("{}://{}:{}", o.protocol, o.host, o.port)
                                }).unwrap_or_default(),
                            });
                        }
                        let n = entries.len();
                        registry.replace_all(entries, cfg.version.clone()).await;
                        rules.replace(global_rules).await;

                        if !config.domain.is_empty() {
                            if let Some(d) = registry.get(&config.domain).await {
                                origin.set_base_url(d.origin_url).await;
                            }
                        }

                        tracing::info!(domains = n, version = %cfg.version, "domain registry updated");
                        last_version = cfg.version;
                    }
                }
                Err(e) => tracing::warn!(error = %e, "config sync failed"),
            }

            // Single-domain fallback if EDGE_DOMAIN set and registry empty
            if !config.domain.is_empty() && registry.len().await == 0 {
                let single = format!(
                    "{}/api/v1/config/{}",
                    config.control_url.trim_end_matches('/'),
                    config.domain
                );
                if let Ok(d) = fetch_one(&client, &single).await {
                    let origin_url =
                        format!("{}://{}:{}", d.origin.protocol, d.origin.host, d.origin.port);
                    origin.set_base_url(origin_url.clone()).await;
                    let mapped: Vec<CacheRule> = d
                        .rules
                        .into_iter()
                        .map(|r| CacheRule {
                            path_pattern: r.path_pattern,
                            ttl_seconds: r.ttl_seconds,
                            priority: r.priority,
                            action: r.action.unwrap_or_else(|| "cache".into()),
                            swr_seconds: r.swr_seconds.unwrap_or(0),
                        })
                        .collect();
                    rules.replace(mapped.clone()).await;
                    registry
                        .upsert(DomainEntry {
                            domain: d.domain,
                            origin_url,
                            rules: mapped,
                            version: d.version,
                            rate_limit_rps: d.rate_limit_rps,
                            rate_limit_burst: d.rate_limit_burst,
                                ignore_query_string: d.ignore_query_string,
                                cors_origins: d.cors_origins.clone(),
                                hotlink_allow_referers: d.hotlink_allow_referers.clone(),
                                origin_timeout_ms: if d.origin_timeout_ms == 0 { 10000 } else { d.origin_timeout_ms },
                                custom_headers: d.custom_headers.clone(),
                                backup_origin_url: d.backup_origin.as_ref().map(|o| {
                                    format!("{}://{}:{}", o.protocol, o.host, o.port)
                                }).unwrap_or_default(),
                        })
                        .await;
                }
            }

            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    });
}

async fn fetch_all(
    client: &Client<HttpConnector, Full<Bytes>>,
    url: &str,
) -> Result<AllConfig, String> {
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

async fn fetch_one(
    client: &Client<HttpConnector, Full<Bytes>>,
    url: &str,
) -> Result<DomainCfg, String> {
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
        return Err(format!("HTTP {status}"));
    }
    serde_json::from_slice(&body).map_err(|e| e.to_string())
}
