//! Pull TLS certs from control plane (bulk + per-domain) and hot-load

use crate::config::EdgeConfig;
use crate::server::cert_store::CertStore;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct EdgeCertResponse {
    domain: String,
    #[serde(default)]
    cert_pem: String,
    #[serde(default)]
    key_pem: String,
    #[serde(default)]
    status: String,
}

pub fn spawn_cert_sync(config: EdgeConfig, store: Arc<CertStore>) {
    tokio::spawn(async move {
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        // Immediate sync on startup so HTTPS can bind without re-issue
        if let Err(e) = sync_once(&client, &config, &store).await {
            tracing::warn!(error = %e, "initial cert sync failed (will retry)");
        }

        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            if let Err(e) = sync_once(&client, &config, &store).await {
                tracing::debug!(error = %e, "cert sync tick failed");
            }
        }
    });
}

async fn sync_once(
    client: &Client<HttpConnector, Full<Bytes>>,
    config: &EdgeConfig,
    store: &Arc<CertStore>,
) -> Result<(), String> {
    let base = config.control_url.trim_end_matches('/');
    let mut applied = 0u32;

    // 1) Bulk active certs
    let bulk_url = format!("{base}/api/v1/certs/edge-sync");
    match fetch_json_vec::<EdgeCertResponse>(client, &bulk_url, &config.agent_token).await {
        Ok(list) => {
            for cert in list {
                if cert.status != "active" && !cert.status.is_empty() {
                    continue;
                }
                if cert.cert_pem.is_empty() || cert.key_pem.is_empty() {
                    continue;
                }
                let names = vec![cert.domain.clone()];
                match store.upsert(&names, cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()) {
                    Ok(()) => {
                        applied += 1;
                        tracing::debug!(domain = %cert.domain, "cert applied from edge-sync");
                    }
                    Err(e) => tracing::warn!(domain = %cert.domain, error = %e, "cert apply failed"),
                }
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "edge-sync unavailable, try single domain");
        }
    }

    // 2) Fallback: EDGE_DOMAIN single fetch
    if !config.domain.is_empty() {
        let url = format!("{base}/api/v1/certs/by-domain/{}", config.domain);
        if let Ok(cert) = fetch_json::<EdgeCertResponse>(client, &url, &config.agent_token).await {
            if (cert.status == "active" || cert.status.is_empty())
                && !cert.cert_pem.is_empty()
                && !cert.key_pem.is_empty()
            {
                let names = vec![cert.domain.clone()];
                if store
                    .upsert(&names, cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
                    .is_ok()
                {
                    applied += 1;
                }
            }
        }
    }

    if applied > 0 {
        tracing::info!(applied, total = store.len(), "cert sync done");
    }
    Ok(())
}

async fn fetch_json_vec<T: for<'de> Deserialize<'de>>(
    client: &Client<HttpConnector, Full<Bytes>>,
    url: &str,
    token: &str,
) -> Result<Vec<T>, String> {
    let mut builder = Request::builder().method("GET").uri(url);
    if !token.is_empty() {
        builder = builder.header("x-lagran-agent-token", token);
    }
    let req = builder
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

async fn fetch_json<T: for<'de> Deserialize<'de>>(
    client: &Client<HttpConnector, Full<Bytes>>,
    url: &str,
    token: &str,
) -> Result<T, String> {
    let mut builder = Request::builder().method("GET").uri(url);
    if !token.is_empty() {
        builder = builder.header("x-lagran-agent-token", token);
    }
    let req = builder
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
