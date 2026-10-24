//! Load TLS material into CertStore (hot-reload, multi-domain SNI)

use crate::config::EdgeConfig;
use crate::server::cert_store::CertStore;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct EdgeCertResponse {
    domain: String,
    cert_pem: String,
    key_pem: String,
    status: String,
}
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct CertListItem {
    domain_name: String,
    status: String,
    has_cert: bool,
    has_key: bool,
    id: String,
}

pub fn spawn_cert_sync(config: EdgeConfig, store: Arc<CertStore>) {
    tokio::spawn(async move {
        if let (Some(cert), Some(key)) = (&config.tls_cert_file, &config.tls_key_file) {
            let cp = PathBuf::from(cert);
            let kp = PathBuf::from(key);
            if cp.exists() && kp.exists() {
                match (tokio::fs::read(&cp).await, tokio::fs::read(&kp).await) {
                    (Ok(c), Ok(k)) => {
                        let names = if config.domain.is_empty() {
                            vec!["localhost".into()]
                        } else {
                            vec![config.domain.clone()]
                        };
                        if let Err(e) = store.upsert(&names, &c, &k) {
                            tracing::error!(error = %e, "local TLS load failed");
                        } else {
                            tracing::info!("local TLS loaded into CertStore");
                        }
                    }
                    (e1, e2) => tracing::error!(?e1, ?e2, "read local TLS files"),
                }
            }
        }

        if config.control_url.is_empty() {
            return;
        }

        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        let mut last: String = String::new();
        loop {
            // Single domain path
            if !config.domain.is_empty() {
                let url = format!(
                    "{}/api/v1/certs/by-domain/{}",
                    config.control_url.trim_end_matches('/'),
                    config.domain
                );
                if let Ok(cert) = fetch_cert(&client, &url).await {
                    if cert.status == "active" && !cert.cert_pem.is_empty() {
                        let fp = format!("{}:{}", cert.cert_pem.len(), cert.key_pem.len());
                        if fp != last {
                            let names = vec![cert.domain.clone()];
                            if let Err(e) = store.upsert(
                                &names,
                                cert.cert_pem.as_bytes(),
                                cert.key_pem.as_bytes(),
                            ) {
                                tracing::error!(error = %e, "apply cert failed");
                            } else {
                                tracing::info!(domain = %cert.domain, "cert hot-updated from control");
                                last = fp;
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}

async fn fetch_cert(
    client: &Client<HttpConnector, Full<Bytes>>,
    url: &str,
) -> Result<EdgeCertResponse, String> {
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
