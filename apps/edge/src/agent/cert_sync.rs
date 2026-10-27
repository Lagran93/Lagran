//! Pull TLS certs from control plane (bulk + per-domain) and hot-load

use crate::agent::ControlClient;
use crate::config::EdgeConfig;
use crate::server::cert_store::CertStore;
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

pub fn spawn_cert_sync(config: EdgeConfig, control: ControlClient, store: Arc<CertStore>) {
    tokio::spawn(async move {
        let mut etag: Option<String> = None;
        // Immediate sync on startup so HTTPS can bind without re-issue.
        if let Err(e) = sync_once(&control, &config, &store, &mut etag).await {
            tracing::warn!(error = %e, "initial cert sync failed (will retry)");
        }

        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            if let Err(e) = sync_once(&control, &config, &store, &mut etag).await {
                tracing::debug!(error = %e, "cert sync tick failed");
            }
        }
    });
}

async fn sync_once(
    control: &ControlClient,
    config: &EdgeConfig,
    store: &Arc<CertStore>,
    etag: &mut Option<String>,
) -> Result<(), String> {
    let mut applied = 0u32;

    // 1) Bulk active certs
    match control
        .get_json_conditional::<Vec<EdgeCertResponse>>(
            "/api/v1/certs/edge-sync",
            etag.as_deref(),
        )
        .await
    {
        Ok(conditional) => {
            if let Some(new_etag) = conditional.etag {
                *etag = Some(new_etag);
            }
            if let Some(list) = conditional.value {
                for cert in list {
                    if cert.status != "active" && !cert.status.is_empty() {
                        continue;
                    }
                    if cert.cert_pem.is_empty() || cert.key_pem.is_empty() {
                        continue;
                    }
                    match store.upsert(
                        std::slice::from_ref(&cert.domain),
                        cert.cert_pem.as_bytes(),
                        cert.key_pem.as_bytes(),
                    ) {
                        Ok(()) => {
                            applied += 1;
                            tracing::debug!(domain = %cert.domain, "cert applied from edge-sync");
                        }
                        Err(e) => {
                            tracing::warn!(domain = %cert.domain, error = %e, "cert apply failed")
                        }
                    }
                }
            } else {
                tracing::debug!("edge cert bundle not modified (304)");
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "edge-sync unavailable, try single domain");
        }
    }

    // 2) Fallback: EDGE_DOMAIN single fetch
    if !config.domain.is_empty() {
        let path = format!("/api/v1/certs/by-domain/{}", config.domain);
        if let Ok(cert) = control.get_json::<EdgeCertResponse>(&path).await {
            if (cert.status == "active" || cert.status.is_empty())
                && !cert.cert_pem.is_empty()
                && !cert.key_pem.is_empty()
                && store
                    .upsert(
                        std::slice::from_ref(&cert.domain),
                        cert.cert_pem.as_bytes(),
                        cert.key_pem.as_bytes(),
                    )
                    .is_ok()
            {
                applied += 1;
            }
        }
    }

    if applied > 0 {
        tracing::info!(applied, total = store.len(), "cert sync done");
    }
    Ok(())
}
