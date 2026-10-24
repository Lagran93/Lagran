use edge::agent::{self, cert_sync, config_sync, metrics_report};
use edge::cache::{self, policy::RuleSet};
use edge::config::registry::DomainRegistry;
use edge::config::EdgeConfig;
use edge::metrics::EdgeMetrics;
use edge::origin::OriginClient;
use edge::server::acme_challenge::ChallengeStore;
use edge::server::cert_store::CertStore;
use edge::server::handler::AppState;
use edge::server::listener;
use edge::server::tls;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lagran_edge=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = EdgeConfig::load();
    tracing::info!(
        http = %config.listen_addr,
        https = ?config.https_listen_addr,
        cache = %config.cache_backend,
        domain = %config.domain,
        "Lagran Edge starting (multi-domain + disk cache)"
    );

    let cache = cache::build_cache(&config).await?;
    let origin = OriginClient::new(config.origin_url.clone());
    let rules = RuleSet::new();
    let metrics = EdgeMetrics::new();
    let cert_store = Arc::new(CertStore::new());
    let challenges = ChallengeStore::new();
    let domains = DomainRegistry::new();

    agent::spawn_heartbeat(config.clone());
    config_sync::spawn_config_sync(
        config.clone(),
        origin.clone(),
        rules.clone(),
        domains.clone(),
    );
    metrics_report::spawn_metrics_report(config.clone(), metrics.clone());
    cert_sync::spawn_cert_sync(config.clone(), cert_store.clone());

    let state = Arc::new(AppState {
        cache,
        origin,
        default_ttl_secs: config.default_ttl_secs,
        rules,
        metrics,
        challenges,
        certs: cert_store.clone(),
        domains,
    });

    let app = listener::create_router(state);

    let http_addr: SocketAddr = config.listen_addr.parse()?;
    let http_app = app.clone();
    let http_handle = tokio::spawn(async move {
        if let Err(e) = tls::serve_http(http_addr, http_app).await {
            tracing::error!(error = %e, "HTTP stopped");
        }
    });

    let https_handle = if let Some(ref https) = config.https_listen_addr {
        let https_addr: SocketAddr = https.parse()?;
        let https_app = app.clone();
        let store = cert_store.clone();
        Some(tokio::spawn(async move {
            for _ in 0..60 {
                if store.len() > 0 {
                    break;
                }
                tracing::info!("waiting for certificate before HTTPS bind…");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            if let Err(e) = tls::serve_https(https_addr, https_app, store).await {
                tracing::error!(error = %e, "HTTPS stopped");
            }
        }))
    } else {
        None
    };

    http_handle.await.ok();
    if let Some(h) = https_handle {
        h.await.ok();
    }
    Ok(())
}
