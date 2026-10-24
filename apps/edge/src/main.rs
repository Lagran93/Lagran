use edge::agent::{self, access_report, cert_sync, config_sync, metrics_report, origin_health};
use edge::cache::{self, policy::RuleSet};
use edge::config::registry::DomainRegistry;
use edge::config::EdgeConfig;
use edge::metrics::EdgeMetrics;
use edge::origin::OriginClient;
use edge::server::access_log::AccessLog;
use edge::server::rate_limit::RateLimiter;
use edge::agent::origin_health::OriginHealthMap;
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
    // Load .env BEFORE EnvFilter reads RUST_LOG
    let _ = dotenvy::dotenv();
    init_tracing();

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
    let access_log = AccessLog::open(
        config.access_log_path.as_deref(),
        &config.node_id,
        config.access_log_buffer,
        config.access_log_json,
    )
    .await;
    let rate_limiter = RateLimiter::new(
        std::env::var("RATE_LIMIT_RPS").ok().and_then(|v| v.parse().ok()).unwrap_or(0),
        std::env::var("RATE_LIMIT_BURST").ok().and_then(|v| v.parse().ok()).unwrap_or(0),
    );
    let origin_health_map = OriginHealthMap::new();
    let domains = DomainRegistry::new();

    agent::spawn_heartbeat(config.clone());
    config_sync::spawn_config_sync(
        config.clone(),
        origin.clone(),
        rules.clone(),
        domains.clone(),
    );
    metrics_report::spawn_metrics_report(config.clone(), metrics.clone());
    access_report::spawn_access_report(config.clone(), access_log.clone());
    origin_health::spawn_origin_health(
        config.clone(),
        domains.clone(),
        origin.clone(),
        origin_health_map.clone(),
    );
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
        access_log,
        rate_limiter,
        origin_health: origin_health_map,
        agent_token: config.agent_token.clone(),
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

fn init_tracing() {
    // RUST_LOG examples:
    //   RUST_LOG=debug
    //   RUST_LOG=edge=debug,tower_http=info
    //   RUST_LOG=info,edge::server=debug,edge::agent=debug
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("edge=debug,tower_http=info")
    });
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_level(true),
        )
        .init();
}
