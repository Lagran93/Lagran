use edge::agent::{self, access_report, cert_sync, config_sync, metrics_report, origin_health};
use edge::cache::{self, policy::RuleSet};
use edge::config::registry::DomainRegistry;
use edge::config::EdgeConfig;
use edge::metrics::EdgeMetrics;
use edge::origin::OriginClient;
use edge::server::access_log::AccessLog;
use edge::server::handler::AppState;
use edge::server::inflight::Inflight;
use edge::server::{listener, tls};
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
    let large_cache = if config.large_cache_enabled {
        Some(
            edge::cache::LargeCache::open(
                &config.large_cache_dir,
                config.large_cache_min_object_bytes,
                config.large_cache_max_object_bytes,
                config.large_cache_max_bytes,
            )
            .await?,
        )
    } else {
        None
    };
    let origin = OriginClient::new(config.origin_url.clone());
    let rules = RuleSet::new();
    let metrics = EdgeMetrics::new();
    let cert_store = Arc::new(edge::server::cert_store::CertStore::with_persist_dir(
        &config.cert_dir,
    ));
    if !cert_store.is_empty() {
        tracing::info!(
            count = cert_store.len(),
            "HTTPS can start with disk-loaded certs"
        );
    }
    let challenges = edge::server::acme_challenge::ChallengeStore::new();
    let access_log = AccessLog::open(
        config.access_log_path.as_deref(),
        &config.node_id,
        config.access_log_buffer,
        config.access_log_json,
    )
    .await;
    let rate_limiter = edge::server::rate_limit::RateLimiter::new(
        std::env::var("RATE_LIMIT_RPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        std::env::var("RATE_LIMIT_BURST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    );
    let origin_health_map = origin_health::OriginHealthMap::new();
    let domains = DomainRegistry::new();
    let control = agent::ControlClient::new(&config);
    let node_control = agent::NodeControl::new();
    let waf_log = edge::server::waf_log::WafLog::new(&config.node_id, 2000);
    let challenge_secret = if !config.challenge_secret.is_empty() {
        config.challenge_secret.clone()
    } else if !config.agent_token.is_empty() {
        format!("{}-challenge", config.agent_token)
    } else {
        random_secret()
    };

    if config.challenge_secret.is_empty() {
        tracing::warn!(
            "CHALLENGE_SECRET is empty; clearance/nonce signatures fall back to AGENT_TOKEN or a random per-process secret. Multi-edge or restart-stable challenge requires an explicit shared CHALLENGE_SECRET."
        );
    }

    agent::spawn_heartbeat(config.clone(), control.clone(), node_control.clone());
    config_sync::spawn_config_sync(
        config.clone(),
        control.clone(),
        origin.clone(),
        rules.clone(),
        domains.clone(),
    );
    metrics_report::spawn_metrics_report(config.clone(), control.clone(), metrics.clone());
    access_report::spawn_access_report(config.clone(), control.clone(), access_log.clone());
    origin_health::spawn_origin_health(
        control.clone(),
        domains.clone(),
        origin.clone(),
        origin_health_map.clone(),
    );
    cert_sync::spawn_cert_sync(config.clone(), control.clone(), cert_store.clone());
    if config.waf_report {
        agent::waf_report::spawn_waf_report(
            control.clone(),
            waf_log.clone(),
            config.waf_report_interval_secs,
        );
    }

    let cc = if config.redis_url.trim().is_empty() {
        edge::server::cc::CcProtector::new()
    } else {
        match edge::server::cc::RedisCc::connect(&config.redis_url).await {
            Ok(redis) => {
                tracing::info!("CC distributed sliding-window counter enabled");
                edge::server::cc::CcProtector::with_redis(Some(redis))
            }
            Err(e) => {
                tracing::warn!(error = %e, "CC Redis unavailable; falling back to in-process counters");
                edge::server::cc::CcProtector::new()
            }
        }
    };

    let state = Arc::new(AppState {
        cache,
        large_cache,
        origin,
        default_ttl_secs: config.default_ttl_secs,
        rules,
        metrics,
        challenges,
        certs: cert_store.clone(),
        domains,
        access_log,
        rate_limiter,
        cc,
        control: control.clone(),
        origin_health: origin_health_map,
        agent_token: config.agent_token.clone(),
        inflight: Inflight::default(),
        waf_log,
        // Pingora overwrites X-Forwarded-For/Proto with the real downstream
        // peer, and the engine is bound only to loopback.
        trust_proxy_headers: true,
        challenge_secret,
        node_control,
        https_redirect_port: config.https_redirect_port,
        max_cacheable_body: config.max_cacheable_body,
    });

    agent::cc_sync::spawn_cc_sync(config.clone(), control.clone(), state.cc.clone());

    let admin_listen = config.admin_listen_addr.clone();
    if let Some(ref admin) = admin_listen {
        if admin == &config.listen_addr {
            anyhow::bail!("EDGE_ADMIN_LISTEN must differ from EDGE_LISTEN");
        }
    }

    // The existing cache/WAF/CC engine stays on a loopback-only Axum listener.
    // Pingora owns the public listener and forwards every data-plane request to
    // this private upstream. When EDGE_ADMIN_LISTEN is unset, management also
    // stays on the data listener for backward compatibility.
    if let Some(admin) = admin_listen {
        let admin_addr: SocketAddr = admin.parse()?;
        let admin_app = listener::create_admin_router(state.clone());
        tracing::info!(admin = %admin_addr, "edge management listener started");
        tokio::spawn(async move {
            if let Err(e) = tls::serve_http(admin_addr, admin_app).await {
                tracing::error!(error = %e, "management listener stopped");
            }
        });
    }

    let pingora_config = config.clone();
    let pingora_certs = cert_store.clone();
    let pingora_state = state.clone();
    std::thread::Builder::new()
        .name("lagran-pingora".into())
        .spawn(move || {
            if let Err(e) = edge::pingora_edge::run(pingora_config, pingora_certs, pingora_state) {
                tracing::error!(error = %e, "Pingora listener stopped");
                std::process::exit(1);
            }
        })?;

    // Keep the Tokio runtime alive for background agents and the optional
    // admin listener; Pingora runs its own runtime on the spawned thread.
    std::future::pending::<()>().await;
    Ok(())
}

fn random_secret() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut buf = [0u8; 32];
    if SystemRandom::new().fill(&mut buf).is_ok() {
        buf.iter().map(|b| format!("{b:02x}")).collect()
    } else {
        format!(
            "{:x}{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        )
    }
}

fn init_tracing() {
    // RUST_LOG examples:
    //   RUST_LOG=debug
    //   RUST_LOG=edge=debug,tower_http=info
    //   RUST_LOG=info,edge::server=debug,edge::agent=debug
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("edge=debug,tower_http=info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_level(true),
        )
        .init();
}
