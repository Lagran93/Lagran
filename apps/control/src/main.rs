use control::api;
use control::config::AppConfig;
use control::repository;
use control::state::AppState;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn is_http_url(value: &str) -> bool {
    (value.starts_with("http://") || value.starts_with("https://"))
        && !value.chars().any(char::is_whitespace)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls may be built with multiple provider features (ring + aws-lc-rs),
    // which leaves no automatic process-level provider. Pick ring explicitly
    // before any TLS client (ACME / hyper-rustls) is constructed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Load .env BEFORE EnvFilter reads RUST_LOG
    let _ = dotenvy::dotenv();

    if handle_cli().await? {
        return Ok(());
    }

    let config = AppConfig::load();
    if !config.public_url.is_empty() && !is_http_url(&config.public_url) {
        anyhow::bail!(
            "CONTROL_PUBLIC_URL must start with http:// or https:// (got {:?})",
            config.public_url
        );
    }
    let tracer_provider = init_tracing(&config);
    const DEFAULT_JWT: &str = "lagran-dev-secret-change-me";
    if config.jwt_secret == DEFAULT_JWT || config.jwt_secret.len() < 16 {
        if config.require_secure_secrets {
            anyhow::bail!(
                "JWT_SECRET is missing or uses the insecure default; set a strong secret or disable REQUIRE_SECURE_SECRETS for local dev"
            );
        }
        tracing::warn!(
            "JWT_SECRET is the built-in default or too short — do not use this in production"
        );
    }
    if control::waf_rulepack::signing_key(&config.waf_rulepack_secret).is_none() {
        if config.require_secure_secrets {
            anyhow::bail!(
                "WAF_RULEPACK_SECRET is not set; signed WAF rulepacks cannot be trusted. Set WAF_RULEPACK_SECRET (and the same value on every edge) or disable REQUIRE_SECURE_SECRETS for local dev"
            );
        }
        tracing::warn!(
            "WAF_RULEPACK_SECRET is not set — edges reject unsigned rulepacks, so managed rulepack updates will not be applied; set it in production"
        );
    }
    if config.agent_token.is_empty() {
        tracing::warn!(
            "AGENT_TOKEN is empty; edge→control agent routes still require per-node tokens, but schedule/DNS global auth is weakened"
        );
    }
    if !config.cors_allowed_origins.is_empty() {
        tracing::info!(
            origins = %config.cors_allowed_origins.join(","),
            "CORS restricted to the configured origins"
        );
    }
    if config.allow_register {
        tracing::warn!("ALLOW_REGISTER=true — open self-registration is enabled");
    }
    tracing::info!("connecting to database...");

    let max_connections = config.database_max_connections.max(2);
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(config.database_min_connections.min(max_connections))
        .acquire_timeout(std::time::Duration::from_secs(
            config.database_acquire_timeout_secs,
        ))
        .connect(&config.database_url)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to connect to database (is postgres up?): {e}\n\
                 DATABASE_URL={}",
                config.database_url
            )
        })?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("migrations applied");

    match control::waf_rulepack::signing_key(&config.waf_rulepack_secret) {
        Some(secret) => {
            match control::waf_rulepack::ensure_seed(&pool, &secret).await {
                Ok(row) => tracing::info!(
                    version = %row.version,
                    slot = %row.slot,
                    "WAF rulepack ready"
                ),
                Err(e) => tracing::warn!(error = %e, "failed to seed WAF rulepack"),
            }
            // The previous slot is deliverable too (pinned domains, grey
            // rollout), so it must also verify with the current key.
            if let Err(e) = control::waf_rulepack::ensure_all_signed(&pool, &secret).await {
                tracing::warn!(error = %e, "failed to re-sign WAF rulepacks");
            }
        }
        None => tracing::warn!("skipping WAF rulepack seed: WAF_RULEPACK_SECRET is not set"),
    }

    if config.seed_demo {
        // Refuse to create the well-known account when secure secrets are
        // enforced: that combination is either a production host or a mistake.
        if config.require_secure_secrets {
            anyhow::bail!(
                "SEED_DEMO=true is incompatible with REQUIRE_SECURE_SECRETS=true: the demo \
                 account has a published password. Set SEED_DEMO=false"
            );
        }
        repository::ensure_demo_user(&pool).await?;
        repository::ensure_demo_domain(&pool).await?;
    } else {
        tracing::info!("SEED_DEMO=false — skipping demo user/domain seed");
    }

    {
        let pool = pool.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                tick.tick().await;
                match control::repository::mark_stale_nodes_offline(&pool, 60).await {
                    Ok(n) if n > 0 => tracing::info!(count = n, "marked stale nodes offline"),
                    Err(e) => tracing::warn!(error = %e, "stale node check failed"),
                    _ => {}
                }
            }
        });
    }

    // Background: retention for access_logs / edge_metrics
    if config.log_retention_days > 0 {
        let pool = pool.clone();
        let days = config.log_retention_days;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                tick.tick().await;
                match control::repository::purge_old_telemetry(&pool, days).await {
                    Ok((a, m)) if a > 0 || m > 0 => {
                        tracing::info!(
                            access_logs = a,
                            metrics = m,
                            days,
                            "telemetry retention purge"
                        )
                    }
                    Err(e) => tracing::warn!(error = %e, "telemetry retention failed"),
                    _ => {}
                }
                match control::repository::purge_old_login_logs(&pool, days).await {
                    Ok(n) if n > 0 => {
                        tracing::info!(login_logs = n, days, "login log retention purge")
                    }
                    Err(e) => tracing::warn!(error = %e, "login log retention failed"),
                    _ => {}
                }
            }
        });
    }

    let addr = config.bind_addr();
    let seed_demo = config.seed_demo;
    let alert_eval_secs = config.alert_eval_secs;
    let redis = if config.redis_url.trim().is_empty() {
        tracing::info!("REDIS_URL not set; using local/PostgreSQL fallbacks");
        None
    } else {
        match control::service::redis::RedisService::connect(config.redis_url.trim()).await {
            Ok(redis) => {
                tracing::info!("connected to Redis");
                Some(std::sync::Arc::new(redis))
            }
            Err(e) => {
                tracing::warn!(error = %e, "Redis unavailable; using local/PostgreSQL fallbacks");
                None
            }
        }
    };
    let state = AppState::new(pool, config, redis);
    control::service::alerting::spawn(
        state.pool.clone(),
        alert_eval_secs,
        state.redis.clone(),
    );
    control::service::prefetch::spawn(state.clone(), 15);
    control::service::config_release::spawn(state.clone(), 10);
    control::service::purge_retry::spawn(
        state.pool.clone(),
        state.config.agent_token.clone(),
    );
    {
        let state = state.clone();
        tokio::spawn(async move {
            control::service::config_version::backfill_missing(&state.pool).await;
        });
    }

    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
            loop {
                tick.tick().await;
                let renewed = control::acme::renew_due(&state).await;
                if renewed > 0 {
                    tracing::info!(renewed, "Let's Encrypt auto-renewal completed");
                }
            }
        });
    }

    let app = api::create_router(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Control plane listening on http://{}", addr);
    if seed_demo {
        tracing::warn!(
            "SEED_DEMO=true: a demo@lagran.dev account with a well-known password exists. \
             Never enable this on a public deployment"
        );
    }

    axum::serve(listener, app).await?;
    if let Some(provider) = tracer_provider {
        let _ = provider.shutdown();
    }
    Ok(())
}

/// Handle management subcommands before starting HTTP/TLS/DB background work.
/// Returning `true` means the command completed and the process must exit.
async fn handle_cli() -> anyhow::Result<bool> {
    let command = std::env::args().nth(1);
    let command = command.as_deref().unwrap_or("serve");
    match command {
        "version" | "-V" | "--version" => {
            println!("lagran-control {} ({})", control::version::VERSION, control::version::GIT_HASH);
            Ok(true)
        }
        "help" | "-h" | "--help" => {
            print_help();
            Ok(true)
        }
        "check-config" | "config-check" => {
            let config = AppConfig::load();
            check_config(&config)?;
            Ok(true)
        }
        "migrate" | "db-migrate" => {
            let config = AppConfig::load();
            check_config(&config)?;
            migrate(&config).await?;
            Ok(true)
        }
        "health" => {
            let config = AppConfig::load();
            health(&config).await?;
            Ok(true)
        }
        "serve" => Ok(false),
        other => {
            anyhow::bail!(
                "unknown command {other:?}\n\n{}",
                help_text()
            );
        }
    }
}

fn check_config(config: &AppConfig) -> anyhow::Result<()> {
    if !config.public_url.is_empty() && !is_http_url(&config.public_url) {
        anyhow::bail!(
            "CONTROL_PUBLIC_URL must start with http:// or https:// (got {:?})",
            config.public_url
        );
    }
    const DEFAULT_JWT: &str = "lagran-dev-secret-change-me";
    if config.jwt_secret == DEFAULT_JWT || config.jwt_secret.len() < 16 {
        if config.require_secure_secrets {
            anyhow::bail!(
                "JWT_SECRET is missing or uses the insecure default; set a strong secret or disable REQUIRE_SECURE_SECRETS"
            );
        }
        eprintln!("warning: JWT_SECRET is the built-in default or too short");
    }
    if config.agent_token.is_empty() {
        eprintln!("warning: AGENT_TOKEN is empty; agent endpoints are weaker");
    }
    println!("config: ok");
    println!("bind: {}", config.bind_addr());
    println!("public_url: {}", if config.public_url.is_empty() { "(derive from request)".to_string() } else { config.public_url.clone() });
    println!("database: configured");
    println!("database_pool: {}..{}", config.database_min_connections, config.database_max_connections);
    println!("redis: {}", if config.redis_url.trim().is_empty() { "disabled" } else { "configured" });
    println!("agent_token: {}", if config.agent_token.is_empty() { "empty" } else { "set" });
    println!("jwt_secret: {}", if config.jwt_secret.len() >= 16 { "set" } else { "weak" });
    println!("jwt_expire_hours: {}", config.jwt_expire_hours);
    println!("allow_register: {}", config.allow_register);
    println!("captcha_enabled: {}", config.captcha_enabled);
    Ok(())
}

async fn migrate(config: &AppConfig) -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections.max(2))
        .connect(&config.database_url)
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to database: {e}"))?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    println!("migrations: applied");
    Ok(())
}

async fn health(config: &AppConfig) -> anyhow::Result<()> {
    let url = std::env::var("CONTROL_HEALTH_URL").unwrap_or_else(|_| {
        let bind = config.bind_addr();
        let host_port = bind
            .rsplit_once(':')
            .map(|(_, port)| format!("127.0.0.1:{port}"))
            .unwrap_or(bind);
        format!("http://{host_port}/health")
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let response = client.get(&url).send().await?;
    let status = response.status();
    println!("health: {} {}", status.as_u16(), status.canonical_reason().unwrap_or(""));
    if !status.is_success() {
        anyhow::bail!("control health check failed: HTTP {}", status.as_u16());
    }
    Ok(())
}

fn help_text() -> &'static str {
    "Lagran Control\n\nUsage:\n  lagran-control [serve]\n  lagran-control check-config\n  lagran-control migrate\n  lagran-control health\n  lagran-control version\n  lagran-control help\n\nEnvironment:\n  CONTROL_BIND, DATABASE_URL, JWT_SECRET, AGENT_TOKEN\n  CONTROL_HEALTH_URL  override health check URL\n"
}

fn print_help() {
    println!("{}", help_text());
}

fn init_tracing(config: &AppConfig) -> Option<SdkTracerProvider> {
    // Prefer RUST_LOG from environment (including values loaded from .env above).
    // Examples:
    //   RUST_LOG=debug
    //   RUST_LOG=control=debug,tower_http=info,sqlx=warn
    //   RUST_LOG=info,control::api=debug
    let mut filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // Default when RUST_LOG is unset or invalid
        tracing_subscriber::EnvFilter::new("control=debug,tower_http=info,sqlx=warn")
    });
    if !config.otel_endpoint.trim().is_empty() {
        // Trace export must not silently depend on the operator's RUST_LOG level.
        if let Ok(directive) = "control::api=info".parse() {
            filter = filter.add_directive(directive);
        }
    }

    let registry = tracing_subscriber::registry().with(filter).with(
        tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_level(true),
    );

    if config.otel_endpoint.trim().is_empty() {
        registry.init();
        return None;
    }

    let exporter = match SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpJson)
        .with_endpoint(config.otel_endpoint.trim())
        .with_timeout(Duration::from_secs(10))
        .build()
    {
        Ok(exporter) => exporter,
        Err(e) => {
            tracing::warn!(error = %e, "OpenTelemetry exporter disabled");
            registry.init();
            return None;
        }
    };
    let resource = Resource::builder()
        .with_service_name(config.otel_service_name.clone())
        .with_attribute(KeyValue::new("deployment.environment", "production"))
        .build();
    let provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            config.otel_sample_ratio,
        ))))
        .with_batch_exporter(exporter)
        .build();
    let tracer = provider.tracer("lagran-control");
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );
    registry
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .init();
    tracing::info!(
        endpoint = %config.otel_endpoint,
        service = %config.otel_service_name,
        "OpenTelemetry trace export enabled"
    );
    Some(provider)
}
