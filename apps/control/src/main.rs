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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls may be built with multiple provider features (ring + aws-lc-rs),
    // which leaves no automatic process-level provider. Pick ring explicitly
    // before any TLS client (ACME / hyper-rustls) is constructed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Load .env BEFORE EnvFilter reads RUST_LOG
    let _ = dotenvy::dotenv();

    let config = AppConfig::load();
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
    if config.agent_token.is_empty() {
        tracing::warn!(
            "AGENT_TOKEN is empty; edge→control agent routes still require per-node tokens, but schedule/DNS global auth is weakened"
        );
    }
    if config.allow_register {
        tracing::warn!("ALLOW_REGISTER=true — open self-registration is enabled");
    }
    tracing::info!("connecting to database...");

    let pool = PgPoolOptions::new()
        .max_connections(10)
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

    if config.seed_demo {
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
            }
        });
    }

    let addr = config.bind_addr();
    let seed_demo = config.seed_demo;
    let alert_eval_secs = config.alert_eval_secs;
    let state = AppState::new(pool, config);
    control::service::alerting::spawn(state.pool.clone(), alert_eval_secs);

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
        tracing::info!("Demo login: demo@lagran.dev / demo123");
    }

    axum::serve(listener, app).await?;
    if let Some(provider) = tracer_provider {
        let _ = provider.shutdown();
    }
    Ok(())
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
