use control::api;
use control::config::AppConfig;
use control::repository;
use control::state::AppState;
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls may be built with multiple provider features (ring + aws-lc-rs),
    // which leaves no automatic process-level provider. Pick ring explicitly
    // before any TLS client (ACME / hyper-rustls) is constructed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Load .env BEFORE EnvFilter reads RUST_LOG
    let _ = dotenvy::dotenv();

    init_tracing();

    let config = AppConfig::load();
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
    let state = AppState::new(pool, config);

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
    Ok(())
}

fn init_tracing() {
    // Prefer RUST_LOG from environment (including values loaded from .env above).
    // Examples:
    //   RUST_LOG=debug
    //   RUST_LOG=control=debug,tower_http=info,sqlx=warn
    //   RUST_LOG=info,control::api=debug
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // Default when RUST_LOG is unset or invalid
        tracing_subscriber::EnvFilter::new("control=debug,tower_http=info,sqlx=warn")
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
