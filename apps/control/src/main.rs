use control::api;
use control::config::AppConfig;
use control::repository;
use control::state::AppState;
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "control=debug,tower_http=debug,sqlx=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = AppConfig::load();
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

    repository::ensure_demo_user(&pool).await?;
    repository::ensure_demo_domain(&pool).await?;

    // Background: mark nodes offline if heartbeat is stale
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

    let addr = config.bind_addr();
    let state = AppState::new(pool, config);
    let app = api::create_router(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Control plane listening on http://{}", addr);
    tracing::info!("Demo login: demo@lagran.dev / demo123");

    axum::serve(listener, app).await?;
    Ok(())
}
