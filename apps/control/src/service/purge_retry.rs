//! Durable purge retry worker.
//!
//! Purges are dispatched to online nodes immediately. Failures (including
//! offline nodes) are persisted and retried with exponential backoff so a node
//! that comes back later still receives the invalidation.

use crate::repository;
use crate::service::agent_http;
use sqlx::PgPool;
use std::time::Duration;

pub fn spawn(pool: PgPool, fallback_token: String) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = run_once(&pool, &fallback_token).await {
                tracing::warn!(error = %e, "purge retry worker failed");
            }
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    });
}

async fn run_once(pool: &PgPool, fallback_token: &str) -> Result<(), sqlx::Error> {
    let rows = repository::due_purge_retries(pool, 50).await?;
    for row in rows {
        if row.attempts >= 9 {
            repository::finish_purge_retry(pool, row.id).await?;
            tracing::error!(node = %row.node_id, attempts = row.attempts, "purge retry exhausted; dropping");
            continue;
        }
        let token = if row.auth_token.is_empty() {
            fallback_token.to_string()
        } else {
            row.auth_token.clone()
        };
        let url = format!("{}/__lagran/purge", row.agent_url.trim_end_matches('/'));
        match agent_http::request_json::<serde_json::Value, _>(
            "POST",
            &url,
            &row.payload.0,
            &token,
        )
        .await
        {
            Ok(_) => {
                repository::finish_purge_retry(pool, row.id).await?;
                tracing::info!(node = %row.node_id, "purge retry delivered");
            }
            Err(e) => {
                repository::defer_purge_retry(pool, row.id, row.attempts, &e).await?;
                tracing::warn!(node = %row.node_id, error = %e, attempts = row.attempts + 1, "purge retry deferred");
            }
        }
    }
    Ok(())
}
