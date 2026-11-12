//! Scheduled cache-warm persistence.

use chrono::{DateTime, Utc};
use sqlx::types::Json;
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PrefetchScheduleRow {
    pub id: Uuid,
    pub domain: String,
    pub paths: Json<Vec<String>>,
    pub headers: Json<HashMap<String, String>>,
    pub interval_minutes: i32,
    pub enabled: bool,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PrefetchTaskRow {
    pub id: Uuid,
    pub domain: String,
    pub url_path: String,
    pub headers: Json<HashMap<String, String>>,
    pub status: String,
    pub message: String,
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

pub async fn list_prefetch_schedules(pool: &PgPool) -> sqlx::Result<Vec<PrefetchScheduleRow>> {
    sqlx::query_as::<_, PrefetchScheduleRow>(
        r#"
        SELECT id, domain, paths, headers, interval_minutes, enabled,
               last_run_at, next_run_at, created_at
        FROM prefetch_schedules
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn create_prefetch_schedule(
    pool: &PgPool,
    domain: &str,
    paths: &[String],
    headers: &HashMap<String, String>,
    interval_minutes: i32,
) -> sqlx::Result<PrefetchScheduleRow> {
    sqlx::query_as::<_, PrefetchScheduleRow>(
        r#"
        INSERT INTO prefetch_schedules (domain, paths, headers, interval_minutes, next_run_at)
        VALUES ($1, $2, $3, $4, NOW())
        RETURNING id, domain, paths, headers, interval_minutes, enabled,
                  last_run_at, next_run_at, created_at
        "#,
    )
    .bind(domain)
    .bind(Json(paths.to_vec()))
    .bind(Json(headers.clone()))
    .bind(interval_minutes)
    .fetch_one(pool)
    .await
}

pub async fn get_prefetch_schedule(
    pool: &PgPool,
    id: Uuid,
) -> sqlx::Result<Option<PrefetchScheduleRow>> {
    sqlx::query_as::<_, PrefetchScheduleRow>(
        r#"
        SELECT id, domain, paths, headers, interval_minutes, enabled,
               last_run_at, next_run_at, created_at
        FROM prefetch_schedules WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn update_prefetch_schedule(
    pool: &PgPool,
    id: Uuid,
    domain: &str,
    paths: &[String],
    headers: &HashMap<String, String>,
    interval_minutes: i32,
    enabled: bool,
) -> sqlx::Result<Option<PrefetchScheduleRow>> {
    sqlx::query_as::<_, PrefetchScheduleRow>(
        r#"
        UPDATE prefetch_schedules SET
            domain = $2, paths = $3, headers = $4, interval_minutes = $5, enabled = $6,
            next_run_at = CASE WHEN $6 THEN NOW() ELSE next_run_at END,
            updated_at = NOW()
        WHERE id = $1
        RETURNING id, domain, paths, headers, interval_minutes, enabled,
                  last_run_at, next_run_at, created_at
        "#,
    )
    .bind(id)
    .bind(domain)
    .bind(Json(paths.to_vec()))
    .bind(Json(headers.clone()))
    .bind(interval_minutes)
    .bind(enabled)
    .fetch_optional(pool)
    .await
}

pub async fn delete_prefetch_schedule(pool: &PgPool, id: Uuid) -> sqlx::Result<bool> {
    let r = sqlx::query("DELETE FROM prefetch_schedules WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn due_prefetch_schedules(
    pool: &PgPool,
    limit: i64,
) -> sqlx::Result<Vec<PrefetchScheduleRow>> {
    sqlx::query_as::<_, PrefetchScheduleRow>(
        r#"
        SELECT id, domain, paths, headers, interval_minutes, enabled,
               last_run_at, next_run_at, created_at
        FROM prefetch_schedules
        WHERE enabled = TRUE AND next_run_at <= NOW()
        ORDER BY next_run_at
        LIMIT $1
        "#,
    )
    .bind(limit.clamp(1, 100))
    .fetch_all(pool)
    .await
}

pub async fn mark_prefetch_schedule_run(
    pool: &PgPool,
    id: Uuid,
    interval_minutes: i32,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        UPDATE prefetch_schedules SET
            last_run_at = NOW(),
            next_run_at = NOW() + make_interval(mins => $2),
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(interval_minutes.max(1))
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn create_prefetch_source(
    pool: &PgPool,
    domain: &str,
    path: &str,
    headers: &HashMap<String, String>,
    source: &str,
) -> sqlx::Result<Uuid> {
    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO prefetch_tasks (domain, url_path, headers, source)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        "#,
    )
    .bind(domain)
    .bind(path)
    .bind(Json(headers.clone()))
    .bind(source)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

pub async fn claim_prefetch_tasks(pool: &PgPool, limit: i64) -> sqlx::Result<Vec<PrefetchTaskRow>> {
    sqlx::query_as::<_, PrefetchTaskRow>(
        r#"
        WITH claimed AS (
            SELECT id FROM prefetch_tasks
            WHERE status = 'pending'
            ORDER BY created_at
            LIMIT $1
            FOR UPDATE SKIP LOCKED
        )
        UPDATE prefetch_tasks t
        SET status = 'running', started_at = NOW(), attempts = t.attempts + 1
        FROM claimed
        WHERE t.id = claimed.id
        RETURNING t.id, t.domain, t.url_path, t.headers, t.status, t.message,
                  t.source, t.created_at, t.finished_at
        "#,
    )
    .bind(limit.clamp(1, 100))
    .fetch_all(pool)
    .await
}

pub async fn finish_prefetch_task(
    pool: &PgPool,
    id: Uuid,
    success: bool,
    message: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        UPDATE prefetch_tasks SET
            status = CASE WHEN $2 THEN 'done' ELSE 'failed' END,
            message = $3,
            finished_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(success)
    .bind(message)
    .execute(pool)
    .await?;
    Ok(())
}

/// Reclaim tasks that were claimed but never finished.
///
/// A task is abandoned when it has been `running` longer than `stale_secs`. Such a
/// row is either retried (`pending`) or, once it has been attempted
/// `max_attempts` times, marked `failed` with a reason — the previous code left it
/// `running` forever, so it was never retried and the console showed a stuck
/// entry that no operator could clear.
///
/// Returns `(requeued, failed)`.
pub async fn reclaim_stale_prefetch_tasks(
    pool: &PgPool,
    stale_secs: i64,
    max_attempts: i32,
) -> sqlx::Result<(u64, u64)> {
    let requeued = sqlx::query(
        r#"
        UPDATE prefetch_tasks
        SET status = 'pending', started_at = NULL,
            message = 'reclaimed: previous attempt did not finish'
        WHERE status = 'running'
          AND started_at IS NOT NULL
          AND started_at < NOW() - make_interval(secs => $1)
          AND attempts < $2
        "#,
    )
    .bind(stale_secs)
    .bind(max_attempts)
    .execute(pool)
    .await?
    .rows_affected();

    let failed = sqlx::query(
        r#"
        UPDATE prefetch_tasks
        SET status = 'failed', finished_at = NOW(),
            message = 'abandoned: exceeded the retry limit'
        WHERE status = 'running'
          AND started_at IS NOT NULL
          AND started_at < NOW() - make_interval(secs => $1)
          AND attempts >= $2
        "#,
    )
    .bind(stale_secs)
    .bind(max_attempts)
    .execute(pool)
    .await?
    .rows_affected();

    Ok((requeued, failed))
}

pub async fn list_prefetch_tasks(pool: &PgPool, limit: i64) -> sqlx::Result<Vec<PrefetchTaskRow>> {
    sqlx::query_as::<_, PrefetchTaskRow>(
        r#"
        SELECT id, domain, url_path, headers, status, message, source, created_at, finished_at
        FROM prefetch_tasks
        ORDER BY created_at DESC
        LIMIT $1
        "#,
    )
    .bind(limit.clamp(1, 500))
    .fetch_all(pool)
    .await
}
