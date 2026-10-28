//! Scheduled cache-warm persistence.

use chrono::{DateTime, Utc};
use sqlx::types::Json;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PrefetchScheduleRow {
    pub id: Uuid,
    pub domain: String,
    pub paths: Json<Vec<String>>,
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
    pub status: String,
    pub message: String,
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

pub async fn list_prefetch_schedules(pool: &PgPool) -> sqlx::Result<Vec<PrefetchScheduleRow>> {
    sqlx::query_as::<_, PrefetchScheduleRow>(
        r#"
        SELECT id, domain, paths, interval_minutes, enabled,
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
    interval_minutes: i32,
) -> sqlx::Result<PrefetchScheduleRow> {
    sqlx::query_as::<_, PrefetchScheduleRow>(
        r#"
        INSERT INTO prefetch_schedules (domain, paths, interval_minutes, next_run_at)
        VALUES ($1, $2, $3, NOW())
        RETURNING id, domain, paths, interval_minutes, enabled,
                  last_run_at, next_run_at, created_at
        "#,
    )
    .bind(domain)
    .bind(Json(paths.to_vec()))
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
        SELECT id, domain, paths, interval_minutes, enabled,
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
    interval_minutes: i32,
    enabled: bool,
) -> sqlx::Result<Option<PrefetchScheduleRow>> {
    sqlx::query_as::<_, PrefetchScheduleRow>(
        r#"
        UPDATE prefetch_schedules SET
            domain = $2, paths = $3, interval_minutes = $4, enabled = $5,
            next_run_at = CASE WHEN $5 THEN NOW() ELSE next_run_at END,
            updated_at = NOW()
        WHERE id = $1
        RETURNING id, domain, paths, interval_minutes, enabled,
                  last_run_at, next_run_at, created_at
        "#,
    )
    .bind(id)
    .bind(domain)
    .bind(Json(paths.to_vec()))
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
        SELECT id, domain, paths, interval_minutes, enabled,
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
    source: &str,
) -> sqlx::Result<Uuid> {
    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO prefetch_tasks (domain, url_path, source)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
    )
    .bind(domain)
    .bind(path)
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
        UPDATE prefetch_tasks t SET status = 'running'
        FROM claimed
        WHERE t.id = claimed.id
        RETURNING t.id, t.domain, t.url_path, t.status, t.message,
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

pub async fn list_prefetch_tasks(pool: &PgPool, limit: i64) -> sqlx::Result<Vec<PrefetchTaskRow>> {
    sqlx::query_as::<_, PrefetchTaskRow>(
        r#"
        SELECT id, domain, url_path, status, message, source, created_at, finished_at
        FROM prefetch_tasks
        ORDER BY created_at DESC
        LIMIT $1
        "#,
    )
    .bind(limit.clamp(1, 500))
    .fetch_all(pool)
    .await
}
