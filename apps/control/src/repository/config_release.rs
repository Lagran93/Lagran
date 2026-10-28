//! Config version + staged release persistence.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConfigVersionRow {
    pub id: Uuid,
    pub domain_id: Uuid,
    pub domain_name: String,
    pub version: i32,
    pub snapshot: Value,
    pub diff: Value,
    pub action: String,
    pub actor: String,
    pub message: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConfigReleaseRow {
    pub id: Uuid,
    pub status: String,
    pub versions: Value,
    pub previous_versions: Value,
    pub target_nodes: Value,
    pub target_domains: Value,
    pub note: String,
    pub created_by: String,
    pub approved_by: String,
    pub error: String,
    pub created_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
    pub published_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

pub async fn latest_version(
    pool: &PgPool,
    domain_id: Uuid,
) -> sqlx::Result<Option<ConfigVersionRow>> {
    sqlx::query_as::<_, ConfigVersionRow>(
        r#"
        SELECT id, domain_id, domain_name, version, snapshot, diff,
               action, actor, message, created_at
        FROM config_versions
        WHERE domain_id = $1
        ORDER BY version DESC
        LIMIT 1
        "#,
    )
    .bind(domain_id)
    .fetch_optional(pool)
    .await
}

pub async fn insert_version(
    pool: &PgPool,
    domain_id: Uuid,
    domain_name: &str,
    snapshot: &Value,
    diff: &Value,
    action: &str,
    actor: &str,
    message: &str,
) -> sqlx::Result<ConfigVersionRow> {
    let mut tx = pool.begin().await?;
    // Serialise version allocation for one domain.
    sqlx::query("SELECT 1 FROM domains WHERE id = $1 FOR UPDATE")
        .bind(domain_id)
        .execute(&mut *tx)
        .await?;
    let version: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM config_versions WHERE domain_id = $1",
    )
    .bind(domain_id)
    .fetch_one(&mut *tx)
    .await?;
    let row = sqlx::query_as::<_, ConfigVersionRow>(
        r#"
        INSERT INTO config_versions
            (domain_id, domain_name, version, snapshot, diff, action, actor, message)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, domain_id, domain_name, version, snapshot, diff,
                  action, actor, message, created_at
        "#,
    )
    .bind(domain_id)
    .bind(domain_name)
    .bind(version)
    .bind(snapshot)
    .bind(diff)
    .bind(action)
    .bind(actor)
    .bind(message)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}

pub async fn list_versions(
    pool: &PgPool,
    domain_name: &str,
    limit: i64,
) -> sqlx::Result<Vec<ConfigVersionRow>> {
    sqlx::query_as::<_, ConfigVersionRow>(
        r#"
        SELECT id, domain_id, domain_name, version, snapshot, diff,
               action, actor, message, created_at
        FROM config_versions
        WHERE ($1 = '' OR domain_name = $1)
        ORDER BY created_at DESC
        LIMIT $2
        "#,
    )
    .bind(domain_name)
    .bind(limit.clamp(1, 500))
    .fetch_all(pool)
    .await
}

pub async fn get_version(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<ConfigVersionRow>> {
    sqlx::query_as::<_, ConfigVersionRow>(
        r#"
        SELECT id, domain_id, domain_name, version, snapshot, diff,
               action, actor, message, created_at
        FROM config_versions
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn set_published_version(
    pool: &PgPool,
    domain_name: &str,
    version_id: Option<Uuid>,
) -> sqlx::Result<u64> {
    let r = sqlx::query("UPDATE domains SET published_version_id = $2 WHERE name = $1")
        .bind(domain_name)
        .bind(version_id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

pub async fn create_release(
    pool: &PgPool,
    versions: &Value,
    previous_versions: &Value,
    target_nodes: &[String],
    target_domains: &[String],
    note: &str,
    created_by: &str,
) -> sqlx::Result<ConfigReleaseRow> {
    sqlx::query_as::<_, ConfigReleaseRow>(
        r#"
        INSERT INTO config_releases
            (versions, previous_versions, target_nodes, target_domains, note, created_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, status, versions, previous_versions, target_nodes, target_domains,
                  note, created_by, approved_by, error, created_at,
                  approved_at, published_at, finished_at
        "#,
    )
    .bind(sqlx::types::Json(versions))
    .bind(sqlx::types::Json(previous_versions))
    .bind(sqlx::types::Json(target_nodes))
    .bind(sqlx::types::Json(target_domains))
    .bind(note)
    .bind(created_by)
    .fetch_one(pool)
    .await
}

pub async fn list_releases(pool: &PgPool, limit: i64) -> sqlx::Result<Vec<ConfigReleaseRow>> {
    sqlx::query_as::<_, ConfigReleaseRow>(
        r#"
        SELECT id, status, versions, previous_versions, target_nodes, target_domains,
               note, created_by, approved_by, error, created_at,
               approved_at, published_at, finished_at
        FROM config_releases
        ORDER BY created_at DESC
        LIMIT $1
        "#,
    )
    .bind(limit.clamp(1, 200))
    .fetch_all(pool)
    .await
}

pub async fn get_release(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<ConfigReleaseRow>> {
    sqlx::query_as::<_, ConfigReleaseRow>(
        r#"
        SELECT id, status, versions, previous_versions, target_nodes, target_domains,
               note, created_by, approved_by, error, created_at,
               approved_at, published_at, finished_at
        FROM config_releases
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn approve_release(
    pool: &PgPool,
    id: Uuid,
    approved_by: &str,
) -> sqlx::Result<Option<ConfigReleaseRow>> {
    sqlx::query_as::<_, ConfigReleaseRow>(
        r#"
        UPDATE config_releases SET
            status = 'approved', approved_by = $2, approved_at = NOW()
        WHERE id = $1 AND status = 'pending_approval'
        RETURNING id, status, versions, previous_versions, target_nodes, target_domains,
                  note, created_by, approved_by, error, created_at,
                  approved_at, published_at, finished_at
        "#,
    )
    .bind(id)
    .bind(approved_by)
    .fetch_optional(pool)
    .await
}

pub async fn start_publishing(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<ConfigReleaseRow>> {
    sqlx::query_as::<_, ConfigReleaseRow>(
        r#"
        UPDATE config_releases SET
            status = 'publishing', published_at = NOW()
        WHERE id = $1 AND status = 'approved'
        RETURNING id, status, versions, previous_versions, target_nodes, target_domains,
                  note, created_by, approved_by, error, created_at,
                  approved_at, published_at, finished_at
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn finish_release(
    pool: &PgPool,
    id: Uuid,
    status: &str,
    error: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        UPDATE config_releases SET
            status = $2, error = $3, finished_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(status)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn set_published_versions(pool: &PgPool, versions: &Value) -> sqlx::Result<()> {
    let Some(map) = versions.as_object() else {
        return Ok(());
    };
    let mut tx = pool.begin().await?;
    for (domain, id) in map {
        let id = id.as_str().and_then(|v| Uuid::parse_str(v).ok());
        sqlx::query("UPDATE domains SET published_version_id = $2 WHERE name = $1")
            .bind(domain)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn report_apply(
    pool: &PgPool,
    release_id: Uuid,
    node_id: &str,
    success: bool,
    error: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO config_release_reports (release_id, node_id, success, error)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (release_id, node_id) DO UPDATE SET
            success = EXCLUDED.success,
            error = EXCLUDED.error,
            reported_at = NOW()
        "#,
    )
    .bind(release_id)
    .bind(node_id)
    .bind(success)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn reports(pool: &PgPool, release_id: Uuid) -> sqlx::Result<Vec<(String, bool, String)>> {
    sqlx::query_as(
        "SELECT node_id, success, error FROM config_release_reports WHERE release_id = $1",
    )
    .bind(release_id)
    .fetch_all(pool)
    .await
}

pub async fn publishing_exists(pool: &PgPool, exclude: Uuid) -> sqlx::Result<bool> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM config_releases WHERE status = 'publishing' AND id <> $1)",
    )
    .bind(exclude)
    .fetch_one(pool)
    .await?;
    Ok(exists)
}

pub async fn active_release_for_node(
    pool: &PgPool,
    node_id: &str,
) -> sqlx::Result<Option<ConfigReleaseRow>> {
    sqlx::query_as::<_, ConfigReleaseRow>(
        r#"
        SELECT id, status, versions, previous_versions, target_nodes, target_domains,
               note, created_by, approved_by, error, created_at,
               approved_at, published_at, finished_at
        FROM config_releases
        WHERE status = 'publishing'
          AND target_nodes ? $1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(node_id)
    .fetch_optional(pool)
    .await
}

pub async fn stale_publishing(
    pool: &PgPool,
    older_than_secs: i64,
) -> sqlx::Result<Vec<ConfigReleaseRow>> {
    sqlx::query_as::<_, ConfigReleaseRow>(
        r#"
        SELECT id, status, versions, previous_versions, target_nodes, target_domains,
               note, created_by, approved_by, error, created_at,
               approved_at, published_at, finished_at
        FROM config_releases
        WHERE status = 'publishing'
          AND published_at < NOW() - make_interval(secs => $1)
        "#,
    )
    .bind(older_than_secs)
    .fetch_all(pool)
    .await
}
