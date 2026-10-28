//! Alert channel, rule and incident persistence.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::types::Json;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AlertChannelRow {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub config: Json<Value>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AlertRuleRow {
    pub id: Uuid,
    pub name: String,
    pub metric: String,
    pub threshold: f64,
    pub window_minutes: i32,
    pub channel_ids: Json<Vec<String>>,
    pub enabled: bool,
    pub cooldown_seconds: i32,
    pub last_triggered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AlertEventRow {
    pub id: i64,
    pub rule_id: Option<Uuid>,
    pub rule_name: String,
    pub fingerprint: String,
    pub severity: String,
    pub status: String,
    pub value: f64,
    pub message: String,
    pub started_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub notified: bool,
    pub created_at: DateTime<Utc>,
}

pub async fn list_alert_channels(pool: &PgPool) -> sqlx::Result<Vec<AlertChannelRow>> {
    sqlx::query_as::<_, AlertChannelRow>(
        r#"
        SELECT id, name, kind, config, enabled, created_at
        FROM alert_channels
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn get_alert_channel(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<AlertChannelRow>> {
    sqlx::query_as::<_, AlertChannelRow>(
        r#"
        SELECT id, name, kind, config, enabled, created_at
        FROM alert_channels WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn create_alert_channel(
    pool: &PgPool,
    name: &str,
    kind: &str,
    config: &Value,
    enabled: bool,
) -> sqlx::Result<AlertChannelRow> {
    sqlx::query_as::<_, AlertChannelRow>(
        r#"
        INSERT INTO alert_channels (name, kind, config, enabled)
        VALUES ($1, $2, $3, $4)
        RETURNING id, name, kind, config, enabled, created_at
        "#,
    )
    .bind(name)
    .bind(kind)
    .bind(config)
    .bind(enabled)
    .fetch_one(pool)
    .await
}

pub async fn update_alert_channel(
    pool: &PgPool,
    id: Uuid,
    name: &str,
    kind: &str,
    config: &Value,
    enabled: bool,
) -> sqlx::Result<Option<AlertChannelRow>> {
    sqlx::query_as::<_, AlertChannelRow>(
        r#"
        UPDATE alert_channels SET
            name = $2, kind = $3, config = $4, enabled = $5, updated_at = NOW()
        WHERE id = $1
        RETURNING id, name, kind, config, enabled, created_at
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(kind)
    .bind(config)
    .bind(enabled)
    .fetch_optional(pool)
    .await
}

pub async fn delete_alert_channel(pool: &PgPool, id: Uuid) -> sqlx::Result<bool> {
    let r = sqlx::query("DELETE FROM alert_channels WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn list_alert_rules(pool: &PgPool) -> sqlx::Result<Vec<AlertRuleRow>> {
    sqlx::query_as::<_, AlertRuleRow>(
        r#"
        SELECT id, name, metric, threshold, window_minutes, channel_ids,
               enabled, cooldown_seconds, last_triggered_at, created_at
        FROM alert_rules
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn get_alert_rule(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<AlertRuleRow>> {
    sqlx::query_as::<_, AlertRuleRow>(
        r#"
        SELECT id, name, metric, threshold, window_minutes, channel_ids,
               enabled, cooldown_seconds, last_triggered_at, created_at
        FROM alert_rules WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn create_alert_rule(
    pool: &PgPool,
    name: &str,
    metric: &str,
    threshold: f64,
    window_minutes: i32,
    channel_ids: &[String],
    enabled: bool,
    cooldown_seconds: i32,
) -> sqlx::Result<AlertRuleRow> {
    sqlx::query_as::<_, AlertRuleRow>(
        r#"
        INSERT INTO alert_rules
            (name, metric, threshold, window_minutes, channel_ids, enabled, cooldown_seconds)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, name, metric, threshold, window_minutes, channel_ids,
                  enabled, cooldown_seconds, last_triggered_at, created_at
        "#,
    )
    .bind(name)
    .bind(metric)
    .bind(threshold)
    .bind(window_minutes)
    .bind(Json(channel_ids.to_vec()))
    .bind(enabled)
    .bind(cooldown_seconds)
    .fetch_one(pool)
    .await
}

pub async fn update_alert_rule(
    pool: &PgPool,
    id: Uuid,
    name: &str,
    metric: &str,
    threshold: f64,
    window_minutes: i32,
    channel_ids: &[String],
    enabled: bool,
    cooldown_seconds: i32,
) -> sqlx::Result<Option<AlertRuleRow>> {
    sqlx::query_as::<_, AlertRuleRow>(
        r#"
        UPDATE alert_rules SET
            name = $2, metric = $3, threshold = $4, window_minutes = $5,
            channel_ids = $6, enabled = $7, cooldown_seconds = $8, updated_at = NOW()
        WHERE id = $1
        RETURNING id, name, metric, threshold, window_minutes, channel_ids,
                  enabled, cooldown_seconds, last_triggered_at, created_at
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(metric)
    .bind(threshold)
    .bind(window_minutes)
    .bind(Json(channel_ids.to_vec()))
    .bind(enabled)
    .bind(cooldown_seconds)
    .fetch_optional(pool)
    .await
}

pub async fn delete_alert_rule(pool: &PgPool, id: Uuid) -> sqlx::Result<bool> {
    let r = sqlx::query("DELETE FROM alert_rules WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn list_alert_events(pool: &PgPool, limit: i64) -> sqlx::Result<Vec<AlertEventRow>> {
    sqlx::query_as::<_, AlertEventRow>(
        r#"
        SELECT id, rule_id, rule_name, fingerprint, severity, status, value,
               message, started_at, resolved_at, notified, created_at
        FROM alert_events
        ORDER BY started_at DESC
        LIMIT $1
        "#,
    )
    .bind(limit.clamp(1, 500))
    .fetch_all(pool)
    .await
}

pub async fn active_alert_events(pool: &PgPool, rule_id: Uuid) -> sqlx::Result<Vec<AlertEventRow>> {
    sqlx::query_as::<_, AlertEventRow>(
        r#"
        SELECT id, rule_id, rule_name, fingerprint, severity, status, value,
               message, started_at, resolved_at, notified, created_at
        FROM alert_events
        WHERE rule_id = $1 AND status = 'firing'
        "#,
    )
    .bind(rule_id)
    .fetch_all(pool)
    .await
}

pub async fn find_firing_alert(
    pool: &PgPool,
    rule_id: Uuid,
    fingerprint: &str,
) -> sqlx::Result<Option<AlertEventRow>> {
    sqlx::query_as::<_, AlertEventRow>(
        r#"
        SELECT id, rule_id, rule_name, fingerprint, severity, status, value,
               message, started_at, resolved_at, notified, created_at
        FROM alert_events
        WHERE rule_id = $1 AND fingerprint = $2 AND status = 'firing'
        "#,
    )
    .bind(rule_id)
    .bind(fingerprint)
    .fetch_optional(pool)
    .await
}

pub async fn insert_alert_event(
    pool: &PgPool,
    rule: &AlertRuleRow,
    fingerprint: &str,
    severity: &str,
    value: f64,
    message: &str,
) -> sqlx::Result<AlertEventRow> {
    sqlx::query_as::<_, AlertEventRow>(
        r#"
        INSERT INTO alert_events
            (rule_id, rule_name, fingerprint, severity, status, value, message)
        VALUES ($1, $2, $3, $4, 'firing', $5, $6)
        RETURNING id, rule_id, rule_name, fingerprint, severity, status, value,
                  message, started_at, resolved_at, notified, created_at
        "#,
    )
    .bind(rule.id)
    .bind(&rule.name)
    .bind(fingerprint)
    .bind(severity)
    .bind(value)
    .bind(message)
    .fetch_one(pool)
    .await
}

pub async fn refresh_alert_event(
    pool: &PgPool,
    id: i64,
    value: f64,
    message: &str,
) -> sqlx::Result<()> {
    sqlx::query("UPDATE alert_events SET value = $2, message = $3 WHERE id = $1")
        .bind(id)
        .bind(value)
        .bind(message)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn resolve_alert_event(pool: &PgPool, id: i64) -> sqlx::Result<()> {
    sqlx::query("UPDATE alert_events SET status = 'resolved', resolved_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn mark_alert_notified(pool: &PgPool, id: i64) -> sqlx::Result<()> {
    sqlx::query("UPDATE alert_events SET notified = TRUE WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn touch_alert_rule(pool: &PgPool, id: Uuid) -> sqlx::Result<()> {
    sqlx::query("UPDATE alert_rules SET last_triggered_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn count_firing_alerts(pool: &PgPool) -> sqlx::Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM alert_events WHERE status = 'firing'")
        .fetch_one(pool)
        .await
}
