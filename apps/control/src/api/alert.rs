//! Alert channels, rules and incident history. Most features are available to
//! authenticated users; node-offline rules remain admin-only.

use crate::middleware::authz::Actor;
use crate::repository::{self, AlertChannelRow, AlertEventRow, AlertRuleRow};
use crate::service::notify;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use uuid::Uuid;

const METRICS: &[&str] = &[
    "origin_unhealthy",
    "cert_expiring",
    "node_offline",
    "cache_hit_ratio",
    "waf_spike",
];

#[derive(Serialize)]
pub struct AlertChannelDto {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub config: Value,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct ChannelInput {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub config: Value,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Serialize)]
pub struct AlertRuleDto {
    pub id: String,
    pub name: String,
    pub metric: String,
    pub threshold: f64,
    pub window_minutes: u32,
    pub channel_ids: Vec<String>,
    pub enabled: bool,
    pub cooldown_seconds: u32,
    pub last_triggered_at: Option<String>,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct RuleInput {
    pub name: String,
    pub metric: String,
    pub threshold: f64,
    #[serde(default = "default_window")]
    pub window_minutes: u32,
    #[serde(default)]
    pub channel_ids: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_cooldown")]
    pub cooldown_seconds: u32,
}

#[derive(Serialize)]
pub struct AlertEventDto {
    pub id: i64,
    pub rule_id: Option<String>,
    pub rule_name: String,
    pub fingerprint: String,
    pub severity: String,
    pub status: String,
    pub value: f64,
    pub message: String,
    pub started_at: String,
    pub resolved_at: Option<String>,
    pub notified: bool,
}

#[derive(Serialize)]
pub struct TestResult {
    pub success: bool,
    pub message: String,
}

fn default_true() -> bool {
    true
}

fn default_window() -> u32 {
    5
}

fn default_cooldown() -> u32 {
    900
}

fn node_alert_forbidden() -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error": "node offline alerts are admin-only"})),
    )
}

fn hidden_node_rule_ids(rules: &[AlertRuleRow]) -> HashSet<Uuid> {
    rules
        .iter()
        .filter(|rule| rule.metric == "node_offline")
        .map(|rule| rule.id)
        .collect()
}

fn filter_visible_events(
    actor: &Actor,
    events: Vec<AlertEventRow>,
    rules: &[AlertRuleRow],
) -> Vec<AlertEventRow> {
    if actor.admin() {
        return events;
    }
    let hidden = hidden_node_rule_ids(rules);
    events
        .into_iter()
        .filter(|event| {
            !event.fingerprint.starts_with("node|")
                && event
                    .rule_id
                    .map(|id| !hidden.contains(&id))
                    .unwrap_or(true)
        })
        .collect()
}

fn bad(msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg.into()})))
}

fn db_error() -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "database error"})),
    )
}

fn parse_uuid(raw: &str) -> Result<Uuid, (StatusCode, Json<Value>)> {
    Uuid::parse_str(raw).map_err(|_| bad("invalid id"))
}

fn channel_dto(row: AlertChannelRow) -> AlertChannelDto {
    AlertChannelDto {
        id: row.id.to_string(),
        name: row.name,
        kind: row.kind,
        config: mask_config(&row.config.0),
        enabled: row.enabled,
        created_at: row.created_at.to_rfc3339(),
    }
}

fn rule_dto(row: AlertRuleRow) -> AlertRuleDto {
    AlertRuleDto {
        id: row.id.to_string(),
        name: row.name,
        metric: row.metric,
        threshold: row.threshold,
        window_minutes: row.window_minutes.max(0) as u32,
        channel_ids: row.channel_ids.0,
        enabled: row.enabled,
        cooldown_seconds: row.cooldown_seconds.max(0) as u32,
        last_triggered_at: row.last_triggered_at.map(|t| t.to_rfc3339()),
        created_at: row.created_at.to_rfc3339(),
    }
}

fn event_dto(row: AlertEventRow) -> AlertEventDto {
    AlertEventDto {
        id: row.id,
        rule_id: row.rule_id.map(|id| id.to_string()),
        rule_name: row.rule_name,
        fingerprint: row.fingerprint,
        severity: row.severity,
        status: row.status,
        value: row.value,
        message: row.message,
        started_at: row.started_at.to_rfc3339(),
        resolved_at: row.resolved_at.map(|t| t.to_rfc3339()),
        notified: row.notified,
    }
}

/// Secrets are never returned to the browser. Keeping a stable mask also lets
/// the edit form submit the unchanged value, which `merge_secrets` restores.
fn mask_config(config: &Value) -> Value {
    let mut out = config.clone();
    if let Some(obj) = out.as_object_mut() {
        for key in ["secret", "password", "bot_token"] {
            if obj
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|v| !v.is_empty())
            {
                obj.insert(key.into(), Value::String("••••••••".into()));
            }
        }
    }
    out
}

fn merge_secrets(old: &Value, new: &mut Value) {
    let (Some(old_obj), Some(new_obj)) = (old.as_object(), new.as_object_mut()) else {
        return;
    };
    for key in ["secret", "password", "bot_token"] {
        if new_obj
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|v| v == "••••••••")
        {
            if let Some(previous) = old_obj.get(key) {
                new_obj.insert(key.into(), previous.clone());
            }
        }
    }
}

fn validate_channel(kind: &str, config: &Value) -> Result<(), String> {
    if !matches!(kind, "email" | "webhook" | "telegram") {
        return Err("kind must be email, webhook or telegram".into());
    }
    let string = |key: &str| {
        config
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string()
    };
    match kind {
        "webhook" => {
            let url = string("url");
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err("webhook url must start with http:// or https://".into());
            }
        }
        "telegram" => {
            if string("bot_token").is_empty() || string("chat_id").is_empty() {
                return Err("telegram bot_token and chat_id are required".into());
            }
            let api_base = string("api_base");
            if !api_base.is_empty()
                && !api_base.starts_with("http://")
                && !api_base.starts_with("https://")
            {
                return Err("telegram api_base must start with http:// or https://".into());
            }
            let proxy = string("proxy");
            if !proxy.is_empty()
                && !proxy.starts_with("http://")
                && !proxy.starts_with("https://")
                && !proxy.starts_with("socks5://")
                && !proxy.starts_with("socks5h://")
            {
                return Err("telegram proxy must be an http(s) or socks5 URL".into());
            }
        }
        "email" => {
            if string("smtp_host").is_empty() || string("from").is_empty() {
                return Err("email smtp_host and from are required".into());
            }
            let has_to = config
                .get("to")
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty());
            if !has_to {
                return Err("email at least one recipient is required".into());
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_rule(input: &RuleInput) -> Result<(), String> {
    if input.name.trim().is_empty() {
        return Err("name is required".into());
    }
    if !METRICS.contains(&input.metric.as_str()) {
        return Err(format!("unknown metric: {}", input.metric));
    }
    if input.window_minutes == 0 {
        return Err("window_minutes must be > 0".into());
    }
    for id in &input.channel_ids {
        Uuid::parse_str(id).map_err(|_| "invalid channel id".to_string())?;
    }
    Ok(())
}

pub async fn list_channels(
    State(state): State<AppState>,
    _actor: Actor,
) -> Result<Json<Vec<AlertChannelDto>>, (StatusCode, Json<Value>)> {
    let rows = repository::list_alert_channels(&state.pool)
        .await
        .map_err(|_| db_error())?;
    Ok(Json(rows.into_iter().map(channel_dto).collect()))
}

pub async fn create_channel(
    State(state): State<AppState>,
    actor: Actor,
    Json(mut input): Json<ChannelInput>,
) -> Result<(StatusCode, Json<AlertChannelDto>), (StatusCode, Json<Value>)> {
    input.kind = input.kind.trim().to_ascii_lowercase();
    validate_channel(&input.kind, &input.config).map_err(bad)?;
    let row = repository::create_alert_channel(
        &state.pool,
        input.name.trim(),
        &input.kind,
        &input.config,
        input.enabled,
    )
    .await
    .map_err(|_| db_error())?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "alert.channel.create",
        input.name.trim(),
        &input.kind,
    )
    .await;
    Ok((StatusCode::CREATED, Json(channel_dto(row))))
}

pub async fn update_channel(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(mut input): Json<ChannelInput>,
) -> Result<Json<AlertChannelDto>, (StatusCode, Json<Value>)> {
    let uid = parse_uuid(&id)?;
    let old = repository::get_alert_channel(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| bad("channel not found"))?;
    merge_secrets(&old.config.0, &mut input.config);
    input.kind = input.kind.trim().to_ascii_lowercase();
    validate_channel(&input.kind, &input.config).map_err(bad)?;
    let row = repository::update_alert_channel(
        &state.pool,
        uid,
        input.name.trim(),
        &input.kind,
        &input.config,
        input.enabled,
    )
    .await
    .map_err(|_| db_error())?
    .ok_or_else(|| bad("channel not found"))?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "alert.channel.update",
        input.name.trim(),
        &input.kind,
    )
    .await;
    Ok(Json(channel_dto(row)))
}

pub async fn delete_channel(
    State(state): State<AppState>,
    _actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let uid = parse_uuid(&id)?;
    repository::delete_alert_channel(&state.pool, uid)
        .await
        .map_err(|_| db_error())?;
    Ok(Json(json!({"success": true})))
}

pub async fn test_channel(
    State(state): State<AppState>,
    _actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<TestResult>, (StatusCode, Json<Value>)> {
    let uid = parse_uuid(&id)?;
    let row = repository::get_alert_channel(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| bad("channel not found"))?;
    let (subject, message, severity) = notify::test_message();
    let result = notify::send_channel(&row.kind, &row.config.0, subject, message, severity).await;
    Ok(Json(match result {
        Ok(()) => TestResult {
            success: true,
            message: "测试通知已发送".into(),
        },
        Err(e) => TestResult {
            success: false,
            message: e,
        },
    }))
}

pub async fn list_rules(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<AlertRuleDto>>, (StatusCode, Json<Value>)> {
    let rows = repository::list_alert_rules(&state.pool)
        .await
        .map_err(|_| db_error())?;
    Ok(Json(
        rows.into_iter()
            .filter(|row| actor.admin() || row.metric != "node_offline")
            .map(rule_dto)
            .collect(),
    ))
}

pub async fn create_rule(
    State(state): State<AppState>,
    actor: Actor,
    Json(input): Json<RuleInput>,
) -> Result<(StatusCode, Json<AlertRuleDto>), (StatusCode, Json<Value>)> {
    validate_rule(&input).map_err(bad)?;
    if !actor.admin() && input.metric == "node_offline" {
        return Err(node_alert_forbidden());
    }
    let row = repository::create_alert_rule(
        &state.pool,
        input.name.trim(),
        &input.metric,
        input.threshold,
        input.window_minutes as i32,
        &input.channel_ids,
        input.enabled,
        input.cooldown_seconds as i32,
    )
    .await
    .map_err(|_| db_error())?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "alert.rule.create",
        input.name.trim(),
        &input.metric,
    )
    .await;
    Ok((StatusCode::CREATED, Json(rule_dto(row))))
}

pub async fn update_rule(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(input): Json<RuleInput>,
) -> Result<Json<AlertRuleDto>, (StatusCode, Json<Value>)> {
    let uid = parse_uuid(&id)?;
    validate_rule(&input).map_err(bad)?;
    let existing = repository::get_alert_rule(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| bad("rule not found"))?;
    if !actor.admin() && (existing.metric == "node_offline" || input.metric == "node_offline") {
        return Err(node_alert_forbidden());
    }
    let row = repository::update_alert_rule(
        &state.pool,
        uid,
        input.name.trim(),
        &input.metric,
        input.threshold,
        input.window_minutes as i32,
        &input.channel_ids,
        input.enabled,
        input.cooldown_seconds as i32,
    )
    .await
    .map_err(|_| db_error())?
    .ok_or_else(|| bad("rule not found"))?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "alert.rule.update",
        input.name.trim(),
        &input.metric,
    )
    .await;
    Ok(Json(rule_dto(row)))
}

pub async fn delete_rule(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let uid = parse_uuid(&id)?;
    let existing = repository::get_alert_rule(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| bad("rule not found"))?;
    if !actor.admin() && existing.metric == "node_offline" {
        return Err(node_alert_forbidden());
    }
    repository::delete_alert_rule(&state.pool, uid)
        .await
        .map_err(|_| db_error())?;
    Ok(Json(json!({"success": true})))
}

#[derive(Deserialize)]
pub struct EventQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    100
}

pub async fn list_events(
    State(state): State<AppState>,
    actor: Actor,
    axum::extract::Query(q): axum::extract::Query<EventQuery>,
) -> Result<Json<Vec<AlertEventDto>>, (StatusCode, Json<Value>)> {
    let rules = repository::list_alert_rules(&state.pool)
        .await
        .map_err(|_| db_error())?;
    let events = repository::list_alert_events(&state.pool, q.limit)
        .await
        .map_err(|_| db_error())?;
    Ok(Json(
        filter_visible_events(&actor, events, &rules)
            .into_iter()
            .map(event_dto)
            .collect(),
    ))
}

pub async fn summary(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let rules = repository::list_alert_rules(&state.pool)
        .await
        .map_err(|_| db_error())?;
    let events = repository::list_alert_events(&state.pool, 200)
        .await
        .map_err(|_| db_error())?;
    let events = filter_visible_events(&actor, events, &rules);
    let firing = events.iter().filter(|e| e.status == "firing").count();
    let resolved = events.iter().filter(|e| e.status == "resolved").count();
    Ok(Json(json!({
        "firing": firing,
        "resolved": resolved,
        "total": events.len(),
    })))
}
