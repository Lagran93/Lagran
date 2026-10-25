//! WAF management: per-domain settings, custom rules, IP lists and events.

use crate::middleware::agent_auth::AgentAuth;
use crate::middleware::authz::Actor;
use crate::repository;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use uuid::Uuid;

const FIELDS: [&str; 6] = ["path", "query", "user_agent", "referer", "method", "ip"];
const OPERATORS: [&str; 4] = ["contains", "equals", "prefix", "suffix"];
const ACTIONS: [&str; 4] = ["block", "allow", "log", "challenge"];

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

fn db_error() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: "database error".into(),
        }),
    )
}

fn forbidden() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorBody {
            error: "forbidden".into(),
        }),
    )
}

fn not_found(msg: &str) -> (StatusCode, Json<ErrorBody>) {
    (StatusCode::NOT_FOUND, Json(ErrorBody { error: msg.into() }))
}

fn bad_request(msg: String) -> (StatusCode, Json<ErrorBody>) {
    (StatusCode::BAD_REQUEST, Json(ErrorBody { error: msg }))
}

fn parse_uuid(id: &str) -> Result<Uuid, (StatusCode, Json<ErrorBody>)> {
    Uuid::parse_str(id.trim()).map_err(|_| bad_request(format!("invalid uuid: {id}")))
}

fn valid_cidr(input: &str) -> bool {
    let input = input.trim();
    let (addr, prefix) = match input.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (input, None),
    };
    let Ok(addr) = addr.parse::<IpAddr>() else {
        return false;
    };
    let max = if addr.is_ipv4() { 32 } else { 128 };
    match prefix {
        None => true,
        Some(p) => p.trim().parse::<u8>().map(|p| p <= max).unwrap_or(false),
    }
}

// ---------------------------------------------------------------- settings

#[derive(Serialize)]
pub struct WafSettingsDto {
    pub enabled: bool,
    pub mode: String,
    pub sqli: bool,
    pub xss: bool,
    pub traversal: bool,
    pub scanners: bool,
    pub challenge_difficulty: u8,
    pub challenge_ttl_secs: u32,
}

impl Default for WafSettingsDto {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "block".into(),
            sqli: true,
            xss: true,
            traversal: true,
            scanners: true,
            challenge_difficulty: 4,
            challenge_ttl_secs: 1800,
        }
    }
}

impl From<repository::WafSettingsRow> for WafSettingsDto {
    fn from(r: repository::WafSettingsRow) -> Self {
        Self {
            enabled: r.enabled,
            mode: r.mode,
            sqli: r.sqli,
            xss: r.xss,
            traversal: r.traversal,
            scanners: r.scanners,
            challenge_difficulty: r.challenge_difficulty.clamp(1, 6) as u8,
            challenge_ttl_secs: r.challenge_ttl_secs.clamp(60, 86_400) as u32,
        }
    }
}

pub async fn get_settings(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<WafSettingsDto>, (StatusCode, Json<ErrorBody>)> {
    let domain_id = parse_uuid(&id)?;
    if !actor.can_read_domain(&state, domain_id).await {
        return Err(forbidden());
    }
    let row = repository::get_waf_settings(&state.pool, domain_id)
        .await
        .map_err(|_| db_error())?;
    Ok(Json(row.map(WafSettingsDto::from).unwrap_or_default()))
}

#[derive(Deserialize)]
pub struct SettingsRequest {
    pub enabled: Option<bool>,
    pub mode: Option<String>,
    pub sqli: Option<bool>,
    pub xss: Option<bool>,
    pub traversal: Option<bool>,
    pub scanners: Option<bool>,
    pub challenge_difficulty: Option<u8>,
    pub challenge_ttl_secs: Option<u32>,
}

pub async fn put_settings(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<SettingsRequest>,
) -> Result<Json<WafSettingsDto>, (StatusCode, Json<ErrorBody>)> {
    let domain_id = parse_uuid(&id)?;
    if !actor.can_write_domain(&state, domain_id).await {
        return Err(forbidden());
    }

    let current = repository::get_waf_settings(&state.pool, domain_id)
        .await
        .map_err(|_| db_error())?
        .map(WafSettingsDto::from)
        .unwrap_or_default();

    let mode = req
        .mode
        .as_deref()
        .unwrap_or(&current.mode)
        .trim()
        .to_ascii_lowercase();
    if mode != "block" && mode != "monitor" {
        return Err(bad_request("mode must be block or monitor".into()));
    }

    let row = repository::upsert_waf_settings(
        &state.pool,
        domain_id,
        req.enabled.unwrap_or(current.enabled),
        &mode,
        req.sqli.unwrap_or(current.sqli),
        req.xss.unwrap_or(current.xss),
        req.traversal.unwrap_or(current.traversal),
        req.scanners.unwrap_or(current.scanners),
        req.challenge_difficulty
            .unwrap_or(current.challenge_difficulty)
            .clamp(1, 6) as i32,
        req.challenge_ttl_secs
            .unwrap_or(current.challenge_ttl_secs)
            .clamp(60, 86_400) as i32,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "upsert waf settings");
        db_error()
    })?;

    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "waf.settings",
        &domain_id.to_string(),
        &format!(
            "enabled={} mode={mode} sqli={} xss={} traversal={} scanners={} challenge={}/{}s",
            row.enabled,
            row.sqli,
            row.xss,
            row.traversal,
            row.scanners,
            row.challenge_difficulty,
            row.challenge_ttl_secs
        ),
    )
    .await;

    Ok(Json(row.into()))
}

// ------------------------------------------------------------------- rules

#[derive(Serialize)]
pub struct WafRuleDto {
    pub id: String,
    pub domain_id: String,
    pub name: String,
    pub field: String,
    pub operator: String,
    pub value: String,
    pub action: String,
    pub priority: i32,
    pub enabled: bool,
    pub created_at: String,
}

impl From<repository::WafRuleRow> for WafRuleDto {
    fn from(r: repository::WafRuleRow) -> Self {
        Self {
            id: r.id.to_string(),
            domain_id: r.domain_id.to_string(),
            name: r.name,
            field: r.field,
            operator: r.operator,
            value: r.value,
            action: r.action,
            priority: r.priority,
            enabled: r.enabled,
            created_at: r.created_at.to_rfc3339(),
        }
    }
}

#[derive(Deserialize)]
pub struct WafRuleRequest {
    pub name: String,
    pub field: String,
    pub operator: String,
    pub value: String,
    pub action: Option<String>,
    pub priority: Option<i32>,
    pub enabled: Option<bool>,
}

struct ValidRule {
    name: String,
    field: String,
    operator: String,
    value: String,
    action: String,
    priority: i32,
    enabled: bool,
}

fn validate_rule(req: &WafRuleRequest) -> Result<ValidRule, (StatusCode, Json<ErrorBody>)> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(bad_request("name required".into()));
    }
    let field = req.field.trim().to_ascii_lowercase();
    if !FIELDS.contains(&field.as_str()) {
        return Err(bad_request(format!(
            "field must be one of {}",
            FIELDS.join(", ")
        )));
    }
    let operator = req.operator.trim().to_ascii_lowercase();
    if !OPERATORS.contains(&operator.as_str()) {
        return Err(bad_request(format!(
            "operator must be one of {}",
            OPERATORS.join(", ")
        )));
    }
    let value = req.value.trim();
    if value.is_empty() {
        return Err(bad_request("value required".into()));
    }
    let action = req
        .action
        .as_deref()
        .unwrap_or("block")
        .trim()
        .to_ascii_lowercase();
    if !ACTIONS.contains(&action.as_str()) {
        return Err(bad_request(format!(
            "action must be one of {}",
            ACTIONS.join(", ")
        )));
    }
    Ok(ValidRule {
        name: name.to_string(),
        field,
        operator,
        value: value.to_string(),
        action,
        priority: req.priority.unwrap_or(0),
        enabled: req.enabled.unwrap_or(true),
    })
}

pub async fn list_rules(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<Vec<WafRuleDto>>, (StatusCode, Json<ErrorBody>)> {
    let domain_id = parse_uuid(&id)?;
    if !actor.can_read_domain(&state, domain_id).await {
        return Err(forbidden());
    }
    let rows = repository::list_waf_rules(&state.pool, domain_id)
        .await
        .map_err(|_| db_error())?;
    Ok(Json(rows.into_iter().map(WafRuleDto::from).collect()))
}

pub async fn create_rule(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<WafRuleRequest>,
) -> Result<(StatusCode, Json<WafRuleDto>), (StatusCode, Json<ErrorBody>)> {
    let domain_id = parse_uuid(&id)?;
    if !actor.can_write_domain(&state, domain_id).await {
        return Err(forbidden());
    }
    let rule = validate_rule(&req)?;
    let row = repository::create_waf_rule(
        &state.pool,
        domain_id,
        &rule.name,
        &rule.field,
        &rule.operator,
        &rule.value,
        &rule.action,
        rule.priority,
        rule.enabled,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "create waf rule");
        db_error()
    })?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "waf.rule.create",
        &domain_id.to_string(),
        &format!(
            "{} {} {} {}",
            rule.field, rule.operator, rule.value, rule.action
        ),
    )
    .await;
    Ok((StatusCode::CREATED, Json(row.into())))
}

pub async fn update_rule(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<WafRuleRequest>,
) -> Result<Json<WafRuleDto>, (StatusCode, Json<ErrorBody>)> {
    let rule_id = parse_uuid(&id)?;
    let existing = repository::get_waf_rule(&state.pool, rule_id)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("rule not found"))?;
    if !actor.can_write_domain(&state, existing.domain_id).await {
        return Err(forbidden());
    }
    let rule = validate_rule(&req)?;
    let row = repository::update_waf_rule(
        &state.pool,
        rule_id,
        &rule.name,
        &rule.field,
        &rule.operator,
        &rule.value,
        &rule.action,
        rule.priority,
        rule.enabled,
    )
    .await
    .map_err(|_| db_error())?
    .ok_or_else(|| not_found("rule not found"))?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "waf.rule.update",
        &row.domain_id.to_string(),
        &row.name,
    )
    .await;
    Ok(Json(row.into()))
}

pub async fn delete_rule(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let rule_id = parse_uuid(&id)?;
    let existing = repository::get_waf_rule(&state.pool, rule_id)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("rule not found"))?;
    if !actor.can_write_domain(&state, existing.domain_id).await {
        return Err(forbidden());
    }
    repository::delete_waf_rule(&state.pool, rule_id)
        .await
        .map_err(|_| db_error())?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "waf.rule.delete",
        &existing.domain_id.to_string(),
        &existing.name,
    )
    .await;
    Ok(Json(serde_json::json!({ "success": true, "id": id })))
}

// --------------------------------------------------------------- IP lists

#[derive(Serialize)]
pub struct WafIpDto {
    pub id: String,
    pub domain_id: String,
    pub kind: String,
    pub ip: String,
    pub note: String,
    pub created_at: String,
}

impl From<repository::WafIpRow> for WafIpDto {
    fn from(r: repository::WafIpRow) -> Self {
        Self {
            id: r.id.to_string(),
            domain_id: r.domain_id.to_string(),
            kind: r.kind,
            ip: r.ip,
            note: r.note,
            created_at: r.created_at.to_rfc3339(),
        }
    }
}

#[derive(Deserialize)]
pub struct WafIpRequest {
    pub kind: String,
    pub ip: String,
    pub note: Option<String>,
}

pub async fn list_ips(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<Vec<WafIpDto>>, (StatusCode, Json<ErrorBody>)> {
    let domain_id = parse_uuid(&id)?;
    if !actor.can_read_domain(&state, domain_id).await {
        return Err(forbidden());
    }
    let rows = repository::list_waf_ips(&state.pool, domain_id)
        .await
        .map_err(|_| db_error())?;
    Ok(Json(rows.into_iter().map(WafIpDto::from).collect()))
}

pub async fn create_ip(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<WafIpRequest>,
) -> Result<(StatusCode, Json<WafIpDto>), (StatusCode, Json<ErrorBody>)> {
    let domain_id = parse_uuid(&id)?;
    if !actor.can_write_domain(&state, domain_id).await {
        return Err(forbidden());
    }
    let kind = req.kind.trim().to_ascii_lowercase();
    if kind != "allow" && kind != "deny" {
        return Err(bad_request("kind must be allow or deny".into()));
    }
    let ip = req.ip.trim();
    if !valid_cidr(ip) {
        return Err(bad_request("ip must be an IP or CIDR".into()));
    }
    let row = repository::create_waf_ip(
        &state.pool,
        domain_id,
        &kind,
        ip,
        req.note.as_deref().unwrap_or(""),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "create waf ip");
        db_error()
    })?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "waf.ip.create",
        &domain_id.to_string(),
        &format!("{kind} {ip}"),
    )
    .await;
    Ok((StatusCode::CREATED, Json(row.into())))
}

pub async fn delete_ip(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let ip_id = parse_uuid(&id)?;
    let existing = repository::get_waf_ip(&state.pool, ip_id)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("ip rule not found"))?;
    if !actor.can_write_domain(&state, existing.domain_id).await {
        return Err(forbidden());
    }
    repository::delete_waf_ip(&state.pool, ip_id)
        .await
        .map_err(|_| db_error())?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "waf.ip.delete",
        &existing.domain_id.to_string(),
        &format!("{} {}", existing.kind, existing.ip),
    )
    .await;
    Ok(Json(serde_json::json!({ "success": true, "id": id })))
}

// ---------------------------------------------------------------- events

#[derive(Serialize)]
pub struct WafEventDto {
    pub id: i64,
    pub ts: String,
    pub domain: String,
    pub node_id: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub action: String,
    pub category: String,
    pub rule_name: String,
    pub mode: String,
}

#[derive(Deserialize)]
pub struct EventIn {
    pub domain: String,
    pub node_id: Option<String>,
    pub client_ip: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub action: String,
    pub category: Option<String>,
    pub rule_name: Option<String>,
    pub mode: Option<String>,
}

#[derive(Deserialize)]
pub struct EventsBody {
    pub events: Vec<EventIn>,
}

#[derive(Serialize)]
pub struct ReportAck {
    pub accepted: usize,
}

/// Edge → control batch upload.
pub async fn report_events(
    State(state): State<AppState>,
    _agent: AgentAuth,
    Json(body): Json<EventsBody>,
) -> Json<ReportAck> {
    let mut inputs = Vec::with_capacity(body.events.len().min(1000));
    for e in body.events.into_iter().take(1000) {
        if e.domain.trim().is_empty() {
            continue;
        }
        inputs.push(repository::WafEventInput {
            domain: e.domain.trim().to_string(),
            node_id: e.node_id.unwrap_or_default(),
            client_ip: e.client_ip.unwrap_or_default(),
            method: e.method.unwrap_or_default(),
            path: e.path.unwrap_or_default(),
            action: e.action,
            category: e.category.unwrap_or_default(),
            rule_name: e.rule_name.unwrap_or_default(),
            mode: e.mode.unwrap_or_else(|| "block".into()),
        });
    }
    let accepted = inputs.len();
    if let Err(e) = repository::insert_waf_events_batch(&state.pool, &inputs).await {
        tracing::error!(error = %e, "insert waf events");
        return Json(ReportAck { accepted: 0 });
    }
    Json(ReportAck { accepted })
}

#[derive(Deserialize)]
pub struct EventsQuery {
    pub domain: Option<String>,
    pub limit: Option<i64>,
    pub action: Option<String>,
}

pub async fn list_events(
    State(state): State<AppState>,
    actor: Actor,
    Query(q): Query<EventsQuery>,
) -> Result<Json<Vec<WafEventDto>>, (StatusCode, Json<ErrorBody>)> {
    let visible: Option<HashSet<String>> = match actor.visible_domain_ids(&state).await {
        None => None,
        Some(ids) => {
            let rows = repository::list_domains(&state.pool)
                .await
                .unwrap_or_default();
            Some(
                rows.into_iter()
                    .filter(|d| ids.contains(&d.id))
                    .map(|d| d.name)
                    .collect(),
            )
        }
    };

    if let Some(ref d) = q.domain {
        if let Some(ref names) = visible {
            if !d.is_empty() && !names.contains(d) {
                return Ok(Json(vec![]));
            }
        }
    }

    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let rows = repository::list_waf_events(&state.pool, q.domain.as_deref(), limit)
        .await
        .map_err(|_| db_error())?;

    let action_filter = q.action.as_deref().unwrap_or("").to_ascii_lowercase();
    Ok(Json(
        rows.into_iter()
            .filter(|r| match &visible {
                None => true,
                Some(names) => names.contains(&r.domain),
            })
            .filter(|r| action_filter.is_empty() || r.action == action_filter)
            .map(|r| WafEventDto {
                id: r.id,
                ts: r.ts.to_rfc3339(),
                domain: r.domain,
                node_id: r.node_id,
                client_ip: r.client_ip,
                method: r.method,
                path: r.path,
                action: r.action,
                category: r.category,
                rule_name: r.rule_name,
                mode: r.mode,
            })
            .collect(),
    ))
}
