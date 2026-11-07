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

async fn record_waf_version(
    state: &AppState,
    domain_id: Uuid,
    actor: &Actor,
    action: &str,
    message: &str,
) {
    if let Ok(Some(row)) = repository::get_domain(&state.pool, domain_id).await {
        let _ = crate::service::config_version::record_domain(
            &state.pool,
            row.id,
            &row.name,
            &actor.email,
            action,
            message,
        )
        .await;
    }
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
    pub rce: bool,
    pub ssrf: bool,
    pub xxe: bool,
    pub log4shell: bool,
    pub crlf: bool,
    pub ssti: bool,
    pub nosql: bool,
    pub ldap: bool,
    pub java: bool,
    pub webshell: bool,
    pub protocol: bool,
    pub challenge_difficulty: u8,
    pub challenge_ttl_secs: u32,
    pub security_level: String,
    pub managed_rulesets: Vec<String>,
    pub waf_rulepack_version: String,
    pub waf_gray_percent: u8,
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
            rce: true,
            ssrf: true,
            xxe: true,
            log4shell: true,
            crlf: true,
            ssti: true,
            nosql: true,
            ldap: true,
            java: true,
            webshell: true,
            protocol: true,
            challenge_difficulty: 4,
            challenge_ttl_secs: 1800,
            security_level: "off".into(),
            managed_rulesets: Vec::new(),
            waf_rulepack_version: String::new(),
            waf_gray_percent: 0,
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
            rce: r.rce,
            ssrf: r.ssrf,
            xxe: r.xxe,
            log4shell: r.log4shell,
            crlf: r.crlf,
            ssti: r.ssti,
            nosql: r.nosql,
            ldap: r.ldap,
            java: r.java,
            webshell: r.webshell,
            protocol: r.protocol,
            challenge_difficulty: r.challenge_difficulty.clamp(1, 6) as u8,
            challenge_ttl_secs: r.challenge_ttl_secs.clamp(60, 86_400) as u32,
            security_level: r.security_level,
            managed_rulesets: crate::waf_rulesets::parse_csv(&r.managed_rulesets),
            waf_rulepack_version: r.waf_rulepack_version,
            waf_gray_percent: r.waf_gray_percent.clamp(0, 100) as u8,
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

#[derive(Serialize)]
pub struct ManagedRulesetDto {
    pub id: &'static str,
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
    pub severity: &'static str,
    pub recommended: bool,
    pub categories: Vec<&'static str>,
    pub category_labels: Vec<&'static str>,
}

/// Static catalog of managed rulesets. No database state is required.
pub async fn list_rulesets() -> Json<Vec<ManagedRulesetDto>> {
    Json(
        crate::waf_rulesets::catalog()
            .iter()
            .map(|r| ManagedRulesetDto {
                id: r.id,
                name: r.name,
                version: r.version,
                description: r.description,
                severity: r.severity,
                recommended: r.recommended,
                categories: r.categories.to_vec(),
                category_labels: r.category_labels.to_vec(),
            })
            .collect(),
    )
}

#[derive(Serialize)]
pub struct RulepackDownload {
    pub version: String,
    pub payload: String,
    pub signature: String,
    pub checksum: String,
}

#[derive(Serialize)]
pub struct RulepackVersionDto {
    pub version: String,
    pub slot: String,
    pub signature: String,
    pub checksum: String,
    pub created_at: String,
    pub created_by: String,
}

impl From<&crate::waf_rulepack::RulepackRow> for RulepackVersionDto {
    fn from(row: &crate::waf_rulepack::RulepackRow) -> Self {
        Self {
            version: row.version.clone(),
            slot: row.slot.clone(),
            signature: row.signature.clone(),
            checksum: row.checksum.clone(),
            created_at: row.created_at.to_rfc3339(),
            created_by: row.created_by.clone(),
        }
    }
}

pub async fn list_rulepacks(
    State(state): State<AppState>,
) -> Result<Json<Vec<RulepackVersionDto>>, (StatusCode, Json<ErrorBody>)> {
    let rows = crate::waf_rulepack::list(&state.pool)
        .await
        .map_err(|_| db_error())?;
    Ok(Json(rows.iter().map(RulepackVersionDto::from).collect()))
}

#[derive(Deserialize)]
pub struct PublishRulepackRequest {
    #[serde(default)]
    pub version: Option<String>,
    /// Optional catalog override. When omitted, the compiled catalog is used.
    #[serde(default)]
    pub rulesets: Option<Vec<crate::waf_rulepack::RulesetEntry>>,
    /// Allow publishing an identical catalog under a new version label.
    #[serde(default)]
    pub force: bool,
}

pub async fn publish_rulepack(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<PublishRulepackRequest>,
) -> Result<Json<RulepackVersionDto>, (StatusCode, Json<ErrorBody>)> {
    if !actor.is_admin {
        return Err(forbidden());
    }
    let version = req
        .version
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            chrono::Utc::now().format("%Y.%m.%d-%H%M%S").to_string()
        });
    crate::waf_rulepack::validate_version(&version).map_err(bad_request)?;
    if let Some(rulesets) = req.rulesets.as_deref() {
        crate::waf_rulepack::validate_rulesets(rulesets).map_err(bad_request)?;
    }
    let candidate = req
        .rulesets
        .clone()
        .unwrap_or_else(crate::waf_rulepack::catalog_entries);
    let candidate_fingerprint = crate::waf_rulepack::catalog_fingerprint(&candidate);
    if !req.force {
        if let Some(active) = crate::waf_rulepack::active(&state.pool)
            .await
            .map_err(|_| db_error())?
        {
            let active_fingerprint = active
                .parse_package()
                .map(|p| crate::waf_rulepack::catalog_fingerprint(&p.rulesets))
                .unwrap_or_default();
            if !active_fingerprint.is_empty()
                && active_fingerprint == candidate_fingerprint
            {
                return Err((
                    StatusCode::CONFLICT,
                    Json(ErrorBody {
                        error: format!(
                            "catalog unchanged (active {}); deploy a new catalog or pass force=true",
                            active.version
                        ),
                    }),
                ));
            }
        }
    }
    let secret = crate::waf_rulepack::signing_key(
        &state.config.waf_rulepack_secret,
        &state.config.agent_token,
    );
    let row = crate::waf_rulepack::publish_with_rulesets(
        &state.pool,
        &secret,
        &version,
        req.rulesets,
        &actor.email,
    )
    .await
        .map_err(|e| {
            tracing::error!(error = %e, "publish waf rulepack");
            db_error()
        })?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "waf.rulepack.publish",
        &version,
        "发布托管 WAF 规则包",
    )
    .await;
    Ok(Json(RulepackVersionDto::from(&row)))
}

pub async fn rollback_rulepack(
    State(state): State<AppState>,
    actor: Actor,
    Path(version): Path<String>,
) -> Result<Json<RulepackVersionDto>, (StatusCode, Json<ErrorBody>)> {
    if !actor.is_admin {
        return Err(forbidden());
    }
    let row = crate::waf_rulepack::rollback(&state.pool, &version)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("rulepack version not found"))?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "waf.rulepack.rollback",
        &version,
        "回滚托管 WAF 规则包",
    )
    .await;
    Ok(Json(RulepackVersionDto::from(&row)))
}

pub async fn retire_rulepack(
    State(state): State<AppState>,
    actor: Actor,
    Path(version): Path<String>,
) -> Result<Json<RulepackVersionDto>, (StatusCode, Json<ErrorBody>)> {
    if !actor.is_admin {
        return Err(forbidden());
    }
    let Some(row) = crate::waf_rulepack::get(&state.pool, &version)
        .await
        .map_err(|_| db_error())?
    else {
        return Err(not_found("rulepack version not found"));
    };
    if row.slot == "active" {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "cannot retire the active rulepack; activate another version first".into(),
            }),
        ));
    }
    let row = crate::waf_rulepack::retire(&state.pool, &version)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("rulepack version not found"))?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "waf.rulepack.retire",
        &version,
        "将规则包版本标记为 retired",
    )
    .await;
    Ok(Json(RulepackVersionDto::from(&row)))
}

pub async fn delete_rulepack(
    State(state): State<AppState>,
    actor: Actor,
    Path(version): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    if !actor.is_admin {
        return Err(forbidden());
    }
    let Some(row) = crate::waf_rulepack::get(&state.pool, &version)
        .await
        .map_err(|_| db_error())?
    else {
        return Err(not_found("rulepack version not found"));
    };
    if row.slot == "active" || row.slot == "previous" {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: format!(
                    "cannot delete {} rulepack; retire it first",
                    row.slot
                ),
            }),
        ));
    }
    let pinned = crate::waf_rulepack::pinned_count(&state.pool, &version)
        .await
        .map_err(|_| db_error())?;
    if pinned > 0 {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: format!(
                    "{pinned} domain(s) still pin rulepack {version}; clear their waf_rulepack_version first"
                ),
            }),
        ));
    }
    let affected = crate::waf_rulepack::delete(&state.pool, &version)
        .await
        .map_err(|_| db_error())?;
    if affected == 0 {
        return Err(not_found("rulepack version not found"));
    }
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "waf.rulepack.delete",
        &version,
        "删除规则包版本",
    )
    .await;
    Ok(Json(serde_json::json!({ "deleted": version })))
}

pub async fn download_rulepack(
    State(state): State<AppState>,
    _agent: AgentAuth,
    Path(version): Path<String>,
) -> Result<Json<RulepackDownload>, (StatusCode, Json<ErrorBody>)> {
    let row = if version == "active" {
        crate::waf_rulepack::active(&state.pool).await
    } else {
        crate::waf_rulepack::get(&state.pool, &version).await
    }
    .map_err(|_| db_error())?
    .ok_or_else(|| not_found("rulepack version not found"))?;
    Ok(Json(RulepackDownload {
        version: row.version,
        payload: row.payload,
        signature: row.signature,
        checksum: row.checksum,
    }))
}

#[derive(Deserialize)]
pub struct SettingsRequest {
    pub enabled: Option<bool>,
    pub mode: Option<String>,
    pub sqli: Option<bool>,
    pub xss: Option<bool>,
    pub traversal: Option<bool>,
    pub scanners: Option<bool>,
    pub rce: Option<bool>,
    pub ssrf: Option<bool>,
    pub xxe: Option<bool>,
    pub log4shell: Option<bool>,
    pub crlf: Option<bool>,
    pub ssti: Option<bool>,
    pub nosql: Option<bool>,
    pub ldap: Option<bool>,
    pub java: Option<bool>,
    pub webshell: Option<bool>,
    pub protocol: Option<bool>,
    pub challenge_difficulty: Option<u8>,
    pub challenge_ttl_secs: Option<u32>,
    pub security_level: Option<String>,
    pub managed_rulesets: Option<Vec<String>>,
    pub waf_rulepack_version: Option<String>,
    pub waf_gray_percent: Option<u8>,
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

    let security_level = req
        .security_level
        .as_deref()
        .unwrap_or(&current.security_level)
        .trim()
        .to_ascii_lowercase();
    if !["off", "low", "medium", "high", "under_attack"].contains(&security_level.as_str()) {
        return Err(bad_request(
            "security_level must be off, low, medium, high or under_attack".into(),
        ));
    }

    let managed_rulesets = match req.managed_rulesets.as_deref() {
        Some(ids) => crate::waf_rulesets::validate_ids(ids)
            .map_err(|e| bad_request(e))?,
        None => current.managed_rulesets.clone(),
    };
    let managed_csv = managed_rulesets.join(",");

    let waf_rulepack_version = req
        .waf_rulepack_version
        .as_deref()
        .unwrap_or(&current.waf_rulepack_version)
        .trim()
        .to_string();
    if !waf_rulepack_version.is_empty() {
        crate::waf_rulepack::validate_version(&waf_rulepack_version)
            .map_err(|e| bad_request(e))?;
        if crate::waf_rulepack::get(&state.pool, &waf_rulepack_version)
            .await
            .map_err(|_| db_error())?
            .is_none()
        {
            return Err(bad_request(format!(
                "unknown WAF rulepack version: {waf_rulepack_version}"
            )));
        }
    }
    let waf_gray_percent = req
        .waf_gray_percent
        .unwrap_or(current.waf_gray_percent)
        .min(100) as i32;

    let row = repository::upsert_waf_settings(
        &state.pool,
        domain_id,
        req.enabled.unwrap_or(current.enabled),
        &mode,
        req.sqli.unwrap_or(current.sqli),
        req.xss.unwrap_or(current.xss),
        req.traversal.unwrap_or(current.traversal),
        req.scanners.unwrap_or(current.scanners),
        req.rce.unwrap_or(current.rce),
        req.ssrf.unwrap_or(current.ssrf),
        req.xxe.unwrap_or(current.xxe),
        req.log4shell.unwrap_or(current.log4shell),
        req.crlf.unwrap_or(current.crlf),
        req.ssti.unwrap_or(current.ssti),
        req.nosql.unwrap_or(current.nosql),
        req.ldap.unwrap_or(current.ldap),
        req.java.unwrap_or(current.java),
        req.webshell.unwrap_or(current.webshell),
        req.protocol.unwrap_or(current.protocol),
        req.challenge_difficulty
            .unwrap_or(current.challenge_difficulty)
            .clamp(1, 6) as i32,
        req.challenge_ttl_secs
            .unwrap_or(current.challenge_ttl_secs)
            .clamp(60, 86_400) as i32,
        &security_level,
        &managed_csv,
        &waf_rulepack_version,
        waf_gray_percent,
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
            "enabled={} mode={mode} level={} sqli={} xss={} traversal={} scanners={} \
             rce={} ssrf={} xxe={} log4shell={} crlf={} ssti={} nosql={} ldap={} \
             java={} webshell={} protocol={} rulesets={} rulepack={} gray={}% challenge={}/{}s",
            row.enabled,
            row.security_level,
            row.sqli,
            row.xss,
            row.traversal,
            row.scanners,
            row.rce,
            row.ssrf,
            row.xxe,
            row.log4shell,
            row.crlf,
            row.ssti,
            row.nosql,
            row.ldap,
            row.java,
            row.webshell,
            row.protocol,
            managed_csv,
            waf_rulepack_version,
            waf_gray_percent,
            row.challenge_difficulty,
            row.challenge_ttl_secs
        ),
    )
    .await;

    record_waf_version(&state, domain_id, &actor, "waf.settings", "更新 WAF 设置").await;
    Ok(Json(row.into()))
}

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
    let header_field = field.strip_prefix("header:").map(|name| {
        let name = name.trim();
        !name.is_empty()
            && name.len() <= 64
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    });
    if !FIELDS.contains(&field.as_str()) && header_field != Some(true) {
        return Err(bad_request(format!(
            "field must be one of {} or header:<name>",
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
    record_waf_version(
        &state,
        domain_id,
        &actor,
        "waf.rule.create",
        &format!("新增 WAF 规则 {}", rule.name),
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
    record_waf_version(
        &state,
        row.domain_id,
        &actor,
        "waf.rule.update",
        &format!("更新 WAF 规则 {}", row.name),
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
    record_waf_version(
        &state,
        existing.domain_id,
        &actor,
        "waf.rule.delete",
        &format!("删除 WAF 规则 {}", existing.name),
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
    record_waf_version(
        &state,
        domain_id,
        &actor,
        "waf.ip.create",
        &format!("新增 WAF IP {kind} {ip}"),
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
    record_waf_version(
        &state,
        existing.domain_id,
        &actor,
        "waf.ip.delete",
        &format!("删除 WAF IP {} {}", existing.kind, existing.ip),
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

#[derive(Deserialize)]
pub struct StatsQuery {
    pub domain: Option<String>,
    pub days: Option<i32>,
}

#[derive(Serialize)]
pub struct CountDto {
    pub key: String,
    pub count: i64,
}

#[derive(Serialize)]
pub struct WafStatsResponse {
    pub days: i32,
    pub total: i64,
    pub by_action: Vec<CountDto>,
    pub by_category: Vec<CountDto>,
    pub by_day: Vec<CountDto>,
    pub top_ips: Vec<CountDto>,
    pub top_rules: Vec<CountDto>,
    pub top_paths: Vec<CountDto>,
}

fn to_counts(rows: Vec<(String, i64)>) -> Vec<CountDto> {
    rows.into_iter()
        .map(|(key, count)| CountDto { key, count })
        .collect()
}

/// Dashboard aggregates for WAF events (project-scoped for non-admins).
pub async fn stats(
    State(state): State<AppState>,
    actor: Actor,
    Query(q): Query<StatsQuery>,
) -> Result<Json<WafStatsResponse>, (StatusCode, Json<ErrorBody>)> {
    let days = q.days.unwrap_or(7).clamp(1, 90);
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

    let domain_filter = q.domain.as_deref().filter(|d| !d.is_empty());
    if let (Some(name), Some(names)) = (domain_filter, &visible) {
        if !names.contains(name) {
            return Ok(Json(WafStatsResponse {
                days,
                total: 0,
                by_action: vec![],
                by_category: vec![],
                by_day: vec![],
                top_ips: vec![],
                top_rules: vec![],
                top_paths: vec![],
            }));
        }
    }
    let domains_vec: Option<Vec<String>> = visible.map(|s| s.into_iter().collect());

    let group = |expr: &'static str, limit: i64| {
        repository::waf_stats_group(
            &state.pool,
            days,
            domain_filter,
            domains_vec.clone(),
            expr,
            limit,
        )
    };

    let by_action = group("action", 20).await.map_err(|_| db_error())?;
    let total = by_action.iter().map(|(_, c)| *c).sum();
    let by_category = group("category", 20).await.map_err(|_| db_error())?;
    let by_day = group("day", 90).await.map_err(|_| db_error())?;
    let top_ips = group("client_ip", 10).await.map_err(|_| db_error())?;
    let top_rules = group("rule_name", 10).await.map_err(|_| db_error())?;
    let top_paths = group("path", 10).await.map_err(|_| db_error())?;

    Ok(Json(WafStatsResponse {
        days,
        total,
        by_action: to_counts(by_action),
        by_category: to_counts(by_category),
        by_day: to_counts(by_day),
        top_ips: to_counts(top_ips),
        top_rules: to_counts(top_rules),
        top_paths: to_counts(top_paths),
    }))
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
