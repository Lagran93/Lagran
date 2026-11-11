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

/// Canonical text form of an IP or CIDR.
///
/// Without this, `10.0.0.1`, `10.0.0.1/32` and `010.0.0.1/32` are three distinct
/// strings in the database even though the edge evaluates them identically. That
/// let one tenant pile up unlimited duplicate entries, each of which the edge
/// scans linearly on every request.
///
/// A bare address is stored as a bare address and an explicit prefix is
/// preserved, so `10.0.0.0/8` keeps its meaning while `10.0.0.1/32` collapses to
/// `10.0.0.1`.
pub fn normalize_cidr(input: &str) -> Option<String> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }
    let (addr, prefix) = match input.split_once('/') {
        Some((a, p)) => (a.trim(), Some(p.trim())),
        None => (input, None),
    };
    let addr: IpAddr = addr.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    match prefix {
        None => Some(addr.to_string()),
        Some(p) => {
            let prefix: u8 = p.parse().ok()?;
            if prefix > max {
                return None;
            }
            if prefix == max {
                // `x/32` and `x/128` name a single host; store the bare address.
                return Some(addr.to_string());
            }
            Some(format!("{addr}/{prefix}"))
        }
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
    let Some(secret) = crate::waf_rulepack::signing_key(&state.config.waf_rulepack_secret) else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorBody {
                error: "WAF_RULEPACK_SECRET is not configured; refusing to publish an \
                        unverifiable rulepack"
                    .into(),
            }),
        ));
    };
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
    // Promote only if the target can actually be signed: a version that the
    // edges cannot verify is not a usable rollback target.
    let Some(secret) = crate::waf_rulepack::signing_key(&state.config.waf_rulepack_secret)
    else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorBody {
                error: "WAF_RULEPACK_SECRET is not configured; cannot re-sign the rulepack"
                    .into(),
            }),
        ));
    };
    let row = crate::waf_rulepack::rollback(&state.pool, &secret, &version)
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
    pub expr: String,
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
            expr: r.expr,
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
    /// Optional boolean DSL. When non-empty, it replaces the single condition.
    pub expr: Option<String>,
}

struct ValidRule {
    name: String,
    field: String,
    operator: String,
    value: String,
    action: String,
    priority: i32,
    enabled: bool,
    expr: String,
}

/// Upper bounds for a stored custom rule.
///
/// `WafRuleOut` is serialised into the config document that every edge holds in
/// memory, so an unbounded `value` is a cross-tenant memory and bandwidth
/// amplifier: one tenant can park megabytes on every node. The limits match the
/// DSL crate's own constants so a value that passes here also fits the parser.
const MAX_RULE_NAME: usize = 128;
const MAX_RULE_VALUE: usize = 512;
const MAX_RULE_EXPR: usize = 1024;

fn validate_rule(req: &WafRuleRequest) -> Result<ValidRule, (StatusCode, Json<ErrorBody>)> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(bad_request("name required".into()));
    }
    // Count characters, not bytes: a CJK rule name is legitimate and must not be
    // rejected for being multi-byte.
    if name.chars().count() > MAX_RULE_NAME {
        return Err(bad_request(format!(
            "name must be at most {MAX_RULE_NAME} characters"
        )));
    }
    let expr = req.expr.as_deref().unwrap_or("").trim().to_string();
    if !expr.is_empty() {
        if expr.chars().count() > MAX_RULE_EXPR {
            return Err(bad_request(format!(
                "expr must be at most {MAX_RULE_EXPR} characters"
            )));
        }
        lagran_waf_dsl::validate(&expr).map_err(|e| {
            bad_request(format!("invalid DSL at position {}: {}", e.position, e.message))
        })?;
    }

    let mut field = req.field.trim().to_ascii_lowercase();
    let mut operator = req.operator.trim().to_ascii_lowercase();
    let mut value = req.value.trim().to_string();
    if expr.is_empty() {
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
        if !OPERATORS.contains(&operator.as_str()) {
            return Err(bad_request(format!(
                "operator must be one of {}",
                OPERATORS.join(", ")
            )));
        }
        if value.is_empty() {
            return Err(bad_request("value required".into()));
        }
        if value.chars().count() > MAX_RULE_VALUE {
            return Err(bad_request(format!(
                "value must be at most {MAX_RULE_VALUE} characters"
            )));
        }
    } else {
        // The DSL supersedes the legacy condition. Keep harmless defaults for
        // old Edge binaries and for the table's NOT NULL columns.
        if field.is_empty() {
            field = "path".into();
        }
        if operator.is_empty() {
            operator = "contains".into();
        }
        if value.is_empty() {
            value = expr.clone();
        }
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
        // Clamped rather than rejected: priority only orders rules, and an
        // out-of-range value carries no useful meaning.
        priority: req.priority.unwrap_or(0).clamp(-1000, 1000),
        enabled: req.enabled.unwrap_or(true),
        expr,
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
        &rule.expr,
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
            "{} {} {} {} expr={}",
            rule.field, rule.operator, rule.value, rule.action, rule.expr
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

/// Whether a submitted string should replace the stored value.
///
/// The wire format uses empty strings for "field omitted", so empty always means
/// "keep what is stored". Getting this wrong made a partial update rewrite the
/// stored rule: `validate_rule` substitutes defaults for empty fields, and in DSL
/// mode it copies the whole expression into `value`.
fn keep_existing(submitted: &str) -> bool {
    submitted.trim().is_empty()
}

pub async fn update_rule(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(mut req): Json<WafRuleRequest>,
) -> Result<Json<WafRuleDto>, (StatusCode, Json<ErrorBody>)> {
    let rule_id = parse_uuid(&id)?;
    let existing = repository::get_waf_rule(&state.pool, rule_id)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("rule not found"))?;
    if !actor.can_write_domain(&state, existing.domain_id).await {
        return Err(forbidden());
    }
    // A partial update (the enable/disable toggle, a rename) must preserve every
    // field the caller did not send. Only back-filling `expr` was not enough:
    // when the request carried an `expr` but no `field`/`operator`/`value`,
    // `validate_rule` filled the legacy columns with defaults and silently
    // rewrote the stored rule (`value` became the whole expression).
    if req.expr.is_none() {
        req.expr = Some(existing.expr.clone());
    }
    // `name`/`field`/`operator`/`value` are required strings in the wire format,
    // so "not supplied" arrives as an empty string. Treat empty as unchanged
    // rather than letting `validate_rule` substitute defaults and rewrite the
    // stored rule.
    if keep_existing(&req.name) {
        req.name = existing.name.clone();
    }
    if keep_existing(&req.field) {
        req.field = existing.field.clone();
    }
    if keep_existing(&req.operator) {
        req.operator = existing.operator.clone();
    }
    if keep_existing(&req.value) {
        // Covers both "caller omitted value" and "caller sent only an expr":
        // `validate_rule` would otherwise replace `value` with the whole
        // expression and destroy the legacy condition columns.
        req.value = existing.value.clone();
    }
    if req.action.is_none() {
        req.action = Some(existing.action.clone());
    }
    if req.priority.is_none() {
        req.priority = Some(existing.priority);
    }
    if req.enabled.is_none() {
        req.enabled = Some(existing.enabled);
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
        &rule.expr,
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
    pub enabled: bool,
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
            enabled: r.enabled,
            created_at: r.created_at.to_rfc3339(),
        }
    }
}

#[derive(Deserialize)]
pub struct WafIpRequest {
    pub kind: String,
    pub ip: String,
    pub note: Option<String>,
    pub enabled: Option<bool>,
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
    let Some(ip) = normalize_cidr(&req.ip) else {
        return Err(bad_request("ip must be an IP or CIDR".into()));
    };
    // Reject duplicates before insert: each extra entry is scanned linearly by
    // every edge on every request, so unbounded duplicates are a cross-tenant
    // amplification vector. The unique index enforces the same rule in the
    // database for concurrent writers.
    if repository::waf_ip_exists(&state.pool, domain_id, &kind, &ip)
        .await
        .map_err(|_| db_error())?
    {
        return Err(bad_request("this IP entry already exists".into()));
    }
    let row = repository::create_waf_ip(
        &state.pool,
        domain_id,
        &kind,
        &ip,
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

pub async fn update_ip(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<WafIpRequest>,
) -> Result<Json<WafIpDto>, (StatusCode, Json<ErrorBody>)> {
    let ip_id = parse_uuid(&id)?;
    let existing = repository::get_waf_ip(&state.pool, ip_id)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("ip rule not found"))?;
    if !actor.can_write_domain(&state, existing.domain_id).await {
        return Err(forbidden());
    }
    let kind = req.kind.trim().to_ascii_lowercase();
    if kind != "allow" && kind != "deny" {
        return Err(bad_request("kind must be allow or deny".into()));
    }
    let Some(ip) = normalize_cidr(&req.ip) else {
        return Err(bad_request("ip must be an IP or CIDR".into()));
    };
    if repository::waf_ip_exists_except(
        &state.pool,
        ip_id,
        existing.domain_id,
        &kind,
        &ip,
    )
    .await
    .map_err(|_| db_error())?
    {
        return Err(bad_request("this IP entry already exists".into()));
    }
    let row = repository::update_waf_ip(
        &state.pool,
        ip_id,
        &kind,
        &ip,
        req.note.as_deref().unwrap_or(""),
        req.enabled.unwrap_or(existing.enabled),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "update waf ip");
        db_error()
    })?
    .ok_or_else(|| not_found("ip rule not found"))?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "waf.ip.update",
        &existing.domain_id.to_string(),
        &format!("{} {} -> {kind} {ip}", existing.kind, existing.ip),
    )
    .await;
    record_waf_version(
        &state,
        existing.domain_id,
        &actor,
        "waf.ip.update",
        &format!("更新 WAF IP {kind} {ip}"),
    )
    .await;
    Ok(Json(row.into()))
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

// ------------------------------------------------------------ Geo/ASN lists

#[derive(Serialize)]
pub struct WafGeoDto {
    pub id: String,
    pub domain_id: String,
    pub kind: String,
    pub value: String,
    pub note: String,
    pub enabled: bool,
    pub created_at: String,
}

impl From<repository::WafGeoRow> for WafGeoDto {
    fn from(r: repository::WafGeoRow) -> Self {
        Self {
            id: r.id.to_string(),
            domain_id: r.domain_id.to_string(),
            kind: r.kind,
            value: r.value,
            note: r.note,
            enabled: r.enabled,
            created_at: r.created_at.to_rfc3339(),
        }
    }
}

#[derive(Deserialize)]
pub struct WafGeoRequest {
    pub kind: String,
    pub value: String,
    pub note: Option<String>,
    pub enabled: Option<bool>,
}

const GEO_KINDS: [&str; 4] = ["country_allow", "country_deny", "asn_allow", "asn_deny"];

fn normalize_country(input: &str) -> Option<String> {
    let code = input.trim().to_ascii_uppercase();
    if code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase()) {
        Some(code)
    } else {
        None
    }
}

/// Accept both `13335` and `AS13335`.
fn normalize_asn(input: &str) -> Option<u32> {
    let value = input.trim();
    let digits = match value
        .get(..2)
        .filter(|prefix| prefix.eq_ignore_ascii_case("as"))
    {
        Some(_) => &value[2..],
        None => value,
    };
    match digits.trim().parse::<u32>() {
        Ok(asn) if asn > 0 => Some(asn),
        _ => None,
    }
}

fn geo_kind_label(kind: &str) -> &'static str {
    match kind {
        "country_allow" => "国家/地区白名单",
        "country_deny" => "国家/地区黑名单",
        "asn_allow" => "ASN 白名单",
        _ => "ASN 黑名单",
    }
}

pub async fn list_geo(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<Vec<WafGeoDto>>, (StatusCode, Json<ErrorBody>)> {
    let domain_id = parse_uuid(&id)?;
    if !actor.can_read_domain(&state, domain_id).await {
        return Err(forbidden());
    }
    let rows = repository::list_waf_geo(&state.pool, domain_id)
        .await
        .map_err(|_| db_error())?;
    Ok(Json(rows.into_iter().map(WafGeoDto::from).collect()))
}

pub async fn create_geo(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<WafGeoRequest>,
) -> Result<(StatusCode, Json<WafGeoDto>), (StatusCode, Json<ErrorBody>)> {
    let domain_id = parse_uuid(&id)?;
    if !actor.can_write_domain(&state, domain_id).await {
        return Err(forbidden());
    }
    let kind = req.kind.trim().to_ascii_lowercase();
    if !GEO_KINDS.contains(&kind.as_str()) {
        return Err(bad_request(format!(
            "kind must be one of {}",
            GEO_KINDS.join(", ")
        )));
    }
    let value = if kind.starts_with("country") {
        let Some(code) = normalize_country(&req.value) else {
            return Err(bad_request(
                "value must be an ISO 3166-1 alpha-2 country code".into(),
            ));
        };
        code
    } else {
        let Some(asn) = normalize_asn(&req.value) else {
            return Err(bad_request(
                "value must be an ASN such as 13335 or AS13335".into(),
            ));
        };
        asn.to_string()
    };
    if repository::waf_geo_exists(&state.pool, domain_id, &kind, &value)
        .await
        .map_err(|_| db_error())?
    {
        return Err(bad_request("this entry already exists".into()));
    }
    let row = repository::create_waf_geo(
        &state.pool,
        domain_id,
        &kind,
        &value,
        req.note.as_deref().unwrap_or(""),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "create waf geo rule");
        db_error()
    })?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "waf.geo.create",
        &domain_id.to_string(),
        &format!("{kind} {value}"),
    )
    .await;
    record_waf_version(
        &state,
        domain_id,
        &actor,
        "waf.geo.create",
        &format!("新增 WAF {} {value}", geo_kind_label(&kind)),
    )
    .await;
    Ok((StatusCode::CREATED, Json(row.into())))
}

pub async fn update_geo(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<WafGeoRequest>,
) -> Result<Json<WafGeoDto>, (StatusCode, Json<ErrorBody>)> {
    let geo_id = parse_uuid(&id)?;
    let existing = repository::get_waf_geo(&state.pool, geo_id)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("geo rule not found"))?;
    if !actor.can_write_domain(&state, existing.domain_id).await {
        return Err(forbidden());
    }
    let kind = req.kind.trim().to_ascii_lowercase();
    if !GEO_KINDS.contains(&kind.as_str()) {
        return Err(bad_request(format!(
            "kind must be one of {}",
            GEO_KINDS.join(", ")
        )));
    }
    let value = if kind.starts_with("country") {
        let Some(code) = normalize_country(&req.value) else {
            return Err(bad_request(
                "value must be an ISO 3166-1 alpha-2 country code".into(),
            ));
        };
        code
    } else {
        let Some(asn) = normalize_asn(&req.value) else {
            return Err(bad_request(
                "value must be an ASN such as 13335 or AS13335".into(),
            ));
        };
        asn.to_string()
    };
    if repository::waf_geo_exists_except(&state.pool, geo_id, existing.domain_id, &kind, &value)
        .await
        .map_err(|_| db_error())?
    {
        return Err(bad_request("this entry already exists".into()));
    }
    let row = repository::update_waf_geo(
        &state.pool,
        geo_id,
        &kind,
        &value,
        req.note.as_deref().unwrap_or(""),
        req.enabled.unwrap_or(existing.enabled),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "update waf geo rule");
        db_error()
    })?
    .ok_or_else(|| not_found("geo rule not found"))?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "waf.geo.update",
        &existing.domain_id.to_string(),
        &format!("{} {} -> {kind} {value}", existing.kind, existing.value),
    )
    .await;
    record_waf_version(
        &state,
        existing.domain_id,
        &actor,
        "waf.geo.update",
        &format!("更新 WAF {} {value}", geo_kind_label(&kind)),
    )
    .await;
    Ok(Json(row.into()))
}

pub async fn delete_geo(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let geo_id = parse_uuid(&id)?;
    let existing = repository::get_waf_geo(&state.pool, geo_id)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("geo rule not found"))?;
    if !actor.can_write_domain(&state, existing.domain_id).await {
        return Err(forbidden());
    }
    repository::delete_waf_geo(&state.pool, geo_id)
        .await
        .map_err(|_| db_error())?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "waf.geo.delete",
        &existing.domain_id.to_string(),
        &format!("{} {}", existing.kind, existing.value),
    )
    .await;
    record_waf_version(
        &state,
        existing.domain_id,
        &actor,
        "waf.geo.delete",
        &format!(
            "删除 WAF {} {}",
            geo_kind_label(&existing.kind),
            existing.value
        ),
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

/// Per-field limits for an uploaded event.
///
/// These columns are `TEXT` with no length check, so an agent could store
/// multi-megabyte values and then have them grouped by the stats queries. They
/// also feed dashboards, so a bound keeps the display sane.
const MAX_EVENT_PATH: usize = 2048;
const MAX_EVENT_FIELD: usize = 256;
const MAX_EVENT_NAME: usize = 128;

/// Trim and truncate a field to at most `max` **characters**.
///
/// Counts characters rather than bytes so a truncated value is always valid
/// UTF-8 and never splits a multi-byte sequence.
fn clamp_event(value: &str, max: usize) -> String {
    value.trim().chars().take(max).collect()
}

/// Edge → control batch upload.
///
/// Events are attributed to a domain by name, so an agent could previously write
/// into any domain's history, including domains it does not serve. The domain is
/// now required to exist, and every free-form field is bounded.
pub async fn report_events(
    State(state): State<AppState>,
    _agent: AgentAuth,
    Json(body): Json<EventsBody>,
) -> Json<ReportAck> {
    // Resolve the set of known domains once per batch instead of per event.
    let known: std::collections::HashSet<String> = repository::list_domains(&state.pool)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|d| d.name.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();

    let mut inputs = Vec::with_capacity(body.events.len().min(1000));
    let mut rejected_domain = 0usize;
    for e in body.events.into_iter().take(1000) {
        let domain = clamp_event(&e.domain, MAX_EVENT_FIELD);
        if domain.is_empty() {
            continue;
        }
        if !known.contains(&domain.to_ascii_lowercase()) {
            // Unknown or foreign domain: drop the event instead of polluting
            // another tenant's history and stats.
            rejected_domain += 1;
            continue;
        }
        inputs.push(repository::WafEventInput {
            domain,
            node_id: clamp_event(&e.node_id.unwrap_or_default(), MAX_EVENT_FIELD),
            client_ip: clamp_event(&e.client_ip.unwrap_or_default(), 64),
            method: clamp_event(&e.method.unwrap_or_default(), 16),
            path: clamp_event(&e.path.unwrap_or_default(), MAX_EVENT_PATH),
            action: clamp_event(&e.action, 32),
            category: clamp_event(&e.category.unwrap_or_default(), MAX_EVENT_NAME),
            rule_name: clamp_event(&e.rule_name.unwrap_or_default(), MAX_EVENT_NAME),
            mode: clamp_event(&e.mode.unwrap_or_else(|| "block".into()), 32),
        });
    }
    if rejected_domain > 0 {
        tracing::warn!(
            rejected = rejected_domain,
            "dropped WAF events for unknown domains"
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_request(name: &str, value: &str) -> WafRuleRequest {
        WafRuleRequest {
            name: name.into(),
            field: "path".into(),
            operator: "contains".into(),
            value: value.into(),
            action: Some("block".into()),
            priority: None,
            enabled: None,
            expr: None,
        }
    }

    /// `value` is shipped to every edge in the config document, so it must be
    /// bounded; one tenant could otherwise park megabytes on every node.
    #[test]
    fn oversized_rule_value_is_rejected() {
        let ok = rule_request("r", &"a".repeat(MAX_RULE_VALUE));
        assert!(validate_rule(&ok).is_ok());

        let too_long = rule_request("r", &"a".repeat(MAX_RULE_VALUE + 1));
        assert!(validate_rule(&too_long).is_err());
    }

    /// Multi-byte values are measured in characters, not bytes.
    #[test]
    fn rule_value_limit_counts_characters() {
        let cjk = rule_request("r", &"中".repeat(MAX_RULE_VALUE));
        assert!(
            validate_rule(&cjk).is_ok(),
            "{} characters must be accepted",
            MAX_RULE_VALUE
        );
    }

    #[test]
    fn oversized_rule_name_is_rejected() {
        let long_name = rule_request(&"n".repeat(MAX_RULE_NAME + 1), "/admin");
        assert!(validate_rule(&long_name).is_err());
        let ok = rule_request(&"n".repeat(MAX_RULE_NAME), "/admin");
        assert!(validate_rule(&ok).is_ok());
    }

    #[test]
    fn oversized_expr_is_rejected() {
        let mut req = rule_request("r", "/admin");
        req.expr = Some(format!("path contains \"{}\"", "a".repeat(MAX_RULE_EXPR)));
        assert!(validate_rule(&req).is_err());
    }

    /// Priority only orders rules; an absurd value is clamped, not rejected.
    #[test]
    fn priority_is_clamped() {
        let mut req = rule_request("r", "/admin");
        req.priority = Some(i32::MAX);
        let high = validate_rule(&req).ok().map(|r| r.priority);
        assert_eq!(high, Some(1000));
        req.priority = Some(i32::MIN);
        let low = validate_rule(&req).ok().map(|r| r.priority);
        assert_eq!(low, Some(-1000));
    }

    /// Empty means "field omitted" in the wire format. Treating it as a value
    /// made a partial update rewrite the stored rule via `validate_rule`'s
    /// defaults (and, in DSL mode, copy the expression into `value`).
    #[test]
    fn keep_existing_preserves_omitted_fields() {
        assert!(keep_existing(""));
        assert!(keep_existing("   "));
        assert!(!keep_existing("/admin"));
        assert!(!keep_existing(" example.com "));
    }

    /// Event fields are bounded so an agent cannot store unbounded text that the
    /// stats queries then group over.
    #[test]
    fn clamp_event_bounds_utf8_safely() {
        let long = "a".repeat(5000);
        assert_eq!(clamp_event(&long, MAX_EVENT_PATH).chars().count(), MAX_EVENT_PATH);
        // Multi-byte input is cut on a character boundary, never mid-sequence.
        let cjk = "中".repeat(1000);
        let cut = clamp_event(&cjk, 10);
        assert_eq!(cut.chars().count(), 10);
        assert_eq!(cut, "中".repeat(10));
        assert_eq!(clamp_event("  spaced  ", 64), "spaced");
    }

    #[test]
    fn event_limits_are_sane() {
        assert!(MAX_EVENT_PATH >= 512);
        assert!(MAX_EVENT_FIELD >= 64);
        assert!(MAX_EVENT_NAME >= 32);
    }


    /// Without canonicalization `10.0.0.1`, `10.0.0.1/32` and a padded form are
    /// distinct strings, which is how duplicates piled up in the first place.
    #[test]
    fn normalize_cidr_collapses_equivalent_forms() {
        for input in ["10.0.0.1", "10.0.0.1/32", " 10.0.0.1 ", "10.0.0.1/32 "] {
            assert_eq!(
                normalize_cidr(input).as_deref(),
                Some("10.0.0.1"),
                "input {input:?}"
            );
        }
        assert_eq!(
            normalize_cidr("2001:db8::1/128").as_deref(),
            Some("2001:db8::1")
        );
        // A real prefix keeps its meaning.
        assert_eq!(normalize_cidr("10.0.0.0/8").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(
            normalize_cidr("2001:db8::/32").as_deref(),
            Some("2001:db8::/32")
        );
    }

    #[test]
    fn normalize_cidr_rejects_invalid_input() {
        for bad in ["", "  ", "not-an-ip", "10.0.0.1/33", "::1/129", "10.0.0.1/x"] {
            assert!(normalize_cidr(bad).is_none(), "{bad:?} must be rejected");
        }
    }
}
