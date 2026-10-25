//! Cache rules: CRUD with path/method/query conditions, browser TTL and a
//! rule tester that mirrors the edge matcher.

use crate::middleware::authz::Actor;
use crate::repository;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const ACTIONS: [&str; 3] = ["cache", "bypass", "no_store"];
const METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

#[derive(Serialize)]
pub struct RuleDto {
    pub id: String,
    pub domain_id: String,
    pub domain_name: String,
    pub path_pattern: String,
    pub ttl_seconds: u64,
    pub priority: i32,
    pub action: String,
    pub swr_seconds: u64,
    pub enabled: bool,
    pub match_methods: String,
    pub match_query: String,
    pub browser_ttl_seconds: u64,
    pub ignore_query: Option<bool>,
    pub note: String,
}

impl RuleDto {
    fn from_row(r: repository::CacheRuleRow, domain_name: &str) -> Self {
        Self {
            id: r.id.to_string(),
            domain_id: r.domain_id.to_string(),
            domain_name: domain_name.to_string(),
            path_pattern: r.path_pattern,
            ttl_seconds: r.ttl_seconds.max(0) as u64,
            priority: r.priority,
            action: r.action,
            swr_seconds: r.swr_seconds.max(0) as u64,
            enabled: r.enabled,
            match_methods: r.match_methods,
            match_query: r.match_query,
            browser_ttl_seconds: r.browser_ttl_seconds.max(0) as u64,
            ignore_query: r.ignore_query,
            note: r.note,
        }
    }
}

#[derive(Deserialize)]
pub struct RulePayload {
    pub path_pattern: Option<String>,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    pub priority: Option<i32>,
    pub action: Option<String>,
    pub swr_seconds: Option<u64>,
    pub enabled: Option<bool>,
    pub match_methods: Option<String>,
    pub match_query: Option<String>,
    pub browser_ttl_seconds: Option<u64>,
    /// `null` = inherit the domain setting, `true/false` = explicit override.
    /// Double option so an explicit `null` can clear an existing override.
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub ignore_query: Option<Option<bool>>,
    pub note: Option<String>,
}

fn deserialize_double_option<'de, D>(
    deserializer: D,
) -> Result<Option<Option<bool>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<bool>::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
pub struct CreateRuleRequest {
    pub domain_id: String,
    #[serde(flatten)]
    pub rule: RulePayload,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

struct Normalized {
    path_pattern: String,
    ttl_seconds: i64,
    priority: i32,
    action: String,
    swr_seconds: i64,
    enabled: bool,
    match_methods: String,
    match_query: String,
    browser_ttl_seconds: i64,
    ignore_query: Option<bool>,
    note: String,
}

fn normalize_path(path: &str) -> Result<String, String> {
    let path = path.trim();
    if path.is_empty() {
        return Err("path_pattern required".into());
    }
    if !path.starts_with('/') && path != "*" {
        return Err("path_pattern must start with /".into());
    }
    if path.len() > 256 {
        return Err("path_pattern is too long".into());
    }
    Ok(path.to_string())
}

fn normalize_methods(raw: &str) -> Result<String, String> {
    let mut out: Vec<String> = Vec::new();
    for part in raw.split(',') {
        let m = part.trim().to_ascii_uppercase();
        if m.is_empty() {
            continue;
        }
        if !METHODS.contains(&m.as_str()) {
            return Err(format!("unsupported method: {m}"));
        }
        if !out.contains(&m) {
            out.push(m);
        }
    }
    Ok(out.join(","))
}

#[allow(clippy::too_many_arguments)]
fn normalize(
    payload: &RulePayload,
    path_pattern: &str,
    action: &str,
    ttl: u64,
    swr: u64,
    methods: &str,
    query: &str,
    browser_ttl: u64,
    priority: i32,
    enabled: bool,
    ignore_query: Option<bool>,
    note: &str,
) -> Result<Normalized, String> {
    let path_pattern = normalize_path(path_pattern)?;
    let action = action.trim().to_ascii_lowercase();
    if !ACTIONS.contains(&action.as_str()) {
        return Err("action must be cache, bypass or no_store".into());
    }
    let ttl_seconds = if action == "cache" { ttl.min(31_536_000) } else { 0 };
    let swr_seconds = if action == "cache" { swr.min(31_536_000) } else { 0 };
    let match_methods = normalize_methods(methods)?;
    let match_query = query.trim().to_string();
    if match_query.len() > 200 {
        return Err("match_query is too long".into());
    }
    let browser_ttl_seconds = if action == "cache" {
        browser_ttl.min(31_536_000)
    } else {
        0
    };
    let note = note.trim().to_string();
    if note.len() > 200 {
        return Err("note is too long".into());
    }
    Ok(Normalized {
        path_pattern,
        ttl_seconds: ttl_seconds as i64,
        priority: payload.priority.unwrap_or(priority),
        action,
        swr_seconds: swr_seconds as i64,
        enabled: payload.enabled.unwrap_or(enabled),
        match_methods,
        match_query,
        browser_ttl_seconds: browser_ttl_seconds as i64,
        ignore_query,
        note,
    })
}

pub async fn list(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<RuleDto>>, (StatusCode, Json<ErrorBody>)> {
    let rows = repository::list_all_rules(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "list rules");
        db_error()
    })?;
    let visible = actor.visible_domain_ids(&state).await;
    Ok(Json(
        rows.into_iter()
            .filter(|(r, _)| match &visible {
                None => true,
                Some(ids) => ids.contains(&r.domain_id),
            })
            .map(|(r, name)| RuleDto::from_row(r, &name))
            .collect(),
    ))
}

pub async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<CreateRuleRequest>,
) -> Result<(StatusCode, Json<RuleDto>), (StatusCode, Json<ErrorBody>)> {
    let domain_id = Uuid::parse_str(&req.domain_id).map_err(|_| bad_request("invalid domain_id"))?;
    if !actor.can_write_domain(&state, domain_id).await {
        return Err(forbidden_body());
    }
    let domain = repository::get_domain(&state.pool, domain_id)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found_body("domain not found"))?;

    let normalized = normalize(
        &req.rule,
        req.rule.path_pattern.as_deref().unwrap_or(""),
        req.rule.action.as_deref().unwrap_or("cache"),
        req.rule.ttl_seconds.unwrap_or(0),
        req.rule.swr_seconds.unwrap_or(0),
        req.rule.match_methods.as_deref().unwrap_or(""),
        req.rule.match_query.as_deref().unwrap_or(""),
        req.rule.browser_ttl_seconds.unwrap_or(0),
        0,
        true,
        req.rule.ignore_query.flatten(),
        req.rule.note.as_deref().unwrap_or(""),
    )
    .map_err(bad_request)?;

    let input = repository::RuleInput {
        path_pattern: &normalized.path_pattern,
        ttl_seconds: normalized.ttl_seconds,
        priority: normalized.priority,
        action: &normalized.action,
        swr_seconds: normalized.swr_seconds,
        enabled: normalized.enabled,
        match_methods: &normalized.match_methods,
        match_query: &normalized.match_query,
        browser_ttl_seconds: normalized.browser_ttl_seconds,
        ignore_query: normalized.ignore_query,
        note: &normalized.note,
    };
    let row = repository::create_rule(&state.pool, domain_id, &input)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "create rule");
            db_error()
        })?;

    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "rule.create",
        &domain.name,
        &format!(
            "{} action={} ttl={} methods={} query={}",
            row.path_pattern, row.action, row.ttl_seconds, row.match_methods, row.match_query
        ),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(RuleDto::from_row(row, &domain.name)),
    ))
}

pub async fn update(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<RulePayload>,
) -> Result<Json<RuleDto>, (StatusCode, Json<ErrorBody>)> {
    let uid = parse_uuid(&id)?;
    let current = repository::get_rule(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found_body("rule not found"))?;
    if !actor.can_write_domain(&state, current.domain_id).await {
        return Err(forbidden_body());
    }
    let domain = repository::get_domain(&state.pool, current.domain_id)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found_body("domain not found"))?;

    // Merge: omitted fields keep their current values.
    let path = req.path_pattern.as_deref().unwrap_or(&current.path_pattern);
    let action = req.action.as_deref().unwrap_or(&current.action);
    let ttl = req.ttl_seconds.unwrap_or(current.ttl_seconds.max(0) as u64);
    let swr = req
        .swr_seconds
        .unwrap_or(current.swr_seconds.max(0) as u64);
    let methods = req
        .match_methods
        .as_deref()
        .unwrap_or(&current.match_methods);
    let query = req
        .match_query
        .as_deref()
        .unwrap_or(&current.match_query);
    let browser_ttl = req
        .browser_ttl_seconds
        .unwrap_or(current.browser_ttl_seconds.max(0) as u64);
    let note = req.note.as_deref().unwrap_or(&current.note);

    let normalized = normalize(
        &req,
        path,
        action,
        ttl,
        swr,
        methods,
        query,
        browser_ttl,
        current.priority,
        current.enabled,
        req.ignore_query.unwrap_or(current.ignore_query),
        note,
    )
    .map_err(bad_request)?;

    let input = repository::RuleInput {
        path_pattern: &normalized.path_pattern,
        ttl_seconds: normalized.ttl_seconds,
        priority: normalized.priority,
        action: &normalized.action,
        swr_seconds: normalized.swr_seconds,
        enabled: normalized.enabled,
        match_methods: &normalized.match_methods,
        match_query: &normalized.match_query,
        browser_ttl_seconds: normalized.browser_ttl_seconds,
        ignore_query: normalized.ignore_query,
        note: &normalized.note,
    };
    let row = repository::update_rule(&state.pool, uid, &input)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "update rule");
            db_error()
        })?
        .ok_or_else(|| not_found_body("rule not found"))?;

    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "rule.update",
        &domain.name,
        &format!("{} action={}", row.path_pattern, row.action),
    )
    .await;
    Ok(Json(RuleDto::from_row(row, &domain.name)))
}

pub async fn delete(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let uid = parse_uuid(&id)?;
    let rule = repository::get_rule(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found_body("rule not found"))?;
    if !actor.can_write_domain(&state, rule.domain_id).await {
        return Err(forbidden_body());
    }
    repository::delete_rule(&state.pool, uid)
        .await
        .map_err(|_| db_error())?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "rule.delete",
        &rule.path_pattern,
        &rule.domain_id.to_string(),
    )
    .await;
    Ok(Json(serde_json::json!({ "success": true, "id": id })))
}

// ---------------------------------------------------------------- tester

#[derive(Deserialize)]
pub struct TestRequest {
    pub domain_id: String,
    pub path: String,
    pub method: Option<String>,
    pub query: Option<String>,
}

#[derive(Serialize)]
pub struct EffectiveDto {
    pub action: String,
    pub ttl_seconds: u64,
    pub swr_seconds: u64,
    pub browser_ttl_seconds: u64,
    pub ignore_query: Option<bool>,
    pub source: String,
}

#[derive(Serialize)]
pub struct TestResponse {
    pub matched: Option<RuleDto>,
    pub effective: EffectiveDto,
    pub note: String,
}

/// Mirrors the edge matcher: enabled rules only, priority desc, then
/// path wildcard + method list + query substring.
fn method_matches(csv: &str, method: &str) -> bool {
    if csv.trim().is_empty() {
        return true;
    }
    csv.split(',')
        .map(|m| m.trim())
        .any(|m| m.eq_ignore_ascii_case(method))
}

fn query_matches(needle: &str, query: &str) -> bool {
    let needle = needle.trim();
    needle.is_empty() || query.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "/*" || pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path == prefix || path.starts_with(&format!("{prefix}/")) || path.starts_with(prefix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    pattern == path
}

fn pick<'a>(
    rows: &'a [repository::CacheRuleRow],
    path: &str,
    method: &str,
    query: &str,
) -> Option<&'a repository::CacheRuleRow> {
    let mut best: Option<&repository::CacheRuleRow> = None;
    for r in rows {
        if !r.enabled
            || !path_matches(&r.path_pattern, path)
            || !method_matches(&r.match_methods, method)
            || !query_matches(&r.match_query, query)
        {
            continue;
        }
        match best {
            Some(b) if b.priority >= r.priority => {}
            _ => best = Some(r),
        }
    }
    best
}

pub async fn test(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<TestRequest>,
) -> Result<Json<TestResponse>, (StatusCode, Json<ErrorBody>)> {
    let domain_id = Uuid::parse_str(&req.domain_id).map_err(|_| bad_request("invalid domain_id"))?;
    if !actor.can_read_domain(&state, domain_id).await {
        return Err(forbidden_body());
    }
    let domain = repository::get_domain(&state.pool, domain_id)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found_body("domain not found"))?;
    let rules = repository::list_rules_for_domain(&state.pool, domain_id)
        .await
        .map_err(|_| db_error())?;

    let path = if req.path.trim().is_empty() {
        "/"
    } else {
        req.path.trim()
    };
    let method = req
        .method
        .as_deref()
        .unwrap_or("GET")
        .trim()
        .to_ascii_uppercase();
    let query = req.query.clone().unwrap_or_default();

    match pick(&rules, path, &method, &query) {
        Some(rule) => {
            let effective = EffectiveDto {
                action: rule.action.clone(),
                ttl_seconds: rule.ttl_seconds.max(0) as u64,
                swr_seconds: rule.swr_seconds.max(0) as u64,
                browser_ttl_seconds: rule.browser_ttl_seconds.max(0) as u64,
                ignore_query: rule.ignore_query,
                source: "rule".into(),
            };
            Ok(Json(TestResponse {
                note: format!("命中优先级 {} 的规则", rule.priority),
                matched: Some(RuleDto::from_row(rule.clone(), &domain.name)),
                effective,
            }))
        }
        None => Ok(Json(TestResponse {
            matched: None,
            effective: EffectiveDto {
                action: "cache".into(),
                ttl_seconds: 0,
                swr_seconds: 0,
                browser_ttl_seconds: 0,
                ignore_query: None,
                source: "default".into(),
            },
            note: "未命中规则：将按源站 Cache-Control / Expires，最后回退域名默认 TTL".into(),
        })),
    }
}

fn parse_uuid(id: &str) -> Result<Uuid, (StatusCode, Json<ErrorBody>)> {
    Uuid::parse_str(id.trim()).map_err(|_| bad_request("invalid id"))
}

fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody { error: msg.into() }),
    )
}

fn db_error() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: "database error".into(),
        }),
    )
}

fn forbidden_body() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorBody {
            error: "forbidden".into(),
        }),
    )
}

fn not_found_body(msg: &str) -> (StatusCode, Json<ErrorBody>) {
    (StatusCode::NOT_FOUND, Json(ErrorBody { error: msg.into() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pattern: &str, priority: i32, methods: &str, query: &str, enabled: bool) -> repository::CacheRuleRow {
        repository::CacheRuleRow {
            id: Uuid::nil(),
            domain_id: Uuid::nil(),
            path_pattern: pattern.into(),
            ttl_seconds: 60,
            priority,
            action: "cache".into(),
            swr_seconds: 0,
            enabled,
            match_methods: methods.into(),
            match_query: query.into(),
            browser_ttl_seconds: 0,
            ignore_query: None,
            note: String::new(),
        }
    }

    #[test]
    fn matcher_conditions_and_priority() {
        let rows = vec![
            row("/*", 0, "", "", true),
            row("/api/*", 10, "GET,POST", "", true),
            row("/api/*", 20, "GET", "debug=1", true),
            row("/api/*", 30, "GET", "", false),
        ];
        assert_eq!(pick(&rows, "/api/x", "GET", "").unwrap().priority, 10);
        assert_eq!(
            pick(&rows, "/api/x", "GET", "debug=1").unwrap().priority,
            20
        );
        assert_eq!(pick(&rows, "/api/x", "POST", "debug=1").unwrap().priority, 10);
        assert_eq!(pick(&rows, "/", "GET", "").unwrap().priority, 0);
        assert_eq!(
            pick(&rows, "/api/x", "DELETE", "debug=1").unwrap().priority,
            0
        );
    }

    #[test]
    fn methods_and_query_normalisation() {
        assert_eq!(normalize_methods("get, post,GET").unwrap(), "GET,POST");
        assert!(normalize_methods("TRACE").is_err());
        assert!(query_matches("debug=1", "a=1&DEBUG=1"));
        assert!(query_matches("", "anything"));
    }
}
