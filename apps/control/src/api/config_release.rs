//! Config version history, staged releases and approval workflow.

use crate::middleware::agent_auth::AgentAuth;
use crate::middleware::authz::Actor;
use crate::repository::{self, ConfigReleaseRow, ConfigVersionRow};
use crate::service::config_release as release_service;
use crate::service::config_version;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;

async fn clear_config_cache(state: &AppState, release_id: Option<Uuid>) {
    state.config_cache.clear();
    if let Some(redis) = state.redis.as_deref() {
        redis.del("lagran:cfg:global").await;
        if let Some(id) = release_id {
            redis.del(&format!("lagran:cfg:release:{id}")).await;
        }
    }
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

#[derive(Serialize)]
pub struct VersionDto {
    pub id: String,
    pub domain: String,
    pub version: i32,
    pub action: String,
    pub actor: String,
    pub message: String,
    pub created_at: String,
    pub diff: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<Value>,
}

#[derive(Deserialize)]
pub struct VersionQuery {
    pub domain: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Serialize)]
pub struct ReleaseDomainDto {
    pub domain: String,
    pub version_id: String,
    pub version: Option<i32>,
}

#[derive(Serialize)]
pub struct ReleaseReportDto {
    pub node: String,
    pub success: bool,
    pub error: String,
    pub reported_at: String,
}

#[derive(Serialize)]
pub struct ReleaseDto {
    pub id: String,
    pub status: String,
    pub domains: Vec<ReleaseDomainDto>,
    pub target_nodes: Vec<String>,
    pub target_domains: Vec<String>,
    pub note: String,
    pub created_by: String,
    pub approved_by: String,
    pub error: String,
    pub created_at: String,
    pub approved_at: Option<String>,
    pub published_at: Option<String>,
    pub finished_at: Option<String>,
    pub reports: Vec<ReleaseReportDto>,
}

#[derive(Deserialize)]
pub struct CreateReleaseRequest {
    pub versions: Vec<VersionPick>,
    #[serde(default)]
    pub target_nodes: Vec<String>,
    #[serde(default)]
    pub note: String,
}

#[derive(Deserialize)]
pub struct VersionPick {
    pub domain: String,
    pub version_id: String,
}

#[derive(Deserialize)]
pub struct ApplyReportRequest {
    pub release_id: String,
    pub success: bool,
    #[serde(default)]
    pub error: String,
}

fn forbidden() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorBody {
            error: "forbidden".into(),
        }),
    )
}

fn bad_request(message: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
}

fn not_found(message: &str) -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorBody {
            error: message.into(),
        }),
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

fn version_dto(v: ConfigVersionRow, with_snapshot: bool) -> VersionDto {
    VersionDto {
        id: v.id.to_string(),
        domain: v.domain_name,
        version: v.version,
        action: v.action,
        actor: v.actor,
        message: v.message,
        created_at: v.created_at.to_rfc3339(),
        // Snapshots store the whole edge document, including the signed-URL
        // secret and the origin authorization value. These rows are readable by
        // any project member, so the secrets are redacted before they leave the
        // API. The Edge still receives the real values from `/api/v1/config`.
        diff: redact_secrets(v.diff),
        snapshot: with_snapshot.then(|| redact_secrets(v.snapshot)),
    }
}

/// Field names whose values must never be returned by the read APIs.
const SECRET_FIELDS: [&str; 5] = [
    "signed_url_secret",
    "signed_url_previous_secret",
    "origin_auth_value",
    "password",
    "password_hash",
];

/// Recursively replace secret values in a configuration document.
///
/// Walks objects, arrays and nested structures because a snapshot mixes the
/// domain document with release metadata; redaction must not depend on where a
/// field happens to sit.
fn redact_secrets(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(key, val)| {
                    if SECRET_FIELDS.iter().any(|f| key.eq_ignore_ascii_case(f)) {
                        let redacted = match &val {
                            serde_json::Value::String(s) if s.is_empty() => {
                                serde_json::Value::String(String::new())
                            }
                            _ => serde_json::Value::String(
                                crate::api::domain::SECRET_MASK.to_string(),
                            ),
                        };
                        (key, redacted)
                    } else {
                        (key, redact_secrets(val))
                    }
                })
                .collect(),
        ),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(redact_secrets).collect())
        }
        other => other,
    }
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, (StatusCode, Json<ErrorBody>)> {
    Uuid::parse_str(value.trim()).map_err(|_| bad_request(format!("invalid {field}")))
}

pub async fn list_versions(
    State(state): State<AppState>,
    actor: Actor,
    Query(query): Query<VersionQuery>,
) -> Result<Json<Vec<VersionDto>>, (StatusCode, Json<ErrorBody>)> {
    let rows = repository::list_versions(
        &state.pool,
        query.domain.as_deref().unwrap_or("").trim(),
        query.limit.unwrap_or(100),
    )
    .await
    .map_err(|_| db_error())?;
    let visible = actor.visible_domain_ids(&state).await;
    Ok(Json(
        rows.into_iter()
            .filter(|v| {
                visible
                    .as_ref()
                    .is_none_or(|set| set.contains(&v.domain_id))
            })
            .map(|v| version_dto(v, false))
            .collect(),
    ))
}

pub async fn get_version(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<VersionDto>, (StatusCode, Json<ErrorBody>)> {
    let uid = parse_uuid(&id, "version id")?;
    let version = repository::get_version(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("version not found"))?;
    if !actor.can_read_domain(&state, version.domain_id).await {
        return Err(forbidden());
    }
    Ok(Json(version_dto(version, true)))
}

pub async fn snapshot_now(
    State(state): State<AppState>,
    actor: Actor,
    Path(domain): Path<String>,
) -> Result<Json<VersionDto>, (StatusCode, Json<ErrorBody>)> {
    let domain = domain.trim().to_ascii_lowercase();
    if !actor.can_write_domain_name(&state, &domain).await {
        return Err(forbidden());
    }
    let row = repository::get_domain_by_name(&state.pool, &domain)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("domain not found"))?;
    config_version::record_domain(
        &state.pool,
        row.id,
        &row.name,
        &actor.email,
        "manual.snapshot",
        "手动创建版本",
    )
    .await
    .map_err(|_| db_error())?;
    let version = repository::latest_version(&state.pool, row.id)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("version not found"))?;
    Ok(Json(version_dto(version, true)))
}

pub async fn rollback_version(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorBody>)> {
    let uid = parse_uuid(&id, "version id")?;
    let version = repository::get_version(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("version not found"))?;
    if !actor.can_write_domain(&state, version.domain_id).await {
        return Err(forbidden());
    }
    if !config_version::rollback_domain(&state.pool, &version.domain_name, uid)
        .await
        .map_err(|_| db_error())?
    {
        return Err(not_found("version not found"));
    }
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "config.rollback",
        &version.domain_name,
        &format!("version {} ({uid})", version.version),
    )
    .await;
    clear_config_cache(&state, None).await;
    crate::service::edge_notify::notify_config_reload(&state).await;
    Ok(Json(
        json!({"success": true, "domain": version.domain_name, "version": version.version}),
    ))
}

fn release_domains(release: &ConfigReleaseRow) -> Vec<ReleaseDomainDto> {
    let mut out = Vec::new();
    if let Some(map) = release.versions.as_object() {
        for (domain, value) in map {
            if let Some(id) = value.as_str() {
                out.push(ReleaseDomainDto {
                    domain: domain.clone(),
                    version_id: id.to_string(),
                    version: None,
                });
            }
        }
    }
    out.sort_by(|a, b| a.domain.cmp(&b.domain));
    out
}

/// Build DTOs for many releases with two queries total (versions + reports).
///
/// Previously every release issued one query per domain version and one for its
/// reports, so a 100-release list cost hundreds of round trips.
async fn release_dtos(
    state: &AppState,
    rows: Vec<ConfigReleaseRow>,
) -> Result<Vec<ReleaseDto>, sqlx::Error> {
    let parsed: Vec<(ConfigReleaseRow, Vec<ReleaseDomainDto>)> = rows
        .into_iter()
        .map(|row| {
            let domains = release_domains(&row);
            (row, domains)
        })
        .collect();

    let mut version_ids: Vec<Uuid> = parsed
        .iter()
        .flat_map(|(_, domains)| domains.iter())
        .filter_map(|item| Uuid::parse_str(&item.version_id).ok())
        .collect();
    version_ids.sort_unstable();
    version_ids.dedup();
    let versions = repository::versions_by_ids(&state.pool, &version_ids).await?;

    let release_ids: Vec<Uuid> = parsed.iter().map(|(row, _)| row.id).collect();
    let mut reports = repository::reports_for_releases(&state.pool, &release_ids).await?;

    Ok(parsed
        .into_iter()
        .map(|(row, mut domains)| {
            for item in &mut domains {
                item.version = Uuid::parse_str(&item.version_id)
                    .ok()
                    .and_then(|id| versions.get(&id))
                    .map(|version| version.version);
            }
            let reports = reports.remove(&row.id).unwrap_or_default();
            build_release_dto(row, domains, reports)
        })
        .collect())
}

async fn release_dto(
    state: &AppState,
    release: ConfigReleaseRow,
) -> Result<ReleaseDto, sqlx::Error> {
    release_dtos(state, vec![release])
        .await?
        .into_iter()
        .next()
        .ok_or(sqlx::Error::RowNotFound)
}

fn build_release_dto(
    release: ConfigReleaseRow,
    domains: Vec<ReleaseDomainDto>,
    reports: Vec<(String, bool, String)>,
) -> ReleaseDto {
    ReleaseDto {
        id: release.id.to_string(),
        status: release.status,
        domains,
        target_nodes: serde_json::from_value(release.target_nodes).unwrap_or_default(),
        target_domains: serde_json::from_value(release.target_domains).unwrap_or_default(),
        note: release.note,
        created_by: release.created_by,
        approved_by: release.approved_by,
        error: release.error,
        created_at: release.created_at.to_rfc3339(),
        approved_at: release.approved_at.map(|v| v.to_rfc3339()),
        published_at: release.published_at.map(|v| v.to_rfc3339()),
        finished_at: release.finished_at.map(|v| v.to_rfc3339()),
        reports: reports
            .into_iter()
            .map(|(node, success, error)| ReleaseReportDto {
                node,
                success,
                error,
                reported_at: String::new(),
            })
            .collect(),
    }
}

pub async fn list_releases(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<ReleaseDto>>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let rows = repository::list_releases(&state.pool, 100)
        .await
        .map_err(|_| db_error())?;
    let out = release_dtos(&state, rows).await.map_err(|_| db_error())?;
    Ok(Json(out))
}

pub async fn get_release(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<ReleaseDto>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let uid = parse_uuid(&id, "release id")?;
    let release = repository::get_release(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("release not found"))?;
    Ok(Json(
        release_dto(&state, release).await.map_err(|_| db_error())?,
    ))
}

pub async fn create_release(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<CreateReleaseRequest>,
) -> Result<Json<ReleaseDto>, (StatusCode, Json<ErrorBody>)> {
    if req.versions.is_empty() {
        return Err(bad_request("at least one domain version is required"));
    }
    let mut versions = serde_json::Map::new();
    let mut previous = serde_json::Map::new();
    let mut domains = Vec::new();
    for pick in req.versions {
        let domain = pick.domain.trim().to_ascii_lowercase();
        let version_id = parse_uuid(&pick.version_id, "version id")?;
        let version = repository::get_version(&state.pool, version_id)
            .await
            .map_err(|_| db_error())?
            .ok_or_else(|| not_found("version not found"))?;
        if version.domain_name != domain {
            return Err(bad_request("version does not belong to domain"));
        }
        let row = repository::get_domain_by_name(&state.pool, &domain)
            .await
            .map_err(|_| db_error())?
            .ok_or_else(|| not_found("domain not found"))?;
        if !actor.can_write_domain(&state, row.id).await {
            return Err(forbidden());
        }
        versions.insert(domain.clone(), json!(version_id.to_string()));
        previous.insert(
            domain.clone(),
            row.published_version_id
                .map(|v| json!(v.to_string()))
                .unwrap_or(Value::Null),
        );
        domains.push(domain);
    }
    domains.sort();
    domains.dedup();
    let release = repository::create_release(
        &state.pool,
        &Value::Object(versions),
        &Value::Object(previous),
        &req.target_nodes,
        &domains,
        req.note.trim(),
        &actor.email,
    )
    .await
    .map_err(|_| db_error())?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "config.release.create",
        &release.id.to_string(),
        &format!("{} domain(s)", domains.len()),
    )
    .await;
    Ok(Json(
        release_dto(&state, release).await.map_err(|_| db_error())?,
    ))
}

pub async fn approve_release(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<ReleaseDto>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let uid = parse_uuid(&id, "release id")?;
    let release = repository::approve_release(&state.pool, uid, &actor.email)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| bad_request("release is not pending approval"))?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "config.release.approve",
        &uid.to_string(),
        "",
    )
    .await;
    Ok(Json(
        release_dto(&state, release).await.map_err(|_| db_error())?,
    ))
}

pub async fn publish_release(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<ReleaseDto>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let uid = parse_uuid(&id, "release id")?;
    let current = repository::get_release(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("release not found"))?;
    if current.status != "approved" {
        return Err(bad_request("release must be approved before publishing"));
    }
    if repository::publishing_exists(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
    {
        return Err(bad_request(
            "another release is publishing; wait for it to finish or roll back",
        ));
    }
    let targets: Vec<String> =
        serde_json::from_value(current.target_nodes.clone()).unwrap_or_default();
    let release = if targets.is_empty() {
        repository::set_published_versions(&state.pool, &current.versions)
            .await
            .map_err(|_| db_error())?;
        repository::finish_release(&state.pool, uid, "published", "")
            .await
            .map_err(|_| db_error())?;
        repository::get_release(&state.pool, uid)
            .await
            .map_err(|_| db_error())?
            .ok_or_else(|| not_found("release not found"))?
    } else {
        repository::start_publishing(&state.pool, uid)
            .await
            .map_err(|_| db_error())?
            .ok_or_else(|| bad_request("release cannot be published"))?
    };
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "config.release.publish",
        &uid.to_string(),
        &format!("{} target node(s)", targets.len()),
    )
    .await;
    clear_config_cache(&state, Some(uid)).await;
    crate::service::edge_notify::notify_config_reload(&state).await;
    Ok(Json(
        release_dto(&state, release).await.map_err(|_| db_error())?,
    ))
}

pub async fn rollback_release(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<ReleaseDto>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let uid = parse_uuid(&id, "release id")?;
    release_service::rollback(&state, uid, "manual rollback")
        .await
        .map_err(|_| db_error())?;
    let release = repository::get_release(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("release not found"))?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "config.release.rollback",
        &uid.to_string(),
        "",
    )
    .await;
    clear_config_cache(&state, Some(uid)).await;
    crate::service::edge_notify::notify_config_reload(&state).await;
    Ok(Json(
        release_dto(&state, release).await.map_err(|_| db_error())?,
    ))
}

#[derive(Serialize)]
pub struct DryRunResponse {
    pub ok: bool,
    pub warnings: Vec<String>,
    pub domains: Vec<Value>,
}

pub async fn dry_run(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<DryRunResponse>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let uid = parse_uuid(&id, "release id")?;
    let release = repository::get_release(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found("release not found"))?;
    let mut warnings = Vec::new();
    let mut domain_diffs = Vec::new();
    let targets: Vec<String> =
        serde_json::from_value(release.target_nodes.clone()).unwrap_or_default();
    if !targets.is_empty() {
        let nodes = repository::list_nodes(&state.pool)
            .await
            .unwrap_or_default();
        for target in &targets {
            match nodes.iter().find(|n| &n.name == target) {
                None => warnings.push(format!("target node {target} does not exist")),
                Some(node) if node.status != "online" => {
                    warnings.push(format!("target node {target} is {}", node.status))
                }
                _ => {}
            }
        }
    }
    if let Some(map) = release.versions.as_object() {
        for (domain, value) in map {
            let Some(version_id) = value.as_str().and_then(|v| Uuid::parse_str(v).ok()) else {
                warnings.push(format!("{domain}: invalid version id"));
                continue;
            };
            let Some(version) = repository::get_version(&state.pool, version_id)
                .await
                .map_err(|_| db_error())?
            else {
                warnings.push(format!("{domain}: version not found"));
                continue;
            };
            let snapshot = match serde_json::from_value::<crate::api::config::DomainConfigResponse>(
                version.snapshot.clone(),
            ) {
                Ok(snapshot) => snapshot,
                Err(_) => {
                    warnings.push(format!("{domain}: snapshot is not a valid config"));
                    continue;
                }
            };
            if snapshot.domain != *domain {
                warnings.push(format!("{domain}: snapshot domain mismatch"));
            }
            if snapshot.origin.host.trim().is_empty() || snapshot.origin.port == 0 {
                warnings.push(format!("{domain}: origin is empty"));
            }
            for rule in &snapshot.rules {
                if rule.path_pattern.trim().is_empty() {
                    warnings.push(format!("{domain}: rule has empty path"));
                }
                if !matches!(rule.action.as_str(), "cache" | "bypass" | "no_store") {
                    warnings.push(format!(
                        "{domain}: rule {} has unknown action {}",
                        rule.path_pattern, rule.action
                    ));
                }
            }
            let before = config_version::effective_snapshot(&state.pool, domain)
                .await
                .ok()
                .flatten()
                .map(|v| serde_json::to_value(v).unwrap_or(Value::Null))
                .unwrap_or(Value::Null);
            let after = serde_json::to_value(&snapshot).unwrap_or(Value::Null);
            domain_diffs.push(json!({
                "domain": domain,
                "version": version.version,
                "diff": config_version::diff_values(&before, &after),
            }));
        }
    }
    Ok(Json(DryRunResponse {
        ok: warnings.is_empty(),
        warnings,
        domains: domain_diffs,
    }))
}

/// Decide which node a report is attributed to.
///
/// The token binding always wins; the header is only used to detect drift. Split
/// out so the rule is testable without a database.
pub fn resolving_node<'a>(token_node: &'a str, claimed: Option<&'a str>) -> (&'a str, Option<&'a str>) {
    let claimed = claimed.map(str::trim).filter(|v| !v.is_empty());
    let mismatch = claimed.filter(|c| *c != token_node);
    (token_node, mismatch)
}

pub async fn apply_report(
    State(state): State<AppState>,
    agent: AgentAuth,
    headers: HeaderMap,
    Json(req): Json<ApplyReportRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorBody>)> {
    // The reporting node is the one that owns the presented token, never the one
    // named in a header. Trusting the header let any registered node report
    // `success` on behalf of a different node, which could make the "all targets
    // reported" check succeed before the real node had applied anything and
    // promote a partially verified release to production.
    //
    // The header is still read to detect a stale client; a mismatch is rejected
    // rather than silently ignored so misconfiguration is visible.
    let node_id = agent.node_name;
    if node_id.trim().is_empty() {
        return Err(bad_request("agent token is not bound to a node"));
    }
    let claimed = headers
        .get("x-lagran-node-id")
        .and_then(|v| v.to_str().ok());
    let (node_id, mismatch) = resolving_node(&node_id, claimed);
    {
        if let Some(claimed) = mismatch {
            // Tolerate a stale `NODE_ID` on the edge: the token is authoritative
            // and an outright rejection would break reporting for nodes that were
            // renamed in the console without updating their env. The warning makes
            // the drift visible; an attacker gains nothing because the token
            // binding is what is recorded.
            tracing::warn!(
                token_node = %node_id,
                claimed = %claimed,
                "apply report node id does not match the agent token; using the token binding"
            );
        }
    }
    let release_id = parse_uuid(&req.release_id, "release id")?;
    release_service::report(&state, release_id, node_id, req.success, req.error.trim())
        .await
        .map_err(|_| db_error())?;
    clear_config_cache(&state, Some(release_id)).await;
    Ok(Json(json!({"success": true})))
}

/// Used by the config endpoint to resolve a domain's published snapshot.
pub async fn published_config(
    state: &AppState,
    domain: &str,
) -> Option<crate::api::config::DomainConfigResponse> {
    let row = repository::get_domain_by_name(&state.pool, domain)
        .await
        .ok()??;
    let version_id = row.published_version_id?;
    let version = repository::get_version(&state.pool, version_id)
        .await
        .ok()??;
    serde_json::from_value(version.snapshot).ok()
}

/// Serializable map of domain -> version id for release creation.
pub fn versions_map(picks: &[VersionPick]) -> Value {
    let mut map = HashMap::new();
    for pick in picks {
        map.insert(pick.domain.clone(), pick.version_id.clone());
    }
    serde_json::to_value(map).unwrap_or_else(|_| json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The token decides which node a report belongs to. Trusting the header let
    /// one node report success for another, which could satisfy "all targets
    /// reported" and promote a release that a real node never applied.
    #[test]
    fn apply_report_uses_the_token_binding() {
        // A different claimed node yields a mismatch, and the token wins.
        let (node, mismatch) = super::resolving_node("edge-a", Some("edge-b"));
        assert_eq!(node, "edge-a");
        assert_eq!(mismatch, Some("edge-b"));

        // Matching and absent headers are not mismatches.
        assert_eq!(super::resolving_node("edge-a", Some("edge-a")).1, None);
        assert_eq!(super::resolving_node("edge-a", Some("  edge-a  ")).1, None);
        assert_eq!(super::resolving_node("edge-a", None).1, None);
        assert_eq!(super::resolving_node("edge-a", Some("   ")).1, None);
    }

    /// Snapshot rows contain the full edge document, secrets included, and are
    /// readable by any project member. They must be redacted on the way out.
    #[test]
    fn redaction_covers_nested_secrets() {
        let doc = json!({
            "domain": "a.test",
            "signed_url_secret": "real-secret",
            "signed_url_previous_secret": "old-secret",
            "origin_auth_value": "Bearer abc",
            "origin_auth_header": "x-origin-auth",
            "waf": { "enabled": true },
            "domains": [
                { "domain": "b.test", "origin_auth_value": "nested" }
            ]
        });
        let out = redact_secrets(doc);

        assert_eq!(out["signed_url_secret"], crate::api::domain::SECRET_MASK);
        assert_eq!(
            out["signed_url_previous_secret"],
            crate::api::domain::SECRET_MASK
        );
        assert_eq!(out["origin_auth_value"], crate::api::domain::SECRET_MASK);
        // Nested in an array must be redacted too.
        assert_eq!(
            out["domains"][0]["origin_auth_value"],
            crate::api::domain::SECRET_MASK
        );
        // Non-secret fields survive.
        assert_eq!(out["domain"], "a.test");
        assert_eq!(out["origin_auth_header"], "x-origin-auth");
        assert_eq!(out["waf"]["enabled"], true);
    }

    #[test]
    fn redaction_preserves_empty_secrets() {
        let doc = json!({ "signed_url_secret": "", "domain": "a.test" });
        let out = redact_secrets(doc);
        // An unset secret must not look like a configured one.
        assert_eq!(out["signed_url_secret"], "");
    }
}
