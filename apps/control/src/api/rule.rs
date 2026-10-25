//! Cache rules CRUD (per-domain rule: TTL / action / SWR)

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
}

#[derive(Deserialize)]
pub struct CreateRuleRequest {
    pub domain_id: String,
    pub path_pattern: String,
    #[serde(default)]
    pub ttl_seconds: u64,
    pub priority: Option<i32>,
    pub action: Option<String>,
    pub swr_seconds: Option<u64>,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
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
            .map(|(r, name)| RuleDto {
                id: r.id.to_string(),
                domain_id: r.domain_id.to_string(),
                domain_name: name,
                path_pattern: r.path_pattern,
                ttl_seconds: r.ttl_seconds.max(0) as u64,
                priority: r.priority,
                action: r.action,
                swr_seconds: r.swr_seconds.max(0) as u64,
            })
            .collect(),
    ))
}

pub async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<CreateRuleRequest>,
) -> Result<(StatusCode, Json<RuleDto>), (StatusCode, Json<ErrorBody>)> {
    let domain_id = Uuid::parse_str(&req.domain_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "invalid domain_id".into(),
            }),
        )
    })?;
    if !actor.can_write_domain(&state, domain_id).await {
        return Err(forbidden_body());
    }
    let domain = repository::get_domain(&state.pool, domain_id)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found_body("domain not found"))?;

    let action = req
        .action
        .as_deref()
        .unwrap_or("cache")
        .trim()
        .to_ascii_lowercase();
    if !ACTIONS.contains(&action.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "action must be cache, bypass or no_store".into(),
            }),
        ));
    }
    if req.path_pattern.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "path_pattern required".into(),
            }),
        ));
    }
    let ttl = if action == "cache" {
        req.ttl_seconds as i64
    } else {
        0
    };

    let row = repository::create_rule(
        &state.pool,
        domain_id,
        req.path_pattern.trim(),
        ttl,
        req.priority.unwrap_or(0),
        &action,
        req.swr_seconds.unwrap_or(0) as i64,
    )
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
            "{} ttl={} action={action}",
            row.path_pattern, row.ttl_seconds
        ),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(RuleDto {
            id: row.id.to_string(),
            domain_id: row.domain_id.to_string(),
            domain_name: domain.name,
            path_pattern: row.path_pattern,
            ttl_seconds: row.ttl_seconds.max(0) as u64,
            priority: row.priority,
            action: row.action,
            swr_seconds: row.swr_seconds.max(0) as u64,
        }),
    ))
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

fn parse_uuid(id: &str) -> Result<Uuid, (StatusCode, Json<ErrorBody>)> {
    Uuid::parse_str(id.trim()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "invalid id".into(),
            }),
        )
    })
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
