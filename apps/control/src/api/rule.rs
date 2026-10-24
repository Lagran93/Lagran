//! Cache rules CRUD

use crate::middleware::AuthUser;
use crate::repository;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize)]
pub struct RuleDto {
    pub id: String,
    pub domain_id: String,
    pub domain_name: String,
    pub path_pattern: String,
    pub ttl_seconds: u64,
    pub priority: i32,
}

#[derive(Deserialize)]
pub struct CreateRuleRequest {
    pub domain_id: String,
    pub path_pattern: String,
    pub ttl_seconds: u64,
    pub priority: Option<i32>,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

pub async fn list(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Result<Json<Vec<RuleDto>>, (StatusCode, Json<ErrorBody>)> {
    let rows = repository::list_all_rules(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "list rules");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "database error".into(),
            }),
        )
    })?;
    Ok(Json(
        rows.into_iter()
            .map(|(r, name)| RuleDto {
                id: r.id.to_string(),
                domain_id: r.domain_id.to_string(),
                domain_name: name,
                path_pattern: r.path_pattern,
                ttl_seconds: r.ttl_seconds as u64,
                priority: r.priority,
            })
            .collect(),
    ))
}

pub async fn create(
    State(state): State<AppState>,
    _user: AuthUser,
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
    let domain = repository::get_domain(&state.pool, domain_id)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "database error".into(),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorBody {
                    error: "domain not found".into(),
                }),
            )
        })?;

    let row = repository::create_rule(
        &state.pool,
        domain_id,
        &req.path_pattern,
        req.ttl_seconds as i64,
        req.priority.unwrap_or(0),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "create rule");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "database error".into(),
            }),
        )
    })?;

    Ok((
        StatusCode::CREATED,
        Json(RuleDto {
            id: row.id.to_string(),
            domain_id: row.domain_id.to_string(),
            domain_name: domain.name,
            path_pattern: row.path_pattern,
            ttl_seconds: row.ttl_seconds as u64,
            priority: row.priority,
        }),
    ))
}

pub async fn delete(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let uid = Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "invalid id".into(),
            }),
        )
    })?;
    let n = repository::delete_rule(&state.pool, uid).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "database error".into(),
            }),
        )
    })?;
    if n == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "rule not found".into(),
            }),
        ));
    }
    Ok(Json(serde_json::json!({ "success": true, "id": id })))
}
