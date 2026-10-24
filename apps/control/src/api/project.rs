//! Multi-tenant projects

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
pub struct ProjectDto {
    pub id: String,
    pub name: String,
    pub owner_id: String,
    pub domain_count: i64,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

fn to_dto(r: repository::ProjectRow) -> ProjectDto {
    ProjectDto {
        id: r.id.to_string(),
        name: r.name,
        owner_id: r.owner_id.to_string(),
        domain_count: r.domain_count.unwrap_or(0),
        created_at: r.created_at.to_rfc3339(),
    }
}

fn user_id(user: &AuthUser) -> Result<Uuid, (StatusCode, Json<ErrorBody>)> {
    Uuid::parse_str(&user.0.sub).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "invalid token subject".into(),
            }),
        )
    })
}

pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<ProjectDto>>, (StatusCode, Json<ErrorBody>)> {
    let uid = user_id(&user)?;
    let rows = repository::list_projects_for_user(&state.pool, uid)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: format!("database error: {e}"),
                }),
            )
        })?;
    Ok(Json(rows.into_iter().map(to_dto).collect()))
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateProjectRequest>,
) -> Result<(StatusCode, Json<ProjectDto>), (StatusCode, Json<ErrorBody>)> {
    if req.name.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "name required".into(),
            }),
        ));
    }
    let uid = user_id(&user)?;
    let row = repository::create_project(&state.pool, req.name.trim(), uid)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: format!("database error: {e}"),
                }),
            )
        })?;
    let _ = repository::insert_audit(
        &state.pool,
        &user.0.email,
        "project.create",
        &row.name,
        &row.id.to_string(),
    )
    .await;
    Ok((StatusCode::CREATED, Json(to_dto(row))))
}

pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<ProjectDto>, (StatusCode, Json<ErrorBody>)> {
    let uid = user_id(&user)?;
    let pid = Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "invalid id".into(),
            }),
        )
    })?;
    if !repository::user_can_access_project(&state.pool, pid, uid)
        .await
        .unwrap_or(false)
    {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: "forbidden".into(),
            }),
        ));
    }
    let row = repository::get_project(&state.pool, pid)
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
                    error: "not found".into(),
                }),
            )
        })?;
    Ok(Json(to_dto(row)))
}

pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let uid = user_id(&user)?;
    let pid = Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "invalid id".into(),
            }),
        )
    })?;
    let n = repository::delete_project(&state.pool, pid, uid)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: format!("database error: {e}"),
                }),
            )
        })?;
    if n == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "not found or not owner".into(),
            }),
        ));
    }
    let _ = repository::insert_audit(
        &state.pool,
        &user.0.email,
        "project.delete",
        &id,
        "",
    )
    .await;
    Ok(Json(serde_json::json!({ "success": true, "id": id })))
}

pub async fn list_domains(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Vec<crate::api::domain::DomainDto>>, (StatusCode, Json<ErrorBody>)> {
    let uid = user_id(&user)?;
    let pid = Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "invalid id".into(),
            }),
        )
    })?;
    if !repository::user_can_access_project(&state.pool, pid, uid)
        .await
        .unwrap_or(false)
    {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: "forbidden".into(),
            }),
        ));
    }
    let rows = repository::list_domains_by_project(&state.pool, pid)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: format!("database error: {e}"),
                }),
            )
        })?;
    Ok(Json(
        rows.into_iter()
            .map(|r| crate::api::domain::DomainDto {
                id: r.id.to_string(),
                name: r.name,
                origin_host: r.origin_host,
                origin_port: r.origin_port as u16,
                origin_proto: r.origin_proto,
                ssl_enabled: r.ssl_enabled,
                status: r.status,
                project_id: r.project_id.map(|u| u.to_string()),
                rate_limit_rps: 0,
                rate_limit_burst: 0,
            })
            .collect(),
    ))
}
