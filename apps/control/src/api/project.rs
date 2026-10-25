//! Multi-tenant projects + membership

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

#[derive(Serialize)]
pub struct MemberDto {
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub joined_at: String,
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub email: String,
    pub role: Option<String>,
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

fn parse_uuid(id: &str) -> Result<Uuid, (StatusCode, Json<ErrorBody>)> {
    Uuid::parse_str(id).map_err(|_| {
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

fn forbidden() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorBody {
            error: "forbidden".into(),
        }),
    )
}

pub async fn list(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<ProjectDto>>, (StatusCode, Json<ErrorBody>)> {
    let rows = repository::list_projects_for_user(&state.pool, actor.id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list projects");
            db_error()
        })?;
    Ok(Json(rows.into_iter().map(to_dto).collect()))
}

pub async fn create(
    State(state): State<AppState>,
    actor: Actor,
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
    let row = repository::create_project(&state.pool, req.name.trim(), actor.id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "create project");
            db_error()
        })?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "project.create",
        &row.name,
        &row.id.to_string(),
    )
    .await;
    Ok((StatusCode::CREATED, Json(to_dto(row))))
}

pub async fn get(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<ProjectDto>, (StatusCode, Json<ErrorBody>)> {
    let pid = parse_uuid(&id)?;
    if !actor.can_read_project(&state, pid).await {
        return Err(forbidden());
    }
    let row = repository::get_project(&state.pool, pid)
        .await
        .map_err(|_| db_error())?
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
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let pid = parse_uuid(&id)?;
    // Only the owner may delete a project.
    if !actor.admin() {
        match repository::project_role(&state.pool, pid, actor.id)
            .await
            .unwrap_or(None)
            .as_deref()
        {
            Some("owner") => {}
            _ => return Err(forbidden()),
        }
    }
    let n = repository::delete_project(&state.pool, pid, actor.id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "delete project");
            db_error()
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
        &actor.email,
        "project.delete",
        &id,
        "",
    )
    .await;
    Ok(Json(serde_json::json!({ "success": true, "id": id })))
}

pub async fn list_domains(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<Vec<crate::api::domain::DomainDto>>, (StatusCode, Json<ErrorBody>)> {
    let pid = parse_uuid(&id)?;
    if !actor.can_read_project(&state, pid).await {
        return Err(forbidden());
    }
    let rows = repository::list_domains_by_project(&state.pool, pid)
        .await
        .map_err(|_| db_error())?;
    Ok(Json(
        rows.into_iter()
            .map(crate::api::domain::to_dto)
            .collect(),
    ))
}

pub async fn list_members(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<Vec<MemberDto>>, (StatusCode, Json<ErrorBody>)> {
    let pid = parse_uuid(&id)?;
    if !actor.can_read_project(&state, pid).await {
        return Err(forbidden());
    }
    let rows = repository::list_project_members(&state.pool, pid)
        .await
        .map_err(|_| db_error())?;
    Ok(Json(
        rows.into_iter()
            .map(|m| MemberDto {
                user_id: m.user_id.to_string(),
                email: m.email,
                name: m.name,
                role: m.role,
                joined_at: m.created_at.to_rfc3339(),
            })
            .collect(),
    ))
}

pub async fn add_member(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> Result<(StatusCode, Json<MemberDto>), (StatusCode, Json<ErrorBody>)> {
    let pid = parse_uuid(&id)?;
    if !actor.can_write_project(&state, pid).await {
        return Err(forbidden());
    }
    let role = req.role.as_deref().unwrap_or("member").trim().to_ascii_lowercase();
    if role != "member" && role != "admin" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "role must be member or admin".into(),
            }),
        ));
    }
    let user = repository::find_user_by_email(&state.pool, req.email.trim())
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorBody {
                    error: "user not found".into(),
                }),
            )
        })?;
    // The owner's role is implicit and must not be overwritten.
    let current = repository::project_role(&state.pool, pid, user.id)
        .await
        .unwrap_or(None);
    if current.as_deref() == Some("owner") {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "user is the project owner".into(),
            }),
        ));
    }

    repository::upsert_project_member(&state.pool, pid, user.id, &role)
        .await
        .map_err(|_| db_error())?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "project.member.add",
        &pid.to_string(),
        &format!("{}={role}", user.email),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(MemberDto {
            user_id: user.id.to_string(),
            email: user.email,
            name: user.name,
            role,
            joined_at: chrono::Utc::now().to_rfc3339(),
        }),
    ))
}

pub async fn remove_member(
    State(state): State<AppState>,
    actor: Actor,
    Path((id, user_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let pid = parse_uuid(&id)?;
    let uid = parse_uuid(&user_id)?;
    if !actor.can_write_project(&state, pid).await {
        return Err(forbidden());
    }
    if repository::project_role(&state.pool, pid, uid)
        .await
        .unwrap_or(None)
        .as_deref()
        == Some("owner")
    {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "cannot remove the project owner".into(),
            }),
        ));
    }
    let n = repository::remove_project_member(&state.pool, pid, uid)
        .await
        .map_err(|_| db_error())?;
    if n == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "member not found".into(),
            }),
        ));
    }
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "project.member.remove",
        &pid.to_string(),
        &uid.to_string(),
    )
    .await;
    Ok(Json(serde_json::json!({ "success": true })))
}
