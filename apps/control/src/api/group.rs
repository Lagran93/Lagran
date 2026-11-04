//! Admin-managed user groups with module-level permissions.

use crate::middleware::authz::Actor;
use crate::permissions;
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
pub struct GroupDto {
    pub id: String,
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub member_count: i64,
    pub member_ids: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Deserialize)]
pub struct GroupRequest {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct MembersRequest {
    pub user_ids: Vec<String>,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody { error: msg.into() }),
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

fn not_found() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorBody {
            error: "group not found".into(),
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

fn parse_uuid(id: &str) -> Result<Uuid, (StatusCode, Json<ErrorBody>)> {
    Uuid::parse_str(id).map_err(|_| bad_request("invalid id"))
}

async fn to_dto(state: &AppState, row: repository::UserGroupRow) -> GroupDto {
    let member_ids = repository::group_member_ids(&state.pool, row.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|id| id.to_string())
        .collect();
    GroupDto {
        id: row.id.to_string(),
        name: row.name,
        description: row.description,
        permissions: row.permissions,
        member_count: row.member_count,
        member_ids,
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
    }
}

fn normalize_permissions(
    input: Option<Vec<String>>,
) -> Result<Vec<String>, (StatusCode, Json<ErrorBody>)> {
    let mut out: Vec<String> = Vec::new();
    for permission in input.unwrap_or_default() {
        let permission = permission.trim().to_ascii_lowercase();
        if !permissions::is_valid(&permission) {
            return Err(bad_request(format!("unknown permission: {permission}")));
        }
        if !out.contains(&permission) {
            out.push(permission);
        }
    }
    out.sort();
    if out.is_empty() {
        return Err(bad_request("at least one permission is required"));
    }
    Ok(out)
}

fn normalize_name(raw: &str) -> Result<String, (StatusCode, Json<ErrorBody>)> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(bad_request("name is required"));
    }
    if name.chars().count() > 80 {
        return Err(bad_request("name is too long"));
    }
    Ok(name.to_string())
}

pub async fn list(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<GroupDto>>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let rows = repository::list_user_groups(&state.pool)
        .await
        .map_err(|_| db_error())?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(to_dto(&state, row).await);
    }
    Ok(Json(out))
}

pub async fn get(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<GroupDto>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let gid = parse_uuid(&id)?;
    let row = repository::get_user_group(&state.pool, gid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(not_found)?;
    Ok(Json(to_dto(&state, row).await))
}

pub async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<GroupRequest>,
) -> Result<(StatusCode, Json<GroupDto>), (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let name = normalize_name(&req.name)?;
    let permissions = normalize_permissions(req.permissions)?;
    let description = req.description.unwrap_or_default().trim().to_string();
    let row = repository::create_user_group(&state.pool, &name, &description, &permissions)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "create user group");
            if e.as_database_error()
                .map(|d| d.is_unique_violation())
                .unwrap_or(false)
            {
                (
                    StatusCode::CONFLICT,
                    Json(ErrorBody {
                        error: "group name already exists".into(),
                    }),
                )
            } else {
                db_error()
            }
        })?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "group.create",
        &name,
        &permissions.join(","),
    )
    .await;
    Ok((StatusCode::CREATED, Json(to_dto(&state, row).await)))
}

pub async fn update(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<GroupRequest>,
) -> Result<Json<GroupDto>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let gid = parse_uuid(&id)?;
    let name = normalize_name(&req.name)?;
    let permissions = normalize_permissions(req.permissions)?;
    let description = req.description.unwrap_or_default().trim().to_string();
    let row = repository::update_user_group(&state.pool, gid, &name, &description, &permissions)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "update user group");
            if e.as_database_error()
                .map(|d| d.is_unique_violation())
                .unwrap_or(false)
            {
                (
                    StatusCode::CONFLICT,
                    Json(ErrorBody {
                        error: "group name already exists".into(),
                    }),
                )
            } else {
                db_error()
            }
        })?
        .ok_or_else(not_found)?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "group.update",
        &name,
        &permissions.join(","),
    )
    .await;
    Ok(Json(to_dto(&state, row).await))
}

pub async fn delete(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let gid = parse_uuid(&id)?;
    let n = repository::delete_user_group(&state.pool, gid)
        .await
        .map_err(|_| db_error())?;
    if n == 0 {
        return Err(not_found());
    }
    let _ = repository::insert_audit(&state.pool, &actor.email, "group.delete", &id, "").await;
    Ok(Json(serde_json::json!({ "success": true, "id": id })))
}

pub async fn members(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let gid = parse_uuid(&id)?;
    let ids = repository::group_member_ids(&state.pool, gid)
        .await
        .map_err(|_| db_error())?;
    Ok(Json(ids.into_iter().map(|id| id.to_string()).collect()))
}

pub async fn set_members(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<MembersRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let gid = parse_uuid(&id)?;
    let mut ids = Vec::with_capacity(req.user_ids.len());
    for raw in req.user_ids {
        ids.push(parse_uuid(&raw)?);
    }
    repository::set_group_members(&state.pool, gid, &ids)
        .await
        .map_err(|_| db_error())?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "group.members",
        &id,
        &format!("{} users", ids.len()),
    )
    .await;
    Ok(Json(serde_json::json!({ "success": true, "count": ids.len() })))
}
