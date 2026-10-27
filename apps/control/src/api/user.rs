//! Admin user management and account administration.

use crate::api::auth::{normalize_email, validate_email, validate_password};
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
pub struct UserDto {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub is_active: bool,
    pub project_count: i64,
    pub created_at: String,
    pub last_login_at: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
    pub role: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    pub role: Option<String>,
    pub is_active: Option<bool>,
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub password: String,
}

#[derive(Serialize)]
pub struct ErrorBody {
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

fn not_found() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorBody {
            error: "user not found".into(),
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

fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody { error: msg.into() }),
    )
}

fn conflict(msg: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::CONFLICT,
        Json(ErrorBody { error: msg.into() }),
    )
}

fn parse_uuid(id: &str) -> Result<Uuid, (StatusCode, Json<ErrorBody>)> {
    Uuid::parse_str(id).map_err(|_| bad_request("invalid id"))
}

fn normalize_role(role: Option<&str>) -> Result<String, (StatusCode, Json<ErrorBody>)> {
    let role = role.unwrap_or("user").trim().to_ascii_lowercase();
    if role != "admin" && role != "user" {
        return Err(bad_request("role must be admin or user"));
    }
    Ok(role)
}

fn to_dto(user: repository::UserRow) -> UserDto {
    UserDto {
        id: user.id.to_string(),
        email: user.email,
        name: user.name,
        role: user.role,
        is_active: user.is_active,
        project_count: user.project_count,
        created_at: user.created_at.to_rfc3339(),
        last_login_at: user.last_login_at.map(|t| t.to_rfc3339()),
    }
}

pub async fn list(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<UserDto>>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let users = repository::list_users(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "list users");
        db_error()
    })?;
    Ok(Json(users.into_iter().map(to_dto).collect()))
}

pub async fn get(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<UserDto>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let uid = parse_uuid(&id)?;
    let user = repository::find_user_by_id(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found())?;
    Ok(Json(to_dto(user)))
}

pub async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserDto>), (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let email = normalize_email(&req.email);
    validate_email(&email).map_err(bad_request)?;
    validate_password(&req.password).map_err(bad_request)?;
    let role = normalize_role(req.role.as_deref())?;
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| email.split('@').next().unwrap_or(&email).to_string());
    if name.chars().count() > 80 {
        return Err(bad_request("name is too long"));
    }
    if repository::find_user_by_email(&state.pool, &email)
        .await
        .map_err(|_| db_error())?
        .is_some()
    {
        return Err(conflict("email already registered"));
    }
    let hash = crate::utils::hash_password(&req.password).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "hash error".into(),
            }),
        )
    })?;
    let user = repository::create_user_with_role(&state.pool, &email, &hash, &name, &role)
        .await
        .map_err(|e| {
            let unique = e
                .as_database_error()
                .map(|d| d.is_unique_violation())
                .unwrap_or(false);
            tracing::error!(error = %e, "admin create user");
            if unique {
                conflict("email already registered")
            } else {
                db_error()
            }
        })?;
    if let Err(e) = repository::ensure_personal_project(&state.pool, user.id).await {
        tracing::warn!(error = %e, user_id = %user.id, "create personal project failed");
    }
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "user.create",
        &user.email,
        &format!("role={role}"),
    )
    .await;
    Ok((StatusCode::CREATED, Json(to_dto(user))))
}

pub async fn update(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserDto>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let uid = parse_uuid(&id)?;
    let current = repository::find_user_by_id(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found())?;

    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&current.name)
        .to_string();
    if name.chars().count() > 80 {
        return Err(bad_request("name is too long"));
    }
    let role = match req.role.as_deref() {
        Some(role) => normalize_role(Some(role))?,
        None => current.role.clone(),
    };
    let is_active = req.is_active.unwrap_or(current.is_active);

    if uid == actor.id && (!is_active || role != "admin") {
        return Err(bad_request("cannot disable or demote your own account"));
    }
    let loses_admin = current.role == "admin"
        && current.is_active
        && (role != "admin" || !is_active);
    if loses_admin {
        let admins = repository::count_active_admins(&state.pool)
            .await
            .map_err(|_| db_error())?;
        if admins <= 1 {
            return Err(conflict("cannot remove the last active administrator"));
        }
    }

    let password_hash = match req.password.as_deref() {
        Some(password) if !password.is_empty() => {
            if uid == actor.id {
                return Err(bad_request("use /auth/me/password to change your own password"));
            }
            validate_password(password).map_err(bad_request)?;
            Some(crate::utils::hash_password(password).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorBody {
                        error: "hash error".into(),
                    }),
                )
            })?)
        }
        _ => None,
    };
    let user = repository::update_user_admin(
        &state.pool,
        uid,
        &name,
        &role,
        is_active,
        password_hash.as_deref(),
    )
    .await
    .map_err(|_| db_error())?
    .ok_or_else(|| not_found())?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "user.update",
        &user.email,
        &format!("role={role} active={is_active}"),
    )
    .await;
    Ok(Json(to_dto(user)))
}

pub async fn reset_password(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let uid = parse_uuid(&id)?;
    validate_password(&req.password).map_err(bad_request)?;
    let hash = crate::utils::hash_password(&req.password).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "hash error".into(),
            }),
        )
    })?;
    if repository::update_user_password(&state.pool, uid, &hash)
        .await
        .map_err(|_| db_error())?
        .is_none()
    {
        return Err(not_found());
    }
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "user.password.reset",
        &uid.to_string(),
        "",
    )
    .await;
    Ok(Json(serde_json::json!({ "success": true })))
}

pub async fn delete(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let uid = parse_uuid(&id)?;
    if uid == actor.id {
        return Err(bad_request("cannot delete your own account"));
    }
    let current = repository::find_user_by_id(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found())?;
    if current.role == "admin" && current.is_active {
        let admins = repository::count_active_admins(&state.pool)
            .await
            .map_err(|_| db_error())?;
        if admins <= 1 {
            return Err(conflict("cannot delete the last active administrator"));
        }
    }
    repository::delete_user(&state.pool, uid)
        .await
        .map_err(|_| db_error())?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "user.delete",
        &current.email,
        "",
    )
    .await;
    Ok(Json(serde_json::json!({ "success": true })))
}
