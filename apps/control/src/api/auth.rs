//! Auth endpoints backed by PostgreSQL + JWT

use crate::middleware::AuthUser;
use crate::repository;
use crate::state::AppState;
use crate::utils::{issue_token, verify_password};
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub is_active: bool,
    pub created_at: String,
    pub last_login_at: Option<String>,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: UserInfo,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

#[derive(Serialize)]
pub struct PublicAuthConfig {
    pub allow_register: bool,
}

#[derive(Deserialize)]
pub struct UpdateProfileRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct ChangePasswordResponse {
    pub success: bool,
    pub token: String,
}

pub(crate) fn to_user_info(user: repository::UserRow) -> UserInfo {
    UserInfo {
        id: user.id.to_string(),
        email: user.email,
        name: user.name,
        role: user.role,
        is_active: user.is_active,
        created_at: user.created_at.to_rfc3339(),
        last_login_at: user.last_login_at.map(|t| t.to_rfc3339()),
    }
}

pub async fn public_config(State(state): State<AppState>) -> Json<PublicAuthConfig> {
    Json(PublicAuthConfig {
        allow_register: state.config.allow_register,
    })
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorBody>)> {
    let email = normalize_email(&req.email);
    let limit_key = format!("login:{email}");
    if !state.login_limiter.check(&limit_key) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorBody {
                error: "too many login attempts, try again later".into(),
            }),
        ));
    }
    let user = repository::find_user_by_email(&state.pool, &email)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "database error".into(),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody {
                    error: "invalid email or password".into(),
                }),
            )
        })?;

    let ok = verify_password(&req.password, &user.password_hash).unwrap_or(false);
    if !ok {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "invalid email or password".into(),
            }),
        ));
    }
    if !user.is_active {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: "account is disabled".into(),
            }),
        ));
    }
    let _ = repository::touch_last_login(&state.pool, user.id).await;

    let token = issue_token(
        user.id,
        &user.email,
        &user.name,
        &state.config.jwt_secret,
        state.config.jwt_expire_hours,
        user.token_version,
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "token error".into(),
            }),
        )
    })?;

    Ok(Json(LoginResponse {
        token,
        user: to_user_info(user),
    }))
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<LoginResponse>), (StatusCode, Json<ErrorBody>)> {
    if !state.config.allow_register {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: "registration is disabled".into(),
            }),
        ));
    }
    let email = normalize_email(&req.email);
    if let Err(msg) = validate_email(&email) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody { error: msg.into() }),
        ));
    }
    let limit_key = format!("register:{email}");
    if !state.login_limiter.check(&limit_key) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorBody {
                error: "too many registration attempts, try again later".into(),
            }),
        ));
    }
    if let Err(msg) = validate_password(&req.password) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: msg.into(),
            }),
        ));
    }
    if repository::find_user_by_email(&state.pool, &email)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "database error".into(),
                }),
            )
        })?
        .is_some()
    {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "email already registered".into(),
            }),
        ));
    }

    let hash = crate::utils::hash_password(&req.password).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "hash error".into(),
            }),
        )
    })?;

    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| email.split('@').next().unwrap_or(&email).to_string());
    if name.chars().count() > 80 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "name is too long".into(),
            }),
        ));
    }
    let user = repository::create_user(&state.pool, &email, &hash, &name)
        .await
        .map_err(|e| {
            let unique = e
                .as_database_error()
                .map(|d| d.is_unique_violation())
                .unwrap_or(false);
            tracing::error!(error = %e, "create user");
            if unique {
                (
                    StatusCode::CONFLICT,
                    Json(ErrorBody {
                        error: "email already registered".into(),
                    }),
                )
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorBody {
                        error: "database error".into(),
                    }),
                )
            }
        })?;

    if let Err(e) = repository::ensure_personal_project(&state.pool, user.id).await {
        tracing::warn!(error = %e, user_id = %user.id, "create personal project failed");
    }
    let _ = repository::touch_last_login(&state.pool, user.id).await;

    let token = issue_token(
        user.id,
        &user.email,
        &user.name,
        &state.config.jwt_secret,
        state.config.jwt_expire_hours,
        user.token_version,
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "token error".into(),
            }),
        )
    })?;

    Ok((
        StatusCode::CREATED,
        Json(LoginResponse {
            token,
            user: to_user_info(user),
        }),
    ))
}

pub async fn me(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
) -> Result<Json<UserInfo>, (StatusCode, Json<ErrorBody>)> {
    let id = Uuid::parse_str(&claims.sub).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "invalid token".into(),
            }),
        )
    })?;

    let user = repository::find_user_by_id(&state.pool, id)
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
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody {
                    error: "user not found".into(),
                }),
            )
        })?;

    if !user.is_active {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: "account is disabled".into(),
            }),
        ));
    }
    if claims.ver != user.token_version {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "session expired".into(),
            }),
        ));
    }
    Ok(Json(to_user_info(user)))
}

pub async fn update_me(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Json(req): Json<UpdateProfileRequest>,
) -> Result<Json<UserInfo>, (StatusCode, Json<ErrorBody>)> {
    let id = Uuid::parse_str(&claims.sub).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "invalid token".into(),
            }),
        )
    })?;
    let name = req.name.trim();
    if name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "name required".into(),
            }),
        ));
    }
    if name.chars().count() > 80 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "name is too long".into(),
            }),
        ));
    }
    let current = repository::find_user_by_id(&state.pool, id)
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
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody {
                    error: "user not found".into(),
                }),
            )
        })?;
    if !current.is_active {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: "account is disabled".into(),
            }),
        ));
    }
    if claims.ver != current.token_version {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "session expired".into(),
            }),
        ));
    }
    let user = repository::update_user_profile(&state.pool, id, name)
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
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody {
                    error: "user not found".into(),
                }),
            )
        })?;
    Ok(Json(to_user_info(user)))
}

pub async fn change_password(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<ChangePasswordResponse>, (StatusCode, Json<ErrorBody>)> {
    let id = Uuid::parse_str(&claims.sub).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "invalid token".into(),
            }),
        )
    })?;
    let user = repository::find_user_by_id(&state.pool, id)
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
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody {
                    error: "user not found".into(),
                }),
            )
        })?;
    if !user.is_active {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: "account is disabled".into(),
            }),
        ));
    }
    if claims.ver != user.token_version {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "session expired".into(),
            }),
        ));
    }
    if !verify_password(&req.current_password, &user.password_hash).unwrap_or(false) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "current password is incorrect".into(),
            }),
        ));
    }
    if let Err(msg) = validate_password(&req.new_password) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: msg.into(),
            }),
        ));
    }
    let hash = crate::utils::hash_password(&req.new_password).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "hash error".into(),
            }),
        )
    })?;
    let Some(new_version) = repository::update_user_password(&state.pool, id, &hash)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "database error".into(),
                }),
            )
        })?
    else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "user not found".into(),
            }),
        ));
    };
    let token = issue_token(
        user.id,
        &user.email,
        &user.name,
        &state.config.jwt_secret,
        state.config.jwt_expire_hours,
        new_version,
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "token error".into(),
            }),
        )
    })?;
    Ok(Json(ChangePasswordResponse {
        success: true,
        token,
    }))
}

pub(crate) fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

pub(crate) fn validate_email(email: &str) -> Result<(), &'static str> {
    if email.len() < 3 || email.len() > 254 {
        return Err("invalid email");
    }
    let Some((local, domain)) = email.split_once('@') else {
        return Err("invalid email");
    };
    if local.is_empty() || domain.is_empty() || domain.contains('@') || !domain.contains('.') {
        return Err("invalid email");
    }
    Ok(())
}

pub(crate) fn validate_password(password: &str) -> Result<(), &'static str> {
    if password.len() < 8 {
        return Err("password must be at least 8 characters");
    }
    let has_letter = password.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    if !has_letter || !has_digit {
        return Err("password must contain letters and digits");
    }
    Ok(())
}
