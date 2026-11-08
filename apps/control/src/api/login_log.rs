//! Authentication attempt history.

use crate::middleware::authz::Actor;
use crate::repository;
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct ListQuery {
    pub limit: Option<i64>,
}

#[derive(Serialize)]
pub struct LoginLogDto {
    pub id: String,
    pub created_at: String,
    pub user_id: Option<String>,
    pub email: String,
    pub client_ip: String,
    pub user_agent: String,
    pub success: bool,
    pub reason: String,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

pub async fn list(
    State(state): State<AppState>,
    actor: Actor,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<LoginLogDto>>, (StatusCode, Json<ErrorBody>)> {
    let limit = query.limit.unwrap_or(200).clamp(1, 500);
    let owner_email = if actor.admin() {
        None
    } else {
        Some(actor.email.as_str())
    };
    let rows = repository::list_login_logs(&state.pool, limit, owner_email)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list login logs");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "database error".into(),
                }),
            )
        })?;

    Ok(Json(
        rows.into_iter()
            .map(|row| LoginLogDto {
                id: row.id.to_string(),
                created_at: row.created_at.to_rfc3339(),
                user_id: row.user_id.map(|id| id.to_string()),
                email: row.email,
                client_ip: row.client_ip,
                user_agent: row.user_agent,
                success: row.success,
                reason: row.reason,
            })
            .collect(),
    ))
}
