//! Operation audit log (admin only)

use crate::middleware::authz::Actor;
use crate::repository;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct AuditDto {
    pub id: String,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub detail: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

pub async fn list(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<AuditDto>>, (StatusCode, Json<ErrorBody>)> {
    if !actor.admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: "admin only".into(),
            }),
        ));
    }
    let rows = repository::list_audit(&state.pool, 100)
        .await
        .unwrap_or_default();
    Ok(Json(
        rows.into_iter()
            .map(|r| AuditDto {
                id: r.id.to_string(),
                actor: r.actor,
                action: r.action,
                resource: r.resource,
                detail: r.detail,
                created_at: r.created_at.to_rfc3339(),
            })
            .collect(),
    ))
}
