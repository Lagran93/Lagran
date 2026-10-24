//! Operation audit log

use crate::middleware::AuthUser;
use crate::repository;
use crate::state::AppState;
use axum::{extract::State, Json};
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

pub async fn list(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Json<Vec<AuditDto>> {
    let rows = repository::list_audit(&state.pool, 100)
        .await
        .unwrap_or_default();
    Json(
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
    )
}
