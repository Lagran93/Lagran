//! Health and readiness endpoints

use crate::state::AppState;
use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
}

#[derive(Serialize)]
pub struct ReadyResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
    pub database: &'static str,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "lagran-control",
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub async fn ready(State(state): State<AppState>) -> Result<Json<ReadyResponse>, StatusCode> {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => Ok(Json(ReadyResponse {
            status: "ready",
            service: "lagran-control",
            version: env!("CARGO_PKG_VERSION"),
            database: "ok",
        })),
        Err(e) => {
            tracing::error!(error = %e, "readiness db check failed");
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}
