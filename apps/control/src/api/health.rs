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




use axum::response::IntoResponse;

/// Minimal Prometheus text for scrape.
pub async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let db = match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(_) => 1,
        Err(_) => 0,
    };
    let body = format!(
        "# HELP lagran_control_up Control plane process up\n# TYPE lagran_control_up gauge\nlagran_control_up 1\n# HELP lagran_control_db_up Database reachable\n# TYPE lagran_control_db_up gauge\nlagran_control_db_up {db}\n"
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}
