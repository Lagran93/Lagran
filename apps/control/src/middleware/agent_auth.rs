//! Validate X-Lagran-Agent-Token for edge → control APIs

use crate::state::AppState;
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

pub struct AgentAuth;

pub struct AgentAuthError;

impl IntoResponse for AgentAuthError {
    fn into_response(self) -> Response {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid or missing agent token" })),
        )
            .into_response()
    }
}

#[async_trait]
impl FromRequestParts<AppState> for AgentAuth {
    type Rejection = AgentAuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let expected = state.config.agent_token.as_str();
        if expected.is_empty() {
            return Ok(AgentAuth);
        }
        let got = parts
            .headers
            .get("x-lagran-agent-token")
            .or_else(|| parts.headers.get("X-Lagran-Agent-Token"))
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if got == expected {
            Ok(AgentAuth)
        } else {
            Err(AgentAuthError)
        }
    }
}
