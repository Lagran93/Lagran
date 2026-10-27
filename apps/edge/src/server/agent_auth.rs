//! Require X-Lagran-Agent-Token on management endpoints.
//!
//! When `agent_token` is empty, management endpoints are **rejected** unless
//! `ALLOW_INSECURE_AGENT=true` (local dev only). Health checks stay open.

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::server::handler::AppState;

pub struct RequireAgentToken;

fn allow_insecure() -> bool {
    matches!(
        std::env::var("ALLOW_INSECURE_AGENT")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for RequireAgentToken {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let expected = state.agent_token.as_str();
        if expected.is_empty() {
            if allow_insecure() {
                return Ok(RequireAgentToken);
            }
            return Err((
                StatusCode::UNAUTHORIZED,
                "agent token required (set AGENT_TOKEN or ALLOW_INSECURE_AGENT=true for local dev)",
            )
                .into_response());
        }
        let got = parts
            .headers
            .get("x-lagran-agent-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if got == expected {
            Ok(RequireAgentToken)
        } else {
            Err((StatusCode::UNAUTHORIZED, "unauthorized agent").into_response())
        }
    }
}
