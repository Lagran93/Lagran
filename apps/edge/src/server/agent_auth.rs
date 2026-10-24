//! Require X-Lagran-Agent-Token on management endpoints

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::server::handler::AppState;

pub struct RequireAgentToken;

#[async_trait]
impl FromRequestParts<Arc<AppState>> for RequireAgentToken {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let expected = state.agent_token.as_str();
        if expected.is_empty() {
            return Ok(RequireAgentToken);
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
