//! Agent authentication.
//!
//! Two distinct credentials are used:
//!
//! * [`AgentAuth`] — edge → control routes. Requires a **per-node token**
//!   created when the node was pre-registered. It is bound to that node name;
//!   unknown tokens and the global token are rejected.
//! * [`ScheduleAuth`] — the DNS scheduler route. Accepts the global
//!   `AGENT_TOKEN` (DNS is not an edge node) or a valid node token.
//!
//! This prevents an unregistered edge from joining just by knowing the global
//! token, and prevents one edge from checking in as a different node.

use crate::repository;
use crate::state::AppState;
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Authenticated edge node, derived from its per-node token.
pub struct AgentAuth {
    pub node_name: String,
}

pub struct ScheduleAuth;

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

fn agent_token(parts: &Parts) -> &str {
    parts
        .headers
        .get("x-lagran-agent-token")
        .or_else(|| parts.headers.get("X-Lagran-Agent-Token"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

#[async_trait]
impl FromRequestParts<AppState> for AgentAuth {
    type Rejection = AgentAuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let got = agent_token(parts);
        if got.is_empty() {
            return Err(AgentAuthError);
        }
        match repository::node_name_for_token(&state.pool, got).await {
            Ok(Some(node_name)) => Ok(Self { node_name }),
            _ => Err(AgentAuthError),
        }
    }
}

#[async_trait]
impl FromRequestParts<AppState> for ScheduleAuth {
    type Rejection = AgentAuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let expected = state.config.agent_token.as_str();
        // Empty global token keeps the old development behavior: auth disabled.
        if expected.is_empty() {
            return Ok(ScheduleAuth);
        }
        let got = agent_token(parts);
        if !expected.is_empty() && got == expected {
            return Ok(ScheduleAuth);
        }
        if repository::node_token_exists(&state.pool, got)
            .await
            .unwrap_or(false)
        {
            return Ok(ScheduleAuth);
        }
        Err(AgentAuthError)
    }
}
