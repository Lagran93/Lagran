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

use crate::state::AppState;
use axum::{
    async_trait,
    extract::{ConnectInfo, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::net::SocketAddr;

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

/// Whether an unset `AGENT_TOKEN` may leave the scheduling API open.
///
/// Off by default. Only a local development environment should set this, and it
/// is logged loudly when used.
fn allow_unauthenticated_schedule() -> bool {
    matches!(
        std::env::var("ALLOW_UNAUTHENTICATED_SCHEDULE")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// The caller's network address, when the router supplied one.
///
/// The agent routes are reachable without a session, so an unknown token is an
/// untrusted input rather than a misconfiguration. The cache uses this to bound
/// how many database lookups one source may trigger (see
/// [`crate::middleware::agent_token_cache`]); it is not an authentication
/// credential and never influences *which* node a token maps to.
fn caller_ip(parts: &Parts) -> Option<std::net::IpAddr> {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

/// Constant-time byte comparison for the shared agent token.
///
/// `==` on `&str` returns on the first differing byte, which leaks the matching
/// prefix length. A 32-byte random token makes remote timing impractical, but the
/// rest of the repository already compares credentials this way; consistency
/// matters once a token is shortened or derived (M4).
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
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
        match state
            .agent_tokens
            .resolve(&state.pool, state.redis.as_deref(), got, caller_ip(parts))
            .await
        {
            Ok(Some(node_name)) => Ok(Self { node_name }),
            Ok(None) => Err(AgentAuthError),
            Err(error) => {
                // A database outage should not be reported as a bad token to
                // the edge; the status stays 401 for compatibility, but the
                // control-plane log carries the real reason.
                tracing::debug!(error = %error, "agent token lookup failed");
                Err(AgentAuthError)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn shared_agent_token_comparison_is_constant_time() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret-longer"));
        assert!(!constant_time_eq(b"", b"x"));
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
        if expected.is_empty() {
            // An unset AGENT_TOKEN used to disable this check entirely, so anyone
            // who could reach the control plane could query `/api/v1/schedule`
            // and read every node's public IP along with the whole scheduling
            // topology. Opening it must now be an explicit, local-development
            // choice rather than the default.
            if allow_unauthenticated_schedule() {
                tracing::warn!(
                    "AGENT_TOKEN is empty and ALLOW_UNAUTHENTICATED_SCHEDULE is set; \
                     the scheduling API is open to anyone who can reach this port"
                );
                return Ok(ScheduleAuth);
            }
            return Err(AgentAuthError);
        }
        let got = agent_token(parts);
        if constant_time_eq(got.as_bytes(), expected.as_bytes()) {
            return Ok(ScheduleAuth);
        }
        if state
            .agent_tokens
            .resolve(&state.pool, state.redis.as_deref(), got, caller_ip(parts))
            .await
            .ok()
            .flatten()
            .is_some()
        {
            return Ok(ScheduleAuth);
        }
        Err(AgentAuthError)
    }
}
