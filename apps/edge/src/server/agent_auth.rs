//! Require `X-Lagran-Agent-Token` on management endpoints.
//!
//! When `agent_token` is empty, management endpoints are **rejected** unless
//! `ALLOW_INSECURE_AGENT=true` (local dev only). Health checks stay open.
//!
//! `/__lagran/metrics` is special: it used to be exempt from this check on the
//! admin listener, which turned a scrape endpoint into an anonymous listing of
//! every tenant's domain names and traffic totals (H1). Metrics now use
//! `METRICS_TOKEN` when it is set and fall back to `AGENT_TOKEN`, matching the
//! control plane's `/metrics` policy — Prometheus can then scrape with a
//! credential that cannot purge, reload or update the node.

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header, request::Parts, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::server::state::AppState;

/// Marker for endpoints that accept only the node (agent) token.
pub struct RequireAgentToken;

/// Marker for the Prometheus exposition endpoint.
///
/// Accepts either `METRICS_TOKEN` (preferred when configured) or `AGENT_TOKEN`,
/// via `x-lagran-metrics-token`, `x-lagran-agent-token` or
/// `Authorization: Bearer`.
pub struct RequireMetricsToken;

pub(crate) fn allow_insecure() -> bool {
    matches!(
        std::env::var("ALLOW_INSECURE_AGENT")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Constant-time byte comparison (no early return on the first mismatch).
///
/// Token equality with `==` leaks the matching prefix length through timing.
/// The control plane already compares `/metrics` credentials this way; the
/// edge management paths now do the same.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

fn agent_token(headers: &HeaderMap) -> &str {
    headers
        .get("x-lagran-agent-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

/// Authorization for every management endpoint except `/__lagran/metrics`.
pub fn agent_authorized(expected: &str, headers: &HeaderMap) -> bool {
    if expected.is_empty() {
        return allow_insecure();
    }
    constant_time_eq(agent_token(headers).as_bytes(), expected.as_bytes())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn presented_metrics_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-lagran-metrics-token")
        .or_else(|| headers.get("x-lagran-agent-token"))
        .and_then(|value| value.to_str().ok())
        .or_else(|| bearer_token(headers))
}

/// Authorization for `/__lagran/metrics`.
///
/// `METRICS_TOKEN` takes precedence when set; otherwise the node token keeps
/// working so existing scrapers do not need a second credential. When neither
/// is configured the endpoint stays closed unless `ALLOW_INSECURE_AGENT=true`,
/// which is the same fail-closed rule the other management endpoints use.
pub fn metrics_authorized(metrics_token: &str, agent_token: &str, headers: &HeaderMap) -> bool {
    let expected = if metrics_token.is_empty() {
        agent_token
    } else {
        metrics_token
    };
    if expected.is_empty() {
        return allow_insecure();
    }
    presented_metrics_token(headers)
        .is_some_and(|presented| constant_time_eq(presented.as_bytes(), expected.as_bytes()))
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for RequireAgentToken {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let expected = state.agent_token.as_str();
        if agent_authorized(expected, &parts.headers) {
            return Ok(RequireAgentToken);
        }
        if expected.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "agent token required (set AGENT_TOKEN or ALLOW_INSECURE_AGENT=true for local dev)",
            )
                .into_response());
        }
        Err((StatusCode::UNAUTHORIZED, "unauthorized agent").into_response())
    }
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for RequireMetricsToken {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let metrics_token = state.metrics_token.as_str();
        let agent_token = state.agent_token.as_str();
        if metrics_authorized(metrics_token, agent_token, &parts.headers) {
            return Ok(RequireMetricsToken);
        }
        if metrics_token.is_empty() && agent_token.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "metrics token required (set METRICS_TOKEN, AGENT_TOKEN or \
                 ALLOW_INSECURE_AGENT=true for local dev)",
            )
                .into_response());
        }
        Err((StatusCode::UNAUTHORIZED, "unauthorized metrics scrape").into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, value.parse().unwrap());
        }
        map
    }

    #[test]
    fn constant_time_eq_matches_only_equal_values() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret-longer"));
        assert!(!constant_time_eq(b"", b"x"));
    }

    #[test]
    fn agent_token_requires_the_configured_value() {
        let token = "node-token";
        assert!(agent_authorized(
            token,
            &headers(&[("x-lagran-agent-token", token)])
        ));
        assert!(!agent_authorized(token, &HeaderMap::new()));
        assert!(!agent_authorized(
            token,
            &headers(&[("x-lagran-agent-token", "other")])
        ));
        // No token configured: the ALLOW_INSECURE_AGENT escape hatch decides.
        assert_eq!(agent_authorized("", &HeaderMap::new()), allow_insecure());
    }

    #[test]
    fn metrics_token_prefers_metrics_token_and_falls_back_to_agent_token() {
        // Dedicated credential when METRICS_TOKEN is configured.
        assert!(metrics_authorized(
            "metrics-secret",
            "node-token",
            &headers(&[("x-lagran-metrics-token", "metrics-secret")])
        ));
        // ...and it is the only one accepted: a scrape cannot use the more
        // powerful purge/update credential once a metrics token exists.
        assert!(!metrics_authorized(
            "metrics-secret",
            "node-token",
            &headers(&[("x-lagran-agent-token", "node-token")])
        ));
        // Without METRICS_TOKEN existing agent-token scrapers keep working.
        assert!(metrics_authorized(
            "",
            "node-token",
            &headers(&[("x-lagran-agent-token", "node-token")])
        ));
        // Prometheus `authorization` blocks send a bearer header.
        assert!(metrics_authorized(
            "metrics-secret",
            "node-token",
            &headers(&[("authorization", "Bearer metrics-secret")])
        ));
        assert!(!metrics_authorized(
            "metrics-secret",
            "node-token",
            &headers(&[("authorization", "Basic metrics-secret")])
        ));
        assert!(!metrics_authorized(
            "metrics-secret",
            "node-token",
            &HeaderMap::new()
        ));
        // Neither token configured: closed unless ALLOW_INSECURE_AGENT.
        assert_eq!(
            metrics_authorized("", "", &HeaderMap::new()),
            allow_insecure()
        );
    }
}
