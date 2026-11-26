//! WebSocket upgrade detection.
//!
//! The tunnel used to live here for the legacy in-process engine. The Pingora
//! data plane tunnels upgrades itself, so only the shared upgrade test remains
//! (阶段 6).

use axum::http::HeaderMap;

/// Returns true if the request is a WebSocket upgrade.
pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let upgrade = headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let connection = headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    upgrade && connection
}
