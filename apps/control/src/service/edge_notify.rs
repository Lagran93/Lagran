//! Best-effort notify online edges to pull config / purge immediately.

use crate::repository;
use crate::service::agent_http;
use crate::state::AppState;

/// POST /__lagran/config/reload on every online edge with an agent_url.
pub async fn notify_config_reload(state: &AppState) {
    let nodes = match repository::list_online_nodes_with_agent(&state.pool).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "list nodes for config notify failed");
            return;
        }
    };
    if nodes.is_empty() {
        return;
    }
    let global = state.config.agent_token.clone();
    for node in nodes {
        let url = format!(
            "{}/__lagran/config/reload",
            node.agent_url.trim_end_matches('/')
        );
        let token = if node.auth_token.is_empty() {
            global.clone()
        } else {
            node.auth_token.clone()
        };
        tokio::spawn(async move {
            let body = serde_json::json!({});
            if let Err(e) = agent_http::post_json_ok(&url, &body, &token).await {
                tracing::debug!(%url, error = %e, "config reload notify failed");
            }
        });
    }
}
