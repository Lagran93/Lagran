//! Staged release finalisation / automatic rollback monitor.

use crate::repository;
use crate::service::edge_notify;
use crate::state::AppState;
use std::time::Duration;
use uuid::Uuid;

pub fn spawn(state: AppState, interval_secs: u64) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(interval_secs.clamp(5, 300));
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = sweep(&state).await {
                tracing::warn!(error = %e, "config release sweep failed");
            }
        }
    });
}

async fn sweep(state: &AppState) -> Result<(), sqlx::Error> {
    let stale = repository::stale_publishing(&state.pool, 120).await?;
    for release in stale {
        tracing::warn!(release = %release.id, "config release timed out; rolling back");
        let _ = repository::finish_release(
            &state.pool,
            release.id,
            "rolled_back",
            "target nodes did not report a successful apply within 120s",
        )
        .await;
        let _ = edge_notify::notify_config_reload(state).await;
    }
    Ok(())
}

pub async fn report(
    state: &AppState,
    release_id: Uuid,
    node_id: &str,
    success: bool,
    error: &str,
) -> Result<(), sqlx::Error> {
    let Some(release) = repository::get_release(&state.pool, release_id).await? else {
        return Ok(());
    };
    if release.status != "publishing" {
        return Ok(());
    }
    repository::report_apply(&state.pool, release_id, node_id, success, error).await?;
    if !success {
        rollback(state, release_id, error).await?;
        return Ok(());
    }
    maybe_finalize(state, release_id).await
}

pub async fn maybe_finalize(state: &AppState, release_id: Uuid) -> Result<(), sqlx::Error> {
    let Some(release) = repository::get_release(&state.pool, release_id).await? else {
        return Ok(());
    };
    if release.status != "publishing" {
        return Ok(());
    }
    let targets: Vec<String> =
        serde_json::from_value(release.target_nodes.clone()).unwrap_or_default();
    if targets.is_empty() {
        return Ok(());
    }
    let reports = repository::reports(&state.pool, release_id).await?;
    if reports.iter().any(|(_, ok, _)| !ok) {
        let message = reports
            .iter()
            .find(|(_, ok, _)| !ok)
            .map(|(node, _, err)| format!("{node}: {err}"))
            .unwrap_or_else(|| "target node reported failure".into());
        rollback(state, release_id, &message).await?;
        return Ok(());
    }
    let reported: std::collections::HashSet<&str> =
        reports.iter().map(|(node, _, _)| node.as_str()).collect();
    if !targets.iter().all(|node| reported.contains(node.as_str())) {
        return Ok(());
    }
    repository::set_published_versions(&state.pool, &release.versions).await?;
    repository::finish_release(&state.pool, release_id, "published", "").await?;
    tracing::info!(release = %release_id, nodes = targets.len(), "config release published");
    let _ = edge_notify::notify_config_reload(state).await;
    Ok(())
}

pub async fn rollback(state: &AppState, release_id: Uuid, reason: &str) -> Result<(), sqlx::Error> {
    let Some(release) = repository::get_release(&state.pool, release_id).await? else {
        return Ok(());
    };
    if release.status == "publishing" {
        repository::finish_release(&state.pool, release_id, "rolled_back", reason).await?;
        tracing::warn!(release = %release_id, reason, "config release rolled back");
        let _ = edge_notify::notify_config_reload(state).await;
    } else if release.status == "published" {
        // Manual rollback of an already-published release restores the
        // previously active versions.
        repository::set_published_versions(&state.pool, &release.previous_versions).await?;
        repository::finish_release(&state.pool, release_id, "rolled_back", reason).await?;
        let _ = edge_notify::notify_config_reload(state).await;
    }
    Ok(())
}
