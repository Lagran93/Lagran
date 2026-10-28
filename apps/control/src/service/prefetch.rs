//! Cache-warm executor and scheduled prefetch dispatch.

use crate::repository::{self, PrefetchTaskRow};
use crate::service::agent_http;
use crate::state::AppState;
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize)]
struct EdgePrefetchReply {
    success: bool,
    warmed: usize,
    failed: usize,
    message: String,
}

pub fn spawn(state: AppState, interval_secs: u64) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(interval_secs.clamp(5, 3600));
        tracing::info!(?interval, "prefetch worker started");
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = run_once(&state).await {
                tracing::warn!(error = %e, "prefetch worker failed");
            }
        }
    });
}

async fn run_once(state: &AppState) -> Result<(), sqlx::Error> {
    enqueue_due_schedules(state).await?;
    let tasks = repository::claim_prefetch_tasks(&state.pool, 20).await?;
    if tasks.is_empty() {
        return Ok(());
    }
    let nodes = repository::list_online_nodes_with_agent(&state.pool)
        .await
        .unwrap_or_default();
    if nodes.is_empty() {
        for task in &tasks {
            let _ = repository::finish_prefetch_task(
                &state.pool,
                task.id,
                false,
                "no online edge agents with agent_url",
            )
            .await;
        }
        return Ok(());
    }
    for task in tasks {
        process_task(state, &task, &nodes).await;
    }
    Ok(())
}

async fn enqueue_due_schedules(state: &AppState) -> Result<(), sqlx::Error> {
    let schedules = repository::due_prefetch_schedules(&state.pool, 20).await?;
    for schedule in schedules {
        for path in &schedule.paths.0 {
            if let Err(e) =
                repository::create_prefetch_source(&state.pool, &schedule.domain, path, "schedule")
                    .await
            {
                tracing::warn!(schedule = %schedule.id, error = %e, "enqueue scheduled prefetch");
            }
        }
        let _ = repository::mark_prefetch_schedule_run(
            &state.pool,
            schedule.id,
            schedule.interval_minutes,
        )
        .await;
    }
    Ok(())
}

async fn process_task(state: &AppState, task: &PrefetchTaskRow, nodes: &[repository::NodeRow]) {
    let mut any = false;
    let mut messages = Vec::new();
    for node in nodes {
        let url = format!("{}/__lagran/prefetch", node.agent_url.trim_end_matches('/'));
        let token = if node.auth_token.is_empty() {
            state.config.agent_token.clone()
        } else {
            node.auth_token.clone()
        };
        let body = serde_json::json!({
            "domain": task.domain,
            "paths": [task.url_path],
        });
        match agent_http::request_json::<EdgePrefetchReply, _>("POST", &url, &body, &token).await {
            Ok(reply) => {
                if reply.success || reply.warmed > 0 {
                    any = true;
                }
                messages.push(format!(
                    "{}: warmed={} failed={} ({})",
                    node.name, reply.warmed, reply.failed, reply.message
                ));
            }
            Err(e) => {
                messages.push(format!("{}: {e}", node.name));
                tracing::warn!(node = %node.name, domain = %task.domain, path = %task.url_path, error = %e, "prefetch dispatch failed");
            }
        }
    }
    let message = messages.join("; ");
    let _ = repository::finish_prefetch_task(&state.pool, task.id, any, &message).await;
}
