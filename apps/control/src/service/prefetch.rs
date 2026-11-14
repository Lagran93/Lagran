//! Cache-warm executor and scheduled prefetch dispatch.

use crate::repository::{self, PrefetchTaskRow};
use crate::service::agent_http;
use crate::state::AppState;
use serde::Deserialize;
use std::time::Duration;

/// How long a claimed task may stay `running` before it is considered abandoned.
///
/// The dispatch timeout for one node is 300s by default and the queue runs tasks
/// sequentially, so this must be comfortably larger than one dispatch.
const STALE_TASK_SECS: i64 = 900;

/// Attempts allowed before an abandoned task is failed instead of retried.
const MAX_ATTEMPTS: i32 = 3;

#[derive(Deserialize)]
struct EdgePrefetchReply {
    success: bool,
    warmed: usize,
    failed: usize,
    message: String,
}

pub fn spawn(state: AppState, interval_secs: u64) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = Duration::from_secs(interval_secs.clamp(5, 3600));
        tracing::info!(?interval, "prefetch worker started");
        loop {
            tokio::time::sleep(interval).await;
            let redis = state.redis.clone();
            if let Some(redis) = redis {
                let lock = match redis
                    .try_lock("lagran:lock:prefetch-worker", Duration::from_secs(120))
                    .await
                {
                    Ok(Some(lock)) => Some(lock),
                    Ok(None) => {
                        tracing::debug!("prefetch worker skipped; another replica holds the lock");
                        continue;
                    }
                    Err(()) => {
                        // Fail closed for the same reason as the others: two replicas
                        // prefetching at once doubles origin traffic for no gain, and
                        // the task bookkeeping assumes one worker.
                        tracing::warn!("Redis lock unavailable; skipping this prefetch round");
                        continue;
                    }
                };
                // Keep the lock alive for the whole round; a queue of slow
                // origins easily exceeds the initial 120 s.
                let renewer = lock.as_ref().map(|lock| {
                    let redis = redis.clone();
                    let lock = lock.clone();
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(Duration::from_secs(45)).await;
                            if !redis
                                .renew_lock(&lock, Duration::from_secs(120))
                                .await
                            {
                                break;
                            }
                        }
                    })
                });
                if let Err(e) = run_once(&state).await {
                    tracing::warn!(error = %e, "prefetch worker failed");
                }
                if let Some(renewer) = renewer {
                    renewer.abort();
                }
                if let Some(lock) = lock.as_ref() {
                    redis.unlock(lock).await;
                }
            } else if let Err(e) = run_once(&state).await {
                tracing::warn!(error = %e, "prefetch worker failed");
            }
        }
    })
}

async fn run_once(state: &AppState) -> Result<(), sqlx::Error> {
    // Release tasks a previous run claimed but never finished, before claiming
    // new ones. Without this a worker that died mid-task left its row `running`
    // forever: never retried, never reported, and impossible to clear from the
    // console.
    match repository::reclaim_stale_prefetch_tasks(&state.pool, STALE_TASK_SECS, MAX_ATTEMPTS).await
    {
        Ok((requeued, failed)) => {
            if requeued > 0 || failed > 0 {
                tracing::warn!(requeued, failed, "reclaimed abandoned prefetch tasks");
            }
        }
        Err(e) => {
            // Never let reclaim block the queue: a broken reclaim must not stop
            // healthy tasks from running.
            tracing::warn!(error = %e, "reclaim prefetch tasks failed");
        }
    }
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
    // Dispatch a few tasks at a time instead of strictly serially. One slow
    // origin used to delay every other tenant's warm-up by up to its 300 s
    // timeout; four in flight keeps the round bounded without hammering edges.
    const CONCURRENCY: usize = 4;
    let nodes = std::sync::Arc::new(nodes);
    let mut set = tokio::task::JoinSet::new();
    for task in tasks {
        while set.len() >= CONCURRENCY {
            if let Some(Err(e)) = set.join_next().await {
                tracing::warn!(error = %e, "prefetch task panicked");
            }
        }
        let state = state.clone();
        let nodes = nodes.clone();
        set.spawn(async move {
            process_task(&state, &task, nodes.as_slice()).await;
        });
    }
    while let Some(result) = set.join_next().await {
        if let Err(e) = result {
            tracing::warn!(error = %e, "prefetch task panicked");
        }
    }
    Ok(())
}

async fn enqueue_due_schedules(state: &AppState) -> Result<(), sqlx::Error> {
    let schedules = repository::due_prefetch_schedules(&state.pool, 20).await?;
    for schedule in schedules {
        for path in &schedule.paths.0 {
            if let Err(e) = repository::create_prefetch_source(
                &state.pool,
                &schedule.domain,
                path,
                &schedule.headers.0,
                "schedule",
            )
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
            "headers": task.headers.0,
        });
        let prefetch_timeout = std::env::var("PREFETCH_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(300)
            .clamp(30, 1800);
        match agent_http::request_json_timeout::<EdgePrefetchReply, _>(
            "POST",
            &url,
            &body,
            &token,
            Duration::from_secs(prefetch_timeout),
        )
        .await
        {
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
