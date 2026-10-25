//! Cache warm / prefetch tasks

use crate::middleware::authz::Actor;
use crate::repository;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct PrefetchRequest {
    pub domain: String,
    pub paths: Vec<String>,
}

#[derive(Serialize)]
pub struct PrefetchResponse {
    pub success: bool,
    pub created: usize,
    pub task_ids: Vec<String>,
}

#[derive(Serialize)]
pub struct PrefetchTaskDto {
    pub id: String,
    pub domain: String,
    pub url_path: String,
    pub status: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

fn forbidden() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorBody {
            error: "forbidden".into(),
        }),
    )
}

pub async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<PrefetchRequest>,
) -> Result<Json<PrefetchResponse>, (StatusCode, Json<ErrorBody>)> {
    if req.domain.is_empty() || req.paths.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "domain and paths required".into(),
            }),
        ));
    }
    if !actor.can_write_domain_name(&state, &req.domain).await {
        return Err(forbidden());
    }
    let mut ids = Vec::new();
    for path in &req.paths {
        let p = if path.starts_with('/') {
            path.clone()
        } else {
            format!("/{path}")
        };
        match repository::create_prefetch(&state.pool, &req.domain, &p).await {
            Ok(id) => ids.push(id.to_string()),
            Err(e) => tracing::error!(error = %e, "prefetch insert"),
        }
    }
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "prefetch",
        &req.domain,
        &format!("{} paths", ids.len()),
    )
    .await;
    Ok(Json(PrefetchResponse {
        success: !ids.is_empty(),
        created: ids.len(),
        task_ids: ids,
    }))
}

pub async fn list(
    State(state): State<AppState>,
    actor: Actor,
) -> Json<Vec<PrefetchTaskDto>> {
    let rows = repository::list_prefetch(&state.pool, 50)
        .await
        .unwrap_or_default();
    let visible = actor.visible_domain_ids(&state).await;
    let visible_names: Option<std::collections::HashSet<String>> = match visible {
        None => None,
        Some(ids) => {
            let rows = repository::list_domains(&state.pool).await.unwrap_or_default();
            Some(
                rows.into_iter()
                    .filter(|d| ids.contains(&d.id))
                    .map(|d| d.name)
                    .collect(),
            )
        }
    };

    Json(
        rows.into_iter()
            .filter(|(_, domain, _, _, _)| match &visible_names {
                None => true,
                Some(names) => names.contains(domain),
            })
            .map(|(id, domain, url_path, status, message)| PrefetchTaskDto {
                id: id.to_string(),
                domain,
                url_path,
                status,
                message,
            })
            .collect(),
    )
}
