//! Cache warm / prefetch tasks

use crate::middleware::authz::Actor;
use crate::repository;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

pub async fn list(State(state): State<AppState>, actor: Actor) -> Json<Vec<PrefetchTaskDto>> {
    let rows = repository::list_prefetch(&state.pool, 50)
        .await
        .unwrap_or_default();
    let visible = actor.visible_domain_ids(&state).await;
    let visible_names: Option<std::collections::HashSet<String>> = match visible {
        None => None,
        Some(ids) => {
            let rows = repository::list_domains(&state.pool)
                .await
                .unwrap_or_default();
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

#[derive(Serialize)]
pub struct PrefetchScheduleDto {
    pub id: String,
    pub domain: String,
    pub paths: Vec<String>,
    pub interval_minutes: u32,
    pub enabled: bool,
    pub last_run_at: Option<String>,
    pub next_run_at: String,
}

#[derive(Deserialize)]
pub struct ScheduleRequest {
    pub domain: String,
    pub paths: Vec<String>,
    #[serde(default = "default_interval")]
    pub interval_minutes: u32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_interval() -> u32 {
    60
}

fn default_enabled() -> bool {
    true
}

fn schedule_dto(row: repository::PrefetchScheduleRow) -> PrefetchScheduleDto {
    PrefetchScheduleDto {
        id: row.id.to_string(),
        domain: row.domain,
        paths: row.paths.0,
        interval_minutes: row.interval_minutes.max(0) as u32,
        enabled: row.enabled,
        last_run_at: row.last_run_at.map(|t| t.to_rfc3339()),
        next_run_at: row.next_run_at.to_rfc3339(),
    }
}

fn normalize_paths(paths: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for path in paths {
        let mut p = path.trim().to_string();
        if p.is_empty() {
            continue;
        }
        if !p.starts_with('/') {
            p.insert(0, '/');
        }
        if !out.iter().any(|existing| existing == &p) {
            out.push(p);
        }
    }
    out
}

pub async fn list_schedules(
    State(state): State<AppState>,
    actor: Actor,
) -> Json<Vec<PrefetchScheduleDto>> {
    let rows = repository::list_prefetch_schedules(&state.pool)
        .await
        .unwrap_or_default();
    let visible = actor.visible_domain_ids(&state).await;
    let visible_names: Option<std::collections::HashSet<String>> = match visible {
        None => None,
        Some(ids) => {
            let rows = repository::list_domains(&state.pool)
                .await
                .unwrap_or_default();
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
            .filter(|r| match &visible_names {
                None => true,
                Some(names) => names.contains(&r.domain),
            })
            .map(schedule_dto)
            .collect(),
    )
}

pub async fn create_schedule(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<ScheduleRequest>,
) -> Result<(StatusCode, Json<PrefetchScheduleDto>), (StatusCode, Json<ErrorBody>)> {
    let domain = req.domain.trim().to_ascii_lowercase();
    let paths = normalize_paths(req.paths);
    if domain.is_empty() || paths.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "domain and paths required".into(),
            }),
        ));
    }
    if !actor.can_write_domain_name(&state, &domain).await {
        return Err(forbidden());
    }
    let interval = req.interval_minutes.clamp(5, 10_080) as i32;
    let row = repository::create_prefetch_schedule(&state.pool, &domain, &paths, interval)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "database error".into(),
                }),
            )
        })?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "prefetch.schedule.create",
        &domain,
        &format!("{} paths every {}m", paths.len(), interval),
    )
    .await;
    Ok((StatusCode::CREATED, Json(schedule_dto(row))))
}

pub async fn update_schedule(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<ScheduleRequest>,
) -> Result<Json<PrefetchScheduleDto>, (StatusCode, Json<ErrorBody>)> {
    let uid = Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "invalid id".into(),
            }),
        )
    })?;
    let domain = req.domain.trim().to_ascii_lowercase();
    let paths = normalize_paths(req.paths);
    if domain.is_empty() || paths.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "domain and paths required".into(),
            }),
        ));
    }
    let existing = repository::get_prefetch_schedule(&state.pool, uid)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "database error".into(),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorBody {
                    error: "schedule not found".into(),
                }),
            )
        })?;
    if !actor.can_write_domain_name(&state, &existing.domain).await
        || !actor.can_write_domain_name(&state, &domain).await
    {
        return Err(forbidden());
    }
    let interval = req.interval_minutes.clamp(5, 10_080) as i32;
    let row = repository::update_prefetch_schedule(
        &state.pool,
        uid,
        &domain,
        &paths,
        interval,
        req.enabled,
    )
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "database error".into(),
            }),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "schedule not found".into(),
            }),
        )
    })?;
    Ok(Json(schedule_dto(row)))
}

pub async fn delete_schedule(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<PrefetchResponse>, (StatusCode, Json<ErrorBody>)> {
    let uid = Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "invalid id".into(),
            }),
        )
    })?;
    let row = repository::get_prefetch_schedule(&state.pool, uid)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "database error".into(),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorBody {
                    error: "schedule not found".into(),
                }),
            )
        })?;
    if !actor.can_write_domain_name(&state, &row.domain).await {
        return Err(forbidden());
    }
    let _ = repository::delete_prefetch_schedule(&state.pool, uid).await;
    Ok(Json(PrefetchResponse {
        success: true,
        created: 0,
        task_ids: vec![],
    }))
}

#[derive(Serialize)]
pub struct PrefetchTaskV2 {
    pub id: String,
    pub domain: String,
    pub url_path: String,
    pub status: String,
    pub message: String,
    pub source: String,
    pub created_at: String,
    pub finished_at: Option<String>,
}

pub async fn list_tasks(State(state): State<AppState>, actor: Actor) -> Json<Vec<PrefetchTaskV2>> {
    let rows = repository::list_prefetch_tasks(&state.pool, 100)
        .await
        .unwrap_or_default();
    let visible = actor.visible_domain_ids(&state).await;
    let visible_names: Option<std::collections::HashSet<String>> = match visible {
        None => None,
        Some(ids) => {
            let rows = repository::list_domains(&state.pool)
                .await
                .unwrap_or_default();
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
            .filter(|r| match &visible_names {
                None => true,
                Some(names) => names.contains(&r.domain),
            })
            .map(|r| PrefetchTaskV2 {
                id: r.id.to_string(),
                domain: r.domain,
                url_path: r.url_path,
                status: r.status,
                message: r.message,
                source: r.source,
                created_at: r.created_at.to_rfc3339(),
                finished_at: r.finished_at.map(|t| t.to_rfc3339()),
            })
            .collect(),
    )
}
