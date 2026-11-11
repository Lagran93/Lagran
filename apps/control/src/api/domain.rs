//! Domain management — RESTful handlers with project-scoped authorization.

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

#[derive(Serialize)]
pub struct DomainDto {
    pub id: String,
    pub name: String,
    pub origin_host: String,
    pub origin_port: u16,
    pub origin_proto: String,
    pub ssl_enabled: bool,
    pub status: String,
    pub project_id: Option<String>,
    pub rate_limit_rps: u32,
    pub rate_limit_burst: u32,
    pub backup_origin_host: String,
    pub backup_origin_port: u16,
    pub backup_origin_proto: String,
    pub origins: Vec<repository::DomainOrigin>,
    pub published_version_id: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateDomainRequest {
    pub name: String,
    #[serde(default)]
    pub origin_host: String,
    pub origin_port: Option<u16>,
    pub origin_proto: Option<String>,
    pub ssl_enabled: Option<bool>,
    pub project_id: Option<String>,
    pub rate_limit_rps: Option<u32>,
    pub rate_limit_burst: Option<u32>,
    pub backup_origin_host: Option<String>,
    pub backup_origin_port: Option<u16>,
    pub backup_origin_proto: Option<String>,
    pub origins: Option<Vec<repository::DomainOrigin>>,
    /// Optional TLS SNI / certificate hostname for the primary origin.
    pub origin_sni: Option<String>,
    /// Optional Host header for the primary origin.
    pub origin_host_header: Option<String>,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

#[derive(Serialize)]
pub struct DeleteResponse {
    pub success: bool,
    pub id: String,
}

pub(crate) fn to_dto(r: repository::DomainRow) -> DomainDto {
    let origins = effective_origins(&r);
    DomainDto {
        id: r.id.to_string(),
        name: r.name,
        origin_host: r.origin_host,
        origin_port: r.origin_port as u16,
        origin_proto: r.origin_proto,
        ssl_enabled: r.ssl_enabled,
        status: r.status,
        project_id: r.project_id.map(|u| u.to_string()),
        rate_limit_rps: r.rate_limit_rps.max(0) as u32,
        rate_limit_burst: r.rate_limit_burst.max(0) as u32,
        backup_origin_host: r.backup_origin_host,
        backup_origin_port: r.backup_origin_port.max(0) as u16,
        backup_origin_proto: if r.backup_origin_proto.is_empty() {
            "http".into()
        } else {
            r.backup_origin_proto
        },
        origins,
        published_version_id: r.published_version_id.map(|u| u.to_string()),
    }
}

pub(crate) fn effective_origins(r: &repository::DomainRow) -> Vec<repository::DomainOrigin> {
    if !r.origins.0.is_empty() {
        return r.origins.0.clone();
    }
    let mut out = vec![repository::DomainOrigin {
        host: r.origin_host.clone(),
        port: r.origin_port.max(0) as u16,
        proto: if r.origin_proto.is_empty() {
            "http".into()
        } else {
            r.origin_proto.clone()
        },
        weight: 100,
        priority: 0,
        enabled: true,
        sni: None,
        host_header: None,
    }];
    if !r.backup_origin_host.is_empty() && r.backup_origin_port > 0 {
        out.push(repository::DomainOrigin {
            host: r.backup_origin_host.clone(),
            port: r.backup_origin_port as u16,
            proto: if r.backup_origin_proto.is_empty() {
                "http".into()
            } else {
                r.backup_origin_proto.clone()
            },
            weight: 100,
            priority: 1,
            enabled: true,
            sni: None,
            host_header: None,
        });
    }
    out
}

fn normalize_origin_meta(value: Option<String>, field: &str) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 253 {
        return Err(format!("{field} is too long"));
    }
    if value
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '/' || c == '@' || c == ':')
        || value.contains("://")
    {
        return Err(format!("{field} is invalid"));
    }
    Ok(Some(value))
}

fn normalize_origins(
    input: Vec<repository::DomainOrigin>,
) -> Result<Vec<repository::DomainOrigin>, String> {
    if input.len() > 16 {
        return Err("at most 16 origins are allowed".into());
    }
    let mut out: Vec<repository::DomainOrigin> = Vec::with_capacity(input.len());
    for mut origin in input {
        origin.host = origin.host.trim().to_ascii_lowercase();
        if origin.host.is_empty() {
            return Err("origin host cannot be empty".into());
        }
        if origin.host.len() > 253 {
            return Err("origin host is too long".into());
        }
        origin.proto = if origin.proto.trim().is_empty() {
            "http".into()
        } else {
            origin.proto.trim().to_ascii_lowercase()
        };
        if origin.proto != "http" && origin.proto != "https" {
            return Err("origin protocol must be http or https".into());
        }
        if origin.port == 0 {
            origin.port = if origin.proto == "https" { 443 } else { 80 };
        }
        origin.sni = normalize_origin_meta(origin.sni, "origin SNI")?;
        origin.host_header = normalize_origin_meta(origin.host_header, "origin Host header")?;
        origin.weight = if origin.weight == 0 {
            100
        } else {
            origin.weight.min(10_000)
        };
        origin.priority = origin.priority.clamp(0, 1000);
        let key = format!("{}:{}:{}", origin.host, origin.port, origin.proto);
        if out
            .iter()
            .any(|o| format!("{}:{}:{}", o.host, o.port, o.proto) == key)
        {
            return Err(format!("duplicate origin: {key}"));
        }
        out.push(origin);
    }
    if out.is_empty() {
        return Err("at least one origin is required".into());
    }
    if !out.iter().any(|o| o.enabled) {
        return Err("at least one origin must be enabled".into());
    }
    out.sort_by_key(|o| (o.priority, std::cmp::Reverse(o.weight)));
    Ok(out)
}

/// Validate/normalise the optional backup origin.
/// Empty host clears it; a missing port defaults by protocol.
fn normalize_backup(host: &str, port: u16, proto: &str) -> Result<(String, i32, String), String> {
    let host = host.trim();
    if host.is_empty() {
        return Ok((String::new(), 0, "http".into()));
    }
    if host.len() > 253 {
        return Err("backup origin host is too long".into());
    }
    let proto = proto.trim().to_ascii_lowercase();
    if proto != "http" && proto != "https" {
        return Err("backup origin protocol must be http or https".into());
    }
    let port = if port == 0 {
        if proto == "https" {
            443
        } else {
            80
        }
    } else {
        port
    };
    Ok((host.to_string(), port as i32, proto))
}

fn parse_uuid(id: &str) -> Result<Uuid, (StatusCode, Json<ErrorBody>)> {
    Uuid::parse_str(id.trim()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: format!("invalid uuid: {id}"),
            }),
        )
    })
}

fn db_error() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: "database error".into(),
        }),
    )
}

fn forbidden() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorBody {
            error: "forbidden".into(),
        }),
    )
}

fn not_found(id: &str) -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorBody {
            error: format!("domain not found: {id}"),
        }),
    )
}

pub async fn list(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<DomainDto>>, (StatusCode, Json<ErrorBody>)> {
    let rows = repository::list_domains(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "list domains");
        db_error()
    })?;
    let visible = actor.visible_domain_ids(&state).await;
    Ok(Json(
        rows.into_iter()
            .filter(|d| match &visible {
                None => true,
                Some(ids) => ids.contains(&d.id),
            })
            .map(to_dto)
            .collect(),
    ))
}

pub async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<CreateDomainRequest>,
) -> Result<(StatusCode, Json<DomainDto>), (StatusCode, Json<ErrorBody>)> {
    let mut normalized_origins = match req.origins.clone() {
        Some(list) => Some(
            normalize_origins(list)
                .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?,
        ),
        None => None,
    };
    let primary = normalized_origins
        .as_ref()
        .and_then(|list| list.iter().find(|o| o.enabled).or_else(|| list.first()))
        .cloned();
    if req.name.trim().is_empty() || (req.origin_host.trim().is_empty() && primary.is_none()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "name and at least one origin are required".into(),
            }),
        ));
    }
    let origin_host = primary
        .as_ref()
        .map(|o| o.host.clone())
        .unwrap_or_else(|| req.origin_host.trim().to_string());
    let port = primary
        .as_ref()
        .map(|o| o.port as i32)
        .unwrap_or_else(|| req.origin_port.unwrap_or(80) as i32);
    let proto = primary
        .as_ref()
        .map(|o| o.proto.clone())
        .unwrap_or_else(|| {
            req.origin_proto.unwrap_or_else(|| {
                if req.ssl_enabled.unwrap_or(false) {
                    "https".into()
                } else {
                    "http".into()
                }
            })
        });
    let ssl = req.ssl_enabled.unwrap_or(proto == "https");

    if normalized_origins.is_none() {
        let sni = normalize_origin_meta(req.origin_sni.clone(), "origin SNI")
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?;
        let host_header =
            normalize_origin_meta(req.origin_host_header.clone(), "origin Host header")
                .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?;
        if sni.is_some() || host_header.is_some() {
            normalized_origins = Some(
                normalize_origins(vec![repository::DomainOrigin {
                    host: origin_host.clone(),
                    port: port as u16,
                    proto: proto.clone(),
                    weight: 100,
                    priority: 0,
                    enabled: true,
                    sni,
                    host_header,
                }])
                .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?,
            );
        }
    }

    // Tenancy: admins may leave a domain unassigned (global); everyone else's
    // domains always live in a project they can write. When no project is
    // chosen we lazily create the user's personal project.
    let project_id = match req.project_id.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => {
            let pid = Uuid::parse_str(s).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorBody {
                        error: "invalid project_id".into(),
                    }),
                )
            })?;
            if !actor.can_write_project(&state, pid).await {
                return Err(forbidden());
            }
            Some(pid)
        }
        None => {
            if actor.admin() {
                None
            } else {
                Some(
                    repository::ensure_personal_project(&state.pool, actor.id)
                        .await
                        .map_err(|_| db_error())?,
                )
            }
        }
    };

    // Normalize before the uniqueness check so `CD.Example.COM.` and
    // `cd.example.com` cannot both be registered: the edge would collapse them
    // onto one registry key and the later write would silently take over.
    let name = normalize_domain_name(&req.name)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?;

    let row = repository::create_domain_with_project(
        &state.pool,
        &name,
        &origin_host,
        port,
        &proto,
        ssl,
        project_id,
    )
    .await
    .map_err(|e| {
        let msg = e.to_string();
        let duplicate = msg.contains("duplicate") || msg.contains("unique");
        if duplicate {
            tracing::warn!(name = %req.name, "domain already exists");
        } else {
            tracing::error!(error = %msg, "create domain");
        }
        let (status, error) = if duplicate {
            (StatusCode::CONFLICT, "域名已存在，请勿重复添加")
        } else {
            (StatusCode::BAD_REQUEST, "数据库错误，请稍后重试")
        };
        (
            status,
            Json(ErrorBody {
                error: error.into(),
            }),
        )
    })?;

    if let Some(ref origins) = normalized_origins {
        repository::set_domain_origins(&state.pool, row.id, origins)
            .await
            .map_err(|_| db_error())?;
    }
    if let Some(rps) = req.rate_limit_rps {
        let burst = req.rate_limit_burst.unwrap_or(rps * 2);
        let _ =
            repository::set_domain_rate_limit(&state.pool, row.id, rps as i32, burst as i32).await;
    }
    if let Some(ref host) = req.backup_origin_host {
        let (h, p, pr) = normalize_backup(
            host,
            req.backup_origin_port.unwrap_or(0),
            req.backup_origin_proto.as_deref().unwrap_or("http"),
        )
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?;
        if !h.is_empty() {
            repository::set_backup_origin(&state.pool, row.id, &h, p, &pr)
                .await
                .map_err(|_| db_error())?;
        }
    }
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "domain.create",
        &row.name,
        &format!("{proto}://{}:{port}", row.origin_host),
    )
    .await;

    // Re-read so the response carries rate limits just written.
    let row = repository::get_domain(&state.pool, row.id)
        .await
        .ok()
        .flatten()
        .unwrap_or(row);
    let _ = crate::service::config_version::record_domain(
        &state.pool,
        row.id,
        &row.name,
        &actor.email,
        "domain.create",
        "创建域名",
    )
    .await;
    Ok((StatusCode::CREATED, Json(to_dto(row))))
}

pub async fn get(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<DomainDto>, (StatusCode, Json<ErrorBody>)> {
    let uid = parse_uuid(&id)?;
    if !actor.can_read_domain(&state, uid).await {
        return Err(not_found(&id));
    }
    let row = repository::get_domain(&state.pool, uid)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "get domain");
            db_error()
        })?
        .ok_or_else(|| not_found(&id))?;
    Ok(Json(to_dto(row)))
}

pub async fn delete(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<ErrorBody>)> {
    let uid = parse_uuid(&id)?;
    let row = repository::get_domain(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found(&id))?;
    if !actor.can_write_domain(&state, uid).await {
        return Err(forbidden());
    }

    repository::delete_domain(&state.pool, uid)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %id, "delete domain");
            db_error()
        })?;
    let _ = repository::resolve_domain_alert_events(&state.pool, &row.name).await;
    state.config_cache.clear();
    if let Some(redis) = state.redis.as_deref() {
        redis.del("lagran:cfg:global").await;
    }
    crate::service::edge_notify::notify_config_reload(&state).await;
    let _ =
        repository::insert_audit(&state.pool, &actor.email, "domain.delete", &row.name, "").await;
    tracing::info!(%id, "domain deleted ok");
    Ok(Json(DeleteResponse { success: true, id }))
}

#[derive(Deserialize)]
pub struct UpdateDomainRequest {
    pub origin_host: Option<String>,
    pub origin_port: Option<u16>,
    pub origin_proto: Option<String>,
    pub ssl_enabled: Option<bool>,
    pub status: Option<String>,
    pub project_id: Option<String>,
    pub rate_limit_rps: Option<u32>,
    pub rate_limit_burst: Option<u32>,
    pub backup_origin_host: Option<String>,
    pub backup_origin_port: Option<u16>,
    pub backup_origin_proto: Option<String>,
    pub origins: Option<Vec<repository::DomainOrigin>>,
    /// Optional TLS SNI / certificate hostname for the primary origin.
    pub origin_sni: Option<String>,
    /// Optional Host header for the primary origin.
    pub origin_host_header: Option<String>,
}

/// PUT /api/v1/domains/{id}
pub async fn update(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<UpdateDomainRequest>,
) -> Result<Json<DomainDto>, (StatusCode, Json<ErrorBody>)> {
    let domain = resolve_domain(&state, &id).await?;
    let uid = domain.id;
    if !actor.can_write_domain(&state, uid).await {
        return Err(forbidden());
    }
    if let Some(ref status) = req.status {
        let s = status.trim().to_lowercase();
        if s != "active" && s != "disabled" {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "status must be active or disabled".into(),
                }),
            ));
        }
    }

    let before = repository::get_domain(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found(&id))?;

    let mut normalized_origins = match req.origins.clone() {
        Some(list) => Some(
            normalize_origins(list)
                .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?,
        ),
        None => None,
    };
    let primary_origin = normalized_origins
        .as_ref()
        .and_then(|list| list.iter().find(|o| o.enabled).or_else(|| list.first()))
        .cloned();
    let host_arg = primary_origin
        .as_ref()
        .map(|o| o.host.clone())
        .or_else(|| req.origin_host.clone());
    let port_arg = primary_origin.as_ref().map(|o| o.port).or(req.origin_port);
    let proto_arg = primary_origin
        .as_ref()
        .map(|o| o.proto.clone())
        .or_else(|| req.origin_proto.clone());
    let ssl_arg = req
        .ssl_enabled
        .or_else(|| primary_origin.as_ref().map(|o| o.proto == "https"));

    let row = repository::update_domain(
        &state.pool,
        uid,
        host_arg.as_deref(),
        port_arg.map(|p| p as i32),
        proto_arg.as_deref(),
        ssl_arg,
        req.status.as_deref(),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "update domain");
        db_error()
    })?
    .ok_or_else(|| not_found(&id))?;

    if normalized_origins.is_none() {
        let sni = normalize_origin_meta(req.origin_sni.clone(), "origin SNI")
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?;
        let host_header =
            normalize_origin_meta(req.origin_host_header.clone(), "origin Host header")
                .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?;
        if req.origin_sni.is_some() || req.origin_host_header.is_some() {
            let mut pool = if before.origins.0.is_empty() {
                vec![repository::DomainOrigin {
                    host: row.origin_host.clone(),
                    port: row.origin_port.max(0) as u16,
                    proto: row.origin_proto.clone(),
                    weight: 100,
                    priority: 0,
                    enabled: true,
                    sni: None,
                    host_header: None,
                }]
            } else {
                before.origins.0.clone()
            };
            if let Some(first) = pool.iter_mut().find(|o| o.enabled) {
                first.host = row.origin_host.clone();
                first.port = row.origin_port.max(0) as u16;
                first.proto = row.origin_proto.clone();
                first.sni = sni;
                first.host_header = host_header;
            }
            normalized_origins = Some(pool);
        }
    }

    if let Some(ref origins) = normalized_origins {
        repository::set_domain_origins(&state.pool, uid, origins)
            .await
            .map_err(|_| db_error())?;
    } else if !before.origins.0.is_empty()
        && (req.origin_host.is_some() || req.origin_port.is_some() || req.origin_proto.is_some())
    {
        // Legacy clients may still edit only the primary fields.
        let mut pool = before.origins.0.clone();
        if let Some(first) = pool.iter_mut().find(|o| o.enabled) {
            first.host = row.origin_host.clone();
            first.port = row.origin_port.max(0) as u16;
            first.proto = row.origin_proto.clone();
        }
        repository::set_domain_origins(&state.pool, uid, &pool)
            .await
            .map_err(|_| db_error())?;
    }

    if req.backup_origin_host.is_some()
        || req.backup_origin_port.is_some()
        || req.backup_origin_proto.is_some()
    {
        let host = req
            .backup_origin_host
            .as_deref()
            .unwrap_or(&before.backup_origin_host);
        let proto = req
            .backup_origin_proto
            .as_deref()
            .unwrap_or(&before.backup_origin_proto);
        let port = req
            .backup_origin_port
            .unwrap_or(before.backup_origin_port.max(0) as u16);
        let (h, p, pr) = normalize_backup(host, port, proto)
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?;
        repository::set_backup_origin(&state.pool, uid, &h, p, &pr)
            .await
            .map_err(|_| db_error())?;
    }
    if let Some(rps) = req.rate_limit_rps {
        let burst = req.rate_limit_burst.unwrap_or(rps * 2);
        let _ = repository::set_domain_rate_limit(&state.pool, uid, rps as i32, burst as i32).await;
    }

    // project_id: Some("") clears (admin only), Some(uuid) moves the domain.
    if let Some(ref pid) = req.project_id {
        let target = if pid.is_empty() {
            if !actor.admin() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorBody {
                        error: "only an admin can unassign a domain".into(),
                    }),
                ));
            }
            None
        } else {
            let parsed = Uuid::parse_str(pid).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorBody {
                        error: "invalid project_id".into(),
                    }),
                )
            })?;
            if !actor.can_write_project(&state, parsed).await {
                return Err(forbidden());
            }
            Some(parsed)
        };
        let _ = repository::assign_domain_project(&state.pool, uid, target).await;
    }

    let row = repository::get_domain(&state.pool, uid)
        .await
        .ok()
        .flatten()
        .unwrap_or(row);
    let _ =
        repository::insert_audit(&state.pool, &actor.email, "domain.update", &row.name, "").await;
    let _ = crate::service::config_version::record_domain(
        &state.pool,
        row.id,
        &row.name,
        &actor.email,
        "domain.update",
        "更新域名配置",
    )
    .await;
    crate::service::edge_notify::notify_config_reload(&state).await;
    Ok(Json(to_dto(row)))
}

#[derive(Deserialize)]
pub struct StatusRequest {
    pub status: String,
}

/// POST /api/v1/domains/{id}/status
pub async fn set_status(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<StatusRequest>,
) -> Result<Json<DomainDto>, (StatusCode, Json<ErrorBody>)> {
    let status = req.status.trim().to_lowercase();
    if status != "active" && status != "disabled" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "status must be active or disabled".into(),
            }),
        ));
    }
    let uid = parse_uuid(&id)?;
    if !actor.can_write_domain(&state, uid).await {
        return Err(forbidden());
    }
    let row = repository::set_domain_status(&state.pool, uid, &status)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "set domain status");
            db_error()
        })?
        .ok_or_else(|| not_found(&id))?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "domain.status",
        &row.name,
        &status,
    )
    .await;
    let _ = crate::service::config_version::record_domain(
        &state.pool,
        row.id,
        &row.name,
        &actor.email,
        "domain.status",
        &format!("状态变更为 {status}"),
    )
    .await;
    crate::service::edge_notify::notify_config_reload(&state).await;
    Ok(Json(to_dto(row)))
}

fn normalize_cache_key_ignore_headers(value: &str) -> Result<String, String> {
    let mut out: Vec<String> = Vec::new();
    for part in value.split(',') {
        let name = part.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        if name != "origin" && name != "accept-language" {
            return Err(format!("unsupported cache key header: {name}"));
        }
        if !out.contains(&name) {
            out.push(name);
        }
    }
    Ok(out.join(","))
}

#[derive(Deserialize)]
pub struct SettingsRequest {
    pub ignore_query_string: Option<bool>,
    pub cache_key_ignore_headers: Option<String>,
    pub cors_origins: Option<String>,
    pub hotlink_allow_referers: Option<String>,
    pub origin_timeout_ms: Option<u32>,
    pub custom_headers: Option<String>,
    pub rate_limit_rps: Option<u32>,
    pub rate_limit_burst: Option<u32>,
    pub cc_enabled: Option<bool>,
    pub cc_rps: Option<u32>,
    pub cc_burst: Option<u32>,
    pub cc_ban_after: Option<u32>,
    pub cc_ban_seconds: Option<u32>,
    pub cc_mode: Option<String>,
    pub cc_allow_ips: Option<String>,
    pub shield_url: Option<String>,
    pub signed_url_enabled: Option<bool>,
    pub signed_url_mode: Option<String>,
    pub signed_url_paths: Option<String>,
    pub signed_url_secret: Option<String>,
    pub signed_url_previous_secret: Option<String>,
    pub signed_url_ttl_secs: Option<u32>,
    pub origin_auth_header: Option<String>,
    pub origin_auth_value: Option<String>,
    pub hotlink_signature_enabled: Option<bool>,
}

#[derive(Serialize)]
pub struct SettingsDto {
    pub ignore_query_string: bool,
    pub cache_key_ignore_headers: String,
    pub cors_origins: String,
    pub hotlink_allow_referers: String,
    pub origin_timeout_ms: u32,
    pub custom_headers: String,
    pub rate_limit_rps: u32,
    pub rate_limit_burst: u32,
    pub cc_enabled: bool,
    pub cc_rps: u32,
    pub cc_burst: u32,
    pub cc_ban_after: u32,
    pub cc_ban_seconds: u32,
    pub cc_mode: String,
    pub cc_allow_ips: String,
    pub shield_url: String,
    pub signed_url_enabled: bool,
    pub signed_url_mode: String,
    pub signed_url_paths: String,
    pub signed_url_secret: String,
    pub signed_url_previous_secret: String,
    pub signed_url_ttl_secs: u32,
    pub origin_auth_header: String,
    pub origin_auth_value: String,
    pub hotlink_signature_enabled: bool,
    /// Whether a signed-URL secret is stored. The secret itself is masked, so
    /// the UI needs this flag to render "已配置 / 未配置" instead of the value.
    pub signed_url_secret_set: bool,
    /// Whether the previous-key slot holds a value.
    ///
    /// The edge accepts both the current and the previous key, so the console
    /// needs this to tell the operator whether links signed with the old key
    /// still work after a rotation.
    pub signed_url_previous_secret_set: bool,
    /// Whether an origin authorization value is stored (value is masked).
    pub origin_auth_value_set: bool,
}

fn settings_dto(s: repository::DomainSettingsRow) -> SettingsDto {
    SettingsDto {
        ignore_query_string: s.ignore_query_string,
        cache_key_ignore_headers: s.cache_key_ignore_headers,
        cors_origins: s.cors_origins,
        hotlink_allow_referers: s.hotlink_allow_referers,
        origin_timeout_ms: s.origin_timeout_ms.max(0) as u32,
        custom_headers: s.custom_headers,
        rate_limit_rps: s.rate_limit_rps.max(0) as u32,
        rate_limit_burst: s.rate_limit_burst.max(0) as u32,
        cc_enabled: s.cc_enabled,
        cc_rps: s.cc_rps.max(0) as u32,
        cc_burst: s.cc_burst.max(0) as u32,
        cc_ban_after: s.cc_ban_after.max(0) as u32,
        cc_ban_seconds: s.cc_ban_seconds.max(0) as u32,
        cc_mode: if s.cc_mode.is_empty() {
            "block".into()
        } else {
            s.cc_mode
        },
        cc_allow_ips: s.cc_allow_ips,
        shield_url: s.shield_url,
        signed_url_enabled: s.signed_url_enabled,
        signed_url_mode: if s.signed_url_mode.is_empty() {
            if s.signed_url_enabled {
                "all".into()
            } else {
                "off".into()
            }
        } else {
            s.signed_url_mode
        },
        signed_url_paths: s.signed_url_paths,
        // Secrets are write-only over the API. Echoing them meant any project
        // member with `domain:read` (a read-only observer) could lift the origin
        // auth credentials and forge signed URLs, defeating both controls.
        signed_url_secret: mask_secret(&s.signed_url_secret),
        signed_url_previous_secret: mask_secret(&s.signed_url_previous_secret),
        signed_url_ttl_secs: s.signed_url_ttl_secs.max(0) as u32,
        origin_auth_header: s.origin_auth_header,
        origin_auth_value: mask_secret(&s.origin_auth_value),
        hotlink_signature_enabled: s.hotlink_signature_enabled,
        signed_url_secret_set: !s.signed_url_secret.is_empty(),
        signed_url_previous_secret_set: !s.signed_url_previous_secret.is_empty(),
        origin_auth_value_set: !s.origin_auth_value.is_empty(),
    }
}

/// Placeholder returned in place of a stored secret.
pub const SECRET_MASK: &str = "********";

/// Mask a stored secret for API responses.
///
/// Callers cannot round-trip this value: writing it back is treated as
/// "keep the stored secret" (see [`is_secret_mask`]), so a client that reads a
/// settings document and PUTs it back unchanged never overwrites the secret with
/// the mask itself.
fn mask_secret(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        SECRET_MASK.to_string()
    }
}

/// True when a submitted value means "leave the stored secret alone".
pub fn is_secret_mask(value: &str) -> bool {
    let value = value.trim();
    value == SECRET_MASK || value.eq_ignore_ascii_case(SECRET_MASK)
}

/// Resolve a secret submitted by a client, ignoring the mask placeholder.
fn submitted_secret(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .filter(|v| !is_secret_mask(v))
        .map(str::to_string)
}

/// Validate the comma-separated hotlink referer whitelist.
///
/// The edge now matches these entries against the parsed `Referer` host with
/// label boundaries, so an entry must be a bare host (`example.com`), a
/// subdomain wildcard (`*.example.com`) or `*`. Rejecting anything else at write
/// time stops operators from pasting a full URL, which would silently never
/// match and lock legitimate referers out.
pub fn validate_hotlink_referers(raw: &str) -> Result<String, String> {
    let mut out = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if entry == "*" {
            out.push("*".to_string());
            continue;
        }
        if entry.len() > 253 {
            return Err("hotlink referer entry is too long".into());
        }
        if entry.contains("://") {
            return Err(format!(
                "hotlink referer {entry:?} must be a bare host such as example.com, not a URL"
            ));
        }
        if entry.contains('/') || entry.contains(' ') {
            return Err(format!(
                "hotlink referer {entry:?} must contain only a host name"
            ));
        }
        let host = entry.strip_prefix("*.").unwrap_or(entry);
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let valid = !host.is_empty()
            && host.contains('.')
            && host.split('.').all(|label| {
                let bytes = label.as_bytes();
                !label.is_empty()
                    && label.len() <= 63
                    && bytes[0] != b'-'
                    && bytes[bytes.len() - 1] != b'-'
                    && bytes
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
            });
        if !valid {
            return Err(format!(
                "hotlink referer {entry:?} is not a valid host name"
            ));
        }
        out.push(if entry.starts_with("*.") {
            format!("*.{host}")
        } else {
            host
        });
    }
    Ok(out.join(","))
}

/// Which sensitive settings a `PUT /settings` request actually changed.
///
/// The audit entry used to read `"updated"` for every settings write, so a
/// review could not tell a cosmetic cache-header tweak from an origin
/// credential rotation. Only **field names** are recorded here: the values are
/// secrets, and an audit log is retained and broadly readable.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SensitiveChanges {
    /// `origin_auth_value` was replaced (value never logged).
    pub origin_auth_value: bool,
    /// `origin_auth_header` was changed.
    pub origin_auth_header: bool,
    /// A new `signed_url_secret` was supplied.
    pub signed_url_secret: bool,
    /// The previous-key slot was written (used for rotation compatibility).
    pub signed_url_previous_secret: bool,
    /// A secret was generated automatically (hotlink signing enabled).
    pub signed_url_secret_generated: bool,
}

impl SensitiveChanges {
    pub fn is_empty(&self) -> bool {
        !(self.origin_auth_value
            || self.origin_auth_header
            || self.signed_url_secret
            || self.signed_url_previous_secret
            || self.signed_url_secret_generated)
    }

    /// Comma-separated field names for the audit `detail` column.
    pub fn to_detail(&self) -> String {
        let mut changed = Vec::new();
        if self.origin_auth_value {
            changed.push("origin_auth_value");
        }
        if self.origin_auth_header {
            changed.push("origin_auth_header");
        }
        if self.signed_url_secret {
            changed.push("signed_url_secret");
        }
        if self.signed_url_previous_secret {
            changed.push("signed_url_previous_secret");
        }
        if self.signed_url_secret_generated {
            changed.push("signed_url_secret(generated)");
        }
        changed.join(",")
    }

    /// Audit detail for a settings update.
    ///
    /// Always names the event, and appends the changed secret fields when there
    /// are any, so the absence of names means "no credential changed".
    pub fn audit_detail(&self) -> String {
        if self.is_empty() {
            "updated".to_string()
        } else {
            format!("updated; sensitive: {}", self.to_detail())
        }
    }
}

/// Canonical domain name, validated.
///
/// The edge lowercases the `Host` header and strips a trailing root dot before
/// looking a domain up, and the registry is keyed on that normalized form. If
/// the control plane stored `CD.Example.COM.` as-is, two tenants could register
/// spellings that collapse to the same edge key and the last write would win.
///
/// Returns the normalized name, or a message suitable for a 400 response.
pub fn normalize_domain_name(raw: &str) -> Result<String, String> {
    let name = raw.trim().to_ascii_lowercase();
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        return Err("domain name is required".into());
    }
    if name.len() > 253 {
        return Err("domain name is too long (max 253 characters)".into());
    }
    if name.parse::<std::net::IpAddr>().is_ok() {
        return Err("use an origin IP instead of registering an IP as a domain name".into());
    }
    if name.contains('*') {
        return Err("wildcard domains are not supported; register each hostname".into());
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err("domain name contains an empty label".into());
        }
        if label.len() > 63 {
            return Err("a domain label exceeds 63 characters".into());
        }
        let bytes = label.as_bytes();
        if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
            return Err("each domain label must start and end with a letter or digit".into());
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return Err("domain name may only contain letters, digits, hyphens and dots".into());
        }
    }
    if !name.contains('.') {
        return Err("domain name must contain at least one dot".into());
    }
    Ok(name.to_string())
}

fn normalize_signed_path(path: &str) -> Result<String, ()> {
    if !path.starts_with('/') {
        return Err(());
    }
    let lower = path.to_ascii_lowercase();
    if path.contains('\\')
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%25")
        || path.chars().any(|c| c.is_control())
    {
        return Err(());
    }
    let mut out = String::new();
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            return Err(());
        }
        out.push('/');
        out.push_str(segment);
    }
    if out.is_empty() {
        out.push('/');
    }
    if path.ends_with('/') && out != "/" {
        out.push('/');
    }
    Ok(out)
}

fn signed_path_protected(mode: &str, patterns: &str, path: &str) -> bool {
    match mode {
        "all" => true,
        "paths" => patterns
            .lines()
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .any(|p| {
                if let Some(prefix) = p.strip_suffix('*') {
                    path.starts_with(prefix)
                } else {
                    path == p
                }
            }),
        _ => false,
    }
}

fn validate_signed_paths(value: &str) -> Result<String, (StatusCode, Json<ErrorBody>)> {
    let mut out = Vec::new();
    for line in value.lines().flat_map(|line| line.split(',')) {
        let pattern = line.trim();
        if pattern.is_empty() {
            continue;
        }
        let invalid = !pattern.starts_with('/')
            || pattern.contains("..")
            || pattern.contains('\\')
            || pattern.to_ascii_lowercase().contains("%2e")
            || pattern.to_ascii_lowercase().contains("%2f")
            || pattern.matches('*').count() > 1
            || (pattern.contains('*') && !pattern.ends_with("/*"));
        if invalid {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "signed_url_paths must be exact paths or prefix/* patterns".into(),
                }),
            ));
        }
        out.push(pattern.to_string());
    }
    Ok(out.join("\n"))
}

fn generate_secret() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; 32];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        return uuid::Uuid::new_v4().simple().to_string();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Deserialize)]
pub struct SignedUrlRequest {
    pub path: Option<String>,
    pub expires_in: Option<u64>,
}

#[derive(Serialize)]
pub struct SignedUrlResponse {
    pub path_and_query: String,
    pub expires: i64,
}

#[derive(Serialize)]
pub struct SignedUrlRotateResponse {
    pub signed_url_secret: String,
    pub signed_url_previous_secret: String,
}

fn signed_canonical(method: &str, host: &str, path: &str, query: &str, expires: &str) -> String {
    let mut pairs: Vec<String> = query
        .split('&')
        .filter(|part| {
            let key = part.split('=').next().unwrap_or("");
            !part.is_empty()
                && !key.eq_ignore_ascii_case("expires")
                && !key.eq_ignore_ascii_case("signature")
                && !key.eq_ignore_ascii_case("sig")
        })
        .map(str::to_string)
        .collect();
    pairs.sort();
    format!(
        "{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        host.to_ascii_lowercase(),
        path,
        pairs.join("&"),
        expires
    )
}

fn sign_path(
    secret: &str,
    method: &str,
    host: &str,
    path_and_query: &str,
    expires: i64,
) -> Result<String, String> {
    let (path, query) = match path_and_query.split_once('?') {
        Some((path, query)) => (path, query),
        None => (path_and_query, ""),
    };
    let expires = expires.to_string();
    let canonical = signed_canonical(method, host, path, query, &expires);
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let tag = ring::hmac::sign(&key, canonical.as_bytes());
    let signature: String = tag.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    let sep = if query.is_empty() { "?" } else { "&" };
    Ok(format!(
        "{path_and_query}{sep}expires={expires}&sig={signature}"
    ))
}

/// POST /api/v1/domains/{id}/signed-url
pub async fn create_signed_url(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<SignedUrlRequest>,
) -> Result<Json<SignedUrlResponse>, (StatusCode, Json<ErrorBody>)> {
    let domain = resolve_domain(&state, &id).await?;
    if !actor.can_write_domain(&state, domain.id).await {
        return Err(forbidden());
    }
    let settings = repository::get_domain_settings(&state.pool, &domain.name)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found(&id))?;
    if !settings.signed_url_enabled || settings.signed_url_secret.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "signed url is not enabled for this domain".into(),
            }),
        ));
    }
    let ttl = if settings.signed_url_ttl_secs <= 0 {
        3600
    } else {
        settings.signed_url_ttl_secs as u64
    };
    let now = chrono::Utc::now().timestamp();
    let expires = now + req.expires_in.unwrap_or(ttl).clamp(1, ttl) as i64;
    let raw_path = req.path.as_deref().unwrap_or("/").trim();
    let raw_path = if raw_path.starts_with('/') {
        raw_path.to_string()
    } else {
        format!("/{raw_path}")
    };
    let path = normalize_signed_path(&raw_path).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "invalid signed url path".into(),
            }),
        )
    })?;
    let mode = if settings.signed_url_mode.is_empty() {
        if settings.signed_url_enabled {
            "all"
        } else {
            "off"
        }
    } else {
        settings.signed_url_mode.as_str()
    };
    let hotlink_only = settings.hotlink_signature_enabled;
    if !hotlink_only
        && (mode == "off" || !signed_path_protected(mode, &settings.signed_url_paths, &path))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "path is not protected by signed url policy".into(),
            }),
        ));
    }
    let signed = sign_path(
        &settings.signed_url_secret,
        "GET",
        &domain.name,
        &path,
        expires,
    )
    .map_err(|_| db_error())?;
    Ok(Json(SignedUrlResponse {
        path_and_query: signed,
        expires,
    }))
}

/// POST /api/v1/domains/{id}/signed-url/rotate
/// Decide which key (if any) should land in the previous-key slot after a
/// rotation.
///
/// Only a key that was actually stored can be a compatibility key. Generating a
/// throwaway value for the empty case would record a key no client ever signed
/// with, and the console would then claim old links still work.
pub fn previous_key_after_rotate(stored: &str) -> Option<String> {
    if stored.trim().is_empty() {
        None
    } else {
        Some(stored.to_string())
    }
}

pub async fn rotate_signed_url(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<SignedUrlRotateResponse>, (StatusCode, Json<ErrorBody>)> {
    let domain = resolve_domain(&state, &id).await?;
    if !actor.can_write_domain(&state, domain.id).await {
        return Err(forbidden());
    }
    let settings = repository::get_domain_settings(&state.pool, &domain.name)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found(&id))?;
    let previous = previous_key_after_rotate(&settings.signed_url_secret);
    let next = generate_secret();
    let mode = if settings.signed_url_mode.is_empty() {
        "all".to_string()
    } else {
        settings.signed_url_mode.clone()
    };
    // Rotating must not flip protection on by itself: leave `enabled` untouched
    // so a key can be provisioned ahead of enabling the feature.
    repository::update_domain_signed_url(
        &state.pool,
        domain.id,
        None,
        Some(&mode),
        Some(&settings.signed_url_paths),
        Some(&next),
        previous.as_deref(),
        Some(settings.signed_url_ttl_secs),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "rotate signed url secret");
        db_error()
    })?;
    // Only the new key is returned. Handing back the previous one extended the
    // window in which a leaked key stayed usable: edges keep accepting it until
    // the next rotation.
    Ok(Json(SignedUrlRotateResponse {
        signed_url_secret: next,
        signed_url_previous_secret: SECRET_MASK.to_string(),
    }))
}

async fn resolve_domain(
    state: &AppState,
    id: &str,
) -> Result<repository::DomainRow, (StatusCode, Json<ErrorBody>)> {
    let row = if let Ok(uid) = Uuid::parse_str(id) {
        repository::get_domain(&state.pool, uid).await
    } else {
        repository::get_domain_by_name(&state.pool, id).await
    };
    row.map_err(|_| db_error())?.ok_or_else(|| not_found(id))
}

/// GET /api/v1/domains/{id}/settings — id can be uuid or domain name
pub async fn get_settings(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<SettingsDto>, (StatusCode, Json<ErrorBody>)> {
    let domain = resolve_domain(&state, &id).await?;
    if !actor.can_read_domain(&state, domain.id).await {
        return Err(forbidden());
    }
    let s = repository::get_domain_settings(&state.pool, &domain.name)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found(&id))?;
    Ok(Json(settings_dto(s)))
}

/// PUT /api/v1/domains/{id}/settings
pub async fn put_settings(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<SettingsRequest>,
) -> Result<Json<SettingsDto>, (StatusCode, Json<ErrorBody>)> {
    let domain = resolve_domain(&state, &id).await?;
    let uid = domain.id;
    let domain_name = domain.name.clone();
    if !actor.can_write_domain(&state, uid).await {
        return Err(forbidden());
    }
    // Snapshot of the current row, used both to compare a few non-secret fields
    // and to know whether a secret already exists.
    let stored_settings = repository::get_domain_settings(&state.pool, &domain_name)
        .await
        .ok()
        .flatten();

    // Tracks credential changes so the audit entry can name them. Values are
    // never recorded: only which field changed.
    //
    // Secrets: any submitted value that is not the mask replaces the secret, so
    // its presence in the request is the signal.
    let mut sensitive = SensitiveChanges::default();
    if submitted_secret(req.origin_auth_value.as_deref()).is_some() {
        sensitive.origin_auth_value = true;
    }
    if submitted_secret(req.signed_url_secret.as_deref()).is_some() {
        sensitive.signed_url_secret = true;
    }
    if submitted_secret(req.signed_url_previous_secret.as_deref()).is_some() {
        sensitive.signed_url_previous_secret = true;
    }
    // The header *name* is not a secret, so compare against the stored value
    // instead of just checking for non-empty: clearing it, renaming it and
    // re-sending the current one are three different events.
    if let (Some(header), Some(current)) =
        (req.origin_auth_header.as_deref(), stored_settings.as_ref())
    {
        if header.trim() != current.origin_auth_header.trim() {
            sensitive.origin_auth_header = true;
        }
    }

    let cc_mode = match req
        .cc_mode
        .as_deref()
        .map(|m| m.trim().to_ascii_lowercase())
    {
        Some(mode) if mode == "block" || mode == "monitor" => Some(mode),
        Some(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "cc_mode must be block or monitor".into(),
                }),
            ))
        }
        None => None,
    };
    let shield_url = req
        .shield_url
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    if let Some(url) = shield_url {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "shield_url must start with http:// or https://".into(),
                }),
            ));
        }
    }
    let cache_key_ignore_headers = match req.cache_key_ignore_headers.as_deref() {
        Some(value) => match normalize_cache_key_ignore_headers(value) {
            Ok(value) => Some(value),
            Err(error) => {
                return Err((StatusCode::BAD_REQUEST, Json(ErrorBody { error })));
            }
        },
        None => None,
    };
    let hotlink_referers = match req.hotlink_allow_referers.as_deref() {
        Some(value) => Some(
            validate_hotlink_referers(value)
                .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?,
        ),
        None => None,
    };
    let n = repository::update_domain_settings(
        &state.pool,
        uid,
        req.ignore_query_string,
        req.cors_origins.as_deref(),
        hotlink_referers.as_deref(),
        // 0 = inherit the edge-wide default; clamp to the same upper bound the
        // edge accepts for the global setting.
        req.origin_timeout_ms.map(|v| v.min(60_000) as i32),
        req.custom_headers.as_deref(),
        req.rate_limit_rps.map(|v| v as i32),
        req.rate_limit_burst.map(|v| v as i32),
        req.cc_enabled,
        req.cc_rps.map(|v| v.min(1_000_000) as i32),
        req.cc_burst.map(|v| v.min(1_000_000) as i32),
        req.cc_ban_after.map(|v| v.min(10_000) as i32),
        req.cc_ban_seconds.map(|v| v.clamp(1, 86_400) as i32),
        cc_mode.as_deref(),
        req.cc_allow_ips.as_deref(),
        shield_url,
        cache_key_ignore_headers.as_deref(),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "update domain settings");
        db_error()
    })?;
    let signed_requested = req.signed_url_enabled.is_some()
        || req.signed_url_mode.is_some()
        || req.signed_url_paths.is_some()
        || req.signed_url_secret.is_some()
        || req.signed_url_previous_secret.is_some()
        || req.signed_url_ttl_secs.is_some();
    let requested_mode = match req
        .signed_url_mode
        .as_deref()
        .map(|m| m.trim().to_ascii_lowercase())
    {
        Some(mode) if mode == "off" || mode == "all" || mode == "paths" => Some(mode),
        Some(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "signed_url_mode must be off, all or paths".into(),
                }),
            ))
        }
        None => req
            .signed_url_enabled
            .map(|enabled| if enabled { "all" } else { "off" }.to_string())
            .or_else(|| {
                req.signed_url_paths.as_ref().map(|paths| {
                    if paths.trim().is_empty() {
                        "off"
                    } else {
                        "paths"
                    }
                    .to_string()
                })
            }),
    };
    let enabled_arg = requested_mode
        .as_ref()
        .map(|mode| mode != "off")
        .or(req.signed_url_enabled);
    let requested_paths = match req.signed_url_paths.as_deref() {
        Some(value) => Some(validate_signed_paths(value)?),
        None => None,
    };
    if requested_mode.as_deref() == Some("paths")
        && requested_paths
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "signed_url_paths is required when mode is paths".into(),
            }),
        ));
    }
    if signed_requested {
        // `submitted_secret` drops the mask placeholder, so re-submitting an
        // unchanged settings document keeps the stored secret instead of
        // replacing it with "********".
        let mut secret = submitted_secret(req.signed_url_secret.as_deref());
        let wanted_on = enabled_arg.unwrap_or(false);
        if wanted_on && secret.is_none() {
            if stored_settings
                .as_ref()
                .map(|s| s.signed_url_secret.is_empty())
                .unwrap_or(true)
            {
                // Enabling signed URLs without supplying a key creates one.
                sensitive.signed_url_secret_generated = true;
                secret = Some(generate_secret());
            }
        }
        repository::update_domain_signed_url(
            &state.pool,
            uid,
            enabled_arg,
            requested_mode.as_deref(),
            requested_paths.as_deref(),
            secret.as_deref(),
            submitted_secret(req.signed_url_previous_secret.as_deref()).as_deref(),
            req.signed_url_ttl_secs.map(|v| v as i32),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "update signed url settings");
            db_error()
        })?;
    }

    let security_requested = req.origin_auth_header.is_some()
        || req.origin_auth_value.is_some()
        || req.hotlink_signature_enabled.is_some();
    if security_requested {
        if req.hotlink_signature_enabled == Some(true) {
            let settings = stored_settings.as_ref().ok_or_else(|| not_found(&id))?;
            if settings.signed_url_secret.is_empty() {
                // Enabling hotlink signing creates a signing key implicitly.
                sensitive.signed_url_secret_generated = true;
                let secret = generate_secret();
                repository::update_domain_signed_url(
                    &state.pool,
                    uid,
                    None,
                    None,
                    None,
                    Some(&secret),
                    None,
                    Some(settings.signed_url_ttl_secs),
                )
                .await
                .map_err(|_| db_error())?;
            }
        }
        repository::update_domain_security(
            &state.pool,
            uid,
            req.origin_auth_header.as_deref().map(str::trim),
            submitted_secret(req.origin_auth_value.as_deref()).as_deref(),
            req.hotlink_signature_enabled,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "update domain security");
            db_error()
        })?;
    }

    if n == 0 {
        return Err(not_found(&id));
    }
    let row = repository::get_domain(&state.pool, uid)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| not_found(&id))?;
    let s = repository::get_domain_settings(&state.pool, &row.name)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found(&id))?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "domain.settings",
        &row.name,
        &sensitive.audit_detail(),
    )
    .await;
    let _ = crate::service::config_version::record_domain(
        &state.pool,
        row.id,
        &row.name,
        &actor.email,
        "domain.settings",
        "更新高级设置",
    )
    .await;
    crate::service::edge_notify::notify_config_reload(&state).await;
    Ok(Json(settings_dto(s)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The edge resolves a domain by the lowercased, root-dot-stripped `Host`.
    /// Anything that normalizes to an existing name must be rejected rather
    /// than stored as a second row that overwrites the first on the edge.
    /// Entries must be bare hosts, otherwise the edge can never match them and
    /// legitimate referers are silently blocked.
    #[test]
    fn hotlink_referers_are_validated() {
        assert_eq!(
            validate_hotlink_referers("Example.COM, *.Foo.com").unwrap(),
            "example.com,*.foo.com"
        );
        assert_eq!(validate_hotlink_referers("*").unwrap(), "*");
        assert_eq!(validate_hotlink_referers("  ").unwrap(), "");

        for bad in [
            "https://example.com",
            "example.com/path",
            "notextension",
            "-bad.com",
            "bad-.com",
            "a..b.com",
        ] {
            assert!(
                validate_hotlink_referers(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    /// A full URL pasted by an operator used to be stored verbatim and never
    /// matched, quietly locking out the very referers it was meant to allow.
    #[test]
    fn hotlink_referer_url_is_rejected_with_a_hint() {
        let err = validate_hotlink_referers("https://example.com/page").unwrap_err();
        assert!(err.contains("bare host"), "unexpected message: {err}");
    }

    /// Generating a key for a domain that never had one must not invent a
    /// "previous" key: no client ever signed with it, and the console would
    /// wrongly report that old links still work.
    #[test]
    fn rotate_does_not_invent_a_previous_key() {
        assert_eq!(super::previous_key_after_rotate(""), None);
        assert_eq!(super::previous_key_after_rotate("   "), None);
        assert_eq!(
            super::previous_key_after_rotate("existing-key").as_deref(),
            Some("existing-key")
        );
    }

    /// The audit entry must name which credentials changed. It used to read
    /// only "updated", so a review could not distinguish an origin credential
    /// rotation from a cosmetic change.
    #[test]
    fn audit_detail_names_changed_secrets() {
        let mut changes = SensitiveChanges::default();
        assert_eq!(changes.audit_detail(), "updated");

        changes.origin_auth_value = true;
        assert_eq!(
            changes.audit_detail(),
            "updated; sensitive: origin_auth_value"
        );

        changes.signed_url_secret = true;
        assert_eq!(
            changes.audit_detail(),
            "updated; sensitive: origin_auth_value,signed_url_secret"
        );

        changes.signed_url_secret_generated = true;
        assert!(changes
            .audit_detail()
            .contains("signed_url_secret(generated)"));
    }

    /// The audit log is retained and broadly readable, so it must never contain
    /// the secret value itself — only its field name.
    #[test]
    fn audit_detail_never_contains_secret_values() {
        let value = "super-secret-origin-token";
        let mut changes = SensitiveChanges::default();
        changes.origin_auth_value = true;
        changes.signed_url_secret = true;
        let detail = changes.audit_detail();
        assert!(!detail.contains(value));
        assert!(!detail.contains(SECRET_MASK));
        assert!(detail.contains("origin_auth_value"));
    }

    /// A request that only touches non-secret settings must not claim a
    /// credential change.
    #[test]
    fn unrelated_settings_update_reports_no_sensitive_change() {
        let changes = SensitiveChanges::default();
        assert!(changes.is_empty());
        assert_eq!(changes.audit_detail(), "updated");
    }

    /// A project member with only `domain:read` must not be able to lift the
    /// origin auth credentials or the signed-URL key from the settings API.
    #[test]
    fn secrets_are_masked_in_responses() {
        assert_eq!(mask_secret("real-secret"), SECRET_MASK);
        assert_eq!(mask_secret(""), "");
        // The mask must be recognizable as "unchanged" by the write path.
        assert!(is_secret_mask(SECRET_MASK));
        assert!(is_secret_mask("  ********  "));
        assert!(!is_secret_mask("real-secret"));
        assert!(!is_secret_mask(""));
    }

    /// Round-tripping a settings document must not overwrite the stored secret
    /// with the mask. This is the failure mode that masking would otherwise
    /// introduce.
    #[test]
    fn masked_value_is_treated_as_unchanged() {
        assert_eq!(submitted_secret(Some(SECRET_MASK)), None);
        assert_eq!(submitted_secret(Some("   ")), None);
        assert_eq!(submitted_secret(None), None);
        assert_eq!(
            submitted_secret(Some("  new-secret  ")).as_deref(),
            Some("new-secret")
        );
    }

    #[test]
    fn domain_name_is_canonicalized() {
        assert_eq!(
            normalize_domain_name("CD.Example.COM").unwrap(),
            "cd.example.com"
        );
        assert_eq!(
            normalize_domain_name("cdn.example.com.").unwrap(),
            "cdn.example.com"
        );
        assert_eq!(normalize_domain_name("  a.b.co  ").unwrap(), "a.b.co");
    }

    #[test]
    fn equivalent_spellings_normalize_to_the_same_name() {
        let forms = [
            "cdn.example.com",
            "CDN.Example.Com",
            "cdn.example.com.",
            "  cdn.example.com  ",
        ];
        let mut seen: Vec<String> = forms
            .iter()
            .map(|f| normalize_domain_name(f).unwrap())
            .collect();
        seen.dedup();
        assert_eq!(seen.len(), 1, "all spellings must collapse to one name");
    }

    #[test]
    fn invalid_domain_names_are_rejected() {
        for bad in [
            "",
            "   ",
            "localhost",
            "127.0.0.1",
            "::1",
            "*.example.com",
            "a..b.com",
            "-bad.example.com",
            "bad-.example.com",
            "has space.com",
            "has_underscore.com",
            "exa mple.com",
        ] {
            assert!(
                normalize_domain_name(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    fn origin(host: &str, weight: u32, priority: i32) -> repository::DomainOrigin {
        repository::DomainOrigin {
            host: host.into(),
            port: 0,
            proto: "https".into(),
            weight,
            priority,
            enabled: true,
            sni: None,
            host_header: None,
        }
    }

    #[test]
    fn origin_pool_sorts_by_priority_and_defaults_port() {
        let pool = normalize_origins(vec![origin("b.test", 10, 2), origin("a.test", 100, 0)])
            .expect("valid");
        assert_eq!(pool[0].host, "a.test");
        assert_eq!(pool[0].port, 443);
        assert_eq!(pool[1].priority, 2);
    }

    #[test]
    fn origin_pool_rejects_duplicates_and_disabled_only() {
        assert!(normalize_origins(vec![origin("a.test", 1, 0), origin("a.test", 1, 0)]).is_err());
        let mut disabled = origin("a.test", 1, 0);
        disabled.enabled = false;
        assert!(normalize_origins(vec![disabled]).is_err());
    }

    #[test]
    fn origin_sni_and_host_header_are_normalized() {
        let mut o = origin("45.63.84.225", 100, 0);
        o.sni = Some("Test-Origin.AKGO.net.".into());
        o.host_header = Some("Test-Origin.AKGO.net".into());
        let pool = normalize_origins(vec![o]).expect("valid sni");
        assert_eq!(pool[0].sni.as_deref(), Some("test-origin.akgo.net"));
        assert_eq!(pool[0].host_header.as_deref(), Some("test-origin.akgo.net"));
    }

    #[test]
    fn legacy_row_expands_to_primary_and_backup() {
        let row = repository::DomainRow {
            id: Uuid::nil(),
            project_id: None,
            name: "cdn.test".into(),
            origin_host: "primary.test".into(),
            origin_port: 80,
            origin_proto: "http".into(),
            ssl_enabled: false,
            status: "active".into(),
            created_at: chrono::Utc::now(),
            rate_limit_rps: 0,
            rate_limit_burst: 0,
            origins: sqlx::types::Json(Vec::new()),
            backup_origin_host: "backup.test".into(),
            backup_origin_port: 443,
            backup_origin_proto: "https".into(),
            shield_url: String::new(),
            published_version_id: None,
        };
        let pool = effective_origins(&row);
        assert_eq!(pool.len(), 2);
        assert_eq!(pool[0].host, "primary.test");
        assert_eq!(pool[1].priority, 1);
    }
}
