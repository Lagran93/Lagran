//! Edge node management: pre-registration, install commands, lifecycle and
//! heartbeat ingest.

use crate::middleware::agent_auth::AgentAuth;
use crate::middleware::authz::Actor;
use crate::repository;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize)]
pub struct NodeDto {
    pub id: String,
    pub name: String,
    pub region: String,
    pub ip: String,
    pub status: String,
    pub last_heartbeat: Option<String>,
    pub agent_url: String,
    pub version: String,
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<f64>,
    pub active_connections: Option<i64>,
    pub created_at: String,
    pub has_token: bool,
}

fn to_dto(r: repository::NodeRow) -> NodeDto {
    NodeDto {
        id: r.id.to_string(),
        name: r.name,
        region: r.region,
        ip: r.ip,
        status: r.status,
        last_heartbeat: r.last_heartbeat.map(|t| t.to_rfc3339()),
        agent_url: r.agent_url,
        version: r.version,
        cpu_usage: r.cpu_usage,
        memory_usage: r.memory_usage,
        active_connections: r.active_connections,
        created_at: r.created_at.to_rfc3339(),
        has_token: !r.auth_token.is_empty(),
    }
}

#[derive(Serialize)]
pub struct InstallCommands {
    pub binary: String,
    pub docker: String,
}

#[derive(Serialize)]
pub struct CreateNodeResponse {
    pub node: NodeDto,
    /// Only returned once at creation; keep it secret.
    pub token: String,
    pub commands: InstallCommands,
}

#[derive(Serialize)]
pub struct NodeDetailResponse {
    pub node: NodeDto,
    pub token: String,
    pub commands: InstallCommands,
}

#[derive(Deserialize)]
pub struct CreateNodeRequest {
    pub name: String,
    pub region: Option<String>,
    pub ip: Option<String>,
    pub agent_url: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateNodeRequest {
    pub name: Option<String>,
    pub region: Option<String>,
    pub agent_url: Option<String>,
}

#[derive(Deserialize)]
pub struct StatusRequest {
    pub enabled: bool,
}

#[derive(Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: Option<String>,
    pub region: Option<String>,
    pub ip: Option<String>,
    pub agent_url: Option<String>,
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<f64>,
    pub active_connections: Option<u64>,
    pub version: Option<String>,
}

#[derive(Serialize)]
pub struct HeartbeatResponse {
    pub accepted: bool,
    pub message: String,
    /// False when an admin disabled the node; the edge stops serving traffic.
    pub enabled: bool,
    pub status: String,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

fn admin(actor: &Actor) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if actor.admin() {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: "admin only".into(),
            }),
        ))
    }
}

fn parse_uuid(id: &str) -> Result<Uuid, (StatusCode, Json<ErrorBody>)> {
    Uuid::parse_str(id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "invalid node id".into(),
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

fn new_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// Public control-plane URL used inside install commands.
fn public_base(state: &AppState, headers: &HeaderMap) -> String {
    if !state.config.public_url.is_empty() {
        return state.config.public_url.trim_end_matches('/').to_string();
    }
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1:8080");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    format!("{}://{}", proto, host)
}

fn install_commands(
    base: &str,
    name: &str,
    region: &str,
    agent_url: &str,
    token: &str,
) -> InstallCommands {
    let agent_url = if agent_url.trim().is_empty() {
        "http://<节点公网IP>:8081".to_string()
    } else {
        agent_url.trim_end_matches('/').to_string()
    };
    let region = if region.is_empty() { "default" } else { region };

    let binary = format!(
        r#"# 在边缘服务器上执行（当前目录包含 lagran-edge 二进制）
export CONTROL_URL={base}
export NODE_ID={name}
export NODE_REGION={region}
export AGENT_URL={agent_url}
export AGENT_TOKEN={token}
export EDGE_LISTEN=0.0.0.0:8081
export CACHE_BACKEND=memory

./lagran-edge"#
    );

    let docker = format!(
        r#"docker run -d --name lagran-edge-{name} --restart=always \
  -p 8081:8081 \
  -e CONTROL_URL={base} \
  -e NODE_ID={name} \
  -e NODE_REGION={region} \
  -e AGENT_URL={agent_url} \
  -e AGENT_TOKEN={token} \
  -e EDGE_LISTEN=0.0.0.0:8081 \
  -e CACHE_BACKEND=memory \
  -v /var/lib/lagran/cache:/data/cache \
  -e DISK_CACHE_DIR=/data/cache \
  lagran-edge:latest"#
    );

    InstallCommands { binary, docker }
}

/// Node inventory (including agent URLs) is infrastructure data: admin only.
pub async fn list(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<NodeDto>>, (StatusCode, Json<ErrorBody>)> {
    admin(&actor)?;
    let rows = repository::list_nodes(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "list nodes");
        db_error()
    })?;
    Ok(Json(rows.into_iter().map(to_dto).collect()))
}

pub async fn create(
    State(state): State<AppState>,
    actor: Actor,
    headers: HeaderMap,
    Json(req): Json<CreateNodeRequest>,
) -> Result<(StatusCode, Json<CreateNodeResponse>), (StatusCode, Json<ErrorBody>)> {
    admin(&actor)?;
    let name = req.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "name must be 1-64 characters".into(),
            }),
        ));
    }
    if repository::get_node_by_name(&state.pool, name)
        .await
        .map_err(|_| db_error())?
        .is_some()
    {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "node name already exists".into(),
            }),
        ));
    }

    let token = new_token();
    let region = req.region.clone().unwrap_or_default();
    let base = public_base(&state, &headers);
    let agent_url = req.agent_url.clone().unwrap_or_default();

    let row = repository::create_node(
        &state.pool,
        name,
        &region,
        req.ip.as_deref().unwrap_or(""),
        &agent_url,
        &token,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "create node");
        db_error()
    })?;

    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "node.create",
        name,
        &format!("region={region} agent_url={agent_url}"),
    )
    .await;

    let commands = install_commands(&base, name, &region, &agent_url, &token);
    Ok((
        StatusCode::CREATED,
        Json(CreateNodeResponse {
            node: to_dto(row),
            token,
            commands,
        }),
    ))
}

pub async fn detail(
    State(state): State<AppState>,
    actor: Actor,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<NodeDetailResponse>, (StatusCode, Json<ErrorBody>)> {
    admin(&actor)?;
    let node_id = parse_uuid(&id)?;
    let row = repository::get_node(&state.pool, node_id)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorBody {
                    error: "node not found".into(),
                }),
            )
        })?;
    let base = public_base(&state, &headers);
    let commands = install_commands(
        &base,
        &row.name,
        &row.region,
        &row.agent_url,
        &row.auth_token,
    );
    Ok(Json(NodeDetailResponse {
        token: row.auth_token.clone(),
        commands,
        node: to_dto(row),
    }))
}

pub async fn update(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<UpdateNodeRequest>,
) -> Result<Json<NodeDto>, (StatusCode, Json<ErrorBody>)> {
    admin(&actor)?;
    let node_id = parse_uuid(&id)?;
    let current = repository::get_node(&state.pool, node_id)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorBody {
                    error: "node not found".into(),
                }),
            )
        })?;

    let name = req
        .name
        .as_deref()
        .unwrap_or(&current.name)
        .trim()
        .to_string();
    if name.is_empty() || name.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "name must be 1-64 characters".into(),
            }),
        ));
    }
    if name != current.name {
        if let Some(other) = repository::get_node_by_name(&state.pool, &name)
            .await
            .map_err(|_| db_error())?
        {
            if other.id != node_id {
                return Err((
                    StatusCode::CONFLICT,
                    Json(ErrorBody {
                        error: "node name already exists".into(),
                    }),
                ));
            }
        }
    }
    let region = req.region.unwrap_or(current.region);
    let agent_url = req.agent_url.unwrap_or(current.agent_url);

    let row = repository::update_node(&state.pool, node_id, &name, &region, &agent_url)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "update node");
            db_error()
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorBody {
                    error: "node not found".into(),
                }),
            )
        })?;

    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "node.update",
        &row.name,
        &format!("region={} agent_url={}", row.region, row.agent_url),
    )
    .await;
    Ok(Json(to_dto(row)))
}

pub async fn set_status(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<StatusRequest>,
) -> Result<Json<NodeDto>, (StatusCode, Json<ErrorBody>)> {
    admin(&actor)?;
    let node_id = parse_uuid(&id)?;
    let status = if req.enabled { "offline" } else { "disabled" };
    let row = repository::set_node_status(&state.pool, node_id, status)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorBody {
                    error: "node not found".into(),
                }),
            )
        })?;

    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        if req.enabled {
            "node.enable"
        } else {
            "node.disable"
        },
        &row.name,
        "",
    )
    .await;
    Ok(Json(to_dto(row)))
}

pub async fn delete(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    admin(&actor)?;
    let node_id = parse_uuid(&id)?;
    let row = repository::get_node(&state.pool, node_id)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorBody {
                    error: "node not found".into(),
                }),
            )
        })?;
    repository::delete_node(&state.pool, node_id)
        .await
        .map_err(|_| db_error())?;
    let _ = repository::insert_audit(&state.pool, &actor.email, "node.delete", &row.name, "").await;
    Ok(Json(serde_json::json!({ "success": true, "id": id })))
}

pub async fn heartbeat(
    State(state): State<AppState>,
    _agent: AgentAuth,
    Json(req): Json<HeartbeatRequest>,
) -> Json<HeartbeatResponse> {
    let node_id = req
        .node_id
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "edge-unknown".into());
    apply_heartbeat(&state, &node_id, &req).await
}

pub async fn heartbeat_by_path(
    State(state): State<AppState>,
    _agent: AgentAuth,
    Path(id): Path<String>,
    Json(req): Json<HeartbeatRequest>,
) -> Json<HeartbeatResponse> {
    apply_heartbeat(&state, &id, &req).await
}

async fn apply_heartbeat(
    state: &AppState,
    node_id: &str,
    req: &HeartbeatRequest,
) -> Json<HeartbeatResponse> {
    let region = req.region.clone().unwrap_or_default();
    let ip = req.ip.clone().unwrap_or_default();
    let agent_url = req.agent_url.clone().unwrap_or_default();
    let version = req.version.clone().unwrap_or_default();
    let active = req.active_connections.map(|v| v as i64);

    match repository::upsert_node_heartbeat(
        &state.pool,
        node_id,
        &region,
        &ip,
        &agent_url,
        req.cpu_usage,
        req.memory_usage,
        active,
        &version,
    )
    .await
    {
        Ok(row) => {
            let enabled = row.status != "disabled";
            tracing::info!(
                node = %node_id,
                status = %row.status,
                %version,
                "heartbeat ok"
            );
            Json(HeartbeatResponse {
                accepted: true,
                message: "ok".into(),
                enabled,
                status: row.status,
            })
        }
        Err(e) => {
            tracing::error!(error = %e, node = %node_id, "heartbeat");
            Json(HeartbeatResponse {
                accepted: false,
                message: e.to_string(),
                enabled: true,
                status: "unknown".into(),
            })
        }
    }
}
