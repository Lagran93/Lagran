//! Domain onboarding diagnostics: DNS, TLS certificate, origin reachability,
//! and an actual edge cache probe.

use crate::middleware::authz::Actor;
use crate::repository;
use crate::service::agent_http;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use uuid::Uuid;

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

#[derive(Serialize)]
pub struct Check {
    pub key: String,
    pub label: String,
    pub ok: bool,
    pub detail: String,
    pub latency_ms: u64,
}

#[derive(Serialize)]
pub struct DiagnoseResponse {
    pub domain: String,
    pub overall: bool,
    pub resolved_ips: Vec<String>,
    pub edge_ips: Vec<String>,
    pub checks: Vec<Check>,
}

fn bad(msg: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody { error: msg.into() }),
    )
}

fn db() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: "database error".into(),
        }),
    )
}

pub async fn diagnose(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<DiagnoseResponse>, (StatusCode, Json<ErrorBody>)> {
    let row = if let Ok(uid) = Uuid::parse_str(&id) {
        repository::get_domain(&state.pool, uid).await
    } else {
        repository::get_domain_by_name(&state.pool, id.trim()).await
    }
    .map_err(|_| db())?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "domain not found".into(),
            }),
        )
    })?;
    if !actor.can_read_domain(&state, row.id).await {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: "forbidden".into(),
            }),
        ));
    }
    if row.name.trim().is_empty() {
        return Err(bad("domain name is empty"));
    }
    let domain = row.name.clone();
    let nodes = repository::list_nodes(&state.pool).await.unwrap_or_default();
    let edge_ips: Vec<String> = nodes
        .iter()
        .filter(|n| n.status == "online")
        .flat_map(|n| [n.public_ip.clone(), n.ip.clone()])
        .filter(|ip| !ip.trim().is_empty())
        .collect();

    let dns_start = Instant::now();
    let lookup_name = domain.clone();
    let resolved = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((lookup_name.as_str(), 443)),
    )
    .await;
    let resolved_ips: Vec<String> = match resolved {
        Ok(Ok(addrs)) => {
            let mut out: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            out.sort();
            out.dedup();
            out
        }
        _ => Vec::new(),
    };
    let dns_ok = !resolved_ips.is_empty();
    let dns_match = edge_ips.is_empty()
        || resolved_ips.iter().any(|ip| edge_ips.iter().any(|edge| edge == ip));
    let dns_detail = if !dns_ok {
        "DNS 未解析出任何地址".to_string()
    } else if edge_ips.is_empty() {
        format!("解析到 {}", resolved_ips.join(", "))
    } else if dns_match {
        format!("解析到边缘节点地址：{}", resolved_ips.join(", "))
    } else {
        format!(
            "解析到 {}，但当前在线节点地址为 {}；如果使用 CNAME，请检查上游解析",
            resolved_ips.join(", "),
            edge_ips.join(", ")
        )
    };

    let tls_start = Instant::now();
    let (tls_ok, tls_detail) = check_tls(&domain).await;
    let origin_start = Instant::now();
    let (origin_ok, origin_detail) = check_origin(&row.origin_host, row.origin_port.max(0) as u16).await;

    let cache_start = Instant::now();
    let (cache_ok, cache_detail) =
        check_cache(&state, &domain, row.ssl_enabled, &nodes).await;

    let checks = vec![
        Check {
            key: "dns".into(),
            label: "DNS 解析".into(),
            ok: dns_ok && dns_match,
            detail: dns_detail,
            latency_ms: dns_start.elapsed().as_millis() as u64,
        },
        Check {
            key: "cert".into(),
            label: "HTTPS 证书".into(),
            ok: tls_ok,
            detail: tls_detail,
            latency_ms: tls_start.elapsed().as_millis() as u64,
        },
        Check {
            key: "origin".into(),
            label: "回源可达".into(),
            ok: origin_ok,
            detail: origin_detail,
            latency_ms: origin_start.elapsed().as_millis() as u64,
        },
        Check {
            key: "cache".into(),
            label: "缓存命中".into(),
            ok: cache_ok,
            detail: cache_detail,
            latency_ms: cache_start.elapsed().as_millis() as u64,
        },
    ];
    let overall = checks[0].ok && checks[1].ok && checks[2].ok;
    Ok(Json(DiagnoseResponse {
        domain,
        overall,
        resolved_ips,
        edge_ips,
        checks,
    }))
}

async fn check_tls(domain: &str) -> (bool, String) {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let Ok(name) = ServerName::try_from(domain.to_string()) else {
        return (false, "域名不能用于 TLS SNI".into());
    };
    let tcp = match tokio::time::timeout(
        Duration::from_secs(6),
        TcpStream::connect((domain, 443)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return (false, format!("无法连接 443：{e}")),
        Err(_) => return (false, "连接 443 超时".into()),
    };
    match tokio::time::timeout(Duration::from_secs(8), connector.connect(name, tcp)).await {
        Ok(Ok(stream)) => {
            let count = stream
                .get_ref()
                .1
                .peer_certificates()
                .map(|c| c.len())
                .unwrap_or(0);
            (true, format!("TLS 握手成功，证书链有效（{count} 张证书）"))
        }
        Ok(Err(e)) => (false, format!("TLS 校验失败：{e}")),
        Err(_) => (false, "TLS 握手超时".into()),
    }
}

async fn check_origin(host: &str, port: u16) -> (bool, String) {
    if host.trim().is_empty() || port == 0 {
        return (false, "源站地址或端口为空".into());
    }
    match tokio::time::timeout(
        Duration::from_secs(6),
        TcpStream::connect((host, port)),
    )
    .await
    {
        Ok(Ok(_)) => (true, format!("TCP 连接 {host}:{port} 成功")),
        Ok(Err(e)) => (false, format!("TCP 连接 {host}:{port} 失败：{e}")),
        Err(_) => (false, format!("TCP 连接 {host}:{port} 超时")),
    }
}

async fn check_cache(
    state: &AppState,
    domain: &str,
    ssl_enabled: bool,
    nodes: &[repository::NodeRow],
) -> (bool, String) {
    let Some(node) = nodes.iter().find(|n| n.status == "online") else {
        return (false, "没有在线边缘节点可执行缓存探测".into());
    };
    let token = if node.auth_token.is_empty() {
        state.config.agent_token.clone()
    } else {
        node.auth_token.clone()
    };
    let endpoint = format!(
        "{}/__lagran/cache-diagnose",
        node.agent_url.trim_end_matches('/')
    );
    let body = json!({
        "domain": domain,
        "path": "/",
        "scheme": if ssl_enabled { "https" } else { "http" },
        "simulate_cookie": false,
        "simulate_authorization": false,
        "request_cache_control": null,
    });
    match agent_http::request_json::<Value, _>("POST", &endpoint, &body, &token).await {
        Ok(value) => {
            let headers = value
                .get("headers")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let get = |name: &str| {
                headers.iter().find_map(|pair| {
                    let arr = pair.as_array()?;
                    let key = arr.first()?.as_str()?;
                    if key.eq_ignore_ascii_case(name) {
                        arr.get(1)?.as_str().map(str::to_string)
                    } else {
                        None
                    }
                })
            };
            let status = value
                .get("status")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let cache = get("x-cache-status")
                .or_else(|| get("x-cache"))
                .unwrap_or_else(|| "UNKNOWN".into());
            let reason = get("x-lagran-cache-reason").unwrap_or_default();
            let ok = cache.eq_ignore_ascii_case("HIT");
            let detail = if reason.is_empty() {
                format!("HTTP {status} · 缓存状态 {cache}")
            } else {
                format!("HTTP {status} · 缓存状态 {cache} · 原因 {reason}")
            };
            (ok, detail)
        }
        Err(e) => (false, format!("边缘探测失败：{e}")),
    }
}
