//! Live cache diagnostics: make a request through the edge and return the
//! X-Lagran-Cache-Reason / cache status headers with a human explanation.

use crate::middleware::authz::Actor;
use crate::repository;
use crate::service::agent_http;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Deserialize)]
pub struct DiagnoseRequest {
    pub domain: String,
    #[serde(default = "default_path")]
    pub path: String,
    pub scheme: Option<String>,
    #[serde(default)]
    pub simulate_cookie: bool,
    #[serde(default)]
    pub simulate_authorization: bool,
    /// Optional `Cache-Control` request header, e.g. no-cache / no-store.
    pub request_cache_control: Option<String>,
}

#[derive(Serialize)]
pub struct DiagnoseResponse {
    pub url: String,
    pub status: u16,
    pub cache_status: String,
    pub cache_reason: String,
    pub age: String,
    pub advice: String,
    pub headers: Vec<(String, String)>,
    pub body_preview: String,
}

fn default_path() -> String {
    "/".into()
}

fn forbidden() -> (StatusCode, Json<Value>) {
    (StatusCode::FORBIDDEN, Json(json!({"error": "forbidden"})))
}

pub async fn diagnose(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<DiagnoseRequest>,
) -> Result<Json<DiagnoseResponse>, (StatusCode, Json<Value>)> {
    let domain = req.domain.trim().to_ascii_lowercase();
    if domain.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "domain is required"})),
        ));
    }
    if !actor.can_read_domain_name(&state, &domain).await {
        return Err(forbidden());
    }
    let row = repository::get_domain_by_name(&state.pool, &domain)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "database error"})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "domain not found"})),
            )
        })?;
    let scheme = req
        .scheme
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| s == "http" || s == "https")
        .unwrap_or_else(|| {
            if row.ssl_enabled {
                "https".into()
            } else {
                "http".into()
            }
        });
    let mut path = req.path.trim().to_string();
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if path.contains('\r') || path.contains('\n') || path.starts_with("/__lagran/") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid path"})),
        ));
    }
    let url = format!("{scheme}://{domain}{path}");
    let mut headers: Vec<(&str, &str)> = vec![("user-agent", "lagran-cache-diagnose/1.0")];
    let cookie_value;
    if req.simulate_cookie {
        cookie_value = "lagran_debug=1".to_string();
        headers.push(("cookie", cookie_value.as_str()));
    }
    let auth_value;
    if req.simulate_authorization {
        auth_value = "Bearer lagran-diagnostic".to_string();
        headers.push(("authorization", auth_value.as_str()));
    }
    let cache_control;
    if let Some(cc) = req
        .request_cache_control
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        cache_control = cc.to_string();
        headers.push(("cache-control", cache_control.as_str()));
    }

    let (status, response_headers, body) = agent_http::get_response(&url, &headers)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, Json(json!({"error": e}))))?;
    let selected = [
        "x-cache",
        "x-cache-status",
        "x-lagran-cache-reason",
        "age",
        "etag",
        "cache-control",
        "vary",
        "content-type",
        "server",
    ];
    let mut out_headers = Vec::new();
    for name in selected {
        if let Some(value) = response_headers.get(name).and_then(|v| v.to_str().ok()) {
            out_headers.push((name.to_string(), value.to_string()));
        }
    }
    let cache_status = response_headers
        .get("x-cache-status")
        .or_else(|| response_headers.get("x-cache"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("UNKNOWN")
        .to_string();
    let mut cache_reason = response_headers
        .get("x-lagran-cache-reason")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if cache_reason.is_empty() {
        cache_reason = match cache_status.as_str() {
            "HIT" => "hit".into(),
            "STALE" => "stale".into(),
            "MISS" | "EXPIRED" => "stored-or-miss".into(),
            _ => "unknown".into(),
        };
    }
    let advice = advice_for(&cache_reason);
    let preview = String::from_utf8_lossy(&body)
        .chars()
        .take(300)
        .collect::<String>();
    Ok(Json(DiagnoseResponse {
        url,
        status,
        cache_status,
        cache_reason,
        age: response_headers
            .get("age")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("—")
            .to_string(),
        advice,
        headers: out_headers,
        body_preview: preview,
    }))
}

fn advice_for(reason: &str) -> String {
    match reason {
        "hit" => "缓存命中。响应来自边缘缓存，无需处理。".into(),
        "stale" => "缓存已过期但仍在 stale-while-revalidate 窗口，先返回旧内容并后台刷新。".into(),
        "cookie" => "请求携带了 Cookie，默认不进入共享缓存。若该 Cookie 与内容无关，可为规则开启 ignore_cookie。".into(),
        "authorization" => "请求携带 Authorization，按安全策略不缓存。".into(),
        "range" => "Range 请求当前不走共享缓存；如需大文件分片缓存，请配置 Range 支持。".into(),
        "no-store" => "请求或响应带有 no-store，禁止存储。".into(),
        "private" => "响应带有 Cache-Control: private，仅允许浏览器缓存。".into(),
        "no-cache" => "响应要求每次回源校验；可为该路径配置显式缓存 TTL 覆盖。".into(),
        "vary:user-agent" => "响应按 User-Agent 变化，当前不存储共享缓存；建议改用更稳定的 Vary 维度。".into(),
        "vary:cookie" => "响应 Vary: Cookie；若 Cookie 与内容无关，可为规则开启 ignore_cookie。".into(),
        "vary" => "响应 Vary 包含不支持的请求头，无法安全共享缓存。".into(),
        "rule-bypass" => "请求命中了 bypass 规则，不会读写缓存。".into(),
        "content-type-bypass" => "源站响应的 Content-Type 命中了 bypass 规则，不写入缓存。".into(),
        "set-cookie" => "源站返回了 Set-Cookie，按安全策略不缓存。".into(),
        "status" => "HTTP 状态码默认不可缓存（仅 200/203/204/300/301/308 可缓存）。".into(),
        "method" => "只有 GET / HEAD 请求使用共享缓存。".into(),
        "ttl-zero" => "计算出的 TTL 为 0，不写入缓存。".into(),
        "body-too-large" => "响应体超过边缘缓存单对象上限，未写入缓存。".into(),
        "stored-or-miss" => "请求已完成回源；若未存储，请查看响应头中的 Cache-Control/Vary 或规则动作。".into(),
        _ => "未识别具体原因，请检查规则、源站 Cache-Control/Vary 与请求头。".into(),
    }
}
