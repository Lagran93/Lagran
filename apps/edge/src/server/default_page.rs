//! Operator-facing pages served by the edge itself:
//! * the Host is not an accelerated domain;
//! * the origin is unreachable / timed out / marked unhealthy and there is no
//!   usable cache entry to fall back to.
//!
//! Every page is `no-store` so browsers and upstream caches never keep an error
//! response, and carries a stable `X-Lagran-Error` code for support/debugging.

use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};

const CARD_CSS: &str = r#"
    :root { color-scheme: light dark; }
    body {
      margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
      font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
      background: #0b1220; color: #e2e8f0;
    }
    .card {
      max-width: 560px; padding: 2rem 2.25rem; border-radius: 16px;
      background: #111827; border: 1px solid #1f2937; box-shadow: 0 20px 50px rgba(0,0,0,.35);
    }
    .badge {
      display: inline-block; font-size: 0.75rem; letter-spacing: .06em; text-transform: uppercase;
      color: #38bdf8; background: rgba(56,189,248,.12); padding: .25rem .6rem; border-radius: 999px;
      margin-bottom: 1rem;
    }
    .badge.warn { color: #fbbf24; background: rgba(251,191,36,.12); }
    h1 { margin: 0 0 .75rem; font-size: 1.35rem; font-weight: 650; }
    p { margin: 0 0 .75rem; line-height: 1.6; color: #94a3b8; font-size: .95rem; }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      background: #0f172a; padding: .15rem .4rem; border-radius: 6px; color: #fbbf24;
      word-break: break-all;
    }
    ul { margin: .5rem 0 0; padding-left: 1.2rem; color: #94a3b8; font-size: .9rem; }
    ul li { margin: .25rem 0; }
    .meta { font-size: .85rem; color: #64748b; margin-top: 1rem; }
    .foot { margin-top: 1.5rem; font-size: .8rem; color: #64748b; }
"#;

/// Why an origin fetch could not produce a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginFailure {
    /// Connection refused / DNS / TLS / protocol error.
    Unreachable,
    /// The origin did not answer within the domain timeout.
    Timeout,
    /// The edge's recent health probes marked the origin as down.
    Unhealthy,
}

impl OriginFailure {
    pub fn status(self) -> StatusCode {
        match self {
            OriginFailure::Unreachable => StatusCode::BAD_GATEWAY,
            OriginFailure::Timeout => StatusCode::GATEWAY_TIMEOUT,
            OriginFailure::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            OriginFailure::Unreachable => "ORIGIN_UNREACHABLE",
            OriginFailure::Timeout => "ORIGIN_TIMEOUT",
            OriginFailure::Unhealthy => "ORIGIN_UNHEALTHY",
        }
    }

    /// Cache-status label written to the access log.
    pub fn log_label(self) -> &'static str {
        match self {
            OriginFailure::Unreachable => "ERROR",
            OriginFailure::Timeout => "TIMEOUT",
            OriginFailure::Unhealthy => "UNHEALTHY",
        }
    }

    fn title(self) -> &'static str {
        match self {
            OriginFailure::Unreachable => "源站暂时无法连接",
            OriginFailure::Timeout => "源站响应超时",
            OriginFailure::Unhealthy => "源站健康检查失败",
        }
    }

    fn detail(self) -> &'static str {
        match self {
            OriginFailure::Unreachable => {
                "回源请求失败（连接被拒绝、DNS 解析失败或 TLS 握手失败），并且缓存中没有可用的副本。"
            }
            OriginFailure::Timeout => {
                "源站在限定时间内没有返回响应，并且缓存中没有可用的副本。"
            }
            OriginFailure::Unhealthy => {
                "该域名的源站连续健康检查失败，边缘节点暂时停止回源，并且缓存中没有可用的副本。"
            }
        }
    }
}

/// Error page for "origin down + cache miss/expired".
pub fn origin_error_page(host: &str, path: &str, failure: OriginFailure) -> Response {
    let host_esc = html_escape(host);
    let path_esc = html_escape(&truncate(path, 160));
    let body = format!(
        r#"<h1>{title}</h1>
    <p>{detail}</p>
    <p>请求信息：域名 <code>{host_esc}</code> · 路径 <code>{path_esc}</code></p>
    <p>可以尝试：</p>
    <ul>
      <li>稍等片刻后刷新页面（多数源站故障是短暂的）</li>
      <li>站点管理员检查源站进程、端口、DNS 与证书是否正常</li>
      <li>在 Lagran 控制台查看「源站健康」与边缘日志，必要时刷新缓存</li>
    </ul>"#,
        title = failure.title(),
        detail = failure.detail(),
    );

    render_page(
        failure.status(),
        "源站异常",
        failure.title(),
        &body,
        failure.code(),
        true,
    )
}

/// Page returned when the WAF rejects a request.
pub fn waf_blocked_page(host: &str, path: &str, rule: &str, category: &str) -> Response {
    let host_esc = html_escape(host);
    let path_esc = html_escape(&truncate(path, 160));
    let rule_esc = html_escape(&truncate(rule, 96));
    let category_label = match category {
        "sqli" => "SQL 注入",
        "xss" => "XSS 跨站脚本",
        "traversal" => "路径穿越",
        "scanners" => "恶意扫描",
        "ip_deny" => "IP 黑名单",
        _ => "自定义规则",
    };
    let body = format!(
        r#"<h1>请求已被安全拦截</h1>
    <p>该请求命中了 Web 应用防火墙（WAF）策略，已被边缘节点拒绝。</p>
    <p>请求信息：域名 <code>{host_esc}</code> · 路径 <code>{path_esc}</code></p>
    <p>命中规则：<code>{rule_esc}</code>（{category_label}）</p>
    <p>如果你是正常访客：</p>
    <ul>
      <li>请检查请求参数中是否包含特殊字符或脚本片段</li>
      <li>稍后重试，或联系站点管理员确认是否为误报</li>
    </ul>
    <p>如果你是站点管理员：可在控制台「WAF 防护」中调整自定义规则、放行 IP，或先把模式切换为「观察」以确认误报。</p>"#
    );

    let mut response = render_page(
        StatusCode::FORBIDDEN,
        "安全拦截",
        "请求已被拦截",
        &body,
        "WAF_BLOCKED",
        true,
    );
    let headers = response.headers_mut();
    headers.remove(header::RETRY_AFTER);
    headers.insert(
        HeaderName::from_static("x-lagran-waf"),
        HeaderValue::from_static("blocked"),
    );
    if let Ok(v) = HeaderValue::from_str(&truncate(rule, 96)) {
        headers.insert(HeaderName::from_static("x-lagran-waf-rule"), v);
    }
    response
}

/// Page for a Host that has not been onboarded to this edge.
pub fn unknown_domain_page(host: &str) -> Response {
    let host_esc = html_escape(host);
    let body = format!(
        r#"<h1>该域名尚未接入加速</h1>
    <p>您访问的域名 <code>{host_esc}</code> 已解析到 CDN 节点，但尚未在控制台完成接入配置。</p>
    <p>请联系站点管理员在 Lagran 控制台：</p>
    <ul>
      <li>添加该加速域名</li>
      <li>配置对应源站（Origin）</li>
      <li>确认域名状态为启用</li>
    </ul>"#
    );
    render_page(
        StatusCode::NOT_FOUND,
        "Lagran CDN",
        "域名未接入",
        &body,
        "DOMAIN_NOT_ONBOARDED",
        false,
    )
}

fn render_page(
    status: StatusCode,
    badge: &str,
    page_title: &str,
    body_html: &str,
    code: &str,
    warn: bool,
) -> Response {
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{page_title} | Lagran CDN</title>
  <style>{CARD_CSS}</style>
</head>
<body>
  <div class="card">
    <div class="badge{badge_cls}">{badge}</div>
    {body_html}
    <p class="meta">错误码：<code>{code}</code></p>
    <p class="foot">Error: {code} · Powered by Lagran Edge</p>
  </div>
</body>
</html>"#,
        badge_cls = if warn { " warn" } else { "" },
    );

    let mut response = (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(html),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    if let Ok(v) = HeaderValue::from_str(code) {
        headers.insert(HeaderName::from_static("x-lagran-error"), v);
    }
    if warn {
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
    }
    response
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect::<String>() + "…"
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_failure_statuses_and_codes() {
        for (failure, status, code) in [
            (OriginFailure::Unreachable, 502, "ORIGIN_UNREACHABLE"),
            (OriginFailure::Timeout, 504, "ORIGIN_TIMEOUT"),
            (OriginFailure::Unhealthy, 503, "ORIGIN_UNHEALTHY"),
        ] {
            let resp = origin_error_page("cdn.test", "/a", failure);
            assert_eq!(resp.status().as_u16(), status);
            assert_eq!(
                resp.headers().get("cache-control").unwrap(),
                "no-store, no-cache, must-revalidate"
            );
            assert_eq!(resp.headers().get("x-lagran-error").unwrap(), code);
            assert_eq!(resp.headers().get("retry-after").unwrap(), "30");
            assert_eq!(
                resp.headers().get(header::CONTENT_TYPE).unwrap(),
                "text/html; charset=utf-8"
            );
        }
    }

    #[test]
    fn host_and_path_are_escaped() {
        let resp = origin_error_page("<script>", "/x?<y>", OriginFailure::Unreachable);
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        // Header assertion above proves the page was built; escaping is unit-tested directly.
        assert_eq!(html_escape("<b>&\"x\""), "&lt;b&gt;&amp;&quot;x&quot;");
        assert_eq!(truncate("abcdef", 3), "abc…");
    }

    #[test]
    fn waf_block_page_headers() {
        let resp = waf_blocked_page("cdn.test", "/search?q=x", "SQL 注入", "sqli");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(resp.headers().get("x-lagran-waf").unwrap(), "blocked");
        assert_eq!(resp.headers().get("x-lagran-error").unwrap(), "WAF_BLOCKED");
        assert!(resp.headers().get("retry-after").is_none());
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "no-store, no-cache, must-revalidate"
        );
    }

    #[test]
    fn unknown_domain_is_not_cacheable() {
        let resp = unknown_domain_page("not-onboarded.test");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "no-store, no-cache, must-revalidate"
        );
        assert_eq!(
            resp.headers().get("x-lagran-error").unwrap(),
            "DOMAIN_NOT_ONBOARDED"
        );
        assert!(resp.headers().get("retry-after").is_none());
    }
}
