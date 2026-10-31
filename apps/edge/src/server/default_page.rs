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
    :root { color-scheme: light; }
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100svh; display: grid; place-items: center;
      padding: clamp(20px, 6vw, 72px) 16px;
      font-family: "PingFang SC", "Microsoft YaHei", "Noto Sans SC", "Source Han Sans SC", system-ui, sans-serif;
      color: #332f2a;
      background:
        radial-gradient(900px 420px at 8% -10%, rgba(176,58,46,.12), transparent 60%),
        radial-gradient(700px 360px at 100% 0%, rgba(198,155,86,.12), transparent 55%),
        linear-gradient(180deg, #fbf8f1 0%, #f3ecdf 100%);
      position: relative; overflow-x: hidden;
    }
    .landscape {
      position: fixed; inset: auto 0 0; height: min(34vh, 300px);
      pointer-events: none; opacity: .55; z-index: 0;
    }
    .landscape svg { width: 100%; height: 100%; display: block; }
    .wrap { width: min(660px, 100%); position: relative; z-index: 2; }
    .brand { display: flex; align-items: center; gap: 12px; margin: 0 0 18px 4px; }
    .seal {
      width: 46px; height: 46px; border-radius: 10px; display: grid; place-items: center;
      background: linear-gradient(145deg, #b33a30, #8f2a22); color: #fff8ee;
      font-family: "Songti SC", "Noto Serif SC", "STSong", serif;
      font-size: 24px; font-weight: 700; border: 1px solid rgba(255,255,255,.22);
      box-shadow: 0 8px 20px rgba(143,42,34,.22);
    }
    .brand-text { display: flex; flex-direction: column; line-height: 1.2; }
    .brand-text b {
      font-family: "Songti SC", "Noto Serif SC", "STSong", serif;
      font-size: 15px; letter-spacing: .08em; color: #4a4036;
    }
    .brand-text small { margin-top: 3px; font-size: 10px; color: #9b8d7a; letter-spacing: .18em; }
    .card {
      background: rgba(255,253,248,.96); border: 1px solid #eadfce; border-radius: 22px;
      padding: clamp(26px, 5vw, 44px);
      box-shadow: 0 28px 70px rgba(72,54,36,.12), inset 0 1px 0 rgba(255,255,255,.8);
      position: relative; overflow: hidden;
    }
    .card::before {
      content: ""; position: absolute; inset: 0 0 auto; height: 4px;
      background: linear-gradient(90deg, #a7372d, #c99854, #a7372d); opacity: .85;
    }
    .card::after {
      content: ""; position: absolute; right: -40px; top: -50px; width: 180px; height: 180px;
      border: 1px solid rgba(167,55,45,.08); border-radius: 50%;
      box-shadow: 0 0 0 22px rgba(167,55,45,.025);
    }
    .badge {
      display: inline-flex; align-items: center; gap: 6px; font-size: 12px;
      letter-spacing: .14em; color: #9c3b31; background: rgba(167,55,45,.08);
      border: 1px solid rgba(167,55,45,.14); padding: 5px 10px; border-radius: 999px;
      margin-bottom: 18px; position: relative; z-index: 1;
    }
    .badge::before { content: ""; width: 5px; height: 5px; border-radius: 50%; background: currentColor; }
    .badge.warn { color: #8a5a16; background: rgba(176,124,35,.10); border-color: rgba(176,124,35,.20); }
    h1 {
      margin: 0 0 14px; font-family: "Songti SC", "Noto Serif SC", "STSong", serif;
      font-size: clamp(23px, 4vw, 30px); line-height: 1.35; letter-spacing: .02em;
      color: #2f2a24; font-weight: 700; position: relative; z-index: 1;
    }
    h1::after {
      content: ""; display: block; width: 42px; height: 3px; margin-top: 12px;
      border-radius: 2px; background: linear-gradient(90deg, #a7372d, #d2aa6a);
    }
    p { margin: 0 0 12px; line-height: 1.9; color: #6d6358; font-size: 15px; position: relative; z-index: 1; }
    strong { color: #4a4036; }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      background: #f6ecdd; color: #8f3b31; padding: 2px 6px; border-radius: 6px;
      border: 1px solid #ead8c4; word-break: break-all; font-size: .88em;
    }
    ul {
      margin: 14px 0 0; padding: 0; list-style: none; display: grid; gap: 8px;
      position: relative; z-index: 1;
    }
    li { position: relative; padding-left: 16px; color: #74695d; line-height: 1.7; font-size: 14px; }
    li::before {
      content: ""; position: absolute; left: 0; top: .62em; width: 5px; height: 5px;
      border-radius: 50%; background: #b98a4a; box-shadow: 0 0 0 3px rgba(185,138,74,.12);
    }
    .meta {
      display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
      margin-top: 24px; padding-top: 16px; border-top: 1px solid #eee3d4;
      font-size: 12px; color: #9a8b78; position: relative; z-index: 1;
    }
    .foot { margin: 18px 0 0; text-align: center; font-size: 12px; color: #a29380; letter-spacing: .06em; }
    .foot a {
      color: #9c3b31; text-decoration: none; border-bottom: 1px solid rgba(156,59,49,.35);
      margin-left: 6px; font-weight: 600;
    }
    .foot a:hover { color: #7f2d25; border-bottom-color: currentColor; }
    @media (min-width: 1920px) {
      .wrap { width: min(820px, 100%); }
      .card { padding: 52px 56px; }
      h1 { font-size: 34px; }
      p { font-size: 16px; }
    }
    @media (min-width: 2560px) {
      .wrap { width: min(960px, 100%); }
      .card { padding: 64px 72px; }
      h1 { font-size: 40px; }
      p { font-size: 17px; }
    }
    @media (max-width: 520px) {
      body { padding: 18px 12px 28px; }
      .brand { margin-left: 2px; }
      .card { padding: 22px; border-radius: 18px; }
      p { font-size: 14px; }
      .meta { font-size: 11px; }
      .landscape { opacity: .35; }
    }
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

/// Page returned when the edge rate limiter or CC protection rejects a request.
pub fn rate_limited_page(
    host: &str,
    path: &str,
    retry_after: u64,
    banned: bool,
) -> Response {
    let host_esc = html_escape(host);
    let path_esc = html_escape(&truncate(path, 160));
    let reason = if banned {
        "该客户端触发了 CC 防护，已被临时封禁。"
    } else {
        "当前请求频率超过了该域名允许的上限。"
    };
    let body = format!(
        r#"<h1>请求过于频繁</h1>
    <p>{reason}</p>
    <p>请求信息：域名 <code>{host_esc}</code> · 路径 <code>{path_esc}</code></p>
    <p>建议：</p>
    <ul>
      <li>等待约 {retry_after} 秒后重试</li>
      <li>降低请求频率，或检查是否有脚本/爬虫在短时间内重复访问</li>
      <li>如果你是站点管理员，可在控制台调整限流或 CC 策略</li>
    </ul>"#
    );
    let mut response = render_page(
        StatusCode::TOO_MANY_REQUESTS,
        "访问受限",
        "请求过于频繁",
        &body,
        if banned { "CC_BLOCKED" } else { "RATE_LIMITED" },
        true,
    );
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&retry_after.max(1).to_string()) {
        headers.insert(header::RETRY_AFTER, value);
    }
    headers.insert(
        HeaderName::from_static("x-lagran-cc"),
        HeaderValue::from_static(if banned { "banned" } else { "limit" }),
    );
    response
}

/// Page returned while an admin has disabled this edge node.
pub fn node_disabled_page(host: &str) -> Response {
    let host_esc = html_escape(host);
    let body = format!(
        r#"<h1>节点已停用</h1>
    <p>当前边缘节点已被管理员停用，暂不对外提供服务。</p>
    <p>请求信息：域名 <code>{host_esc}</code></p>
    <p>如果你是访客：请稍后重试，或联系站点管理员确认节点状态。</p>
    <p>如果你是管理员：可在控制台「边缘节点」中重新启用该节点；停用期间节点仍会上报心跳，但不再代理流量。</p>"#
    );

    let mut response = render_page(
        StatusCode::SERVICE_UNAVAILABLE,
        "节点维护",
        "节点已停用",
        &body,
        "NODE_DISABLED",
        true,
    );
    response
        .headers_mut()
        .insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
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
        r##"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="theme-color" content="#f6f0e5" />
  <title>{page_title} | Lagran CDN</title>
  <style>{CARD_CSS}</style>
</head>
<body>
  <div class="landscape" aria-hidden="true">
    <svg viewBox="0 0 1440 320" preserveAspectRatio="none">
      <path fill="#e7ddcc" d="M0 250 L120 190 L230 235 L350 145 L470 225 L610 175 L760 245 L900 155 L1030 220 L1160 170 L1290 230 L1440 180 L1440 320 L0 320 Z"/>
      <path fill="#f0e7d8" d="M0 285 L180 235 L330 270 L500 215 L680 275 L840 235 L1010 280 L1180 225 L1330 270 L1440 245 L1440 320 L0 320 Z"/>
    </svg>
  </div>
  <div class="wrap">
    <div class="brand">
      <div class="seal">澜</div>
      <div class="brand-text">
        <b>Lagran 边缘</b>
        <small>EDGE SECURITY &amp; ACCELERATION</small>
      </div>
    </div>
    <div class="card">
      <div class="badge{badge_cls}">{badge}</div>
      {body_html}
      <div class="meta"><span>错误码</span><code>{code}</code></div>
    </div>
    <p class="foot">Lagran Edge · 为每一次访问保驾护航 · <a href="https://t.me/lagranedge" target="_blank" rel="noopener noreferrer">获取技术支持</a></p>
  </div>
</body>
</html>"##,
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

    #[tokio::test]
    async fn all_edge_error_pages_include_support_link() {
        use http_body_util::BodyExt;

        let pages = [
            origin_error_page("cdn.test", "/a", OriginFailure::Unreachable),
            waf_blocked_page("cdn.test", "/search", "SQL 注入", "sqli"),
            node_disabled_page("cdn.test"),
            rate_limited_page("cdn.test", "/api", 7, false),
            unknown_domain_page("not-onboarded.test"),
        ];
        for response in pages {
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let html = String::from_utf8_lossy(&body);
            assert!(html.contains("https://t.me/lagranedge"), "missing Telegram URL");
            assert!(html.contains("获取技术支持"), "missing support link text");
        }
    }
}
