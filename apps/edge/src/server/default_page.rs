//! Default page when Host is not an accelerated domain

use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};

pub fn unknown_domain_page(host: &str) -> Response {
    let host_esc = html_escape(host);
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>域名未接入 | Lagran CDN</title>
  <style>
    :root {{ color-scheme: light dark; }}
    body {{
      margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
      font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
      background: #0b1220; color: #e2e8f0;
    }}
    .card {{
      max-width: 520px; padding: 2rem 2.25rem; border-radius: 16px;
      background: #111827; border: 1px solid #1f2937; box-shadow: 0 20px 50px rgba(0,0,0,.35);
    }}
    .badge {{
      display: inline-block; font-size: 0.75rem; letter-spacing: .06em; text-transform: uppercase;
      color: #38bdf8; background: rgba(56,189,248,.12); padding: .25rem .6rem; border-radius: 999px;
      margin-bottom: 1rem;
    }}
    h1 {{ margin: 0 0 .75rem; font-size: 1.35rem; font-weight: 650; }}
    p {{ margin: 0 0 .75rem; line-height: 1.6; color: #94a3b8; font-size: .95rem; }}
    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      background: #0f172a; padding: .15rem .4rem; border-radius: 6px; color: #fbbf24;
    }}
    ul {{ margin: .5rem 0 0; padding-left: 1.2rem; color: #94a3b8; font-size: .9rem; }}
    .foot {{ margin-top: 1.5rem; font-size: .8rem; color: #64748b; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">Lagran CDN</div>
    <h1>该域名尚未接入加速</h1>
    <p>您访问的域名 <code>{host_esc}</code> 已解析到 CDN 节点，但尚未在控制台完成接入配置。</p>
    <p>请联系站点管理员在 Lagran 控制台：</p>
    <ul>
      <li>添加该加速域名</li>
      <li>配置对应源站（Origin）</li>
      <li>确认域名状态为启用</li>
    </ul>
    <p class="foot">Error: DOMAIN_NOT_ONBOARDED · Powered by Lagran Edge</p>
  </div>
</body>
</html>"#
    );
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(html),
    )
        .into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
