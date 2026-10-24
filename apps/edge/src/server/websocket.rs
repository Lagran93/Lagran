//! WebSocket reverse proxy (TCP tunnel after HTTP Upgrade)

use anyhow::{Context, Result};
use axum::http::HeaderMap;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

/// Returns true if request is a WebSocket upgrade
pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let upgrade = headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let connection = headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    upgrade && connection
}

/// Build origin host:port from origin_url like https://host:443
pub fn origin_tcp_addr(origin_url: &str) -> Result<(String, u16, bool)> {
    let url = origin_url.trim_end_matches('/');
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else {
        ("http", url)
    };
    let hostport = rest.split('/').next().unwrap_or(rest);
    let (host, port) = if let Some((h, p)) = hostport.rsplit_once(':') {
        (
            h.to_string(),
            p.parse()
                .unwrap_or(if scheme == "https" { 443 } else { 80 }),
        )
    } else {
        (
            hostport.to_string(),
            if scheme == "https" { 443 } else { 80 },
        )
    };
    Ok((host, port, scheme == "https"))
}

/// Proxy WebSocket: upgrade both sides and bi-directionally copy bytes.
pub async fn proxy_websocket(
    client_upgrade: OnUpgrade,
    origin_url: &str,
    path_and_query: &str,
    req_headers: &HeaderMap,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (host, port, _tls) = origin_tcp_addr(origin_url)?;
    let addr = format!("{host}:{port}");
    let mut origin_stream = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("connect origin ws {addr}"))?;

    let path = if path_and_query.starts_with('/') {
        path_and_query.to_string()
    } else {
        format!("/{path_and_query}")
    };
    let mut req_buf = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
    );
    for name in [
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-protocol",
        "sec-websocket-extensions",
        "origin",
    ] {
        if let Some(v) = req_headers.get(name).and_then(|v| v.to_str().ok()) {
            req_buf.push_str(&format!("{name}: {v}\r\n"));
        }
    }
    req_buf.push_str("\r\n");
    origin_stream.write_all(req_buf.as_bytes()).await?;

    let mut buf = vec![0u8; 4096];
    let n = origin_stream.read(&mut buf).await?;
    let head = String::from_utf8_lossy(&buf[..n]);
    if !head.starts_with("HTTP/1.1 101") && !head.starts_with("HTTP/1.0 101") {
        anyhow::bail!(
            "origin ws upgrade failed: {}",
            head.lines().next().unwrap_or("")
        );
    }

    let client_upgraded = client_upgrade.await.context("client upgrade")?;
    let mut client_io = TokioIo::new(client_upgraded);

    let (mut cr, mut cw) = tokio::io::split(&mut client_io);
    let (mut or, mut ow) = origin_stream.split();
    let c2o = tokio::io::copy(&mut cr, &mut ow);
    let o2c = tokio::io::copy(&mut or, &mut cw);
    tokio::select! {
        r = c2o => { let _ = r; }
        r = o2c => { let _ = r; }
    }
    Ok(())
}
