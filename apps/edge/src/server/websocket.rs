//! WebSocket reverse proxy.
//!
//! Flow: validate the client upgrade → perform a real RFC 6455 handshake with
//! the origin (TCP or TLS) → answer the client with the origin's negotiated
//! `Sec-WebSocket-Accept`/subprotocol → tunnel bytes in both directions.

use anyhow::{anyhow, bail, Context, Result};
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode, Version};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Duration;

const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HEAD_BYTES: usize = 16 * 1024;

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
    let default_port = if scheme == "https" { 443 } else { 80 };
    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        // IPv6 literal: [::1]:8080
        match rest.split_once(']') {
            Some((h, tail)) => (
                h.to_string(),
                tail.trim_start_matches(':')
                    .parse()
                    .unwrap_or(default_port),
            ),
            None => (hostport.to_string(), default_port),
        }
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        (h.to_string(), p.parse().unwrap_or(default_port))
    } else {
        (hostport.to_string(), default_port)
    };
    if host.is_empty() {
        bail!("origin url has no host: {origin_url}");
    }
    Ok((host, port, scheme == "https"))
}

/// `Sec-WebSocket-Accept` for a client key (SHA-1 + base64, RFC 6455 §4.2.2).
pub fn accept_key(key: &str) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(key.as_bytes());
    ctx.update(WS_GUID);
    base64::engine::general_purpose::STANDARD.encode(ctx.finish().as_ref())
}

/// Origin connection, either plain TCP or TLS.
enum Upstream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Upstream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Upstream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Upstream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Upstream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Upstream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Upstream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Upstream::Plain(s) => Pin::new(s).poll_flush(cx),
            Upstream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Upstream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Upstream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

async fn connect_upstream(origin_url: &str, timeout: Duration) -> Result<Upstream> {
    let (host, port, tls) = origin_tcp_addr(origin_url)?;
    let addr = format!("{host}:{port}");
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow!("origin ws connect timeout: {addr}"))?
        .with_context(|| format!("connect origin ws {addr}"))?;
    tcp.set_nodelay(true).ok();
    if !tls {
        return Ok(Upstream::Plain(tcp));
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|_| anyhow!("invalid TLS server name: {host}"))?;
    let stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| anyhow!("origin TLS handshake timeout: {addr}"))?
        .context("origin TLS handshake")?;
    Ok(Upstream::Tls(Box::new(stream)))
}

struct HandshakeReply {
    headers: HeaderMap,
    leftover: Vec<u8>,
}

async fn origin_handshake(
    upstream: &mut Upstream,
    host: &str,
    port: u16,
    tls: bool,
    path_and_query: &str,
    client_headers: &HeaderMap,
) -> Result<HandshakeReply> {
    let path = if path_and_query.starts_with('/') {
        path_and_query.to_string()
    } else {
        format!("/{path_and_query}")
    };
    let default_port = if tls { 443 } else { 80 };
    let host_header = if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };

    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
    );
    for name in [
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-protocol",
        "sec-websocket-extensions",
        "origin",
        "user-agent",
    ] {
        if let Some(v) = client_headers.get(name).and_then(|v| v.to_str().ok()) {
            req.push_str(&format!("{name}: {v}\r\n"));
        }
    }
    req.push_str("\r\n");
    upstream.write_all(req.as_bytes()).await?;
    upstream.flush().await?;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        let n = upstream.read(&mut chunk).await?;
        if n == 0 {
            bail!("origin closed connection during ws handshake");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_HEAD_BYTES {
            bail!("origin ws handshake headers too large");
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let leftover = buf[head_end..].to_vec();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("bad ws status line: {status_line:?}"))?;
    if status != 101 {
        bail!("origin refused ws upgrade: {status_line}");
    }

    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(k.trim().as_bytes()),
                HeaderValue::from_str(v.trim()),
            ) {
                headers.insert(name, value);
            }
        }
    }
    Ok(HandshakeReply { headers, leftover })
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Perform the client-side upgrade response and move bytes until either side closes.
pub async fn handle_upgrade(
    req: Request<Body>,
    origin_url: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    timeout_ms: u64,
) -> Response {
    if req.version() != Version::HTTP_11 {
        return (StatusCode::BAD_REQUEST, "WebSocket requires HTTP/1.1").into_response();
    }
    let Some(client_key) = headers
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return (StatusCode::BAD_REQUEST, "missing Sec-WebSocket-Key").into_response();
    };
    let Some(on_upgrade) = req.extensions().get::<OnUpgrade>().cloned() else {
        return (StatusCode::BAD_REQUEST, "connection does not support upgrades").into_response();
    };

    let timeout = Duration::from_millis(timeout_ms.clamp(1_000, 30_000));
    let (host, port, tls) = match origin_tcp_addr(origin_url) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "invalid websocket origin");
            return (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response();
        }
    };
    let mut upstream = match connect_upstream(origin_url, timeout).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "websocket origin connect failed");
            return (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response();
        }
    };
    let reply = match origin_handshake(&mut upstream, &host, port, tls, path_and_query, headers).await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "websocket origin handshake failed");
            return (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response();
        }
    };

    let accept = reply
        .headers
        .get("sec-websocket-accept")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| accept_key(&client_key));

    let mut out = Response::new(Body::empty());
    *out.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let out_headers = out.headers_mut();
    out_headers.insert(
        HeaderName::from_static("upgrade"),
        HeaderValue::from_static("websocket"),
    );
    out_headers.insert(
        HeaderName::from_static("connection"),
        HeaderValue::from_static("Upgrade"),
    );
    if let Ok(v) = HeaderValue::from_str(&accept) {
        out_headers.insert(HeaderName::from_static("sec-websocket-accept"), v);
    }
    for name in ["sec-websocket-protocol", "sec-websocket-extensions"] {
        if let Some(v) = reply.headers.get(name) {
            out_headers.insert(HeaderName::from_static(name), v.clone());
        }
    }

    let leftover = reply.leftover;
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let mut client = TokioIo::new(upgraded);
                if !leftover.is_empty() {
                    if let Err(e) = client.write_all(&leftover).await {
                        tracing::debug!(error = %e, "ws: writing buffered origin frames failed");
                        return;
                    }
                }
                match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
                    Ok((c2o, o2c)) => tracing::debug!(c2o, o2c, "websocket tunnel closed"),
                    Err(e) => tracing::debug!(error = %e, "websocket tunnel error"),
                }
            }
            Err(e) => tracing::warn!(error = %e, "client websocket upgrade failed"),
        }
    });

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_detection() {
        let mut h = HeaderMap::new();
        h.insert("upgrade", HeaderValue::from_static("websocket"));
        h.insert("connection", HeaderValue::from_static("keep-alive, Upgrade"));
        assert!(is_websocket_upgrade(&h));
        h.insert("upgrade", HeaderValue::from_static("h2c"));
        assert!(!is_websocket_upgrade(&h));
    }

    #[test]
    fn origin_addr_parsing() {
        assert_eq!(
            origin_tcp_addr("https://origin.test").unwrap(),
            ("origin.test".into(), 443, true)
        );
        assert_eq!(
            origin_tcp_addr("http://127.0.0.1:8080/base").unwrap(),
            ("127.0.0.1".into(), 8080, false)
        );
        assert_eq!(
            origin_tcp_addr("https://[::1]:8443").unwrap(),
            ("::1".into(), 8443, true)
        );
    }

    #[test]
    fn accept_matches_rfc_example() {
        // RFC 6455 §1.3 example
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn finds_header_terminator() {
        let buf = b"HTTP/1.1 101 OK\r\nA: b\r\n\r\nrest";
        let pos = find_subsequence(buf, b"\r\n\r\n").unwrap();
        assert_eq!(pos, buf.len() - 4 - 4);
    }
}
