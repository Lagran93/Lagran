//! Tiny blocking HTTP(S) client for the control-plane scheduler.
//!
//! Keeps a small pool of persistent HTTP/1.1 connections. The old client opened
//! a fresh TCP/TLS connection for every DNS cache miss and read the response
//! until a socket timeout; both are avoided here.

use anyhow::{anyhow, Context, Result};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

#[derive(Debug, Clone, Default)]
pub struct ScheduleReply {
    pub ip: Option<IpAddr>,
    pub backup: Option<IpAddr>,
    pub ttl: u32,
}

#[derive(Debug, Clone)]
struct Target {
    tls: bool,
    host: String,
    port: u16,
    base_path: String,
}

pub struct ControlClient {
    target: Target,
    token: String,
    timeout: Duration,
    idle: Mutex<Vec<Box<dyn ReadWrite>>>,
}

fn parse_target(url: &str) -> Result<Target> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| anyhow!("CONTROL_URL must start with http:// or https://"))?;
    let tls = match scheme.to_ascii_lowercase().as_str() {
        "http" => false,
        "https" => true,
        other => return Err(anyhow!("unsupported CONTROL_URL scheme: {other}")),
    };

    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, String::new()),
    };
    // Plaintext is only acceptable to a control plane on this machine. Over the
    // network the response carries node public IPs and scheduling data, and the
    // request carries the agent token; anyone on the path could read the token,
    // rewrite the schedule, or inject a poisoned response into the connection
    // pool. The default URL is loopback, so local development is unaffected.
    if !tls && !host_is_loopback(authority_host(authority)) {
        return Err(anyhow!(
            "CONTROL_URL uses http:// for non-loopback host {:?}; use https://",
            authority_host(authority)
        ));
    }
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let (h, tail) = stripped
            .split_once(']')
            .ok_or_else(|| anyhow!("invalid IPv6 authority"))?;
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(if tls { 443 } else { 80 });
        (h.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
                (h.to_string(), p.parse::<u16>()?)
            }
            _ => (authority.to_string(), if tls { 443 } else { 80 }),
        }
    };
    if host.is_empty() {
        return Err(anyhow!("CONTROL_URL host is empty"));
    }
    Ok(Target {
        tls,
        host,
        port,
        base_path: path.trim_end_matches('/').to_string(),
    })
}

fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn connect(target: &Target, timeout: Duration) -> Result<Box<dyn ReadWrite>> {
    let addrs: Vec<_> = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .with_context(|| format!("resolve {}:{}", target.host, target.port))?
        .collect();
    let mut last_err = None;
    let mut tcp = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    let tcp = tcp.ok_or_else(|| anyhow!("connect failed: {:?}", last_err))?;
    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(timeout)).ok();
    tcp.set_nodelay(true).ok();
    if !target.tls {
        return Ok(Box::new(tcp));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(target.host.clone())
        .map_err(|_| anyhow!("invalid TLS server name"))?;
    let conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;
    Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Largest response body the control client will buffer.
///
/// DNS only reads small JSON documents (a schedule reply, a ban list), so a few
/// megabytes is generous. Without a cap, `Content-Length` and the chunk-size field
/// were trusted verbatim: a compromised or misbehaving control plane could make
/// this process allocate until the OOM killer ran, taking authoritative DNS down
/// with it. The connection pool made it worse — a poisoned connection stayed in
/// the pool and could be reused for the next request.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Host part of an authority, without userinfo or port.
fn authority_host(authority: &str) -> &str {
    let after_user = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    if let Some(rest) = after_user.strip_prefix('[') {
        return rest.split_once(']').map(|(h, _)| h).unwrap_or(rest);
    }
    after_user
        .split_once(':')
        .map(|(h, _)| h)
        .unwrap_or(after_user)
}

/// Whether a host literal names this machine.
///
/// Only literal addresses and `localhost` count. A hostname that merely resolves
/// to a loopback address is not enough: DNS is exactly what this process talks to,
/// so a resolution-based check could be steered.
fn host_is_loopback(host: &str) -> bool {
    let host = host.trim();
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback(),
        Err(_) => false,
    }
}

fn read_more(stream: &mut dyn ReadWrite, buf: &mut Vec<u8>) -> Result<bool> {
    let mut chunk = [0u8; 4096];
    match stream.read(&mut chunk) {
        Ok(0) => Ok(false),
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Read one response from a persistent connection.
/// Returns (status, body, reusable).
fn read_response(stream: &mut dyn ReadWrite) -> Result<(u16, Vec<u8>, bool)> {
    let mut raw = Vec::with_capacity(4096);
    let head_end = loop {
        if let Some(pos) = find(&raw, b"\r\n\r\n") {
            break pos + 4;
        }
        if raw.len() > 64 * 1024 {
            return Err(anyhow!("response header too large"));
        }
        if !read_more(stream, &mut raw)? {
            return Err(anyhow!("connection closed before response header"));
        }
    };

    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("missing HTTP status"))?;

    let mut content_length = None;
    let mut chunked = false;
    let mut close = false;
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if k == "content-length" {
                content_length = v.parse::<usize>().ok();
            } else if k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked") {
                chunked = true;
            } else if k == "connection" && v.eq_ignore_ascii_case("close") {
                close = true;
            }
        }
    }

    let mut body = raw[head_end..].to_vec();
    if let Some(len) = content_length {
        // Trust nothing: refuse before allocating rather than while reading.
        if len > MAX_BODY_BYTES {
            return Err(anyhow!(
                "HTTP body too large: Content-Length {len} exceeds {MAX_BODY_BYTES}"
            ));
        }
        while body.len() < len {
            if !read_more(stream, &mut body)? {
                return Err(anyhow!("short HTTP body"));
            }
            if body.len() > MAX_BODY_BYTES {
                return Err(anyhow!("HTTP body exceeded {MAX_BODY_BYTES} bytes"));
            }
        }
        body.truncate(len);
        return Ok((status, body, !close));
    }
    if chunked {
        let body = decode_chunked(stream, body)?;
        return Ok((status, body, !close));
    }

    // No framing: read until close/timeout. Never reuse this connection. Bounded,
    // because an origin that never closes would otherwise stream forever.
    while read_more(stream, &mut body)? {
        if body.len() > MAX_BODY_BYTES {
            return Err(anyhow!("HTTP body exceeded {MAX_BODY_BYTES} bytes"));
        }
    }
    Ok((status, body, false))
}

fn decode_chunked(stream: &mut dyn ReadWrite, mut raw: Vec<u8>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = loop {
            if let Some(pos) = find(&raw, b"\r\n") {
                break pos;
            }
            if !read_more(stream, &mut raw)? {
                return Err(anyhow!("malformed chunk"));
            }
        };
        let line = String::from_utf8_lossy(&raw[..line_end]);
        let size_str = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|_| anyhow!("bad chunk size"))?;
        // A chunk header is attacker-controlled too: `ffffffffffff` used to
        // allocate that many bytes in one grow.
        if size > MAX_BODY_BYTES || out.len().saturating_add(size) > MAX_BODY_BYTES {
            return Err(anyhow!(
                "chunked body exceeds {MAX_BODY_BYTES} bytes (chunk {size}, have {})",
                out.len()
            ));
        }
        raw.drain(..line_end + 2);
        if size == 0 {
            // Consume optional trailer headers so the connection is reusable.
            loop {
                let end = loop {
                    if let Some(pos) = find(&raw, b"\r\n") {
                        break pos;
                    }
                    if !read_more(stream, &mut raw)? {
                        return Ok(out);
                    }
                };
                if end == 0 {
                    raw.drain(..2);
                    return Ok(out);
                }
                raw.drain(..end + 2);
            }
        }
        while raw.len() < size + 2 {
            if !read_more(stream, &mut raw)? {
                return Err(anyhow!("short chunk"));
            }
        }
        out.extend_from_slice(&raw[..size]);
        raw.drain(..size + 2);
    }
}

impl ControlClient {
    pub fn new(url: &str, token: &str, timeout: Duration) -> Result<Self> {
        Ok(Self {
            target: parse_target(url)?,
            token: token.to_string(),
            timeout,
            idle: Mutex::new(Vec::new()),
        })
    }

    fn take_connection(&self) -> Option<Box<dyn ReadWrite>> {
        self.idle.lock().ok().and_then(|mut pool| pool.pop())
    }

    fn put_connection(&self, conn: Box<dyn ReadWrite>) {
        if let Ok(mut pool) = self.idle.lock() {
            if pool.len() < 8 {
                pool.push(conn);
            }
        }
    }

    pub fn schedule(
        &self,
        qname: &str,
        subnet: Option<&str>,
        client_ip: Option<IpAddr>,
    ) -> Result<ScheduleReply> {
        let mut path = format!(
            "{}/api/v1/schedule?domain={}",
            self.target.base_path,
            url_encode(qname)
        );
        if let Some(subnet) = subnet {
            path.push_str("&subnet=");
            path.push_str(&url_encode(subnet));
        } else if let Some(ip) = client_ip {
            path.push_str("&ip=");
            path.push_str(&url_encode(&ip.to_string()));
        }
        let host_header = if (self.target.tls && self.target.port == 443)
            || (!self.target.tls && self.target.port == 80)
        {
            self.target.host.clone()
        } else {
            format!("{}:{}", self.target.host, self.target.port)
        };
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/json\r\nx-lagran-agent-token: {}\r\nConnection: keep-alive\r\n\r\n",
            self.token
        );

        let mut last_err = None;
        for attempt in 0..2 {
            let mut conn = match self.take_connection() {
                Some(c) => c,
                None => match connect(&self.target, self.timeout) {
                    Ok(c) => c,
                    Err(e) => {
                        last_err = Some(e);
                        continue;
                    }
                },
            };
            let result = (|| -> Result<(u16, Vec<u8>, bool)> {
                conn.write_all(request.as_bytes())?;
                read_response(&mut *conn)
            })();
            match result {
                Ok((status, body, reusable)) => {
                    if !(200..300).contains(&status) {
                        return Err(anyhow!("control returned HTTP {status}"));
                    }
                    if reusable {
                        self.put_connection(conn);
                    }
                    return parse_schedule(&body);
                }
                Err(e) => {
                    last_err = Some(e);
                    // A pooled connection may have been closed by the server;
                    // retry once with a fresh connection. The request is GET.
                    if attempt == 1 {
                        break;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("scheduler request failed")))
    }
}

fn parse_schedule(body: &[u8]) -> Result<ScheduleReply> {
    let v: serde_json::Value = serde_json::from_slice(body).context("parse schedule JSON")?;
    let parse_ip = |p: &serde_json::Value| {
        p.get("public_ip")
            .and_then(|v| v.as_str())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
    };
    let primary = parse_ip(&v["primary"]);
    let backup = parse_ip(&v["backup"]);
    let ttl = v
        .get("ttl")
        .and_then(|t| t.as_u64())
        .unwrap_or(30)
        .clamp(5, 300) as u32;
    Ok(ScheduleReply {
        ip: primary,
        backup,
        ttl,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    #[test]
    fn reuses_a_keepalive_connection() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_srv = accepted.clone();
        let body = r#"{"primary":{"public_ip":"203.0.113.10"},"ttl":30}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
            body.len(),
            body
        );
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                accepted_srv.fetch_add(1, Ordering::Relaxed);
                let response = response.clone();
                thread::spawn(move || {
                    let mut stream = stream;
                    loop {
                        let mut buf = [0u8; 4096];
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                if stream.write_all(response.as_bytes()).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        let client = ControlClient::new(
            &format!("http://127.0.0.1:{port}"),
            "token",
            Duration::from_secs(2),
        )
        .unwrap();
        let first = client.schedule("a.test", None, None).unwrap();
        let second = client.schedule("b.test", None, None).unwrap();
        assert_eq!(first.ip, Some(Ipv4Addr::new(203, 0, 113, 10).into()));
        assert_eq!(second.ip, first.ip);
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn http_is_allowed_only_for_loopback() {
        for ok in [
            "http://127.0.0.1:8080",
            "http://127.0.0.1",
            "http://localhost:8080",
            "http://[::1]:8080",
        ] {
            assert!(parse_target(ok).is_ok(), "{ok} should be accepted");
        }
        for bad in [
            "http://control.example.com",
            "http://10.0.0.5:8080",
            "http://192.168.1.10",
            "http://[2001:db8::1]:8080",
        ] {
            assert!(
                parse_target(bad).is_err(),
                "{bad} is plaintext to a remote host and must be refused"
            );
        }
    }

    #[test]
    fn https_is_allowed_for_any_host() {
        for ok in [
            "https://control.example.com",
            "https://10.0.0.5:8443",
            "https://[2001:db8::1]/",
        ] {
            assert!(parse_target(ok).is_ok(), "{ok} should be accepted");
        }
    }

    #[test]
    fn authority_host_strips_userinfo_and_port() {
        assert_eq!(
            authority_host("control.example.com:8080"),
            "control.example.com"
        );
        assert_eq!(authority_host("control.example.com"), "control.example.com");
        assert_eq!(
            authority_host("user:pass@control.example.com"),
            "control.example.com"
        );
        assert_eq!(authority_host("[::1]:8080"), "::1");
        assert_eq!(authority_host("[::1]"), "::1");
    }

    #[test]
    fn loopback_detection_is_literal_only() {
        assert!(host_is_loopback("127.0.0.1"));
        assert!(host_is_loopback("127.1.2.3"));
        assert!(host_is_loopback("::1"));
        assert!(host_is_loopback("LOCALHOST"));
        // A hostname that merely resolves to loopback is not trusted: DNS is what
        // this process talks to, so a resolution-based check could be steered.
        assert!(!host_is_loopback("localhost.attacker.test"));
        assert!(!host_is_loopback("10.0.0.5"));
        assert!(!host_is_loopback("example.com"));
        assert!(!host_is_loopback(""));
    }

    /// A chunk header claiming more than the cap must fail without allocating.
    #[test]
    fn oversized_chunk_is_rejected() {
        let mut stream = std::io::Cursor::new(b"ffffffff\r\ndata".to_vec());
        let mut raw = Vec::new();
        let err = decode_chunked(&mut dyn_read(&mut stream), raw.drain(..).collect())
            .expect_err("oversized chunk must be rejected");
        assert!(
            err.to_string().contains("exceeds"),
            "unexpected error: {err}"
        );
    }

    /// `Content-Length` larger than the cap must be refused before reading.
    #[test]
    fn oversized_content_length_is_rejected() {
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        let mut stream = std::io::Cursor::new(head.into_bytes());
        let err = read_response(&mut dyn_read(&mut stream))
            .expect_err("oversized Content-Length must be rejected");
        assert!(
            err.to_string().contains("too large"),
            "unexpected error: {err}"
        );
    }

    /// A normal small body still parses.
    #[test]
    fn small_body_is_accepted() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec();
        let mut stream = std::io::Cursor::new(raw);
        let (status, body, _) = read_response(&mut dyn_read(&mut stream)).expect("parse");
        assert_eq!(status, 200);
        assert_eq!(body, b"hello".to_vec());
    }

    fn dyn_read(r: &mut std::io::Cursor<Vec<u8>>) -> TestStream<'_> {
        TestStream(r)
    }

    struct TestStream<'a>(&'a mut std::io::Cursor<Vec<u8>>);

    impl std::io::Read for TestStream<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl std::io::Write for TestStream<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
