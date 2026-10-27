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
        while body.len() < len {
            if !read_more(stream, &mut body)? {
                return Err(anyhow!("short HTTP body"));
            }
        }
        body.truncate(len);
        return Ok((status, body, !close));
    }
    if chunked {
        let body = decode_chunked(stream, body)?;
        return Ok((status, body, !close));
    }

    // No framing: read until close/timeout. Never reuse this connection.
    while read_more(stream, &mut body)? {}
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
}
