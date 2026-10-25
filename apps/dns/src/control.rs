//! Tiny blocking HTTP(S) client for the control-plane scheduler.

use anyhow::{anyhow, Context, Result};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

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
            _ => (
                authority.to_string(),
                if tls { 443 } else { 80 },
            ),
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

fn read_http_body(stream: &mut dyn ReadWrite) -> Result<Vec<u8>> {
    let mut raw = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > 4 * 1024 * 1024 {
                    return Err(anyhow!("control response too large"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => return Err(e.into()),
        }
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed HTTP response"))?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let body = raw[split + 4..].to_vec();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("missing HTTP status"))?;
    if !(200..300).contains(&status) {
        return Err(anyhow!("control returned HTTP {status}"));
    }
    let mut content_length = None;
    let mut chunked = false;
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if k == "content-length" {
                content_length = v.parse::<usize>().ok();
            } else if k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked") {
                chunked = true;
            }
        }
    }
    if chunked {
        return decode_chunked(&body);
    }
    if let Some(len) = content_length {
        if body.len() < len {
            return Err(anyhow!("short HTTP body"));
        }
        return Ok(body[..len].to_vec());
    }
    Ok(body)
}

fn decode_chunked(mut body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| anyhow!("malformed chunk"))?;
        let line = String::from_utf8_lossy(&body[..line_end]);
        let size_str = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|_| anyhow!("bad chunk size"))?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size {
            return Err(anyhow!("short chunk"));
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size..];
        if body.starts_with(b"\r\n") {
            body = &body[2..];
        }
    }
}

impl ControlClient {
    pub fn new(url: &str, token: &str, timeout: Duration) -> Result<Self> {
        Ok(Self {
            target: parse_target(url)?,
            token: token.to_string(),
            timeout,
        })
    }

    pub fn schedule(
        &self,
        qname: &str,
        subnet: Option<&str>,
        client_ip: Option<IpAddr>,
    ) -> Result<ScheduleReply> {
        let mut path = format!("{}/api/v1/schedule?domain={}", self.target.base_path, url_encode(qname));
        if let Some(subnet) = subnet {
            path.push_str("&subnet=");
            path.push_str(&url_encode(subnet));
        } else if let Some(ip) = client_ip {
            path.push_str("&ip=");
            path.push_str(&url_encode(&ip.to_string()));
        }
        let mut stream = connect(&self.target, self.timeout)?;
        let host_header = if (self.target.tls && self.target.port == 443)
            || (!self.target.tls && self.target.port == 80)
        {
            self.target.host.clone()
        } else {
            format!("{}:{}", self.target.host, self.target.port)
        };
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/json\r\nx-lagran-agent-token: {}\r\nConnection: close\r\n\r\n",
            self.token
        );
        stream.write_all(request.as_bytes())?;
        let body = read_http_body(&mut *stream)?;
        let v: serde_json::Value = serde_json::from_slice(&body).context("parse schedule JSON")?;
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
}
