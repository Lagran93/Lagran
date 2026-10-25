//! Admin DNS resolution test: sends a real A/ECS query to the configured
//! authoritative DNS and returns the answer for the console.

use crate::middleware::authz::Actor;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
pub struct DnsTestRequest {
    pub name: String,
    /// Optional client IP/subnet used as EDNS Client Subnet.
    pub ip: Option<String>,
}

#[derive(Serialize)]
pub struct DnsAnswer {
    pub ip: String,
    pub ttl: u32,
}

#[derive(Serialize)]
pub struct DnsTestResponse {
    pub server: String,
    pub name: String,
    pub rcode: u8,
    pub truncated: bool,
    pub answers: Vec<DnsAnswer>,
    pub elapsed_ms: u64,
}

fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0);
}

fn parse_subnet(input: &str) -> Option<(IpAddr, u8)> {
    let (addr, prefix) = match input.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().ok()?),
        None => (input, 32),
    };
    let addr: IpAddr = addr.trim().parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return None;
    }
    Some((addr, prefix))
}

fn build_query(name: &str, subnet: Option<(IpAddr, u8)>) -> Vec<u8> {
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(1);
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // RD=0
    out.extend_from_slice(&1u16.to_be_bytes()); // QD
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&u16::from(subnet.is_some()).to_be_bytes());
    encode_name(&mut out, name);
    out.extend_from_slice(&1u16.to_be_bytes()); // A
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    if let Some((addr, prefix)) = subnet {
        out.push(0);
        out.extend_from_slice(&41u16.to_be_bytes()); // OPT
        out.extend_from_slice(&1232u16.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        let (family, bytes) = match addr {
            IpAddr::V4(v4) => (1u16, v4.octets().to_vec()),
            IpAddr::V6(v6) => (2u16, v6.octets().to_vec()),
        };
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&8u16.to_be_bytes());
        rdata.extend_from_slice(&((4 + bytes.len()) as u16).to_be_bytes());
        rdata.extend_from_slice(&family.to_be_bytes());
        rdata.push(prefix);
        rdata.push(0);
        rdata.extend_from_slice(&bytes);
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    out
}

fn skip_name(buf: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    let mut hops = 0;
    loop {
        let len = *buf.get(pos)?;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        pos += 1 + len as usize;
        hops += 1;
        if hops > 64 {
            return None;
        }
    }
}

fn parse_response(buf: &[u8]) -> (u8, bool, Vec<DnsAnswer>) {
    if buf.len() < 12 {
        return (2, false, vec![]);
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = (flags & 0x000F) as u8;
    let truncated = flags & 0x0200 != 0;
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        let Some(p) = skip_name(buf, pos) else {
            return (2, truncated, vec![]);
        };
        pos = p + 4;
    }
    let mut answers = Vec::new();
    for _ in 0..an {
        let Some(p) = skip_name(buf, pos) else {
            break;
        };
        if p + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let ttl = u32::from_be_bytes([buf[p + 4], buf[p + 5], buf[p + 6], buf[p + 7]]);
        let rdlen = u16::from_be_bytes([buf[p + 8], buf[p + 9]]) as usize;
        let rdata = p + 10;
        if rdata + rdlen > buf.len() {
            break;
        }
        if rtype == 1 && rdlen == 4 {
            answers.push(DnsAnswer {
                ip: Ipv4Addr::new(buf[rdata], buf[rdata + 1], buf[rdata + 2], buf[rdata + 3])
                    .to_string(),
                ttl,
            });
        }
        pos = rdata + rdlen;
    }
    (rcode, truncated, answers)
}

pub async fn test(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<DnsTestRequest>,
) -> Result<Json<DnsTestResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !actor.admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "admin only" })),
        ));
    }
    let name = req.name.trim().trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid name" })),
        ));
    }
    let server = state.config.dns_test_server.clone();
    let subnet = req.ip.as_deref().and_then(parse_subnet);
    let query = build_query(name, subnet);
    let started = Instant::now();
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
    })?;
    sock.set_read_timeout(Some(Duration::from_millis(1500)))
        .ok();
    let addr: SocketAddr = match server.parse() {
        Ok(a) => a,
        Err(_) => {
            let mut addrs = match tokio::net::lookup_host(&server).await {
                Ok(a) => a,
                Err(_) => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "error": "invalid DNS_TEST_SERVER" })),
                    ))
                }
            };
            match addrs.next() {
                Some(a) => a,
                None => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "error": "DNS_TEST_SERVER not resolvable" })),
                    ))
                }
            }
        }
    };
    sock.send_to(&query, addr).map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
    })?;
    let mut buf = [0u8; 4096];
    let (rcode, truncated, answers) = match sock.recv_from(&mut buf) {
        Ok((n, _)) => parse_response(&buf[..n]),
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
            return Err((
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({ "error": "DNS query timeout" })),
            ))
        }
        Err(e) => {
            return Err((
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": e.to_string() })),
            ))
        }
    };
    Ok(Json(DnsTestResponse {
        server,
        name: name.to_string(),
        rcode,
        truncated,
        answers,
        elapsed_ms: started.elapsed().as_millis() as u64,
    }))
}
