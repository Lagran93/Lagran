//! Geo/ISP-aware edge node selection (Phase 1).
//!
//! Client geo can come from an explicit override (DNS plugin already resolved
//! it) or from a local JSON CIDR table (`GEOIP_JSON_PATH`). Node scoring is
//! intentionally simple: province/city/ISP match + weight - load.

use crate::repository;
use crate::state::AppState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, Default, Serialize)]
pub struct GeoInfo {
    pub country: String,
    pub province: String,
    pub city: String,
    pub isp: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GeoRule {
    cidr: String,
    #[serde(default)]
    country: String,
    #[serde(default)]
    province: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    isp: String,
}

#[derive(Debug, Clone)]
struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(input: &str) -> Option<Self> {
        let (addr, prefix) = input.trim().split_once('/')?;
        let addr: IpAddr = addr.trim().parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.trim().parse::<u8>().ok()?;
        if prefix > max {
            return None;
        }
        Some(Self { addr, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
struct Rule {
    cidr: Cidr,
    geo: GeoInfo,
}

/// CIDR → geo table loaded from a JSON file.
#[derive(Clone, Default)]
pub struct GeoTable {
    rules: Arc<Vec<Rule>>,
}

impl GeoTable {
    pub fn load(path: &str) -> Self {
        if path.trim().is_empty() {
            return Self::default();
        }
        let Ok(raw) = std::fs::read_to_string(path) else {
            tracing::warn!(path, "geoip json not found; scheduling falls back to weights");
            return Self::default();
        };
        let parsed: Vec<GeoRule> = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(path, error = %e, "invalid geoip json");
                return Self::default();
            }
        };
        let mut rules = Vec::with_capacity(parsed.len());
        for r in parsed {
            let Some(cidr) = Cidr::parse(&r.cidr) else {
                tracing::warn!(cidr = %r.cidr, "invalid CIDR in geoip json");
                continue;
            };
            rules.push(Rule {
                cidr,
                geo: GeoInfo {
                    country: r.country,
                    province: r.province,
                    city: r.city,
                    isp: r.isp,
                },
            });
        }
        // Longest prefix wins; sort descending once.
        rules.sort_by_key(|r| std::cmp::Reverse(r.cidr.prefix));
        tracing::info!(count = rules.len(), path, "geoip table loaded");
        Self {
            rules: Arc::new(rules),
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        self.rules
            .iter()
            .find(|r| r.cidr.contains(ip))
            .map(|r| r.geo.clone())
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScheduleRequest {
    pub domain: Option<String>,
    pub ip: Option<String>,
    pub subnet: Option<String>,
    /// Explicit overrides (used when a DNS plugin already resolved geo).
    pub country: Option<String>,
    pub province: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct NodeRef {
    pub name: String,
    pub public_ip: String,
    pub region: String,
    pub province: String,
    pub city: String,
    pub isp: String,
    pub weight: i32,
}

#[derive(Debug, Serialize)]
pub struct Candidate {
    pub name: String,
    pub public_ip: String,
    pub region: String,
    pub province: String,
    pub city: String,
    pub isp: String,
    pub weight: i32,
    pub score: i32,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct ScheduleResponse {
    pub domain: String,
    pub ttl: u64,
    pub client: GeoInfo,
    pub primary: Option<NodeRef>,
    pub backup: Option<NodeRef>,
    pub candidates: Vec<Candidate>,
    pub note: String,
}

fn client_ip(req: &ScheduleRequest) -> Option<IpAddr> {
    if let Some(ip) = req.ip.as_deref().filter(|s| !s.trim().is_empty()) {
        if let Ok(ip) = ip.trim().parse::<IpAddr>() {
            return Some(ip);
        }
    }
    let subnet = req.subnet.as_deref()?.trim();
    let addr = subnet.split('/').next()?.trim();
    addr.parse::<IpAddr>().ok()
}

fn resolve_geo(state: &AppState, req: &ScheduleRequest) -> (GeoInfo, Option<IpAddr>) {
    let ip = client_ip(req);
    let mut geo = ip
        .and_then(|ip| state.geo.lookup(ip))
        .unwrap_or_default();
    if let Some(v) = req.country.as_deref().filter(|s| !s.is_empty()) {
        geo.country = v.to_string();
    }
    if let Some(v) = req.province.as_deref().filter(|s| !s.is_empty()) {
        geo.province = v.to_string();
    }
    if let Some(v) = req.city.as_deref().filter(|s| !s.is_empty()) {
        geo.city = v.to_string();
    }
    if let Some(v) = req.isp.as_deref().filter(|s| !s.is_empty()) {
        geo.isp = v.to_string();
    }
    (geo, ip)
}

fn eq_ignore(a: &str, b: &str) -> bool {
    !a.is_empty() && a.eq_ignore_ascii_case(b)
}

fn score_node(node: &repository::NodeRow, geo: &GeoInfo) -> (i32, String) {
    let mut score = node.weight.clamp(0, 1000);
    let mut reasons = vec![format!("weight={}", node.weight)];
    if eq_ignore(&node.country, &geo.country) {
        score += 5;
    }
    if eq_ignore(&node.province, &geo.province) {
        score += 80;
        reasons.push("same-province".into());
    }
    if eq_ignore(&node.city, &geo.city) {
        score += 20;
        reasons.push("same-city".into());
    }
    if eq_ignore(&node.isp, &geo.isp) {
        score += 40;
        reasons.push("same-isp".into());
    }
    if let Some(cpu) = node.cpu_usage {
        let penalty = (cpu.clamp(0.0, 100.0) * 0.3) as i32;
        if penalty > 0 {
            score -= penalty;
            reasons.push(format!("cpu-{penalty}"));
        }
    }
    if let Some(mem) = node.memory_usage {
        let penalty = (mem.clamp(0.0, 100.0) * 0.2) as i32;
        if penalty > 0 {
            score -= penalty;
            reasons.push(format!("mem-{penalty}"));
        }
    }
    (score, reasons.join(" "))
}

pub async fn resolve(state: &AppState, req: ScheduleRequest) -> ScheduleResponse {
    let (client, _ip) = resolve_geo(state, &req);
    let ttl = state.schedule_ttl;
    let domain = req.domain.clone().unwrap_or_default();

    let nodes = repository::list_nodes(&state.pool).await.unwrap_or_default();
    let mut candidates: Vec<(i32, Candidate)> = nodes
        .into_iter()
        .filter(|n| n.status == "online" && !n.public_ip.trim().is_empty())
        .map(|n| {
            let (score, reason) = score_node(&n, &client);
            (
                score,
                Candidate {
                    name: n.name,
                    public_ip: n.public_ip,
                    region: n.region,
                    province: n.province,
                    city: n.city,
                    isp: n.isp,
                    weight: n.weight,
                    score,
                    reason,
                },
            )
        })
        .collect();
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.name.cmp(&b.1.name)));

    let to_ref = |c: &Candidate| NodeRef {
        name: c.name.clone(),
        public_ip: c.public_ip.clone(),
        region: c.region.clone(),
        province: c.province.clone(),
        city: c.city.clone(),
        isp: c.isp.clone(),
        weight: c.weight,
    };
    let primary = candidates.first().map(|(_, c)| to_ref(c));
    let backup = candidates.get(1).map(|(_, c)| to_ref(c));
    let note = if candidates.is_empty() {
        "没有可调度的在线节点（需状态 online 且填写 public_ip）".to_string()
    } else {
        format!("共 {} 个候选节点", candidates.len())
    };
    let top: Vec<Candidate> = candidates.into_iter().take(5).map(|(_, c)| c).collect();

    tracing::info!(
        domain = %domain,
        client_ip = ?_ip,
        province = %client.province,
        isp = %client.isp,
        primary = ?primary.as_ref().map(|p| p.name.as_str()),
        "scheduling decision"
    );

    ScheduleResponse {
        domain,
        ttl,
        client,
        primary,
        backup,
        candidates: top,
        note,
    }
}

pub async fn resolve_agent(
    State(state): State<AppState>,
    _agent: crate::middleware::agent_auth::AgentAuth,
    axum::extract::Query(req): axum::extract::Query<ScheduleRequest>,
) -> Json<ScheduleResponse> {
    Json(resolve(&state, req).await)
}

pub async fn test(
    State(state): State<AppState>,
    actor: crate::middleware::authz::Actor,
    Json(req): Json<ScheduleRequest>,
) -> Result<Json<ScheduleResponse>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    if !actor.admin() {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "admin only" })),
        ));
    }
    Ok(Json(resolve(&state, req).await))
}
