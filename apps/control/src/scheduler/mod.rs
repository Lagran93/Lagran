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

/// CIDR -> geo table. Supports the V2Ray/Loyalsoldier `geoip.dat` protobuf
/// format and the legacy JSON format.
#[derive(Clone, Default)]
pub struct GeoTable {
    rules: Arc<Vec<Rule>>,
}

impl GeoTable {
    pub fn load(path: &str) -> Self {
        if path.trim().is_empty() {
            return Self::default();
        }
        let Ok(raw) = std::fs::read(path) else {
            tracing::warn!(
                path,
                "geoip file not found; scheduling falls back to weights"
            );
            return Self::default();
        };

        let dat = is_dat(path, &raw);
        let parsed = if dat {
            parse_dat(&raw)
        } else {
            parse_json(&raw)
        };
        let mut rules = match parsed {
            Ok(rules) => rules,
            Err(e) => {
                tracing::error!(path, dat, error = %e, "invalid geoip file");
                return Self::default();
            }
        };

        // Longest prefix wins; sort descending once.
        rules.sort_by_key(|r| std::cmp::Reverse(r.cidr.prefix));
        tracing::info!(
            count = rules.len(),
            path,
            format = if dat { "dat" } else { "json" },
            "geoip table loaded"
        );
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

fn is_dat(path: &str, raw: &[u8]) -> bool {
    if let Some(ext) = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
    {
        if ext.eq_ignore_ascii_case("dat") {
            return true;
        }
        if ext.eq_ignore_ascii_case("json") {
            return false;
        }
    }
    // Unknown extension: JSON starts with `[` or `{`; protobuf does not.
    raw.iter()
        .find(|b| !b.is_ascii_whitespace())
        .map(|b| *b != b'[' && *b != b'{')
        .unwrap_or(true)
}

fn parse_json(raw: &[u8]) -> Result<Vec<Rule>, String> {
    let parsed: Vec<GeoRule> =
        serde_json::from_slice(raw).map_err(|e| format!("invalid JSON: {e}"))?;
    let mut rules = Vec::with_capacity(parsed.len());
    for r in parsed {
        let Some(cidr) = Cidr::parse(&r.cidr) else {
            tracing::warn!(cidr = %r.cidr, "invalid CIDR in geoip JSON");
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
    Ok(rules)
}

/// `geoip.dat` is a V2Ray `GeoIPList` protobuf:
///
/// ```text
/// GeoIPList { repeated GeoIP entry = 1; }
/// GeoIP { string country_code = 1; repeated CIDR cidr = 2;
///         bool inverse_match = 3; bytes resource_hash = 4; string code = 5; }
/// CIDR { bytes ip = 1; uint32 prefix = 2; string ip_addr = 68000; }
/// ```
///
/// Loyalsoldier's file also contains non-country categories such as
/// `private`/`telegram`; those are ignored because this table drives country
/// scheduling. Province/city/ISP are not present in DAT, so they stay empty.
fn parse_dat(raw: &[u8]) -> Result<Vec<Rule>, String> {
    let mut reader = ProtoReader::new(raw);
    let mut rules = Vec::new();
    while !reader.eof() {
        let (field, wire) = reader.key()?;
        if field == 1 && wire == 2 {
            let entry = reader.bytes()?;
            parse_dat_entry(entry, &mut rules)?;
        } else {
            reader.skip(wire)?;
        }
    }
    Ok(rules)
}

fn parse_dat_entry(data: &[u8], rules: &mut Vec<Rule>) -> Result<(), String> {
    let mut reader = ProtoReader::new(data);
    let mut country = String::new();
    let mut fallback_code = String::new();
    let mut cidrs = Vec::new();
    let mut inverse = false;

    while !reader.eof() {
        let (field, wire) = reader.key()?;
        match (field, wire) {
            (1, 2) => country = String::from_utf8_lossy(reader.bytes()?).trim().to_string(),
            (2, 2) => {
                if let Some(cidr) = parse_dat_cidr(reader.bytes()?)? {
                    cidrs.push(cidr);
                }
            }
            (3, 0) => inverse = reader.varint()? != 0,
            (5, 2) => fallback_code = String::from_utf8_lossy(reader.bytes()?).trim().to_string(),
            _ => reader.skip(wire)?,
        }
    }

    if inverse {
        // The current table cannot represent "all except this CIDR"; skipping
        // is safer than treating it as a normal country match.
        return Ok(());
    }
    let code = if country.is_empty() {
        fallback_code
    } else {
        country
    };
    if !is_country_code(&code) {
        return Ok(());
    }
    let country = code.to_ascii_uppercase();
    for cidr in cidrs {
        rules.push(Rule {
            cidr,
            geo: GeoInfo {
                country: country.clone(),
                province: String::new(),
                city: String::new(),
                isp: String::new(),
            },
        });
    }
    Ok(())
}

fn parse_dat_cidr(data: &[u8]) -> Result<Option<Cidr>, String> {
    let mut reader = ProtoReader::new(data);
    let mut ip_bytes: Option<Vec<u8>> = None;
    let mut ip_addr: Option<String> = None;
    let mut prefix: Option<u32> = None;

    while !reader.eof() {
        let (field, wire) = reader.key()?;
        match (field, wire) {
            (1, 2) => ip_bytes = Some(reader.bytes()?.to_vec()),
            (2, 0) => prefix = Some(reader.varint()? as u32),
            (68000, 2) => {
                ip_addr = Some(String::from_utf8_lossy(reader.bytes()?).trim().to_string())
            }
            _ => reader.skip(wire)?,
        }
    }

    let addr = match ip_bytes.as_deref() {
        Some([a, b, c, d]) => IpAddr::from([*a, *b, *c, *d]),
        Some(bytes) if bytes.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            IpAddr::from(octets)
        }
        Some(_) => return Ok(None),
        None => match ip_addr {
            Some(ref value) => {
                let (host, embedded_prefix) = value
                    .split_once('/')
                    .map(|(h, p)| (h, p.parse::<u8>().ok()))
                    .unwrap_or((value.as_str(), None));
                if prefix.is_none() {
                    prefix = embedded_prefix.map(u32::from);
                }
                match host.trim().parse::<IpAddr>() {
                    Ok(ip) => ip,
                    Err(_) => return Ok(None),
                }
            }
            None => return Ok(None),
        },
    };
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.unwrap_or(max);
    if prefix > max {
        return Ok(None);
    }
    Ok(Some(Cidr {
        addr,
        prefix: prefix as u8,
    }))
}

fn is_country_code(code: &str) -> bool {
    code.len() == 2 && code.chars().all(|c| c.is_ascii_alphabetic())
}

struct ProtoReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ProtoReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn eof(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn varint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = *self
                .data
                .get(self.pos)
                .ok_or_else(|| "truncated varint".to_string())?;
            self.pos += 1;
            if shift >= 64 {
                return Err("varint overflow".into());
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn key(&mut self) -> Result<(u32, u8), String> {
        let key = self.varint()?;
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        if field == 0 {
            return Err("invalid protobuf field 0".into());
        }
        Ok((field, wire))
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.varint()? as usize;
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| "protobuf length overflow".to_string())?;
        if end > self.data.len() {
            return Err("truncated protobuf field".into());
        }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn skip(&mut self, wire: u8) -> Result<(), String> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => self.skip_bytes(8)?,
            2 => {
                self.bytes()?;
            }
            5 => self.skip_bytes(4)?,
            _ => return Err(format!("unsupported protobuf wire type {wire}")),
        }
        Ok(())
    }

    fn skip_bytes(&mut self, n: usize) -> Result<(), String> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| "protobuf skip overflow".to_string())?;
        if end > self.data.len() {
            return Err("truncated protobuf field".into());
        }
        self.pos = end;
        Ok(())
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
    let mut geo = ip.and_then(|ip| state.geo.lookup(ip)).unwrap_or_default();
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

    let nodes = repository::list_nodes(&state.pool)
        .await
        .unwrap_or_default();
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
    _agent: crate::middleware::agent_auth::ScheduleAuth,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                return out;
            }
        }
    }

    fn field(number: u32, data: &[u8]) -> Vec<u8> {
        let mut out = varint(u64::from(number) << 3 | 2);
        out.extend(varint(data.len() as u64));
        out.extend_from_slice(data);
        out
    }

    fn varint_field(number: u32, value: u64) -> Vec<u8> {
        let mut out = varint(u64::from(number) << 3);
        out.extend(varint(value));
        out
    }

    fn cidr(ip: [u8; 4], prefix: u8) -> Vec<u8> {
        let mut out = field(1, &ip);
        out.extend(varint_field(2, u64::from(prefix)));
        out
    }

    fn geoip_entry(code: &str, cidr_bytes: &[u8], inverse: bool) -> Vec<u8> {
        let mut out = field(1, code.as_bytes());
        out.extend(field(2, cidr_bytes));
        if inverse {
            out.extend(varint_field(3, 1));
        }
        out
    }

    fn dat(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in entries {
            out.extend(field(1, entry));
        }
        out
    }

    #[test]
    fn parses_loyalsoldier_dat_country_cidrs() {
        let bytes = dat(&[geoip_entry("cn", &cidr([1, 2, 3, 0], 24), false)]);
        let rules = parse_dat(&bytes).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].geo.country, "CN");
        let table = GeoTable {
            rules: Arc::new(rules),
        };
        assert_eq!(
            table.lookup("1.2.3.9".parse().unwrap()).unwrap().country,
            "CN"
        );
        assert!(table.lookup("1.2.4.9".parse().unwrap()).is_none());
    }

    #[test]
    fn ignores_dat_non_country_and_inverse_entries() {
        let bytes = dat(&[
            geoip_entry("private", &cidr([10, 0, 0, 0], 8), false),
            geoip_entry("telegram", &cidr([91, 108, 0, 0], 16), false),
            geoip_entry("cn", &cidr([1, 2, 3, 0], 24), true),
        ]);
        assert!(parse_dat(&bytes).unwrap().is_empty());
    }

    #[test]
    fn legacy_json_still_loads() {
        let raw = br#"[{"cidr":"1.2.3.0/24","country":"CN","province":"Guangdong"}]"#;
        let rules = parse_json(raw).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].geo.province, "Guangdong");
    }

    #[test]
    fn detects_dat_by_extension_or_content() {
        let protobuf = dat(&[geoip_entry("cn", &cidr([1, 2, 3, 0], 24), false)]);
        assert!(is_dat("/tmp/geoip.dat", &protobuf));
        assert!(!is_dat("/tmp/geoip.json", b"[]"));
        assert!(is_dat("/tmp/unknown", &protobuf));
        assert!(!is_dat("/tmp/unknown", b" [ {\"cidr\":\"1.2.3.0/24\"} ]"));
    }

    #[test]
    fn loads_dat_from_disk() {
        let path = std::env::temp_dir().join(format!(
            "lagran-geoip-{}-{:?}.dat",
            std::process::id(),
            std::thread::current().id()
        ));
        let protobuf = dat(&[geoip_entry("cn", &cidr([1, 2, 3, 0], 24), false)]);
        std::fs::write(&path, protobuf).unwrap();
        let table = GeoTable::load(path.to_str().unwrap());
        assert_eq!(
            table.lookup("1.2.3.4".parse().unwrap()).unwrap().country,
            "CN"
        );
        let _ = std::fs::remove_file(path);
    }
}
