//! Lightweight Web Application Firewall evaluated at the edge.
//!
//! Scope (deliberately dependency-free):
//! * IP allow/deny lists (IPv4/IPv6, CIDR);
//! * managed signatures for SQL injection, XSS, path traversal and common
//!   vulnerability scanners;
//! * per-domain custom rules (field + operator + value, block/allow/log).
//!
//! The body is not inspected: WAF runs before the proxy reads a request body,
//! and CDN traffic is dominated by GET/HEAD. Managed checks cover the
//! path/query/UA/referer, which is where most automated attacks show up.

use axum::http::HeaderMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WafMode {
    /// Record matches but let traffic through (rollout / tuning).
    Monitor,
    /// Reject matched traffic with the WAF block page.
    #[default]
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafAction {
    Block,
    Allow,
    Log,
    /// Serve a JS proof-of-work challenge; a signed clearance cookie lets the
    /// client through on subsequent requests.
    Challenge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafField {
    Path,
    Query,
    UserAgent,
    Referer,
    Method,
    Ip,
}

impl WafField {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "path" | "uri" => Some(WafField::Path),
            "query" | "args" => Some(WafField::Query),
            "user_agent" | "user-agent" | "ua" => Some(WafField::UserAgent),
            "referer" | "referrer" => Some(WafField::Referer),
            "method" => Some(WafField::Method),
            "ip" => Some(WafField::Ip),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafOp {
    Contains,
    Equals,
    Prefix,
    Suffix,
}

impl WafOp {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "contains" => Some(WafOp::Contains),
            "equals" | "eq" => Some(WafOp::Equals),
            "prefix" | "starts_with" => Some(WafOp::Prefix),
            "suffix" | "ends_with" => Some(WafOp::Suffix),
            _ => None,
        }
    }

    fn matches(self, haystack: &str, needle: &str) -> bool {
        match self {
            WafOp::Contains => haystack.contains(needle),
            WafOp::Equals => haystack == needle,
            WafOp::Prefix => haystack.starts_with(needle),
            WafOp::Suffix => haystack.ends_with(needle),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WafRule {
    pub name: String,
    pub field: WafField,
    pub op: WafOp,
    /// Lower-cased at construction time.
    pub value: String,
    pub action: WafAction,
    pub priority: i32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct ManagedRules {
    pub sqli: bool,
    pub xss: bool,
    pub traversal: bool,
    pub scanners: bool,
}

impl Default for ManagedRules {
    fn default() -> Self {
        Self {
            sqli: true,
            xss: true,
            traversal: true,
            scanners: true,
        }
    }
}

/// IPv4/IPv6 network with a CIDR prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    pub fn parse(input: &str) -> Option<Self> {
        let input = input.trim();
        if input.is_empty() {
            return None;
        }
        let (addr_part, prefix_part) = match input.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (input, None),
        };
        let addr: IpAddr = addr_part.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_part {
            Some(p) => p.trim().parse::<u8>().ok()?,
            None => max,
        };
        if prefix > max {
            return None;
        }
        Some(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
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

pub fn parse_ip(input: &str) -> Option<IpAddr> {
    let input = input.trim();
    // Bracket form is common in Host headers, not here; keep strict.
    input.parse::<IpAddr>().ok()
}

#[derive(Debug, Clone)]
pub struct WafConfig {
    pub enabled: bool,
    pub mode: WafMode,
    pub managed: ManagedRules,
    pub rules: Vec<WafRule>,
    pub ip_allow: Vec<IpNet>,
    pub ip_deny: Vec<IpNet>,
    /// Number of leading hex zeroes the challenge hash must have (1..=6).
    pub challenge_difficulty: u8,
    /// How long a solved challenge keeps the client cleared (seconds).
    pub challenge_ttl_secs: u64,
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: WafMode::Block,
            managed: ManagedRules::default(),
            rules: Vec::new(),
            ip_allow: Vec::new(),
            ip_deny: Vec::new(),
            challenge_difficulty: 4,
            challenge_ttl_secs: 1800,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WafVerdict {
    pub action: WafAction,
    pub rule_name: String,
    /// sqli / xss / traversal / scanners / ip_deny / custom
    pub category: String,
}

impl WafVerdict {
    pub fn is_block(&self) -> bool {
        self.action == WafAction::Block
    }
}

/// Request view used by the evaluator (already decoded where needed).
pub struct WafRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub user_agent: &'a str,
    pub referer: &'a str,
    pub ip: Option<IpAddr>,
    #[allow(dead_code)]
    pub headers: &'a HeaderMap,
}

const SQLI: &[&str] = &[
    "union select",
    "union/**/select",
    "union all select",
    "' or '1'='1",
    "\" or \"1\"=\"1",
    "or 1=1--",
    "and 1=1--",
    "information_schema",
    "sleep(",
    "benchmark(",
    "extractvalue(",
    "updatexml(",
    "load_file(",
    "' or 1=1",
];

const XSS: &[&str] = &[
    "<script",
    "</script",
    "javascript:",
    "onerror=",
    "onload=",
    "onmouseover=",
    "<iframe",
    "srcdoc=",
    "document.cookie",
];

const TRAVERSAL: &[&str] = &[
    "../",
    "..\\",
    "/etc/passwd",
    "/etc/shadow",
    "boot.ini",
    "win.ini",
    "..%2f",
    "%2e%2e",
];

const SCANNER_UA: &[&str] = &[
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "acunetix",
    "nessus",
    "dirbuster",
    "zgrab",
    "wpscan",
];

const SCANNER_PATH: &[&str] = &[
    "/.env",
    "/.git/",
    "/wp-login.php",
    "/wp-admin",
    "/phpmyadmin",
    "/actuator",
    "/server-status",
    "/.DS_Store",
];

/// Percent-decode then lower-case (ASCII). Invalid escapes are kept verbatim.
pub fn decode_lower(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_ascii_lowercase()
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

/// Evaluate the WAF for one request. Returns the first matching verdict.
pub fn evaluate(cfg: &WafConfig, req: &WafRequest) -> Option<WafVerdict> {
    if !cfg.enabled {
        return None;
    }

    // An explicit allow-list entry bypasses every other check.
    if let Some(ip) = req.ip {
        if cfg.ip_allow.iter().any(|net| net.contains(ip)) {
            return None;
        }
        if cfg.ip_deny.iter().any(|net| net.contains(ip)) {
            return Some(WafVerdict {
                action: WafAction::Block,
                rule_name: "IP 黑名单".into(),
                category: "ip_deny".into(),
            });
        }
    }

    let path = decode_lower(req.path);
    let query = decode_lower(req.query);
    let ua = decode_lower(req.user_agent);
    let referer = decode_lower(req.referer);
    let haystack = format!("{path}?{query} {ua} {referer}");

    if cfg.managed.sqli && contains_any(&haystack, SQLI) {
        return Some(verdict("SQL 注入", "sqli"));
    }
    if cfg.managed.xss && contains_any(&haystack, XSS) {
        return Some(verdict("XSS 跨站脚本", "xss"));
    }
    if cfg.managed.traversal && contains_any(&haystack, TRAVERSAL) {
        return Some(verdict("路径穿越", "traversal"));
    }
    if cfg.managed.scanners {
        if contains_any(&ua, SCANNER_UA) {
            return Some(verdict("恶意扫描器", "scanners"));
        }
        if contains_any(&path, SCANNER_PATH) {
            return Some(verdict("敏感路径探测", "scanners"));
        }
    }

    // Custom rules: highest priority first, first match wins.
    let mut rules: Vec<&WafRule> = cfg.rules.iter().filter(|r| r.enabled).collect();
    rules.sort_by_key(|r| std::cmp::Reverse(r.priority));
    let method = req.method.to_ascii_lowercase();
    let ip_text = req.ip.map(|i| i.to_string()).unwrap_or_default();
    for rule in rules {
        let value: &str = match rule.field {
            WafField::Path => &path,
            WafField::Query => &query,
            WafField::UserAgent => &ua,
            WafField::Referer => &referer,
            WafField::Method => &method,
            WafField::Ip => &ip_text,
        };
        if rule.op.matches(value, &rule.value) {
            return Some(WafVerdict {
                action: rule.action,
                rule_name: rule.name.clone(),
                category: "custom".into(),
            });
        }
    }

    None
}

fn verdict(name: &str, category: &str) -> WafVerdict {
    WafVerdict {
        action: WafAction::Block,
        rule_name: name.to_string(),
        category: category.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> WafConfig {
        WafConfig {
            enabled: true,
            mode: WafMode::Block,
            managed: ManagedRules::default(),
            rules: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            challenge_difficulty: 4,
            challenge_ttl_secs: 1800,
        }
    }

    fn req<'a>(
        headers: &'a HeaderMap,
        path: &'a str,
        query: &'a str,
        ua: &'a str,
    ) -> WafRequest<'a> {
        WafRequest {
            method: "GET",
            path,
            query,
            user_agent: ua,
            referer: "",
            ip: Some("198.51.100.10".parse().unwrap()),
            headers,
        }
    }

    #[test]
    fn detects_sqli_xss_and_traversal() {
        let c = cfg();
        let h = HeaderMap::new();
        assert_eq!(
            evaluate(
                &c,
                &req(&h, "/search", "q=1%27%20or%20%271%27=%271", "curl")
            )
            .unwrap()
            .category,
            "sqli"
        );
        assert_eq!(
            evaluate(
                &c,
                &req(&h, "/x", "q=%3Cscript%3Ealert(1)%3C/script%3E", "curl"),
            )
            .unwrap()
            .category,
            "xss"
        );
        assert_eq!(
            evaluate(&c, &req(&h, "/../../etc/passwd", "", "curl"))
                .unwrap()
                .category,
            "traversal"
        );
        assert!(evaluate(&c, &req(&h, "/", "", "curl")).is_none());
    }

    #[test]
    fn detects_scanners_by_ua_and_path() {
        let c = cfg();
        let h = HeaderMap::new();
        assert_eq!(
            evaluate(&c, &req(&h, "/", "", "sqlmap/1.7"))
                .unwrap()
                .category,
            "scanners"
        );
        assert_eq!(
            evaluate(&c, &req(&h, "/.git/config", "", "curl"))
                .unwrap()
                .category,
            "scanners"
        );
    }

    #[test]
    fn disabled_waf_never_matches() {
        let mut c = cfg();
        c.enabled = false;
        let h = HeaderMap::new();
        assert!(evaluate(&c, &req(&h, "/", "q=union select", "sqlmap")).is_none());
    }

    #[test]
    fn ip_allow_and_deny_lists() {
        let mut c = cfg();
        let h = HeaderMap::new();
        c.ip_deny.push(IpNet::parse("203.0.113.0/24").unwrap());
        let mut r = req(&h, "/", "q=union select", "curl");
        r.ip = Some("203.0.113.9".parse().unwrap());
        let v = evaluate(&c, &r).unwrap();
        assert_eq!(v.category, "ip_deny");

        c.ip_allow.push(IpNet::parse("203.0.113.9").unwrap());
        assert!(evaluate(&c, &r).is_none(), "allow-list bypasses everything");

        // A different address in the denied range is still blocked.
        r.ip = Some("203.0.113.10".parse().unwrap());
        assert_eq!(evaluate(&c, &r).unwrap().category, "ip_deny");
    }

    #[test]
    fn cidr_parsing_and_matching() {
        let net = IpNet::parse("10.0.0.0/8").unwrap();
        assert!(net.contains("10.1.2.3".parse().unwrap()));
        assert!(!net.contains("11.1.2.3".parse().unwrap()));
        assert!(IpNet::parse("10.0.0.0/33").is_none());
        assert!(IpNet::parse("not-an-ip").is_none());

        let v6 = IpNet::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn custom_rule_priority_and_actions() {
        let mut c = cfg();
        c.managed = ManagedRules {
            sqli: false,
            xss: false,
            traversal: false,
            scanners: false,
        };
        c.rules = vec![
            WafRule {
                name: "allow health".into(),
                field: WafField::Path,
                op: WafOp::Equals,
                value: "/health".into(),
                action: WafAction::Allow,
                priority: 100,
                enabled: true,
            },
            WafRule {
                name: "block admin".into(),
                field: WafField::Path,
                op: WafOp::Prefix,
                value: "/admin".into(),
                action: WafAction::Block,
                priority: 10,
                enabled: true,
            },
        ];

        let h = HeaderMap::new();
        assert_eq!(
            evaluate(&c, &req(&h, "/admin/users", "", "curl"))
                .unwrap()
                .rule_name,
            "block admin"
        );
        let allow = evaluate(&c, &req(&h, "/health", "", "curl")).unwrap();
        assert_eq!(allow.action, WafAction::Allow);
        assert!(evaluate(&c, &req(&h, "/public", "", "curl")).is_none());
    }

    #[test]
    fn log_rule_does_not_block() {
        let mut c = cfg();
        c.managed = ManagedRules {
            sqli: false,
            xss: false,
            traversal: false,
            scanners: false,
        };
        c.rules = vec![WafRule {
            name: "observe api".into(),
            field: WafField::Path,
            op: WafOp::Prefix,
            value: "/api/".into(),
            action: WafAction::Log,
            priority: 0,
            enabled: true,
        }];
        let h = HeaderMap::new();
        let v = evaluate(&c, &req(&h, "/api/x", "", "curl")).unwrap();
        assert_eq!(v.action, WafAction::Log);
        assert!(!v.is_block());
    }

    #[test]
    fn decodes_percent_escapes() {
        assert_eq!(decode_lower("%3Cscript%3E"), "<script>");
        assert_eq!(decode_lower("A%20B"), "a b");
        assert_eq!(decode_lower("100%"), "100%");
    }
}
