//! Cache key, TTL/RFC-9111 policy, validators and cache status labels.
//!
//! Precedence for a response that is otherwise cacheable:
//!   1. explicit path rule (`ttl_seconds > 0`)
//!   2. `s-maxage`, then `max-age` from the origin `Cache-Control`
//!   3. `Expires` - `Date` (or now, when `Date` is absent)
//!   4. the domain/default TTL
//!
//! `no-store`, `private`, `no-cache` without an explicit rule TTL, `max-age=0`
//! without a rule, and non-trivial `Vary` prevent storing. A cache rule with an
//! explicit TTL may override the origin's `no-cache`; `ignore_cookie` also allows
//! `Vary: Cookie` for deliberately shared static assets.

use axum::http::{header, HeaderMap, Method, Request};
use lagran_cache::CacheEntry;
use regex::Regex;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

/// Standard CDN-style cache status labels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheStatus {
    /// Served from cache within fresh TTL
    Hit,
    /// Not in cache; fetched from origin
    Miss,
    /// Entry existed but hard-expired (treated as miss path)
    Expired,
    /// Non-cacheable method/path (POST etc.)
    Dynamic,
    /// Explicitly bypassed (rule or Cache-Control)
    Bypass,
    /// Conditional request matched (304) from cached etag
    Revalidated,
    /// Served stale content within SWR window
    Stale,
    /// Stale served while background revalidation in progress
    Updating,
    /// No cache decision (errors, rate limit before cache)
    None,
    Unknown,
}

impl CacheStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CacheStatus::Hit => "HIT",
            CacheStatus::Miss => "MISS",
            CacheStatus::Expired => "EXPIRED",
            CacheStatus::Dynamic => "DYNAMIC",
            CacheStatus::Bypass => "BYPASS",
            CacheStatus::Revalidated => "REVALIDATED",
            CacheStatus::Stale => "STALE",
            CacheStatus::Updating => "UPDATING",
            CacheStatus::None => "NONE",
            CacheStatus::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Cache,
    Bypass,
    NoStore,
}

impl RuleAction {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "bypass" | "no_cache" => RuleAction::Bypass,
            "no_store" | "nostore" => RuleAction::NoStore,
            _ => RuleAction::Cache,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RuleAction::Cache => "cache",
            RuleAction::Bypass => "bypass",
            RuleAction::NoStore => "no_store",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheRule {
    pub path_pattern: String,
    /// glob | regex
    pub match_type: String,
    /// Compiled regex for `match_type = regex`; invalid regex is ignored.
    pub regex: Option<Regex>,
    pub ttl_seconds: u64,
    pub priority: i32,
    /// cache | bypass | no_store
    pub action: String,
    /// stale-while-revalidate seconds
    pub swr_seconds: u64,
    pub enabled: bool,
    /// Comma separated methods; empty matches all.
    pub match_methods: String,
    /// Case-insensitive substring of the raw query string.
    pub match_query: String,
    /// Optional case-insensitive response `Content-Type` substring.
    pub match_content_type: String,
    /// `Cache-Control: max-age` override sent to clients (0 = keep origin).
    pub browser_ttl_seconds: u64,
    /// Override the domain's ignore_query setting; `None` inherits it.
    pub ignore_query: Option<bool>,
    /// Cache this rule's responses even when the request carries cookies.
    pub ignore_cookie: bool,
}

impl CacheRule {
    pub fn simple(path: String, ttl: u64, priority: i32) -> Self {
        Self {
            path_pattern: path,
            match_type: "glob".into(),
            regex: None,
            ttl_seconds: ttl,
            priority,
            action: "cache".into(),
            swr_seconds: 0,
            enabled: true,
            match_methods: String::new(),
            match_query: String::new(),
            browser_ttl_seconds: 0,
            ignore_query: None,
            ignore_cookie: false,
            match_content_type: String::new(),
        }
    }

    pub fn action_kind(&self) -> RuleAction {
        RuleAction::parse(&self.action)
    }
}

/// Result of applying the matched path rule before origin headers are known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub action: RuleAction,
    /// `None` means "derive from origin response headers, then default TTL".
    pub ttl_override: Option<u64>,
    pub swr_secs: u64,
    /// Override the `Cache-Control: max-age` we send to clients.
    pub browser_ttl_secs: Option<u64>,
    /// Override the domain's ignore-query-string setting.
    pub ignore_query: Option<bool>,
    /// Cache despite request cookies (opt-in per rule).
    pub ignore_cookie: bool,
}

impl Default for ResolvedPolicy {
    fn default() -> Self {
        Self {
            action: RuleAction::Cache,
            ttl_override: None,
            swr_secs: 0,
            browser_ttl_secs: None,
            ignore_query: None,
            ignore_cookie: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheDecision {
    pub ttl_secs: u64,
    pub swr_secs: u64,
}

#[derive(Debug, Clone)]
pub struct MatchedPolicy {
    pub ttl_seconds: u64,
    pub swr_seconds: u64,
    pub action: String,
    pub browser_ttl_seconds: u64,
    pub ignore_query: Option<bool>,
    pub ignore_cookie: bool,
    pub match_methods: String,
    pub match_query: String,
    pub match_content_type: String,
}

#[derive(Clone, Default)]
pub struct RuleSet {
    inner: Arc<RwLock<Vec<CacheRule>>>,
}

impl RuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn replace(&self, mut rules: Vec<CacheRule>) {
        rules.sort_by_key(|r| std::cmp::Reverse(r.priority));
        *self.inner.write().await = rules;
    }

    pub async fn resolve(&self, path: &str, method: &str, query: &str) -> Option<ResolvedPolicy> {
        let rules = self.inner.read().await;
        match_rule(&rules, path, method, query).map(rule_policy)
    }

    pub async fn match_ttl(&self, path: &str, method: &str, query: &str) -> Option<u64> {
        self.resolve(path, method, query)
            .await
            .map(|p| p.ttl_override.unwrap_or(0))
    }

    pub async fn match_policy(
        &self,
        path: &str,
        method: &str,
        query: &str,
    ) -> Option<MatchedPolicy> {
        let rules = self.inner.read().await;
        match_rule(&rules, path, method, query).map(|r| MatchedPolicy {
            ttl_seconds: r.ttl_seconds,
            swr_seconds: r.swr_seconds,
            action: r.action.clone(),
            browser_ttl_seconds: r.browser_ttl_seconds,
            ignore_query: r.ignore_query,
            ignore_cookie: r.ignore_cookie,
            match_methods: r.match_methods.clone(),
            match_query: r.match_query.clone(),
            match_content_type: r.match_content_type.clone(),
        })
    }
}

/// Highest-priority enabled rule matching path + method + query.
pub fn match_rule<'a>(
    rules: &'a [CacheRule],
    path: &str,
    method: &str,
    query: &str,
) -> Option<&'a CacheRule> {
    let mut best: Option<&CacheRule> = None;
    for r in rules {
        // Content-Type rules can only be decided after the response arrives.
        if !r.enabled
            || !r.match_content_type.trim().is_empty()
            || !request_matches_rule(r, path, method, query)
        {
            continue;
        }
        match best {
            Some(b) if b.priority >= r.priority => {}
            _ => best = Some(r),
        }
    }
    best
}

/// Resolve the effective rule after the origin response headers are known.
/// Content-Type-specific rules participate here; rules without a Content-Type
/// condition still match any response.
pub fn match_rule_for_response<'a>(
    rules: &'a [CacheRule],
    path: &str,
    method: &str,
    query: &str,
    content_type: &str,
) -> Option<&'a CacheRule> {
    let content_type = content_type.trim().to_ascii_lowercase();
    let mut best: Option<&CacheRule> = None;
    for r in rules {
        if !r.enabled || !request_matches_rule(r, path, method, query) {
            continue;
        }
        let needle = r.match_content_type.trim().to_ascii_lowercase();
        if !needle.is_empty() && !content_type.contains(&needle) {
            continue;
        }
        match best {
            Some(b) if b.priority >= r.priority => {}
            _ => best = Some(r),
        }
    }
    best
}

pub fn request_matches_rule(rule: &CacheRule, path: &str, method: &str, query: &str) -> bool {
    rule_path_matches(rule, path)
        && method_matches_rule(&rule.match_methods, method)
        && query_matches_rule(&rule.match_query, query)
}

fn rule_path_matches(rule: &CacheRule, path: &str) -> bool {
    if rule.match_type.eq_ignore_ascii_case("regex") {
        rule.regex
            .as_ref()
            .map(|re| re.is_match(path))
            .unwrap_or(false)
    } else {
        path_matches(&rule.path_pattern, path)
    }
}

fn method_matches_rule(csv: &str, method: &str) -> bool {
    if csv.trim().is_empty() {
        return true;
    }
    csv.split(',')
        .map(str::trim)
        .any(|m| m.eq_ignore_ascii_case(method))
}

fn query_matches_rule(needle: &str, query: &str) -> bool {
    let needle = needle.trim();
    needle.is_empty()
        || query
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
}

pub fn rule_policy(rule: &CacheRule) -> ResolvedPolicy {
    ResolvedPolicy {
        action: rule.action_kind(),
        ttl_override: (rule.ttl_seconds > 0).then_some(rule.ttl_seconds),
        swr_secs: rule.swr_seconds,
        browser_ttl_secs: (rule.browser_ttl_seconds > 0).then_some(rule.browser_ttl_seconds),
        ignore_query: rule.ignore_query,
        ignore_cookie: rule.ignore_cookie,
    }
}

/// Resolve the effective policy for a request from a domain's rule list.
pub fn resolve_rule_policy(
    rules: &[CacheRule],
    path: &str,
    method: &str,
    query: &str,
) -> ResolvedPolicy {
    match_rule(rules, path, method, query)
        .map(rule_policy)
        .unwrap_or_default()
}

pub fn resolve_rule_policy_for_response(
    rules: &[CacheRule],
    path: &str,
    method: &str,
    query: &str,
    content_type: &str,
) -> ResolvedPolicy {
    match_rule_for_response(rules, path, method, query, content_type)
        .map(rule_policy)
        .unwrap_or_default()
}

pub fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "/*" || pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path == prefix
            || path.starts_with(&format!("{prefix}/"))
            || path.starts_with(prefix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    pattern == path
}

#[derive(Debug, Default)]
struct CacheControl {
    no_store: bool,
    no_cache: bool,
    private: bool,
    s_maxage: Option<u64>,
    max_age: Option<u64>,
    swr: Option<u64>,
}

fn parse_cache_control(value: &str) -> CacheControl {
    let mut cc = CacheControl::default();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (name, val) = match part.split_once('=') {
            Some((n, v)) => (
                n.trim().to_ascii_lowercase(),
                Some(v.trim().trim_matches('"')),
            ),
            None => (part.to_ascii_lowercase(), None),
        };
        match name.as_str() {
            "no-store" => cc.no_store = true,
            "no-cache" => cc.no_cache = true,
            "private" => cc.private = true,
            "s-maxage" => cc.s_maxage = val.and_then(|v| v.parse().ok()),
            "max-age" => cc.max_age = val.and_then(|v| v.parse().ok()),
            "stale-while-revalidate" => cc.swr = val.and_then(|v| v.parse().ok()),
            _ => {}
        }
    }
    cc
}

pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Whether a status code can be stored at all.
pub fn status_is_cacheable(status: u16) -> bool {
    matches!(status, 200 | 203 | 204 | 300 | 301 | 308)
}

/// `Vary` is only safe for us when it names fields the cache can safely ignore
/// or explicitly normalise. `Accept-Encoding` is forced to identity upstream;
/// `Accept-Language` is part of the cache key; `Cookie` is allowed only when the
/// matching rule explicitly opts into `ignore_cookie`.
fn vary_allows_storage(vary: Option<&str>, ignore_cookie: bool) -> bool {
    match vary {
        None => true,
        Some(v) => {
            let fields: Vec<&str> = v
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            fields.iter().all(|f| {
                f.eq_ignore_ascii_case("accept-encoding")
                    || f.eq_ignore_ascii_case("accept-language")
                    || (ignore_cookie && f.eq_ignore_ascii_case("cookie"))
            })
        }
    }
}

fn expires_ttl(headers: &[(String, String)]) -> Option<u64> {
    let expires = httpdate::parse_http_date(header_value(headers, "expires")?).ok()?;
    let now = header_value(headers, "date")
        .and_then(|d| httpdate::parse_http_date(d).ok())
        .unwrap_or_else(SystemTime::now);
    Some(
        expires
            .duration_since(now)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

/// Decide the TTL for a response, or `None` when it must not be stored.
pub fn decide_storage(
    status: u16,
    headers: &[(String, String)],
    policy: ResolvedPolicy,
    default_ttl_secs: u64,
) -> Option<CacheDecision> {
    if !status_is_cacheable(status) {
        return None;
    }
    if !vary_allows_storage(header_value(headers, "vary"), policy.ignore_cookie) {
        return None;
    }

    let cc = header_value(headers, "cache-control")
        .map(parse_cache_control)
        .unwrap_or_default();
    if cc.no_store || cc.private {
        return None;
    }
    // `no-cache` means "revalidate", not "never store". An explicit rule TTL is
    // an operator override (for example CSS/JS 7 days), so let it win; without
    // a rule TTL keep the conservative origin behaviour.
    if cc.no_cache && policy.ttl_override.is_none() {
        return None;
    }

    let origin_ttl = cc.s_maxage.or(cc.max_age).or_else(|| expires_ttl(headers));

    // Explicit rule TTL wins over the origin; otherwise honour the origin.
    let ttl = match policy.ttl_override {
        Some(t) => t,
        None => origin_ttl.unwrap_or(default_ttl_secs),
    };
    if ttl == 0 {
        return None;
    }

    let swr = if policy.swr_secs > 0 {
        policy.swr_secs
    } else {
        cc.swr.unwrap_or(0)
    };

    Some(CacheDecision {
        ttl_secs: ttl,
        swr_secs: swr,
    })
}

pub fn request_method_cacheable(method: &Method) -> bool {
    method == Method::GET || method == Method::HEAD
}

/// The WAF clearance cookie is edge-internal and is never forwarded upstream
/// for cacheable requests. It must not make an otherwise public asset
/// non-cacheable.
pub fn has_non_clearance_cookie(headers: &HeaderMap) -> bool {
    let Some(raw) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    raw.split(';').any(|part| {
        let name = part.trim().split_once('=').map(|(k, _)| k.trim()).unwrap_or("");
        !name.is_empty() && !name.eq_ignore_ascii_case("lagran_clearance")
    })
}

/// Requests whose responses must never be served from / stored in the shared
/// cache: authenticated or personalised traffic, conditional-range probes, and
/// explicit `no-store` from the client. `no-cache`/`max-age=0` remain
/// cache-eligible so they can revalidate an existing entry.
pub fn request_bypasses_cache<B>(req: &Request<B>, ignore_cookie: bool) -> bool {
    if req.headers().contains_key(header::AUTHORIZATION)
        || (!ignore_cookie && has_non_clearance_cookie(req.headers()))
        || req.headers().contains_key(header::RANGE)
    {
        return true;
    }
    if let Some(cc) = req
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
    {
        if cc.to_ascii_lowercase().contains("no-store") {
            return true;
        }
    }
    false
}

pub fn cache_key<B>(req: &Request<B>) -> String {
    cache_key_opts(req, false)
}

pub fn cache_key_opts<B>(req: &Request<B>, ignore_query: bool) -> String {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    let path = if ignore_query {
        req.uri().path().to_string()
    } else {
        req.uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string())
    };
    cache_key_for_request(req.method(), host, &path, req.headers())
}

/// Stable cache key including the normalized `Accept-Language` value.
///
/// `Vary: Accept-Language` is accepted by the storage policy, so the key must
/// include the language to avoid serving a Chinese object to an English client
/// (or vice versa). The tag is hashed to keep keys bounded and purge-friendly.
pub fn cache_key_for_request(
    method: &Method,
    host: &str,
    path: &str,
    headers: &HeaderMap,
) -> String {
    let base = cache_key_for(method, host, path);
    let Some(lang) = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
    else {
        return base;
    };
    let normalized = lang
        .split(',')
        .map(|tag| tag.trim().to_ascii_lowercase())
        .filter(|tag| !tag.is_empty())
        .collect::<Vec<_>>()
        .join(",");
    if normalized.is_empty() {
        base
    } else {
        format!("{base}|lang={:x}", fnv1a64(normalized.as_bytes()))
    }
}

/// Stable cache key: `METHOD:host:path[?query]` (host lowercased, port stripped).
pub fn cache_key_for(method: &Method, host: &str, path: &str) -> String {
    let host = host.trim().to_ascii_lowercase();
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.split_once(']').map(|(ip, _)| ip))
        .unwrap_or(&host);
    let host = host.split(':').next().unwrap_or(host);
    format!("{}:{}:{}", method.as_str(), host, path)
}

// ---- validators -----------------------------------------------------------

/// FNV-1a 64-bit: stable across processes and Rust releases (unlike DefaultHasher).
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

pub fn stable_hash_str(s: &str) -> u64 {
    fnv1a64(s.as_bytes())
}

const ETAG_FULL_LIMIT: usize = 64 * 1024;

/// Strong validator over the representation. Large bodies hash their ends plus
/// the length so hashing stays O(1)-ish per request.
pub fn compute_etag(entry: &CacheEntry) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let body = &entry.body;
    let chunk = if body.len() <= ETAG_FULL_LIMIT {
        &body[..]
    } else {
        &body[..32 * 1024]
    };
    for b in chunk {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    if body.len() > ETAG_FULL_LIMIT {
        let tail = &body[body.len() - 32 * 1024..];
        for b in tail {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h ^= entry.status as u64;
    h ^= (body.len() as u64).rotate_left(17);
    format!("\"{h:016x}\"")
}

pub fn etag_matches(if_none_match: &str, etag: &str) -> bool {
    let target = normalize_etag(etag);
    for candidate in if_none_match.split(',') {
        let candidate = candidate.trim();
        if candidate == "*" {
            return true;
        }
        if normalize_etag(candidate) == target {
            return true;
        }
    }
    false
}

fn normalize_etag(s: &str) -> &str {
    let s = s.trim();
    s.strip_prefix("W/").unwrap_or(s).trim_matches('"')
}

// ---- helpers used by the proxy handler ------------------------------------

/// Remove hop-by-hop / connection-managed headers before forwarding either way.
pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Headers that must not be replayed from a cached response.
pub fn is_uncacheable_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "set-cookie"
        || n == "set-cookie2"
        || n == "content-length"
        || n == "age"
        || n == "date"
        || n == "etag"
        || is_hop_by_hop(&n)
}

/// Response headers that are dropped when proxying back to the client.
pub fn strip_response_headers(headers: &mut HeaderMap) {
    let names: Vec<String> = headers
        .keys()
        .filter(|k| {
            let n = k.as_str().to_ascii_lowercase();
            is_hop_by_hop(&n) || n == "content-length"
        })
        .map(|k| k.as_str().to_string())
        .collect();
    for n in names {
        if let Ok(name) = axum::http::HeaderName::from_bytes(n.as_bytes()) {
            headers.remove(name);
        }
    }
}

pub fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn secs_until_epoch(epoch: u64) -> u64 {
    epoch.saturating_sub(now_epoch_secs())
}

pub fn duration_secs(d: Duration) -> u64 {
    d.as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn rule(path: &str, ttl: u64, priority: i32, action: &str, swr: u64) -> CacheRule {
        CacheRule {
            path_pattern: path.into(),
            match_type: "glob".into(),
            regex: None,
            ttl_seconds: ttl,
            priority,
            action: action.into(),
            swr_seconds: swr,
            enabled: true,
            match_methods: String::new(),
            match_query: String::new(),
            browser_ttl_seconds: 0,
            ignore_query: None,
            ignore_cookie: false,
            match_content_type: String::new(),
        }
    }

    fn rule_with(
        path: &str,
        priority: i32,
        enabled: bool,
        methods: &str,
        query: &str,
        browser_ttl: u64,
        ignore_query: Option<bool>,
    ) -> CacheRule {
        CacheRule {
            path_pattern: path.into(),
            match_type: "glob".into(),
            regex: None,
            ttl_seconds: 60,
            priority,
            action: "cache".into(),
            swr_seconds: 0,
            enabled,
            match_methods: methods.into(),
            match_query: query.into(),
            browser_ttl_seconds: browser_ttl,
            ignore_query,
            ignore_cookie: false,
            match_content_type: String::new(),
        }
    }

    #[test]
    fn path_matching_variants() {
        assert!(path_matches("/*", "/anything"));
        assert!(path_matches("/static/*", "/static/a.js"));
        assert!(path_matches("/static/*", "/static"));
        assert!(path_matches("/img*", "/img/x.png"));
        assert!(path_matches("/imag*", "/images/x.png"));
        assert!(!path_matches("/img*", "/other"));
        assert!(path_matches("/exact", "/exact"));
        assert!(!path_matches("/exact", "/exact2"));
    }

    #[test]
    fn regex_rule_matches_file_suffix() {
        let mut r = rule("/", 86400, 100, "cache", 0);
        r.match_type = "regex".into();
        r.regex = Some(Regex::new(r"\.(css|js)$").unwrap());
        assert!(request_matches_rule(&r, "/assets/app.js", "GET", ""));
        assert!(request_matches_rule(&r, "/style.css", "GET", ""));
        assert!(!request_matches_rule(&r, "/index.html", "GET", ""));
        assert!(!request_matches_rule(&r, "/app.js.map", "GET", ""));
    }

    #[test]
    fn content_type_rule_matches_only_after_response() {
        let mut html_bypass = rule("/*", 0, 100, "bypass", 0);
        html_bypass.match_content_type = "text/html".into();
        let js_cache = rule("/*", 3600, 10, "cache", 0);
        let rules = vec![html_bypass, js_cache];

        // Request-time matching must defer Content-Type rules.
        assert_eq!(
            resolve_rule_policy(&rules, "/app.js", "GET", "").action,
            RuleAction::Cache
        );

        let html = resolve_rule_policy_for_response(
            &rules,
            "/",
            "GET",
            "",
            "text/html; charset=utf-8",
        );
        assert_eq!(html.action, RuleAction::Bypass);

        let js = resolve_rule_policy_for_response(
            &rules,
            "/app.js",
            "GET",
            "",
            "application/javascript",
        );
        assert_eq!(js.action, RuleAction::Cache);
        assert_eq!(js.ttl_override, Some(3600));
    }

    #[test]
    fn rule_priority_and_action() {
        let rules = vec![
            rule("/*", 60, 0, "cache", 0),
            rule("/api/*", 0, 10, "bypass", 0),
        ];
        let p = resolve_rules(&rules, "/api/users");
        assert_eq!(p.action, RuleAction::Bypass);
        assert_eq!(p.ttl_override, None);

        let p = resolve_rules(&rules, "/img/a.png");
        assert_eq!(p.action, RuleAction::Cache);
        assert_eq!(p.ttl_override, Some(60));
    }

    fn resolve_rules(rules: &[CacheRule], path: &str) -> ResolvedPolicy {
        match_rule(rules, path, "GET", "")
            .map(rule_policy)
            .unwrap_or_default()
    }

    #[test]
    fn conditions_filter_and_disable_rules() {
        let rules = vec![
            rule_with("/api/*", 0, true, "", "", 0, None),
            rule_with("/api/*", 20, true, "GET,POST", "", 0, None),
            rule_with("/api/*", 30, true, "GET", "debug=1", 0, None),
            rule_with("/api/*", 40, false, "GET", "", 0, None),
        ];
        assert_eq!(
            match_rule(&rules, "/api/x", "GET", "").unwrap().priority,
            20
        );
        assert_eq!(
            match_rule(&rules, "/api/x", "POST", "debug=1")
                .unwrap()
                .priority,
            20
        );
        assert_eq!(
            match_rule(&rules, "/api/x", "GET", "a=1&DEBUG=1")
                .unwrap()
                .priority,
            30
        );
        assert_eq!(
            match_rule(&rules, "/api/x", "DELETE", "").unwrap().priority,
            0
        );
    }

    #[test]
    fn policy_carries_browser_ttl_and_query_override() {
        let rules = vec![rule_with("/img/*", 5, true, "", "", 3600, Some(true))];
        let p = resolve_rules(&rules, "/img/a.png");
        assert_eq!(p.browser_ttl_secs, Some(3600));
        assert_eq!(p.ignore_query, Some(true));
    }

    fn hdrs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn origin_max_age_used_when_no_rule() {
        let d = decide_storage(
            200,
            &hdrs(&[(
                "Cache-Control",
                "public, max-age=120, stale-while-revalidate=30",
            )]),
            ResolvedPolicy::default(),
            60,
        )
        .unwrap();
        assert_eq!(d.ttl_secs, 120);
        assert_eq!(d.swr_secs, 30);
    }

    #[test]
    fn s_maxage_wins_over_max_age() {
        let d = decide_storage(
            200,
            &hdrs(&[("cache-control", "max-age=10, s-maxage=300")]),
            ResolvedPolicy::default(),
            60,
        )
        .unwrap();
        assert_eq!(d.ttl_secs, 300);
    }

    #[test]
    fn rule_ttl_overrides_origin() {
        let policy = ResolvedPolicy {
            action: RuleAction::Cache,
            ttl_override: Some(5),
            swr_secs: 10,
            browser_ttl_secs: None,
            ignore_query: None,
            ignore_cookie: false,
        };
        let d =
            decide_storage(200, &hdrs(&[("cache-control", "max-age=600")]), policy, 60).unwrap();
        assert_eq!(d.ttl_secs, 5);
        assert_eq!(d.swr_secs, 10);
    }

    #[test]
    fn no_store_private_no_cache_block_storage() {
        let policy = ResolvedPolicy::default();
        for cc in ["no-store", "private", "no-cache", "max-age=0"] {
            assert!(
                decide_storage(200, &hdrs(&[("cache-control", cc)]), policy, 60).is_none(),
                "{cc} must not be cached"
            );
        }
    }

    #[test]
    fn explicit_rule_ttl_overrides_origin_no_cache() {
        let mut policy = ResolvedPolicy::default();
        policy.ttl_override = Some(604_800);
        assert!(
            decide_storage(
                200,
                &hdrs(&[("cache-control", "no-cache")]),
                policy,
                60
            )
            .is_some(),
            "CSS/JS rule TTL must override origin no-cache"
        );
        assert!(
            decide_storage(
                200,
                &hdrs(&[("cache-control", "no-store")]),
                policy,
                60
            )
            .is_none()
        );
        assert!(
            decide_storage(
                200,
                &hdrs(&[("cache-control", "private")]),
                policy,
                60
            )
            .is_none()
        );
    }

    #[test]
    fn vary_blocks_unless_encoding_only() {
        let policy = ResolvedPolicy::default();
        assert!(decide_storage(200, &hdrs(&[("vary", "Accept-Encoding")]), policy, 60).is_some());
        assert!(decide_storage(200, &hdrs(&[("vary", "User-Agent")]), policy, 60).is_none());
    }

    #[test]
    fn ignore_cookie_allows_vary_cookie() {
        let mut policy = ResolvedPolicy::default();
        assert!(decide_storage(200, &hdrs(&[("vary", "Cookie")]), policy, 60).is_none());
        policy.ignore_cookie = true;
        assert!(
            decide_storage(200, &hdrs(&[("vary", "Cookie")]), policy, 60).is_some(),
            "explicit ignore_cookie must allow Vary: Cookie static assets"
        );
        assert!(
            decide_storage(200, &hdrs(&[("vary", "Cookie, Accept-Encoding")]), policy, 60)
                .is_some()
        );
    }

    #[test]
    fn expires_is_used_as_fallback() {
        let expires = httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(90));
        let d = decide_storage(
            200,
            &hdrs(&[("expires", &expires)]),
            ResolvedPolicy::default(),
            60,
        )
        .unwrap();
        assert!(d.ttl_secs >= 85 && d.ttl_secs <= 90, "got {}", d.ttl_secs);
    }

    #[test]
    fn uncacheable_status_and_empty_ttl() {
        assert!(decide_storage(404, &[], ResolvedPolicy::default(), 60).is_none());
        assert!(decide_storage(200, &[], ResolvedPolicy::default(), 0).is_none());
    }

    #[test]
    fn etag_stability_and_matching() {
        let e1 = CacheEntry::new(200, vec![], Bytes::from_static(b"hello world"));
        let e2 = CacheEntry::new(200, vec![], Bytes::from_static(b"hello world"));
        assert_eq!(compute_etag(&e1), compute_etag(&e2));
        let tag = compute_etag(&e1);
        assert!(etag_matches(&tag, &tag));
        assert!(etag_matches(&format!("W/{tag}"), &tag));
        assert!(etag_matches(&format!("\"other\", {tag}"), &tag));
        assert!(etag_matches("*", &tag));
        assert!(!etag_matches("\"nope\"", &tag));
    }

    #[test]
    fn request_cacheability_rules() {
        let plain = Request::builder()
            .uri("http://cdn.test/a.js")
            .body(())
            .unwrap();
        assert!(request_method_cacheable(plain.method()));
        assert!(!request_bypasses_cache(&plain, false));

        for (name, value) in [
            ("authorization", "Bearer x"),
            ("cookie", "sid=1"),
            ("range", "bytes=0-10"),
            ("cache-control", "no-store"),
        ] {
            let req = Request::builder()
                .uri("http://cdn.test/a.js")
                .header(name, value)
                .body(())
                .unwrap();
            assert!(request_bypasses_cache(&req, false), "{name} should bypass");
        }

        let cookie = Request::builder()
            .uri("http://cdn.test/a.js")
            .header("cookie", "sid=1")
            .body(())
            .unwrap();
        assert!(!request_bypasses_cache(&cookie, true));

        let clearance = Request::builder()
            .uri("http://cdn.test/a.js")
            .header("cookie", "lagran_clearance=1793089070.908f")
            .body(())
            .unwrap();
        assert!(
            !request_bypasses_cache(&clearance, false),
            "edge-internal clearance cookie must not bypass public caching"
        );

        let clearance_plus_session = Request::builder()
            .uri("http://cdn.test/a.js")
            .header("cookie", "lagran_clearance=1793089070.908f; sid=1")
            .body(())
            .unwrap();
        assert!(
            request_bypasses_cache(&clearance_plus_session, false),
            "a real application cookie must still bypass"
        );

        let reload = Request::builder()
            .uri("http://cdn.test/a.js")
            .header("cache-control", "max-age=0")
            .body(())
            .unwrap();
        assert!(!request_bypasses_cache(&reload, false));

        let revalidate = Request::builder()
            .uri("http://cdn.test/a.js")
            .header("cache-control", "no-cache")
            .body(())
            .unwrap();
        assert!(
            !request_bypasses_cache(&revalidate, false),
            "no-cache must revalidate, not bypass"
        );
    }

    #[test]
    fn cache_key_normalizes_host_and_includes_method() {
        let req = Request::builder()
            .method("GET")
            .uri("http://CDN.Example:8080/a/b?x=1")
            .header("host", "CDN.Example:8080")
            .body(())
            .unwrap();
        assert_eq!(cache_key(&req), "GET:cdn.example:/a/b?x=1");
        assert_eq!(cache_key_opts(&req, true), "GET:cdn.example:/a/b");
    }
}
