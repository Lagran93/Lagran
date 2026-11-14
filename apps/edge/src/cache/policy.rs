//! Cache key, TTL/RFC-9111 policy, validators and cache status labels.
//!
//! Precedence for a response that is otherwise cacheable:
//!   1. explicit path rule (`ttl_seconds > 0`)
//!   2. `s-maxage`, then `max-age` from the origin `Cache-Control`
//!   3. `Expires` - `Date` (or now, when `Date` is absent)
//!   4. the domain/default TTL
//!
//! `no-store`, `private`, `no-cache`, `max-age=0`/`s-maxage=0`, a
//! `Set-Cookie`, and non-trivial `Vary` prevent storing. `no-cache` is never
//! overridden by a path rule: a cache may store such a response only if it
//! revalidates before every reuse, and this edge either serves fresh entries
//! or bypasses, so it must not be kept as a fresh entry. `s-maxage`,
//! `must-revalidate` and `proxy-revalidate` disable stale serving.
//! `ignore_cookie` lets cookie-bearing requests share a cache object, but a
//! `Vary: Cookie` response is still rejected because Cookie is not in the key.

use axum::http::{header, HeaderMap, Method, Request};
use lagran_cache::CacheEntry;
use regex::Regex;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

/// Internal cache metadata: which validator came from the origin.
/// Values: `etag`, `last-modified`, `computed`.
pub const VALIDATOR_SOURCE_HEADER: &str = "x-lagran-validator-source";

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
        let s = s.trim();
        if s.eq_ignore_ascii_case("bypass") || s.eq_ignore_ascii_case("no_cache") {
            RuleAction::Bypass
        } else if s.eq_ignore_ascii_case("no_store") || s.eq_ignore_ascii_case("nostore") {
            RuleAction::NoStore
        } else {
            RuleAction::Cache
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
    /// Rule override for cache-key header ignore. None inherits the domain.
    /// Empty string explicitly ignores none.
    pub ignore_key_headers: Option<String>,
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
            ignore_key_headers: None,
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
    /// Effective key-header ignore mask (ORIGIN / ACCEPT_LANGUAGE).
    pub key_ignore: u8,
    /// Rule tri-state for Origin: None inherits the domain, Some(true) ignores,
    /// Some(false) keeps it in the key.
    pub key_ignore_origin: Option<bool>,
    /// Rule tri-state for Accept-Language.
    pub key_ignore_language: Option<bool>,
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
            key_ignore: 0,
            key_ignore_origin: None,
            key_ignore_language: None,
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
    let content_type = content_type.trim();
    let mut best: Option<&CacheRule> = None;
    for r in rules {
        if !r.enabled || !request_matches_rule(r, path, method, query) {
            continue;
        }
        let needle = r.match_content_type.trim();
        if !needle.is_empty() && !contains_ascii_case_insensitive(content_type, needle) {
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
    needle.is_empty() || contains_ascii_case_insensitive(query, needle)
}

/// Match with the same ASCII-only case folding as `to_ascii_lowercase`,
/// without allocating lowercase copies for every configured rule.
fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    needle.is_empty()
        || (needle.len() <= haystack.len()
            && haystack
                .windows(needle.len())
                .any(|window| window.eq_ignore_ascii_case(needle)))
}

pub fn rule_policy(rule: &CacheRule) -> ResolvedPolicy {
    let header_modes = header_modes(rule.ignore_key_headers.as_deref());
    ResolvedPolicy {
        action: rule.action_kind(),
        ttl_override: (rule.ttl_seconds > 0).then_some(rule.ttl_seconds),
        swr_secs: rule.swr_seconds,
        browser_ttl_secs: (rule.browser_ttl_seconds > 0).then_some(rule.browser_ttl_seconds),
        ignore_query: rule.ignore_query,
        ignore_cookie: rule.ignore_cookie,
        key_ignore: 0,
        key_ignore_origin: header_modes.origin,
        key_ignore_language: header_modes.language,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyHeaderModes {
    /// None = inherit the domain, Some(true) = ignore, Some(false) = keep.
    pub origin: Option<bool>,
    pub language: Option<bool>,
}

/// Parse the rule's tri-state header policy. New values look like
/// `origin=inherit,accept-language=ignore`; old values remain supported as a
/// full override list (`origin,accept-language`, `''`, or absent).
pub fn header_modes(value: Option<&str>) -> KeyHeaderModes {
    let Some(value) = value else {
        return KeyHeaderModes::default();
    };
    let value = value.trim();
    if value.is_empty() {
        return KeyHeaderModes {
            origin: Some(false),
            language: Some(false),
        };
    }
    if !value.contains('=') {
        return KeyHeaderModes {
            origin: Some(
                value
                    .split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("origin")),
            ),
            language: Some(
                value
                    .split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("accept-language")),
            ),
        };
    }
    let mut modes = KeyHeaderModes::default();
    for part in value.split(',') {
        let Some((name, state)) = part.split_once('=') else {
            continue;
        };
        let state = state.trim();
        let state = if state.eq_ignore_ascii_case("ignore") {
            Some(true)
        } else if state.eq_ignore_ascii_case("keep") {
            Some(false)
        } else if state.eq_ignore_ascii_case("inherit") {
            None
        } else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("origin") {
            modes.origin = state;
        } else if name.eq_ignore_ascii_case("accept-language") {
            modes.language = state;
        }
    }
    modes
}

pub const KEY_IGNORE_ORIGIN: u8 = 1;
pub const KEY_IGNORE_ACCEPT_LANGUAGE: u8 = 2;

pub fn parse_key_ignore_headers(value: &str) -> u8 {
    let mut mask = 0;
    for part in value.split(',') {
        let name = part.trim();
        if name.eq_ignore_ascii_case("origin") {
            mask |= KEY_IGNORE_ORIGIN;
        } else if name.eq_ignore_ascii_case("accept-language") {
            mask |= KEY_IGNORE_ACCEPT_LANGUAGE;
        }
    }
    mask
}

pub fn key_ignore_mask_for_header(name: &str) -> u8 {
    if name.eq_ignore_ascii_case("origin") {
        KEY_IGNORE_ORIGIN
    } else if name.eq_ignore_ascii_case("accept-language") {
        KEY_IGNORE_ACCEPT_LANGUAGE
    } else {
        0
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

/// Fill the domain default when the matched rule did not explicitly set a
/// cache-key header policy.
pub fn apply_key_ignore_default(policy: &mut ResolvedPolicy, domain_value: &str) {
    let mut mask = parse_key_ignore_headers(domain_value);
    if let Some(ignore) = policy.key_ignore_origin {
        if ignore {
            mask |= KEY_IGNORE_ORIGIN;
        } else {
            mask &= !KEY_IGNORE_ORIGIN;
        }
    }
    if let Some(ignore) = policy.key_ignore_language {
        if ignore {
            mask |= KEY_IGNORE_ACCEPT_LANGUAGE;
        } else {
            mask &= !KEY_IGNORE_ACCEPT_LANGUAGE;
        }
    }
    policy.key_ignore = mask;
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

pub fn resolve_rule_policy_for_response_with_domain(
    rules: &[CacheRule],
    path: &str,
    method: &str,
    query: &str,
    content_type: &str,
    domain_key_ignore: &str,
) -> ResolvedPolicy {
    let mut policy = resolve_rule_policy_for_response(rules, path, method, query, content_type);
    apply_key_ignore_default(&mut policy, domain_key_ignore);
    policy
}

pub fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "/*" || pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        // The final historical starts_with(prefix) branch already subsumes
        // the equality and slash-child checks; avoid formatting a temp String.
        return path.starts_with(prefix);
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
    must_revalidate: bool,
    proxy_revalidate: bool,
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
            "must-revalidate" => cc.must_revalidate = true,
            "proxy-revalidate" => cc.proxy_revalidate = true,
            "s-maxage" => cc.s_maxage = val.and_then(|v| v.parse().ok()),
            "max-age" => cc.max_age = val.and_then(|v| v.parse().ok()),
            "stale-while-revalidate" => cc.swr = val.and_then(|v| v.parse().ok()),
            _ => {}
        }
    }
    cc
}

/// Multiple field lines are equivalent to one comma-separated field value
/// (RFC 9110 §5.3). Cache-Control/Vary must not silently ignore the second line.
fn joined_header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    let values: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(values.join(","))
    }
}

/// `decide_storage_reason` for a live `HeaderMap`, without materialising it.
///
/// Response paths used to call `header_vec()` first, allocating two `String`s per
/// header (20-40 headers, so ~40-80 allocations) just to answer four lookups and
/// then drop the vector.
pub fn decide_storage_reason_map(
    status: u16,
    headers: &http::HeaderMap,
    policy: ResolvedPolicy,
    default_ttl_secs: u64,
) -> Result<CacheDecision, &'static str> {
    decide_storage_with(
        status,
        &|name| headers.get(name).and_then(|v| v.to_str().ok()),
        &|name| joined_map_value(headers, name),
        policy,
        default_ttl_secs,
    )
}

/// Join repeated header values without allocating for the single-value case.
fn joined_map_value(headers: &http::HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?.trim();
    if first.is_empty() {
        return None;
    }
    if values.next().is_none() {
        return Some(first.to_string());
    }
    let mut out = String::from(first);
    for value in headers.get_all(name).iter().skip(1) {
        let value = value.to_str().ok().map(str::trim).unwrap_or("");
        if value.is_empty() {
            continue;
        }
        out.push_str(", ");
        out.push_str(value);
    }
    Some(out)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Whether a status code can be stored at all.
pub fn status_is_cacheable(status: u16) -> bool {
    matches!(status, 200 | 203 | 204 | 300 | 301 | 308)
}

/// Decide the TTL for a response, or the operator-facing reason it cannot be
/// stored.
pub fn decide_storage_reason(
    status: u16,
    headers: &[(String, String)],
    policy: ResolvedPolicy,
    default_ttl_secs: u64,
) -> Result<CacheDecision, &'static str> {
    decide_storage_with(
        status,
        &|name| header_value(headers, name),
        &|name| joined_header_value(headers, name),
        policy,
        default_ttl_secs,
    )
}

/// Shared decision logic over an abstract header source.
///
/// `get` returns the first value of a header, `joined` the comma-joined values,
/// and `raw` the first value verbatim (used for HTTP dates). Callers backed by a
/// `HeaderMap` avoid allocating; callers backed by cache metadata pass closures
/// over their owned pairs.
fn decide_storage_with<'a>(
    status: u16,
    get: &dyn Fn(&str) -> Option<&'a str>,
    joined: &dyn Fn(&str) -> Option<String>,
    policy: ResolvedPolicy,
    default_ttl_secs: u64,
) -> Result<CacheDecision, &'static str> {
    if !status_is_cacheable(status) {
        return Err("status");
    }
    if get("set-cookie").is_some() {
        return Err("set-cookie");
    }
    if let Some(field) = vary_reject_reason(
        joined("vary").as_deref(),
        policy.ignore_cookie,
        policy.key_ignore,
    ) {
        return Err(field);
    }

    let cc = joined("cache-control")
        .map(|v| parse_cache_control(&v))
        .unwrap_or_default();
    if cc.no_store {
        return Err("no-store");
    }
    if cc.private {
        return Err("private");
    }
    // no-cache means "revalidate before every reuse". This edge does not keep a
    // separate validator-only entry, so the only standards-correct choice is to
    // not store it. A path rule must not turn it into a fresh shared object.
    if cc.no_cache {
        return Err("no-cache");
    }

    let origin_ttl = cc.s_maxage.or(cc.max_age).or_else(|| {
        // Inline rather than calling `expires_ttl`: that takes a slice, and a
        // closure returning a borrowed value cannot be passed through a trait
        // object without a higher-ranked lifetime bound.
        let expires = httpdate::parse_http_date(get("expires")?).ok()?;
        let now = get("date")
            .and_then(|d| httpdate::parse_http_date(d).ok())
            .unwrap_or_else(SystemTime::now);
        Some(
            expires
                .duration_since(now)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
    });
    // Explicit zero lifetime is an origin instruction, not an invitation for a
    // path rule to make the response fresh.
    if origin_ttl == Some(0) {
        return Err("ttl-zero");
    }

    // Explicit rule TTL wins over the origin; otherwise honour the origin.
    let mut ttl = match policy.ttl_override {
        Some(t) => t,
        None => origin_ttl.unwrap_or(default_ttl_secs),
    };
    if ttl == 0 {
        return Err("ttl-zero");
    }
    // RFC 9111 §4.2.3: a response's age reduces its remaining freshness. This
    // used to be ignored, so `max-age=60, Age:59` from an upstream cache was
    // stored as fresh for another full minute. A skewed `Date` is capped at one
    // day so a broken origin clock cannot zero every TTL.
    let origin_age = {
        let header_age = get("age")
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let date_age = get("date")
            .and_then(|value| httpdate::parse_http_date(value).ok())
            .and_then(|date| SystemTime::now().duration_since(date).ok())
            .map(|age| age.as_secs().min(86_400))
            .unwrap_or(0);
        header_age.max(date_age)
    };
    ttl = ttl.saturating_sub(origin_age);
    if ttl == 0 {
        return Err("ttl-zero");
    }

    // s-maxage implies proxy-revalidate for shared caches. must-revalidate and
    // proxy-revalidate forbid serving stale on normal cache hits.
    let must_revalidate = cc.must_revalidate || cc.proxy_revalidate || cc.s_maxage.is_some();
    let swr = if must_revalidate {
        0
    } else if policy.swr_secs > 0 {
        policy.swr_secs
    } else {
        cc.swr.unwrap_or(0)
    };

    Ok(CacheDecision {
        // Clamp before these values become deadlines: `parse::<u64>()` accepts
        // values that overflow every `SystemTime`/`Instant` addition downstream.
        ttl_secs: lagran_cache::clamp_ttl_secs(ttl),
        swr_secs: lagran_cache::clamp_ttl_secs(swr),
    })
}

/// Decide the TTL for a response, or `None` when it must not be stored.
pub fn decide_storage(
    status: u16,
    headers: &[(String, String)],
    policy: ResolvedPolicy,
    default_ttl_secs: u64,
) -> Option<CacheDecision> {
    decide_storage_reason(status, headers, policy, default_ttl_secs).ok()
}

fn vary_reject_reason(
    vary: Option<&str>,
    _ignore_cookie: bool,
    key_ignore: u8,
) -> Option<&'static str> {
    let v = vary?;
    for field in v.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if field.eq_ignore_ascii_case("accept-encoding") {
            // Only the identity representation is fetched/stored, so it is
            // safe to serve it to any Accept-Encoding client.
            continue;
        }
        if field.eq_ignore_ascii_case("accept-language") || field.eq_ignore_ascii_case("origin") {
            if cache_key_header_ignored(field, key_ignore) {
                // The operator explicitly removed this header from the key.
                // Treat the Vary field as ignored too, otherwise the response
                // cannot be cached at all on sites with a blanket CORS Vary.
                continue;
            }
            continue;
        }
        if field.eq_ignore_ascii_case("access-control-request-method")
            || field.eq_ignore_ascii_case("access-control-request-headers")
            || field.eq_ignore_ascii_case("access-control-request-private-network")
        {
            // These are OPTIONS preflight headers and are absent from normal
            // GET/HEAD requests. Some CORS middlewares add them to every
            // response's Vary; ignoring them here keeps GET/HEAD cacheable
            // without putting ACR* into the GET/HEAD cache key. OPTIONS
            // preflight caching is not enabled yet; revisit this when it is.
            continue;
        }
        if field.eq_ignore_ascii_case("user-agent") {
            return Some("vary:user-agent");
        }
        if field.eq_ignore_ascii_case("cookie") {
            return Some("vary:cookie");
        }
        if field == "*" {
            return Some("vary:*");
        }
        return Some("vary");
    }
    None
}

/// Header names removed from the cache key by edge configuration. Vary on any
/// of these must make the response uncacheable instead of mixing variants.
static CACHE_KEY_IGNORED_HEADERS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

pub fn configure_cache_key_ignored_headers(headers: Vec<String>) {
    let normalized: Vec<String> = headers
        .into_iter()
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect();
    let _ = CACHE_KEY_IGNORED_HEADERS.set(normalized);
}

fn cache_key_header_ignored(name: &str, key_ignore: u8) -> bool {
    (key_ignore & key_ignore_mask_for_header(name)) != 0
        || CACHE_KEY_IGNORED_HEADERS
            .get()
            .is_some_and(|headers| headers.iter().any(|entry| entry.eq_ignore_ascii_case(name)))
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
        let name = part
            .trim()
            .split_once('=')
            .map(|(k, _)| k.trim())
            .unwrap_or("");
        !name.is_empty() && !name.eq_ignore_ascii_case("lagran_clearance")
    })
}

/// Requests whose responses must never be served from / stored in the shared
/// cache: authenticated or personalised traffic, client `no-store`/`no-cache`
/// (`max-age=0` and `Pragma: no-cache`), conditional-range probes. A request
/// that demands revalidation bypasses the fresh-hit path; fetching from origin
/// is standards-correct when this edge has no per-request revalidation loop.
/// Why a request bypasses the shared cache. The returned value is exposed as
/// `X-Lagran-Cache-Reason` for operator diagnostics.
pub fn request_bypass_reason<B>(req: &Request<B>, ignore_cookie: bool) -> Option<&'static str> {
    request_bypass_reason_headers(req.headers(), ignore_cookie)
}

pub fn request_bypass_reason_headers(
    headers: &HeaderMap,
    ignore_cookie: bool,
) -> Option<&'static str> {
    if headers.contains_key(header::AUTHORIZATION) {
        return Some("authorization");
    }
    if !ignore_cookie && has_non_clearance_cookie(headers) {
        return Some("cookie");
    }
    if let Some(reason) = request_cache_control_reason(headers) {
        return Some(reason);
    }
    None
}

fn request_cache_control_reason(headers: &HeaderMap) -> Option<&'static str> {
    for value in headers.get_all(header::CACHE_CONTROL).iter() {
        let Ok(cc) = value.to_str() else {
            continue;
        };
        for part in cc.split(',') {
            let part = part.trim();
            let name = part.split('=').next().unwrap_or(part).trim();
            if name.eq_ignore_ascii_case("no-store") {
                return Some("no-store");
            }
            if name.eq_ignore_ascii_case("no-cache") {
                return Some("request-no-cache");
            }
            if let Some((name, value)) = part.split_once('=') {
                if name.trim().eq_ignore_ascii_case("max-age")
                    && value.trim().trim_matches('"').parse::<u64>().ok() == Some(0)
                {
                    return Some("request-max-age-0");
                }
            }
        }
    }
    for value in headers.get_all(header::PRAGMA).iter() {
        let Ok(pragma) = value.to_str() else {
            continue;
        };
        if pragma
            .split(',')
            .map(|p| p.trim())
            .any(|p| p.eq_ignore_ascii_case("no-cache"))
        {
            return Some("request-pragma-no-cache");
        }
    }
    None
}

pub fn request_bypasses_cache<B>(req: &Request<B>, ignore_cookie: bool) -> bool {
    request_bypass_reason(req, ignore_cookie).is_some()
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

/// Stable cache key including request headers covered by accepted `Vary`
/// fields. `Accept-Language` and CORS request headers are hashed into the key
/// so `Vary: Origin`/preflight variants can be stored without leaking a
/// response to a different origin.
pub fn cache_key_for_request(
    method: &Method,
    host: &str,
    path: &str,
    headers: &HeaderMap,
) -> String {
    cache_key_for_request_with_mask(method, host, path, headers, 0, &[])
}

/// Cache key with an explicit list of request headers that must not
/// participate. Used when a deployment knows those headers do not vary the
/// response body (for example a single-language site ignoring
/// `Accept-Language`, or a fixed CORS origin ignoring `Origin`).
pub fn cache_key_for_request_with_ignored(
    method: &Method,
    host: &str,
    path: &str,
    headers: &HeaderMap,
    ignore_headers: &[String],
) -> String {
    cache_key_for_request_with_mask(method, host, path, headers, 0, ignore_headers)
}

pub fn cache_key_for_request_with_mask(
    method: &Method,
    host: &str,
    path: &str,
    headers: &HeaderMap,
    key_ignore: u8,
    ignore_headers: &[String],
) -> String {
    let host = crate::config::registry::normalize_host(host);
    cache_key_for_normalized_request(
        method.as_str(),
        &host,
        path,
        headers,
        key_ignore,
        ignore_headers,
    )
}

/// Build a cache key when the caller already holds a normalized host and a
/// canonical method string. This avoids re-normalizing the host and cloning a
/// `Method` on every request.
pub fn cache_key_for_normalized_request(
    method: &str,
    host: &str,
    path: &str,
    headers: &HeaderMap,
    key_ignore: u8,
    ignore_headers: &[String],
) -> String {
    let ignored = |name: &str| {
        (key_ignore & key_ignore_mask_for_header(name)) != 0
            || ignore_headers
                .iter()
                .any(|entry| entry.eq_ignore_ascii_case(name))
    };
    let mut key = cache_key_for_normalized(method, host, path);
    if !ignored("accept-language") {
        if let Some(lang) = headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok())
        {
            append_normalized_vary_hash(&mut key, "lang", lang);
        }
    }
    if !ignored("origin") {
        if let Some(value) = headers.get("origin").and_then(|v| v.to_str().ok()) {
            append_normalized_vary_hash(&mut key, "origin", value);
        }
    }
    // Access-Control-Request-* only exist on CORS preflight OPTIONS. They are
    // deliberately not part of GET/HEAD keys: preflight caching is not enabled
    // yet, and adding them to ordinary requests only fragments the cache.
    if *method == Method::OPTIONS {
        for (name, label) in [
            ("access-control-request-method", "acrm"),
            ("access-control-request-headers", "acrh"),
            ("access-control-request-private-network", "acrpn"),
        ] {
            if ignored(name) {
                continue;
            }
            if let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) {
                append_normalized_vary_hash(&mut key, label, value);
            }
        }
    }
    key
}

fn append_normalized_vary_hash(key: &mut String, label: &str, value: &str) {
    let Some(hash) = fnv1a64_normalized_csv(value) else {
        return;
    };
    key.push('|');
    key.push_str(label);
    key.push('=');
    push_hex(hash, key);
}

fn fnv1a64_normalized_csv(value: &str) -> Option<u64> {
    let mut hash = FNV_OFFSET_BASIS;
    let mut found = false;
    for part in value.split(',') {
        let part = part.trim().as_bytes();
        if part.is_empty() {
            continue;
        }
        if found {
            hash = fnv1a64_byte(hash, b',');
        }
        for byte in part {
            hash = fnv1a64_byte(hash, byte.to_ascii_lowercase());
        }
        found = true;
    }
    found.then_some(hash)
}

fn push_hex(mut value: u64, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buffer = [0_u8; 16];
    let mut start = buffer.len();
    loop {
        start -= 1;
        buffer[start] = HEX[(value & 0x0f) as usize];
        value >>= 4;
        if value == 0 {
            break;
        }
    }
    if let Ok(hex) = std::str::from_utf8(&buffer[start..]) {
        out.push_str(hex);
    }
}

/// Stable cache key: `METHOD:host:path[?query]`.
///
/// The host goes through [`crate::config::registry::normalize_host`], the same
/// function that keys the domain registry. Using a second, subtly different
/// normalization here is what allowed one domain's objects to be stored under a
/// key another domain could produce.
pub fn cache_key_for(method: &Method, host: &str, path: &str) -> String {
    let host = crate::config::registry::normalize_host(host);
    cache_key_for_normalized(method.as_str(), &host, path)
}

fn cache_key_for_normalized(method: &str, host: &str, path: &str) -> String {
    let mut key = String::with_capacity(
        method
            .len()
            .saturating_add(host.len())
            .saturating_add(path.len())
            .saturating_add(48),
    );
    key.push_str(method);
    key.push(':');
    key.push_str(host);
    key.push(':');
    key.push_str(path);
    key
}

// ---- validators -----------------------------------------------------------

/// FNV-1a 64-bit: stable across processes and Rust releases (unlike DefaultHasher).
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

#[inline]
fn fnv1a64_byte(hash: u64, byte: u8) -> u64 {
    (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
}

pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for b in bytes {
        hash = fnv1a64_byte(hash, *b);
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
    // Above the full-hash limit only the head and tail are hashed, which is not
    // a representation hash. Emit a weak validator so `If-None-Match` can still
    // match, but `If-Range` (which requires a strong validator) cannot silently
    // resume a changed object.
    if body.len() > ETAG_FULL_LIMIT {
        format!("W/\"{h:016x}\"")
    } else {
        format!("\"{h:016x}\"")
    }
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
            | "alt-svc"
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
        || n == "x-lagran-cache-reason"
        || n == "x-lagran-validator-source"
        || is_hop_by_hop(&n)
}

/// Response headers that are dropped when proxying back to the client.
pub fn strip_response_headers(headers: &mut HeaderMap) {
    let names: Vec<String> = headers
        .keys()
        .filter(|k| {
            let n = k.as_str().to_ascii_lowercase();
            is_hop_by_hop(&n)
                || n == "content-length"
                || n == "x-lagran-cache-reason"
                || n == "x-lagran-validator-source"
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
    use axum::http::HeaderValue;
    use bytes::Bytes;

    #[test]
    fn strips_alt_svc_from_origin_responses() {
        let mut headers = HeaderMap::new();
        headers.insert("alt-svc", HeaderValue::from_static("h3=\":443\""));
        headers.insert("content-type", HeaderValue::from_static("text/html"));
        strip_response_headers(&mut headers);
        assert!(headers.get("alt-svc").is_none());
        assert!(headers.get("content-type").is_some());
    }

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
            ignore_key_headers: None,
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
            ignore_key_headers: None,
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
        // Preserve the old broad prefix behavior of a trailing `/*` rule.
        assert!(path_matches("/static/*", "/static2/app.js"));
    }

    #[test]
    fn case_insensitive_rule_search_matches_ascii_lowercase_semantics() {
        for (haystack, needle) in [
            ("DEBUG=1", "debug=1"),
            ("application/JSON; charset=utf-8", "JSON"),
            ("路径?值=Ä", "值=Ä"),
            ("aBc", "BCd"),
            ("abc", ""),
        ] {
            assert_eq!(
                contains_ascii_case_insensitive(haystack, needle),
                haystack
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase()),
                "haystack={haystack:?}, needle={needle:?}"
            );
        }
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

        let html =
            resolve_rule_policy_for_response(&rules, "/", "GET", "", "text/html; charset=utf-8");
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
    fn oversized_ttl_and_swr_are_clamped() {
        let d = decide_storage(
            200,
            &hdrs(&[("cache-control", "max-age=18446744073709551615")]),
            ResolvedPolicy::default(),
            60,
        )
        .unwrap();
        assert_eq!(d.ttl_secs, lagran_cache::MAX_TTL_SECS);

        let d = decide_storage(
            200,
            &hdrs(&[(
                "cache-control",
                "max-age=60, stale-while-revalidate=18446744073709551615",
            )]),
            ResolvedPolicy::default(),
            60,
        )
        .unwrap();
        assert_eq!(d.ttl_secs, 60);
        assert_eq!(d.swr_secs, lagran_cache::MAX_TTL_SECS);

        // A rule may carry the same out-of-range value; it is clamped too.
        let policy = ResolvedPolicy {
            ttl_override: Some(u64::MAX),
            swr_secs: u64::MAX,
            ..ResolvedPolicy::default()
        };
        let d = decide_storage(200, &hdrs(&[("cache-control", "max-age=60")]), policy, 60).unwrap();
        assert_eq!(d.ttl_secs, lagran_cache::MAX_TTL_SECS);
        assert_eq!(d.swr_secs, lagran_cache::MAX_TTL_SECS);
    }

    #[test]
    fn origin_age_reduces_ttl() {
        let d = decide_storage(
            200,
            &hdrs(&[("cache-control", "max-age=60"), ("age", "45")]),
            ResolvedPolicy::default(),
            60,
        )
        .unwrap();
        assert_eq!(d.ttl_secs, 15);

        assert!(decide_storage(
            200,
            &hdrs(&[("cache-control", "max-age=60"), ("age", "60")]),
            ResolvedPolicy::default(),
            60,
        )
        .is_none());
    }

    #[test]
    fn large_computed_etag_is_weak() {
        let entry = CacheEntry::new(200, vec![], bytes::Bytes::from(vec![7u8; 128 * 1024]));
        let etag = compute_etag(&entry);
        assert!(etag.starts_with("W/"), "got {etag}");
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
            key_ignore: 0,
            key_ignore_origin: None,
            key_ignore_language: None,
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
    fn explicit_rule_ttl_cannot_override_origin_no_cache() {
        let policy = ResolvedPolicy {
            ttl_override: Some(604_800),
            ..Default::default()
        };
        assert!(
            decide_storage(200, &hdrs(&[("cache-control", "no-cache")]), policy, 60).is_none(),
            "no-cache requires revalidation; a rule TTL must not create a fresh shared entry"
        );
        assert!(decide_storage(200, &hdrs(&[("cache-control", "no-store")]), policy, 60).is_none());
        assert!(decide_storage(200, &hdrs(&[("cache-control", "private")]), policy, 60).is_none());
        assert!(
            decide_storage(200, &hdrs(&[("cache-control", "max-age=0")]), policy, 60).is_none(),
            "explicit zero freshness must not be overridden by a rule TTL"
        );
    }

    #[test]
    fn proxy_revalidation_disables_stale_while_revalidate() {
        let d = decide_storage(
            200,
            &hdrs(&[("cache-control", "s-maxage=60, stale-while-revalidate=120")]),
            ResolvedPolicy::default(),
            60,
        )
        .unwrap();
        assert_eq!(d.ttl_secs, 60);
        assert_eq!(d.swr_secs, 0, "s-maxage implies proxy-revalidate");
    }

    #[test]
    fn multiple_cache_control_lines_are_combined() {
        let headers = hdrs(&[
            ("cache-control", "max-age=60"),
            ("cache-control", "no-store"),
        ]);
        assert!(decide_storage(200, &headers, ResolvedPolicy::default(), 60).is_none());
    }

    #[test]
    fn vary_blocks_unless_encoding_only() {
        let policy = ResolvedPolicy::default();
        assert!(decide_storage(200, &hdrs(&[("vary", "Accept-Encoding")]), policy, 60).is_some());
        assert!(decide_storage(200, &hdrs(&[("vary", "User-Agent")]), policy, 60).is_none());
    }

    #[test]
    fn cors_vary_is_allowed_and_cache_keyed() {
        let policy = ResolvedPolicy::default();
        assert!(
            decide_storage(200, &hdrs(&[("vary", "origin")]), policy, 60).is_some(),
            "Origin Vary is cacheable because GET/HEAD keys carry Origin"
        );
        assert!(
            decide_storage(
                200,
                &hdrs(&[(
                    "vary",
                    "access-control-request-method, access-control-request-headers"
                )]),
                policy,
                60
            )
            .is_some(),
            "GET/HEAD ignore preflight-only Vary fields so CORS middleware headers do not disable caching"
        );

        let method = Method::GET;
        let mut first = HeaderMap::new();
        first.insert("origin", "https://a.example".parse().unwrap());
        let mut second = HeaderMap::new();
        second.insert("origin", "https://b.example".parse().unwrap());
        let a = cache_key_for_request(&method, "cdn.test", "/file.mp4", &first);
        let b = cache_key_for_request(&method, "cdn.test", "/file.mp4", &second);
        assert_ne!(a, b);
        assert!(a.contains("|origin="));
        let plain = cache_key_for_request(&method, "cdn.test", "/file.mp4", &HeaderMap::new());
        assert_ne!(plain, a);
    }

    #[test]
    fn domain_and_rule_key_ignore_masks() {
        assert_eq!(parse_key_ignore_headers("origin"), KEY_IGNORE_ORIGIN);
        assert_eq!(
            parse_key_ignore_headers("accept-language, origin"),
            KEY_IGNORE_ORIGIN | KEY_IGNORE_ACCEPT_LANGUAGE
        );
        let mut policy = ResolvedPolicy::default();
        apply_key_ignore_default(&mut policy, "accept-language");
        assert_eq!(policy.key_ignore, KEY_IGNORE_ACCEPT_LANGUAGE);
        policy.key_ignore_origin = Some(true);
        apply_key_ignore_default(&mut policy, "accept-language");
        assert_eq!(
            policy.key_ignore,
            KEY_IGNORE_ORIGIN | KEY_IGNORE_ACCEPT_LANGUAGE
        );

        let mut headers = HeaderMap::new();
        headers.insert("origin", "https://a.example".parse().unwrap());
        headers.insert("accept-language", "zh-CN".parse().unwrap());
        let no_ignore = cache_key_for_request(&Method::GET, "cdn.test", "/x", &headers);
        let ignored = cache_key_for_request_with_mask(
            &Method::GET,
            "cdn.test",
            "/x",
            &headers,
            KEY_IGNORE_ORIGIN | KEY_IGNORE_ACCEPT_LANGUAGE,
            &[],
        );
        assert!(!ignored.contains("|origin="));
        assert!(!ignored.contains("|lang="));
        assert_ne!(no_ignore, ignored);

        let policy = ResolvedPolicy {
            key_ignore: KEY_IGNORE_ORIGIN,
            ..Default::default()
        };
        assert!(decide_storage(200, &hdrs(&[("vary", "origin")]), policy, 60).is_some());
    }

    #[test]
    fn rule_key_ignore_overrides_domain() {
        let mut rule = CacheRule::simple("/api/*".into(), 60, 10);
        rule.ignore_key_headers = Some("origin=ignore,accept-language=inherit".into());
        let mut policy = rule_policy(&rule);
        assert_eq!(policy.key_ignore_origin, Some(true));
        assert_eq!(policy.key_ignore_language, None);
        apply_key_ignore_default(&mut policy, "accept-language");
        assert_eq!(
            policy.key_ignore,
            KEY_IGNORE_ORIGIN | KEY_IGNORE_ACCEPT_LANGUAGE
        );

        rule.ignore_key_headers = Some("origin=keep,accept-language=keep".into());
        let mut policy = rule_policy(&rule);
        apply_key_ignore_default(&mut policy, "accept-language");
        assert_eq!(policy.key_ignore, 0);
    }

    #[test]
    fn regex_rule_can_ignore_language() {
        let mut rule = CacheRule::simple(r"\.(css|js|bin)$".into(), 60, 0);
        rule.match_type = "regex".into();
        rule.regex = Some(regex::Regex::new(r"\.(css|js|bin)$").unwrap());
        rule.ignore_key_headers = Some("origin=ignore,accept-language=ignore".into());
        let mut policy = rule_policy(&rule);
        apply_key_ignore_default(&mut policy, "");
        assert_eq!(
            policy.key_ignore,
            KEY_IGNORE_ORIGIN | KEY_IGNORE_ACCEPT_LANGUAGE
        );

        let mut headers = HeaderMap::new();
        headers.insert("accept-language", "zh-CN,zh;q=0.9".parse().unwrap());
        let key = cache_key_for_request_with_mask(
            &Method::GET,
            "test.akgo.net",
            "/testfile.10m.bin",
            &headers,
            policy.key_ignore,
            &[],
        );
        assert_eq!(key, "GET:test.akgo.net:/testfile.10m.bin");
    }

    #[test]
    fn preflight_headers_only_affect_options_keys() {
        let mut headers = HeaderMap::new();
        headers.insert("access-control-request-method", "PUT".parse().unwrap());
        headers.insert("origin", "https://a.example".parse().unwrap());
        let get = cache_key_for_request(&Method::GET, "cdn.test", "/api", &headers);
        let mut origin_only = HeaderMap::new();
        origin_only.insert("origin", "https://a.example".parse().unwrap());
        let get_origin = cache_key_for_request(&Method::GET, "cdn.test", "/api", &origin_only);
        assert!(!get.contains("|acrm="));
        assert_eq!(get, get_origin, "ACR* must not fragment GET keys");

        let options = cache_key_for_request(&Method::OPTIONS, "cdn.test", "/api", &headers);
        assert!(options.contains("|acrm="));
        assert_ne!(options, get);
    }

    #[test]
    fn normalized_vary_hash_matches_joined_lowercase_value() {
        for value in ["", " , ", "zh-CN, en;q=0.8", " A ,, B ", "路径,Ä"] {
            let normalized = value
                .split(',')
                .map(|part| part.trim().to_ascii_lowercase())
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(",");
            let expected = (!normalized.is_empty()).then(|| fnv1a64(normalized.as_bytes()));
            assert_eq!(fnv1a64_normalized_csv(value), expected, "value={value:?}");
        }
    }

    #[test]
    fn hex_appending_matches_standard_formatting() {
        for value in [0, 1, 15, 16, 0x1234_abcd, u64::MAX] {
            let mut out = String::new();
            push_hex(value, &mut out);
            assert_eq!(out, format!("{value:x}"));
        }
    }

    #[test]
    fn ignored_cache_key_headers_share_one_object() {
        let method = Method::GET;
        let mut headers = HeaderMap::new();
        headers.insert("accept-language", "zh-CN,zh;q=0.9".parse().unwrap());
        headers.insert("origin", "https://www.example.com".parse().unwrap());
        let plain = cache_key_for_request(&method, "cdn.test", "/app.js", &HeaderMap::new());
        let varied = cache_key_for_request(&method, "cdn.test", "/app.js", &headers);
        assert_ne!(plain, varied);
        let ignored = vec!["accept-language".to_string(), "origin".to_string()];
        assert_eq!(
            cache_key_for_request_with_ignored(&method, "cdn.test", "/app.js", &headers, &ignored),
            plain
        );
    }

    #[test]
    fn vary_cookie_is_rejected() {
        let mut policy = ResolvedPolicy::default();
        assert!(decide_storage(200, &hdrs(&[("vary", "Cookie")]), policy, 60).is_none());
        policy.ignore_cookie = true;
        assert!(
            decide_storage(200, &hdrs(&[("vary", "Cookie")]), policy, 60).is_none(),
            "the key does not carry Cookie, so a Vary: Cookie response must not be stored"
        );
        assert!(decide_storage(
            200,
            &hdrs(&[("vary", "Cookie, Accept-Encoding")]),
            policy,
            60
        )
        .is_none());
    }

    #[test]
    fn vary_on_ignored_header_is_ignored() {
        configure_cache_key_ignored_headers(vec!["accept-language".into()]);
        assert!(decide_storage(
            200,
            &hdrs(&[("vary", "Accept-Language")]),
            ResolvedPolicy::default(),
            60
        )
        .is_some());
    }

    #[test]
    fn vary_star_is_rejected() {
        assert!(
            decide_storage(200, &hdrs(&[("vary", "*")]), ResolvedPolicy::default(), 60).is_none()
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
            ("cache-control", "no-store"),
        ] {
            let req = Request::builder()
                .uri("http://cdn.test/a.js")
                .header(name, value)
                .body(())
                .unwrap();
            assert!(request_bypasses_cache(&req, false), "{name} should bypass");
        }

        // Range is handled by the range-slice path, not as a cache bypass.
        let range = Request::builder()
            .uri("http://cdn.test/a.js")
            .header("range", "bytes=0-10")
            .body(())
            .unwrap();
        assert!(!request_bypasses_cache(&range, false));
        assert_eq!(request_bypass_reason(&range, false), None);

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
        assert!(request_bypasses_cache(&reload, false));
        assert_eq!(
            request_bypass_reason(&reload, false),
            Some("request-max-age-0")
        );

        let revalidate = Request::builder()
            .uri("http://cdn.test/a.js")
            .header("cache-control", "no-cache")
            .body(())
            .unwrap();
        assert!(
            request_bypasses_cache(&revalidate, false),
            "a request no-cache must not be served a fresh shared entry"
        );
        assert_eq!(
            request_bypass_reason(&revalidate, false),
            Some("request-no-cache")
        );

        let pragma = Request::builder()
            .uri("http://cdn.test/a.js")
            .header("pragma", "no-cache")
            .body(())
            .unwrap();
        assert_eq!(
            request_bypass_reason(&pragma, false),
            Some("request-pragma-no-cache")
        );
    }

    /// The cache key and the domain registry must agree on host normalization:
    /// any divergence stores one domain's objects under a key another domain
    /// can produce.
    #[test]
    fn cache_key_host_matches_registry_normalization() {
        use crate::config::registry::normalize_host;
        let method = Method::GET;
        for raw in [
            "Example.COM:443",
            "example.com.",
            "[2001:db8::1]:8080",
            "2001:db8::1",
            "cdn.test:8080",
        ] {
            let key = cache_key_for(&method, raw, "/a");
            let expected = format!("GET:{}:/a", normalize_host(raw));
            assert_eq!(key, expected, "host {raw}");
        }
        // A non-port suffix must not collide with the bare host.
        assert_ne!(
            cache_key_for(&method, "example.com:evil", "/a"),
            cache_key_for(&method, "example.com", "/a")
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
    /// The borrowed and owned entry points must agree.
    ///
    /// `decide_storage_reason_map` exists only to skip materialising a header
    /// vector on the response path. If the two ever diverge, caching decisions
    /// would depend on which data plane handled the request.
    #[test]
    fn map_and_slice_decisions_agree() {
        let policy = ResolvedPolicy::default();
        let cases: &[&[(&str, &str)]] = &[
            &[],
            &[("cache-control", "max-age=600")],
            &[("cache-control", "no-store")],
            &[("cache-control", "private")],
            &[("cache-control", "no-cache")],
            &[("cache-control", "max-age=0")],
            &[("set-cookie", "sid=1")],
            &[("vary", "*")],
            &[("cache-control", "s-maxage=120")],
            &[("expires", "Thu, 01 Jan 2099 00:00:00 GMT")],
            &[("cache-control", "max-age=60"), ("set-cookie", "a=1")],
        ];
        for case in cases {
            let slice: Vec<(String, String)> = case
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let mut map = http::HeaderMap::new();
            for (k, v) in case.iter() {
                map.insert(
                    http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    http::header::HeaderValue::from_str(v).unwrap(),
                );
            }
            let owned = decide_storage_reason(200, &slice, policy, 3600);
            let borrowed = decide_storage_reason_map(200, &map, policy, 3600);
            match (owned, borrowed) {
                (Ok(a), Ok(b)) => {
                    assert_eq!(a.ttl_secs, b.ttl_secs, "ttl differs for {case:?}");
                    assert_eq!(a.swr_secs, b.swr_secs, "swr differs for {case:?}");
                }
                (Err(a), Err(b)) => assert_eq!(a, b, "reject reason differs for {case:?}"),
                (a, b) => panic!("diverged for {case:?}: {a:?} vs {b:?}"),
            }
        }
    }

    /// Repeated header values are joined identically on both paths.
    #[test]
    fn repeated_headers_join_the_same_way() {
        let policy = ResolvedPolicy::default();
        let slice = vec![
            ("cache-control".to_string(), "max-age=60".to_string()),
            ("cache-control".to_string(), "no-store".to_string()),
        ];
        let mut map = http::HeaderMap::new();
        map.append(
            http::header::CACHE_CONTROL,
            http::header::HeaderValue::from_static("max-age=60"),
        );
        map.append(
            http::header::CACHE_CONTROL,
            http::header::HeaderValue::from_static("no-store"),
        );
        // `no-store` anywhere must reject on both paths.
        assert!(decide_storage_reason(200, &slice, policy, 3600).is_err());
        assert!(decide_storage_reason_map(200, &map, policy, 3600).is_err());
    }
}
