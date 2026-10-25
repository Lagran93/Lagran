//! Cache key, TTL policy, and cache status labels

use axum::http::Request;
use std::sync::Arc;
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

#[derive(Debug, Clone)]
pub struct CacheRule {
    pub path_pattern: String,
    pub ttl_seconds: u64,
    pub priority: i32,
    /// bypass | cache | no_store
    pub action: String,
    /// stale-while-revalidate seconds
    pub swr_seconds: u64,
}

impl CacheRule {
    pub fn simple(path: String, ttl: u64, priority: i32) -> Self {
        Self {
            path_pattern: path,
            ttl_seconds: ttl,
            priority,
            action: "cache".into(),
            swr_seconds: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MatchedPolicy {
    pub ttl_seconds: u64,
    pub swr_seconds: u64,
    pub action: String,
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
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        *self.inner.write().await = rules;
    }

    pub async fn match_ttl(&self, path: &str) -> Option<u64> {
        self.match_policy(path).await.map(|p| p.ttl_seconds)
    }

    pub async fn match_policy(&self, path: &str) -> Option<MatchedPolicy> {
        let rules = self.inner.read().await;
        for r in rules.iter() {
            if path_matches(&r.path_pattern, path) {
                return Some(MatchedPolicy {
                    ttl_seconds: r.ttl_seconds,
                    swr_seconds: r.swr_seconds,
                    action: r.action.clone(),
                });
            }
        }
        None
    }
}

fn path_matches(pattern: &str, path: &str) -> bool {
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
    path == pattern
}

pub fn cache_key<B>(req: &Request<B>) -> String {
    cache_key_opts(req, false)
}

pub fn cache_key_opts<B>(req: &Request<B>, ignore_query: bool) -> String {
    let method = req.method().as_str();
    let path = if ignore_query {
        req.uri().path().to_string()
    } else {
        req.uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string())
    };
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    let host = host.split(':').next().unwrap_or(host);
    format!("{method}:{host}:{path}")
}

pub fn is_cacheable<B>(req: &Request<B>) -> bool {
    req.method() == axum::http::Method::GET || req.method() == axum::http::Method::HEAD
}

/// Respect request Cache-Control: no-cache / no-store
pub fn request_bypasses_cache<B>(req: &Request<B>) -> bool {
    if let Some(cc) = req
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
    {
        let cc = cc.to_ascii_lowercase();
        if cc.contains("no-store") || cc.contains("no-cache") || cc.contains("max-age=0") {
            return true;
        }
    }
    if req.headers().contains_key("pragma") {
        if let Some(p) = req.headers().get("pragma").and_then(|v| v.to_str().ok()) {
            if p.eq_ignore_ascii_case("no-cache") {
                return true;
            }
        }
    }
    false
}
