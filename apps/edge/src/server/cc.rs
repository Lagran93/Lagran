//! CC (L7 flood) protection: per-domain, aggregated-client sliding-window
//! rate limiting with automatic temporary bans.
//!
//! Counters can optionally be shared through Redis so multiple edge nodes see a
//! single sliding window; without Redis the process-local fallback remains
//! available. IPv4 clients are aggregated by /24 and IPv6 clients by /64 so
//! rotating addresses inside one allocation cannot bypass the limit.

use crate::waf::IpNet;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};

const WINDOW: Duration = Duration::from_secs(1);
const STATE_TTL: Duration = Duration::from_secs(600);
const REDIS_TIMEOUT: Duration = Duration::from_millis(15);
const IPV4_PREFIX: u8 = 24;
const IPV6_PREFIX: u8 = 64;

/// Request class used to keep independent CC budgets. Authentication endpoints
/// get a smaller budget, static/download assets a larger one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcPathClass {
    Static,
    Auth,
    Api,
    Download,
    Dynamic,
}

impl CcPathClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Auth => "auth",
            Self::Api => "api",
            Self::Download => "download",
            Self::Dynamic => "dynamic",
        }
    }

    fn limit(self, base: u32) -> u32 {
        let factors = path_factors();
        match self {
            Self::Static => base.saturating_mul(factors.static_multiplier),
            Self::Auth => (base / factors.auth_divisor).max(1),
            Self::Download => base.saturating_mul(factors.download_multiplier),
            Self::Api | Self::Dynamic => base,
        }
    }
}

struct PathFactors {
    static_multiplier: u32,
    auth_divisor: u32,
    download_multiplier: u32,
}

fn path_factors() -> &'static PathFactors {
    static FACTORS: OnceLock<PathFactors> = OnceLock::new();
    FACTORS.get_or_init(|| {
        let read = |name: &str, default: u32| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(default)
                .max(1)
        };
        PathFactors {
            static_multiplier: read("CC_STATIC_MULTIPLIER", 8),
            auth_divisor: read("CC_AUTH_DIVISOR", 2),
            download_multiplier: read("CC_DOWNLOAD_MULTIPLIER", 2),
        }
    })
}

fn extension(path: &str) -> Option<&str> {
    let last = path.rsplit('/').next()?;
    let (_, ext) = last.rsplit_once('.')?;
    (!ext.is_empty()).then_some(ext)
}

/// Classify a request path for CC budgeting.
pub fn classify_path(path: &str) -> CcPathClass {
    let path = path.split('?').next().unwrap_or(path).to_ascii_lowercase();
    if [
        "/login",
        "/signin",
        "/register",
        "/signup",
        "/auth",
        "/api/v1/auth",
        "/password",
        "/captcha",
        "/forgot",
        "/reset",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
    {
        return CcPathClass::Auth;
    }
    if path.starts_with("/static/")
        || path.starts_with("/assets/")
        || path.starts_with("/_nuxt/")
        || matches!(
            extension(&path),
            Some(
                "css"
                    | "js"
                    | "mjs"
                    | "map"
                    | "png"
                    | "jpg"
                    | "jpeg"
                    | "gif"
                    | "webp"
                    | "svg"
                    | "ico"
                    | "woff"
                    | "woff2"
                    | "ttf"
                    | "otf"
                    | "wasm"
            )
        )
    {
        return CcPathClass::Static;
    }
    if matches!(
        extension(&path),
        Some(
            "zip"
                | "tar"
                | "gz"
                | "tgz"
                | "bz2"
                | "xz"
                | "iso"
                | "dmg"
                | "exe"
                | "apk"
                | "mp4"
                | "webm"
                | "mkv"
                | "mp3"
                | "m3u8"
                | "ts"
        )
    ) {
        return CcPathClass::Download;
    }
    if path.starts_with("/api/") {
        return CcPathClass::Api;
    }
    CcPathClass::Dynamic
}

/// Aggregate a client address into the CC accounting group.
///
/// IPv4 uses /24 and IPv6 uses /64 by default. IPv4-mapped IPv6 addresses are
/// treated as IPv4 so `::ffff:203.0.113.5` and `203.0.113.5` share a bucket.
pub fn client_group(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => ipv4_group(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => ipv4_group(v4),
            None => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                format!("{}/{IPV6_PREFIX}", Ipv6Addr::from(octets).to_string())
            }
        },
    }
}

fn ipv4_group(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.0/{IPV4_PREFIX}", o[0], o[1], o[2])
}

/// Optional Redis-backed sliding-window counter.
///
/// A sorted set per `domain|client-group` stores request timestamps. The Lua
/// script removes entries older than one second, checks the cardinality and
/// inserts the current request atomically. Redis is never the source of truth
/// for bans; if it is unavailable the caller falls back to local state.
#[derive(Clone)]
pub struct RedisCc {
    conn: redis::aio::ConnectionManager,
    prefix: String,
    seq: Arc<AtomicU64>,
}

impl RedisCc {
    pub async fn connect(url: &str) -> Result<Self, String> {
        let client = redis::Client::open(url).map_err(|e| format!("invalid REDIS_URL: {e}"))?;
        let conn = tokio::time::timeout(Duration::from_secs(2), client.get_connection_manager())
            .await
            .map_err(|_| "redis connection timeout".to_string())?
            .map_err(|e| format!("redis connection failed: {e}"))?;
        let prefix = std::env::var("CC_REDIS_PREFIX")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "lagran:cc".to_string());
        Ok(Self {
            conn,
            prefix,
            seq: Arc::new(AtomicU64::new(0)),
        })
    }

    async fn over_limit(&self, key: &str, limit: u32, window_ms: u64) -> Option<bool> {
        let mut conn = self.conn.clone();
        let member = format!(
            "{}:{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            self.seq.fetch_add(1, Ordering::Relaxed)
        );
        let script = redis::Script::new(
            r#"
            local t = redis.call('TIME')
            local now = (tonumber(t[1]) * 1000) + math.floor(tonumber(t[2]) / 1000)
            local window = tonumber(ARGV[1])
            local limit = tonumber(ARGV[2])
            redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - window)
            local count = redis.call('ZCARD', KEYS[1])
            if count < limit then
                redis.call('ZADD', KEYS[1], now, ARGV[3])
                redis.call('PEXPIRE', KEYS[1], window * 2)
                return 0
            end
            return 1
            "#,
        );
        let redis_key = format!("{}:win:{}", self.prefix, key);
        let result: i64 = tokio::time::timeout(
            REDIS_TIMEOUT,
            script
                .key(redis_key)
                .arg(window_ms as i64)
                .arg(i64::from(limit))
                .arg(member)
                .invoke_async(&mut conn),
        )
        .await
        .ok()?
        .ok()?;
        Some(result != 0)
    }
}

fn client_key(host: &str, ip: IpAddr) -> String {
    format!("{host}|{}", client_group(ip))
}

fn group_key_of(counter_key: &str) -> &str {
    counter_key
        .rsplit_once('|')
        .map(|(group, _)| group)
        .unwrap_or(counter_key)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CcMode {
    #[default]
    Block,
    Monitor,
}

impl CcMode {
    pub fn parse(raw: &str) -> Self {
        if raw.eq_ignore_ascii_case("monitor") {
            Self::Monitor
        } else {
            Self::Block
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Monitor => "monitor",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CcConfig {
    pub enabled: bool,
    /// Allowed requests per second per client IP.
    pub rps: u32,
    /// Extra burst requests allowed in the same one-second window.
    pub burst: u32,
    /// Number of overloaded windows before the IP is banned.
    pub ban_after: u32,
    pub ban_seconds: u64,
    pub mode: CcMode,
    /// Client CIDRs that are never rate limited or banned.
    pub allow_ips: Vec<IpNet>,
    /// Domain-wide request budget. When exceeded, CC enters attack mode.
    /// Populated from the domain's existing rate_limit_rps setting.
    pub global_rps: u32,
    pub global_burst: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcDecision {
    Allow,
    Limit {
        retry_after: u64,
    },
    Banned {
        retry_after: u64,
        newly_banned: bool,
    },
}

impl CcDecision {
    pub fn is_banned(self) -> bool {
        matches!(self, Self::Banned { .. })
    }

    pub fn retry_after(self) -> u64 {
        match self {
            Self::Allow => 0,
            Self::Limit { retry_after } | Self::Banned { retry_after, .. } => retry_after,
        }
    }
}

struct ClientState {
    window_start: Instant,
    count: u32,
    /// The current window already exceeded the limit. Used so one over-limit
    /// second does not immediately cancel its own violation on the next tick.
    window_over: bool,
    violations: u32,
    banned_until: Option<Instant>,
    last_seen: Instant,
    /// This local ban was successfully reported to the control plane and may
    /// be cleared when the shared list no longer contains it.
    reported: bool,
}

struct GlobalState {
    window_start: Instant,
    count: u32,
}

#[derive(Clone, Default)]
pub struct CcProtector {
    inner: Arc<Mutex<HashMap<String, ClientState>>>,
    /// Domain-wide counters used to trigger automatic attack mode.
    global: Arc<Mutex<HashMap<String, GlobalState>>>,
    /// Domains currently in automatic attack mode.
    attack_until: Arc<Mutex<HashMap<String, Instant>>>,
    /// Bans pulled from the control plane, keyed by aggregated client group.
    shared: Arc<RwLock<HashMap<String, Instant>>>,
    /// CIDR bans pulled from the control plane.
    shared_nets: Arc<RwLock<Vec<(String, IpNet, Instant)>>>,
    /// Optional shared sliding-window counters.
    redis: Option<RedisCc>,
}

impl CcProtector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_redis(redis: Option<RedisCc>) -> Self {
        Self {
            redis,
            ..Self::default()
        }
    }

    /// Replace the shared ban overlay with the active list from the control
    /// plane. Keys are `host|ip`; they are normalized to the same aggregated
    /// group used by request accounting.
    pub async fn replace_shared(&self, bans: Vec<(String, u64)>) {
        let now = Instant::now();
        let mut map = HashMap::with_capacity(bans.len());
        let mut nets = Vec::new();
        let mut active = HashSet::with_capacity(bans.len());
        for (key, secs) in bans {
            if secs == 0 {
                continue;
            }
            let Some((host, target)) = key.split_once('|') else {
                continue;
            };
            let until = now + Duration::from_secs(secs);
            if target.contains('/') {
                if let Some(net) = IpNet::parse(target) {
                    active.insert(format!("{host}|{target}"));
                    nets.push((host.to_string(), net, until));
                }
            } else if let Ok(ip) = target.parse::<IpAddr>() {
                let normalized = format!("{host}|{}", client_group(ip));
                active.insert(normalized.clone());
                map.insert(normalized, until);
            }
        }
        *self.shared.write().await = map;
        *self.shared_nets.write().await = nets;

        // A reported local ban that disappeared from the control plane was
        // manually removed (or expired): clear it locally as well. Bans that
        // failed to report stay on their local timer.
        let mut local = self.inner.lock().await;
        for (key, state) in local.iter_mut() {
            if state.reported && !active.contains(group_key_of(key)) {
                state.banned_until = None;
                state.violations = 0;
                state.reported = false;
            }
        }
    }

    /// Mark the local ban as successfully reported so a later shared-list
    /// removal can clear it.
    pub async fn mark_reported(&self, host: &str, ip: IpAddr) {
        let group = client_key(host, ip);
        let prefix = format!("{group}|");
        let mut local = self.inner.lock().await;
        for (key, state) in local.iter_mut() {
            if key == &group || key.starts_with(&prefix) {
                state.reported = true;
            }
        }
    }

    #[cfg(test)]
    async fn shared_len(&self) -> usize {
        self.shared.read().await.len()
    }

    /// Consume one slot from the domain-wide budget. Shared through Redis when
    /// configured so attack mode follows the whole edge fleet.
    async fn global_over(&self, host: &str, limit: u32) -> bool {
        if let Some(redis) = self.redis.as_ref() {
            if let Some(over) = redis
                .over_limit(&format!("global:{host}"), limit, WINDOW.as_millis() as u64)
                .await
            {
                return over;
            }
        }
        let now = Instant::now();
        let mut map = self.global.lock().await;
        if map.len() > 10_000 {
            map.retain(|_, state| now.duration_since(state.window_start) < STATE_TTL);
        }
        let state = map.entry(host.to_string()).or_insert(GlobalState {
            window_start: now,
            count: 0,
        });
        if now.duration_since(state.window_start) >= WINDOW {
            state.window_start = now;
            state.count = 0;
        }
        state.count = state.count.saturating_add(1);
        state.count > limit
    }

    async fn mark_attack(&self, host: &str) {
        let until = Instant::now() + Duration::from_secs(60);
        self.attack_until
            .lock()
            .await
            .insert(host.to_string(), until);
    }

    async fn in_attack(&self, host: &str) -> bool {
        let now = Instant::now();
        let mut map = self.attack_until.lock().await;
        match map.get(host).copied() {
            Some(until) if until > now => true,
            Some(_) => {
                map.remove(host);
                false
            }
            None => false,
        }
    }

    /// Check one request. `host` scopes the ban to the domain, `ip` scopes it
    /// to the client. A monitor-mode result is still returned so the caller can
    /// log it; the caller must only enforce decisions in block mode.
    pub async fn check(
        &self,
        host: &str,
        path: &str,
        ip: IpAddr,
        cfg: &CcConfig,
        cleared: bool,
    ) -> CcDecision {
        if !cfg.enabled {
            return CcDecision::Allow;
        }
        if cfg.allow_ips.iter().any(|net| net.contains(ip)) {
            return CcDecision::Allow;
        }

        let group_key = client_key(host, ip);
        let class = classify_path(path);
        let key = format!("{group_key}|{}", class.as_str());
        let now = Instant::now();
        if let Some(until) = self.shared.read().await.get(&group_key).copied() {
            if until > now {
                return CcDecision::Banned {
                    retry_after: remaining(until, now),
                    newly_banned: false,
                };
            }
        }
        let net_until = {
            let nets = self.shared_nets.read().await;
            nets.iter()
                .find(|(net_host, net, until)| net_host == host && *until > now && net.contains(ip))
                .map(|(_, _, until)| *until)
        };
        if let Some(until) = net_until {
            return CcDecision::Banned {
                retry_after: remaining(until, now),
                newly_banned: false,
            };
        }
        let mut in_attack = self.in_attack(host).await;
        let global_limit = cfg.global_rps.saturating_add(cfg.global_burst);
        if global_limit > 0 && self.global_over(host, global_limit).await {
            in_attack = true;
            self.mark_attack(host).await;
            // A clearance cookie lets an interactive browser continue
            // through attack mode, subject to the halved per-client limit.
            if !cleared {
                return CcDecision::Limit { retry_after: 1 };
            }
        }
        // rps=0 with enabled=true is treated as "observe only"; no meaningful
        // per-client threshold exists, so do not ban.
        if cfg.rps == 0 {
            return CcDecision::Allow;
        }

        let mut limit = class.limit(cfg.rps.saturating_add(cfg.burst));
        if cleared {
            limit = limit.saturating_mul(2);
        } else if in_attack {
            limit = (limit / 2).max(1);
        }

        // Use Redis for the shared sliding window when configured. A Redis
        // failure falls through to the local fixed-window fallback below.
        if let Some(redis) = self.redis.as_ref() {
            match redis
                .over_limit(&key, limit, WINDOW.as_millis() as u64)
                .await
            {
                Some(false) => return CcDecision::Allow,
                Some(true) => return self.note_over_limit(&key, cfg, now).await,
                None => {}
            }
        }

        let mut map = self.inner.lock().await;
        if map.len() > 50_000 {
            map.retain(|_, s| {
                s.last_seen.elapsed() < STATE_TTL
                    && s.banned_until.map(|until| until > now).unwrap_or(true)
            });
        }

        let state = map.entry(key.clone()).or_insert_with(|| ClientState {
            window_start: now,
            count: 0,
            window_over: false,
            violations: 0,
            banned_until: None,
            last_seen: now,
            reported: false,
        });
        state.last_seen = now;

        if let Some(until) = state.banned_until {
            if until > now {
                return CcDecision::Banned {
                    retry_after: remaining(until, now),
                    newly_banned: false,
                };
            }
            state.banned_until = None;
            state.window_start = now;
            state.count = 0;
            state.violations = 0;
            state.window_over = false;
        }

        if now.duration_since(state.window_start) >= WINDOW {
            if !state.window_over {
                // One clean window forgives one earlier violation.
                state.violations = state.violations.saturating_sub(1);
            }
            state.window_start = now;
            state.count = 0;
            state.window_over = false;
        }
        state.count = state.count.saturating_add(1);

        if state.count <= limit {
            return CcDecision::Allow;
        }

        // Count one violation per overloaded window, not per request. A burst
        // of 100 requests in one second must not consume 100 ban strikes.
        if state.window_over {
            return CcDecision::Limit {
                retry_after: remaining(state.window_start + WINDOW, now),
            };
        }
        state.window_over = true;
        state.violations = state.violations.saturating_add(1);
        if cfg.ban_after > 0 && cfg.ban_seconds > 0 && state.violations >= cfg.ban_after {
            let until = now + Duration::from_secs(cfg.ban_seconds);
            state.banned_until = Some(until);
            state.violations = 0;
            state.window_over = false;
            state.reported = false;
            self.shared
                .write()
                .await
                .insert(group_key_of(&key).to_string(), until);
            return CcDecision::Banned {
                retry_after: cfg.ban_seconds,
                newly_banned: true,
            };
        }

        CcDecision::Limit {
            retry_after: remaining(state.window_start + WINDOW, now),
        }
    }

    /// Record one overloaded window when the Redis counter already decided the
    /// request is over the limit. Local state only tracks ban strikes, not the
    /// request count.
    async fn note_over_limit(&self, key: &str, cfg: &CcConfig, now: Instant) -> CcDecision {
        let mut map = self.inner.lock().await;
        if map.len() > 50_000 {
            map.retain(|_, s| {
                s.last_seen.elapsed() < STATE_TTL
                    && s.banned_until.map(|until| until > now).unwrap_or(true)
            });
        }
        let state = map.entry(key.to_string()).or_insert_with(|| ClientState {
            window_start: now,
            count: 0,
            window_over: false,
            violations: 0,
            banned_until: None,
            last_seen: now,
            reported: false,
        });
        state.last_seen = now;
        if let Some(until) = state.banned_until {
            if until > now {
                return CcDecision::Banned {
                    retry_after: remaining(until, now),
                    newly_banned: false,
                };
            }
            state.banned_until = None;
            state.window_start = now;
            state.violations = 0;
            state.window_over = false;
        }
        if now.duration_since(state.window_start) >= WINDOW {
            if !state.window_over {
                state.violations = state.violations.saturating_sub(1);
            }
            state.window_start = now;
            state.window_over = false;
        }
        if state.window_over {
            return CcDecision::Limit {
                retry_after: remaining(state.window_start + WINDOW, now),
            };
        }
        state.window_over = true;
        state.violations = state.violations.saturating_add(1);
        if cfg.ban_after > 0 && cfg.ban_seconds > 0 && state.violations >= cfg.ban_after {
            let until = now + Duration::from_secs(cfg.ban_seconds);
            state.banned_until = Some(until);
            state.violations = 0;
            state.window_over = false;
            state.reported = false;
            self.shared
                .write()
                .await
                .insert(group_key_of(&key).to_string(), until);
            return CcDecision::Banned {
                retry_after: cfg.ban_seconds,
                newly_banned: true,
            };
        }
        CcDecision::Limit {
            retry_after: remaining(state.window_start + WINDOW, now),
        }
    }
}

fn remaining(until: Instant, now: Instant) -> u64 {
    until.saturating_duration_since(now).as_secs().max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CcConfig {
        CcConfig {
            enabled: true,
            rps: 1,
            burst: 0,
            ban_after: 1,
            ban_seconds: 60,
            mode: CcMode::Block,
            allow_ips: Vec::new(),
            global_rps: 0,
            global_burst: 0,
        }
    }

    #[tokio::test]
    async fn limits_and_auto_bans_per_ip() {
        let cc = CcProtector::new();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let cfg = config();

        assert_eq!(
            cc.check("a.test", "/", ip, &cfg, false).await,
            CcDecision::Allow
        );
        assert!(matches!(
            cc.check("a.test", "/", ip, &cfg, false).await,
            CcDecision::Banned { .. }
        ));
        assert!(matches!(
            cc.check("a.test", "/", ip, &cfg, false).await,
            CcDecision::Banned { .. }
        ));
        // A different domain has its own counter.
        assert_eq!(
            cc.check("b.test", "/", ip, &cfg, false).await,
            CcDecision::Allow
        );
    }

    #[tokio::test]
    async fn ban_after_counts_windows_not_requests() {
        let cc = CcProtector::new();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let cfg = CcConfig {
            enabled: true,
            rps: 1,
            burst: 0,
            ban_after: 2,
            ban_seconds: 60,
            ..config()
        };
        assert_eq!(
            cc.check("a.test", "/", ip, &cfg, false).await,
            CcDecision::Allow
        );
        // Same window: the first over-limit request is one strike; the next
        // over-limit request must not add another strike.
        assert!(matches!(
            cc.check("a.test", "/", ip, &cfg, false).await,
            CcDecision::Limit { .. }
        ));
        assert!(matches!(
            cc.check("a.test", "/", ip, &cfg, false).await,
            CcDecision::Limit { .. }
        ));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        // A clean second window starts with count 1, then exceeds: second strike.
        assert_eq!(
            cc.check("a.test", "/", ip, &cfg, false).await,
            CcDecision::Allow
        );
        assert!(matches!(
            cc.check("a.test", "/", ip, &cfg, false).await,
            CcDecision::Banned { .. }
        ));
    }

    #[tokio::test]
    async fn shared_ban_applies_to_all_nodes() {
        let cc = CcProtector::new();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let cfg = CcConfig {
            enabled: true,
            rps: 100,
            ..config()
        };
        cc.replace_shared(vec![(format!("a.test|{ip}"), 60)]).await;
        assert_eq!(cc.shared_len().await, 1);
        assert!(matches!(
            cc.check("a.test", "/", ip, &cfg, false).await,
            CcDecision::Banned {
                newly_banned: false,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn shared_cidr_ban_matches_client() {
        let cc = CcProtector::new();
        let ip: IpAddr = "203.0.113.77".parse().unwrap();
        let cfg = config();
        cc.replace_shared(vec![("a.test|203.0.113.0/24".into(), 60)])
            .await;
        assert!(matches!(
            cc.check("a.test", "/", ip, &cfg, false).await,
            CcDecision::Banned { .. }
        ));
        assert_eq!(
            cc.check("b.test", "/", ip, &cfg, false).await,
            CcDecision::Allow
        );
    }

    #[tokio::test]
    async fn allowlist_bypasses_cc() {
        let cc = CcProtector::new();
        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        let mut cfg = config();
        cfg.allow_ips.push(IpNet::parse("10.0.0.0/24").unwrap());
        for _ in 0..10 {
            assert_eq!(
                cc.check("a.test", "/", ip, &cfg, false).await,
                CcDecision::Allow
            );
        }
    }

    #[tokio::test]
    async fn disabled_is_unlimited() {
        let cc = CcProtector::new();
        let ip: IpAddr = "203.0.113.6".parse().unwrap();
        let mut cfg = config();
        cfg.enabled = false;
        for _ in 0..10 {
            assert_eq!(
                cc.check("a.test", "/", ip, &cfg, false).await,
                CcDecision::Allow
            );
        }
    }

    #[test]
    fn aggregates_ipv4_and_ipv6_clients() {
        assert_eq!(
            client_group("203.0.113.5".parse().unwrap()),
            "203.0.113.0/24"
        );
        assert_eq!(
            client_group("::ffff:203.0.113.5".parse().unwrap()),
            "203.0.113.0/24"
        );
        assert_eq!(
            client_group("2001:db8:1:2:3:4:5:6".parse().unwrap()),
            "2001:db8:1:2::/64"
        );
    }

    #[tokio::test]
    async fn clients_in_same_prefix_share_the_limit() {
        let cc = CcProtector::new();
        let first: IpAddr = "203.0.113.5".parse().unwrap();
        let second: IpAddr = "203.0.113.6".parse().unwrap();
        let cfg = config();
        assert_eq!(
            cc.check("a.test", "/", first, &cfg, false).await,
            CcDecision::Allow
        );
        assert!(matches!(
            cc.check("a.test", "/", second, &cfg, false).await,
            CcDecision::Banned { .. }
        ));
    }

    #[tokio::test]
    async fn cleared_browser_gets_higher_cc_budget() {
        let cc = CcProtector::new();
        let ip: IpAddr = "198.51.100.20".parse().unwrap();
        let cfg = CcConfig {
            enabled: true,
            rps: 2,
            burst: 0,
            ban_after: 0,
            ban_seconds: 0,
            ..config()
        };
        for _ in 0..2 {
            assert_eq!(
                cc.check("a.test", "/", ip, &cfg, false).await,
                CcDecision::Allow
            );
        }
        assert!(matches!(
            cc.check("a.test", "/", ip, &cfg, false).await,
            CcDecision::Limit { .. }
        ));
        assert_eq!(
            cc.check("a.test", "/", ip, &cfg, true).await,
            CcDecision::Allow
        );
        assert!(matches!(
            cc.check("a.test", "/", ip, &cfg, true).await,
            CcDecision::Limit { .. }
        ));
    }

    #[tokio::test]
    async fn redis_sliding_window_is_shared_when_configured() {
        let Ok(url) = std::env::var("REDIS_TEST_URL") else {
            return;
        };
        let key = format!(
            "cc-test-{}:203.0.113.0/24",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let a = RedisCc::connect(&url).await.expect("redis A");
        let b = RedisCc::connect(&url).await.expect("redis B");
        assert_eq!(a.over_limit(&key, 2, 1000).await, Some(false));
        assert_eq!(b.over_limit(&key, 2, 1000).await, Some(false));
        assert_eq!(a.over_limit(&key, 2, 1000).await, Some(true));
    }

    #[tokio::test]
    async fn global_budget_triggers_attack_mode_across_ips() {
        let cc = CcProtector::new();
        let first: IpAddr = "198.51.100.30".parse().unwrap();
        let second: IpAddr = "198.51.100.40".parse().unwrap();
        let cfg = CcConfig {
            enabled: true,
            rps: 100,
            burst: 0,
            ban_after: 0,
            ban_seconds: 0,
            global_rps: 1,
            global_burst: 0,
            ..config()
        };
        assert_eq!(
            cc.check("a.test", "/", first, &cfg, false).await,
            CcDecision::Allow
        );
        assert!(matches!(
            cc.check("a.test", "/", second, &cfg, false).await,
            CcDecision::Limit { .. }
        ));
        // A clearance cookie can continue through attack mode.
        assert_eq!(
            cc.check("a.test", "/", second, &cfg, true).await,
            CcDecision::Allow
        );
    }

    #[test]
    fn classifies_request_paths() {
        assert_eq!(classify_path("/assets/app.js"), CcPathClass::Static);
        assert_eq!(classify_path("/_nuxt/x.css"), CcPathClass::Static);
        assert_eq!(classify_path("/login"), CcPathClass::Auth);
        assert_eq!(classify_path("/api/v1/auth/login"), CcPathClass::Auth);
        assert_eq!(classify_path("/api/v1/domains"), CcPathClass::Api);
        assert_eq!(classify_path("/download/file.zip"), CcPathClass::Download);
        assert_eq!(classify_path("/"), CcPathClass::Dynamic);
    }

    #[tokio::test]
    async fn auth_and_static_paths_get_independent_budgets() {
        let cc = CcProtector::new();
        let ip: IpAddr = "198.51.100.10".parse().unwrap();
        let cfg = CcConfig {
            enabled: true,
            rps: 1,
            burst: 0,
            ban_after: 0,
            ban_seconds: 0,
            ..config()
        };
        // auth: max(1, 1 / 2) = 1 request.
        for _ in 0..1 {
            assert_eq!(
                cc.check("a.test", "/login", ip, &cfg, false).await,
                CcDecision::Allow
            );
        }
        assert!(matches!(
            cc.check("a.test", "/login", ip, &cfg, false).await,
            CcDecision::Limit { .. }
        ));
        // The static bucket is independent and has an 8x budget.
        for _ in 0..8 {
            assert_eq!(
                cc.check("a.test", "/assets/app.js", ip, &cfg, false).await,
                CcDecision::Allow
            );
        }
        assert!(matches!(
            cc.check("a.test", "/assets/app.js", ip, &cfg, false).await,
            CcDecision::Limit { .. }
        ));
    }
}
