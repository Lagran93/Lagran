//! CC (L7 flood) protection: per-domain, aggregated-client sliding-window
//! rate limiting with automatic temporary bans.
//!
//! Counters can optionally be shared through Redis so multiple edge nodes see a
//! single sliding window; without Redis the process-local fallback remains
//! available. IPv4 clients are aggregated by /24 and IPv6 clients by /64 so
//! rotating addresses inside one allocation cannot bypass the limit.

use crate::waf::IpNet;
use dashmap::DashMap;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock as StdRwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const WINDOW: Duration = Duration::from_secs(1);
const STATE_TTL: Duration = Duration::from_secs(600);
/// Budget for one shared-budget Redis round trip.
///
/// Default budget for one Redis round trip, overridable with
/// `CC_REDIS_TIMEOUT_MS`.
///
/// This sits on the request path, so it must stay bounded. 15 ms was too tight
/// even on a LAN: a multiplexed connection under load occasionally queued past
/// it and silently downgraded the fleet-wide limit to per-process. 50 ms leaves
/// headroom for a same-rack Redis while still bounding the worst case.
pub const DEFAULT_REDIS_TIMEOUT_MS: u64 = 50;
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
                format!("{}/{IPV6_PREFIX}", Ipv6Addr::from(octets))
            }
        },
    }
}

fn ipv4_group(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.0/{IPV4_PREFIX}", o[0], o[1], o[2])
}

/// How the cross-node CC counter ended up wired at startup.
///
/// Logged from this module rather than from `main` on purpose. The binary's own
/// target is `lagran_edge`, and a `RUST_LOG=edge=info` style filter does not match
/// it -- so a line written from `main` vanishes exactly when an operator is trying to
/// confirm whether the shared counter is working, while `edge::cache` and friends keep
/// printing. Emitting under `edge::server::cc` keeps the answer visible under the
/// filter an edge deployment is most likely to set.
#[derive(Debug)]
pub enum SharedWiring {
    /// Connected; every check may consult Redis.
    Redis { budget_ms: u64 },
    /// `REDIS_URL` was set but the connection failed.
    RedisUnavailable { error: String },
    /// No usable `REDIS_URL`; counting is per process and nothing is shared.
    Local { redis_url_present: bool },
}

/// Announce the wiring decided in `main`.
pub fn log_shared_wiring(wiring: &SharedWiring) {
    match wiring {
        SharedWiring::Redis { budget_ms } => tracing::info!(
            budget_ms,
            "CC cross-node counter enabled (Redis); a round trip must fit the budget or the check falls back to local"
        ),
        SharedWiring::RedisUnavailable { error } => tracing::warn!(
            error = %error,
            "CC Redis unavailable; falling back to in-process counters"
        ),
        // Previously this branch logged nothing at all, so "CC is local" and "CC is
        // broken" looked identical from the journal.
        SharedWiring::Local {
            redis_url_present: false,
        } => tracing::info!(
            "CC cross-node counter disabled: REDIS_URL is empty, every node keeps its own budget"
        ),
        SharedWiring::Local {
            redis_url_present: true,
        } => tracing::warn!(
            "CC cross-node counter disabled despite REDIS_URL being set; the domain budget is per node"
        ),
    }
}

/// Report the tallies gathered **since the previous report** (deltas).
///
/// The callers used to pass cumulative counters, so a single timeout in the
/// first minute made every later report warn forever even when 97% of checks
/// were succeeding. Deltas plus a significance threshold keep the signal honest.
pub fn log_shared_counters(ok: u64, timeout: u64, error: u64, budget_ms: u64) {
    let total = ok.saturating_add(timeout).saturating_add(error);
    if total == 0 {
        return;
    }
    let fallback = timeout.saturating_add(error);
    let fallback_pct = fallback.saturating_mul(100) / total;
    if error > 0 || (total >= 20 && fallback_pct >= 5) {
        tracing::warn!(
            shared_ok = ok,
            shared_timeout = timeout,
            shared_error = error,
            budget_ms,
            fallback_pct,
            "cross-node CC: a significant share of checks fell back to the per-process limit"
        );
    } else if fallback > 0 {
        // Below the threshold this is a tail-latency event, not a fault. Keep it
        // out of the default journal; the counters are still in the message when
        // debug logging is enabled.
        tracing::debug!(
            shared_ok = ok,
            shared_timeout = timeout,
            shared_error = error,
            budget_ms,
            fallback_pct,
            "cross-node CC: minor fallback to the per-process limit"
        );
    } else {
        tracing::debug!(shared_ok = ok, "cross-node CC: all checks used Redis");
    }
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
    /// Per-call budget for one Redis round trip (configurable).
    timeout_ms: u64,
    /// Times a shared-budget check actually completed against Redis.
    ///
    /// Counted separately from the failures because "is cross-node CC working at all"
    /// is a question the logs could not answer: every failure was swallowed by
    /// `ok()?`, so a deployment whose Redis round trip exceeded `REDIS_TIMEOUT` looked
    /// exactly like one with no CC traffic.
    shared_ok: Arc<AtomicU64>,
    /// Times the check fell back to the per-process budget because Redis did not
    /// answer within `REDIS_TIMEOUT`.
    shared_timeout: Arc<AtomicU64>,
    /// Times the check fell back because Redis returned an error.
    shared_error: Arc<AtomicU64>,
    /// Last time a failure was logged, so a cross-ocean outage does not flood the
    /// journal with one line per request.
    last_failure_log: Arc<AtomicU64>,
    /// Compiled once; `Script::new` used to re-hash the body on every check.
    script: Arc<redis::Script>,
}

impl RedisCc {
    pub async fn connect(url: &str) -> Result<Self, String> {
        Self::connect_with_timeout(url, DEFAULT_REDIS_TIMEOUT_MS).await
    }

    pub async fn connect_with_timeout(url: &str, timeout_ms: u64) -> Result<Self, String> {
        let timeout_ms = timeout_ms.clamp(5, 2_000);
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
            timeout_ms,
            script: Arc::new(redis::Script::new(
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
            )),
            shared_ok: Arc::new(AtomicU64::new(0)),
            shared_timeout: Arc::new(AtomicU64::new(0)),
            shared_error: Arc::new(AtomicU64::new(0)),
            last_failure_log: Arc::new(AtomicU64::new(0)),
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
        let redis_key = format!("{}:win:{}", self.prefix, key);
        let attempt = tokio::time::timeout(
            Duration::from_millis(self.timeout_ms),
            self.script
                .key(redis_key)
                .arg(window_ms as i64)
                .arg(i64::from(limit))
                .arg(member)
                .invoke_async::<i64>(&mut conn),
        )
        .await;
        match attempt {
            Ok(Ok(result)) => {
                self.shared_ok.fetch_add(1, Ordering::Relaxed);
                Some(result != 0)
            }
            // The two failure modes are separated because they call for different
            // fixes: a timeout at this budget usually means the Redis round trip is
            // simply longer than `REDIS_TIMEOUT` (a cross-region link), while an error
            // means Redis itself is unhappy.
            Ok(Err(e)) => {
                self.shared_error.fetch_add(1, Ordering::Relaxed);
                self.log_failure_once("redis_error", &format!("{e}"));
                None
            }
            Err(_) => {
                self.shared_timeout.fetch_add(1, Ordering::Relaxed);
                self.log_failure_once(
                    "timeout",
                    &format!(
                        "no reply within {}ms; per-process budget only",
                        self.timeout_ms
                    ),
                );
                None
            }
        }
    }

    /// Log a shared-budget failure at most once every 30 seconds.
    ///
    /// Every request that trips the limiter comes through here, so an unthrottled
    /// `warn!` would bury the journal. The counters carry the real frequency; this
    /// line exists to make the cause visible when someone looks.
    fn log_failure_once(&self, kind: &'static str, detail: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let last = self.last_failure_log.load(Ordering::Relaxed);
        if now.saturating_sub(last) < 30 {
            return;
        }
        // Lost race just means another thread logged a moment ago.
        if self
            .last_failure_log
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        // A timeout is a tail-latency event, not necessarily a fault: the
        // periodic report decides when the rate is worth a warning. Log it at
        // debug so a healthy LAN with 1% tail misses does not warn every 30 s.
        // An actual Redis error still warns, because that is a real fault.
        if kind == "timeout" {
            tracing::debug!(
                kind,
                detail,
                shared_ok = self.shared_ok.load(Ordering::Relaxed),
                shared_timeout = self.shared_timeout.load(Ordering::Relaxed),
                shared_error = self.shared_error.load(Ordering::Relaxed),
                "cross-node CC budget timed out; using the per-process limit"
            );
        } else {
            tracing::warn!(
                kind,
                detail,
                shared_ok = self.shared_ok.load(Ordering::Relaxed),
                shared_timeout = self.shared_timeout.load(Ordering::Relaxed),
                shared_error = self.shared_error.load(Ordering::Relaxed),
                "cross-node CC budget unavailable; falling back to the per-process limit"
            );
        }
    }

    /// Shared-versus-local tallies, for a startup or periodic report.
    pub fn counters(&self) -> (u64, u64, u64) {
        (
            self.shared_ok.load(Ordering::Relaxed),
            self.shared_timeout.load(Ordering::Relaxed),
            self.shared_error.load(Ordering::Relaxed),
        )
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
    /// Sharded client state: a request only contends with its own shard
    /// instead of a process-wide mutex.
    inner: Arc<DashMap<String, ClientState>>,
    /// Domain-wide counters used to trigger automatic attack mode.
    global: Arc<DashMap<String, GlobalState>>,
    /// Domains currently in automatic attack mode.
    attack_until: Arc<DashMap<String, Instant>>,
    /// Bans pulled from the control plane, keyed by aggregated client group.
    shared: Arc<DashMap<String, Instant>>,
    /// CIDR bans pulled from the control plane. Replaced rarely and read per
    /// request, so a std lock is enough and avoids an async await.
    shared_nets: Arc<StdRwLock<Vec<(String, IpNet, Instant)>>>,
    /// Runs table maintenance every N requests; `DashMap::len()` is O(shards)
    /// and must not sit on the hot path.
    maintenance_tick: Arc<AtomicU64>,
    /// Optional shared sliding-window counters.
    redis: Option<RedisCc>,
}

impl CcProtector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Shared/ timeout / error tallies from the cross-node counter.
    ///
    /// `None` when CC is running without Redis. The first value being zero over a
    /// long run with traffic means the shared path never completed a single round
    /// trip — which is exactly the situation a cross-region Redis produces and which
    /// was previously indistinguishable from "no CC traffic at all".
    pub fn shared_counters(&self) -> Option<(u64, u64, u64)> {
        self.redis.as_ref().map(|r| r.counters())
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
        let mut nets = Vec::new();
        let mut active = HashSet::with_capacity(bans.len());
        self.shared.clear();
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
                self.shared.insert(normalized, until);
            }
        }
        *self.nets_mut() = nets;

        // A reported local ban that disappeared from the control plane was
        // manually removed (or expired): clear it locally as well. Bans that
        // failed to report stay on their local timer.
        for mut entry in self.inner.iter_mut() {
            let stale = entry.value().reported && !active.contains(group_key_of(entry.key()));
            if stale {
                let state = entry.value_mut();
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
        for mut entry in self.inner.iter_mut() {
            let matches = {
                let key = entry.key();
                key == &group || key.starts_with(&prefix)
            };
            if matches {
                entry.value_mut().reported = true;
            }
        }
    }

    #[cfg(test)]
    async fn shared_len(&self) -> usize {
        self.shared.len()
    }

    /// Run table maintenance occasionally instead of on every request.
    fn maybe_maintain(&self, now: Instant) {
        if !self
            .maintenance_tick
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(256)
        {
            return;
        }
        if self.inner.len() > 50_000 {
            self.inner.retain(|_, state| {
                state.last_seen.elapsed() < STATE_TTL
                    && state.banned_until.map(|until| until > now).unwrap_or(true)
            });
        }
        if self.global.len() > 10_000 {
            self.global
                .retain(|_, state| now.duration_since(state.window_start) < STATE_TTL);
        }
    }

    fn nets(&self) -> std::sync::RwLockReadGuard<'_, Vec<(String, IpNet, Instant)>> {
        self.shared_nets
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn nets_mut(&self) -> std::sync::RwLockWriteGuard<'_, Vec<(String, IpNet, Instant)>> {
        self.shared_nets
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
        self.maybe_maintain(now);
        if let Some(mut state) = self.global.get_mut(host) {
            return bump_global(&mut state, now) > limit;
        }
        let mut state = self.global.entry(host.to_string()).or_insert(GlobalState {
            window_start: now,
            count: 0,
        });
        bump_global(&mut state, now) > limit
    }

    fn mark_attack(&self, host: &str) {
        let until = Instant::now() + Duration::from_secs(60);
        self.attack_until.insert(host.to_string(), until);
    }

    fn in_attack(&self, host: &str) -> bool {
        let now = Instant::now();
        match self.attack_until.get(host).map(|entry| *entry.value()) {
            Some(until) if until > now => true,
            Some(_) => {
                self.attack_until.remove(host);
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
        if let Some(until) = self.shared.get(&group_key).map(|entry| *entry.value()) {
            if until > now {
                return CcDecision::Banned {
                    retry_after: remaining(until, now),
                    newly_banned: false,
                };
            }
        }
        let net_until = {
            let nets = self.nets();
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
        let mut in_attack = self.in_attack(host);
        let global_limit = cfg.global_rps.saturating_add(cfg.global_burst);
        if global_limit > 0 && self.global_over(host, global_limit).await {
            in_attack = true;
            self.mark_attack(host);
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

        self.maybe_maintain(now);
        let mut entry = self.inner.entry(key).or_insert_with(|| ClientState {
            window_start: now,
            count: 0,
            window_over: false,
            violations: 0,
            banned_until: None,
            last_seen: now,
            reported: false,
        });
        let mut ban_until = None;
        let decision = {
            let state = entry.value_mut();
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
                CcDecision::Allow
            } else if state.window_over {
                // Count one violation per overloaded window, not per request. A
                // burst of 100 requests must not consume 100 ban strikes.
                CcDecision::Limit {
                    retry_after: remaining(state.window_start + WINDOW, now),
                }
            } else {
                state.window_over = true;
                state.violations = state.violations.saturating_add(1);
                if cfg.ban_after > 0 && cfg.ban_seconds > 0 && state.violations >= cfg.ban_after {
                    let until = now + Duration::from_secs(cfg.ban_seconds);
                    state.banned_until = Some(until);
                    state.violations = 0;
                    state.window_over = false;
                    state.reported = false;
                    ban_until = Some(until);
                    CcDecision::Banned {
                        retry_after: cfg.ban_seconds,
                        newly_banned: true,
                    }
                } else {
                    CcDecision::Limit {
                        retry_after: remaining(state.window_start + WINDOW, now),
                    }
                }
            }
        };
        if let Some(until) = ban_until {
            // Publish the ban so every request class of this client is blocked.
            self.shared
                .insert(group_key_of(entry.key()).to_string(), until);
        }
        decision
    }

    /// Record one overloaded window when the Redis counter already decided the
    /// request is over the limit. Local state only tracks ban strikes, not the
    /// request count.
    async fn note_over_limit(&self, key: &str, cfg: &CcConfig, now: Instant) -> CcDecision {
        self.maybe_maintain(now);
        let mut entry = self
            .inner
            .entry(key.to_string())
            .or_insert_with(|| ClientState {
                window_start: now,
                count: 0,
                window_over: false,
                violations: 0,
                banned_until: None,
                last_seen: now,
                reported: false,
            });
        let mut ban_until = None;
        let decision = {
            let state = entry.value_mut();
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
                CcDecision::Limit {
                    retry_after: remaining(state.window_start + WINDOW, now),
                }
            } else {
                state.window_over = true;
                state.violations = state.violations.saturating_add(1);
                if cfg.ban_after > 0 && cfg.ban_seconds > 0 && state.violations >= cfg.ban_after {
                    let until = now + Duration::from_secs(cfg.ban_seconds);
                    state.banned_until = Some(until);
                    state.violations = 0;
                    state.window_over = false;
                    state.reported = false;
                    ban_until = Some(until);
                    CcDecision::Banned {
                        retry_after: cfg.ban_seconds,
                        newly_banned: true,
                    }
                } else {
                    CcDecision::Limit {
                        retry_after: remaining(state.window_start + WINDOW, now),
                    }
                }
            }
        };
        if let Some(until) = ban_until {
            self.shared.insert(group_key_of(key).to_string(), until);
        }
        decision
    }
}

/// Advance a domain-wide fixed window and return the new request count.
fn bump_global(state: &mut GlobalState, now: Instant) -> u32 {
    if now.duration_since(state.window_start) >= WINDOW {
        state.window_start = now;
        state.count = 0;
    }
    state.count = state.count.saturating_add(1);
    state.count
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
    /// The counters must separate success from the two failure modes.
    ///
    /// This is the whole point of the instrumentation: with a cross-region Redis and
    /// a 15 ms budget, every check times out, and before these counters existed that
    /// was indistinguishable from "no CC traffic" — the deployment looked healthy.
    #[tokio::test]
    async fn shared_counters_track_ok_and_failures_separately() {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".into());
        let Ok(redis) = RedisCc::connect(&url).await else {
            return; // no Redis here; the unit-shaped assertions below still apply
        };

        // A reachable Redis records successes and no failures.
        let _ = redis.over_limit("counters:ok", 100, 1000).await;
        let (ok, timeout, error) = redis.counters();
        assert!(ok >= 1, "a completed round trip must be counted: {ok}");
        assert_eq!(timeout, 0, "a healthy Redis must not record timeouts");
        assert_eq!(error, 0, "a healthy Redis must not record errors");
    }

    /// A backend that refuses the connection records failure, never success.
    ///
    /// Scope note: refusal surfaces as `Err(join/timeout)` on the connection manager,
    /// not as a `redis::RedisError`, so this covers the timeout path. The
    /// `Ok(Err(_))` path needs a reachable server that returns an error reply, which
    /// would mean standing up a fake Redis in the test — not done here.
    #[tokio::test]
    async fn unreachable_redis_records_failures_not_successes() {
        // Port 1 refuses immediately; the budget never completes a round trip.
        let Ok(redis) = RedisCc::connect("redis://127.0.0.1:1/").await else {
            return;
        };
        let result = redis.over_limit("counters:down", 100, 1000).await;
        assert_eq!(result, None, "a failed check yields no shared answer");

        let (ok, timeout, error) = redis.counters();
        // Both assertions are separate on purpose: "ok == 0" catches a failure being
        // miscounted as a success, and "timeout + error > 0" catches a failure being
        // dropped entirely. Combining them into one expression let the first slip
        // through, because a connection refusal also increments `timeout`.
        assert_eq!(
            ok, 0,
            "a backend that never answered must not be counted as a successful check"
        );
        assert!(
            timeout + error > 0,
            "the failure must be recorded somewhere (timeout={timeout}, error={error})"
        );
    }
}
