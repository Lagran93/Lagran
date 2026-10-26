//! CC (L7 flood) protection: per-domain, per-IP fixed-window rate limiting
//! with automatic temporary IP bans.
//!
//! State is intentionally in-memory: a ban is cheap to recreate and should not
//! become a database write per attack request. Counters are cleaned up
//! opportunistically so a rotating source IP cannot grow the map forever.

use crate::waf::IpNet;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

const WINDOW: Duration = Duration::from_secs(1);
const STATE_TTL: Duration = Duration::from_secs(600);

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

#[derive(Clone, Default)]
pub struct CcProtector {
    inner: Arc<Mutex<HashMap<String, ClientState>>>,
    /// Bans pulled from the control plane, keyed by `host|ip`.
    shared: Arc<RwLock<HashMap<String, Instant>>>,
}

impl CcProtector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the shared ban overlay with the active list from the control
    /// plane. Keys are `host|ip`, values are remaining seconds.
    pub async fn replace_shared(&self, bans: Vec<(String, u64)>) {
        let now = Instant::now();
        let mut map = HashMap::with_capacity(bans.len());
        for (key, secs) in bans {
            if secs > 0 {
                map.insert(key, now + Duration::from_secs(secs));
            }
        }
        let active: HashSet<String> = map.keys().cloned().collect();
        *self.shared.write().await = map;

        // A reported local ban that disappeared from the control plane was
        // manually removed (or expired): clear it locally as well. Bans that
        // failed to report stay on their local timer.
        let mut local = self.inner.lock().await;
        for (key, state) in local.iter_mut() {
            if state.reported && !active.contains(key) {
                state.banned_until = None;
                state.violations = 0;
                state.reported = false;
            }
        }
    }

    /// Mark the local ban as successfully reported so a later shared-list
    /// removal can clear it.
    pub async fn mark_reported(&self, host: &str, ip: IpAddr) {
        let key = format!("{host}|{ip}");
        if let Some(state) = self.inner.lock().await.get_mut(&key) {
            state.reported = true;
        }
    }

    #[cfg(test)]
    async fn shared_len(&self) -> usize {
        self.shared.read().await.len()
    }

    /// Check one request. `host` scopes the ban to the domain, `ip` scopes it
    /// to the client. A monitor-mode result is still returned so the caller can
    /// log it; the caller must only enforce decisions in block mode.
    pub async fn check(&self, host: &str, ip: IpAddr, cfg: &CcConfig) -> CcDecision {
        if !cfg.enabled {
            return CcDecision::Allow;
        }
        if cfg.allow_ips.iter().any(|net| net.contains(ip)) {
            return CcDecision::Allow;
        }

        let key = format!("{host}|{ip}");
        let now = Instant::now();
        if let Some(until) = self.shared.read().await.get(&key).copied() {
            if until > now {
                return CcDecision::Banned {
                    retry_after: remaining(until, now),
                    newly_banned: false,
                };
            }
        }
        // rps=0 with enabled=true is treated as "observe only"; no meaningful
        // threshold exists, so do not ban.
        if cfg.rps == 0 {
            return CcDecision::Allow;
        }

        let limit = cfg.rps.saturating_add(cfg.burst);

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
            self.shared.write().await.insert(key, until);
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
        }
    }

    #[tokio::test]
    async fn limits_and_auto_bans_per_ip() {
        let cc = CcProtector::new();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let cfg = config();

        assert_eq!(cc.check("a.test", ip, &cfg).await, CcDecision::Allow);
        assert!(matches!(
            cc.check("a.test", ip, &cfg).await,
            CcDecision::Banned { .. }
        ));
        assert!(matches!(
            cc.check("a.test", ip, &cfg).await,
            CcDecision::Banned { .. }
        ));
        // A different domain has its own counter.
        assert_eq!(cc.check("b.test", ip, &cfg).await, CcDecision::Allow);
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
        assert_eq!(cc.check("a.test", ip, &cfg).await, CcDecision::Allow);
        // Same window: the first over-limit request is one strike; the next
        // over-limit request must not add another strike.
        assert!(matches!(
            cc.check("a.test", ip, &cfg).await,
            CcDecision::Limit { .. }
        ));
        assert!(matches!(
            cc.check("a.test", ip, &cfg).await,
            CcDecision::Limit { .. }
        ));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        // A clean second window starts with count 1, then exceeds: second strike.
        assert_eq!(cc.check("a.test", ip, &cfg).await, CcDecision::Allow);
        assert!(matches!(
            cc.check("a.test", ip, &cfg).await,
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
            cc.check("a.test", ip, &cfg).await,
            CcDecision::Banned {
                newly_banned: false,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn allowlist_bypasses_cc() {
        let cc = CcProtector::new();
        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        let mut cfg = config();
        cfg.allow_ips.push(IpNet::parse("10.0.0.0/24").unwrap());
        for _ in 0..10 {
            assert_eq!(cc.check("a.test", ip, &cfg).await, CcDecision::Allow);
        }
    }

    #[tokio::test]
    async fn disabled_is_unlimited() {
        let cc = CcProtector::new();
        let ip: IpAddr = "203.0.113.6".parse().unwrap();
        let mut cfg = config();
        cfg.enabled = false;
        for _ in 0..10 {
            assert_eq!(cc.check("a.test", ip, &cfg).await, CcDecision::Allow);
        }
    }
}
