//! Per-source UDP query rate limiting.
//!
//! An authoritative DNS server answers a very small query with a response up to
//! ~4 KB, and a spoofed source address makes the amplification someone else's
//! problem. Without a per-source budget a single host can also simply flood the
//! worker pool. This module keeps a token bucket per source and, for arbitrary
//! source addresses, a per-prefix bucket so one attacker cannot starve a whole
//! address range by rotating individual addresses.
//!
//! The design is deliberately small: a fixed-size table with a periodic sweep,
//! no background task, and no allocation on the hot path beyond a key format.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Bucket refill interval. A source may send `capacity` queries per window.
const WINDOW: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Queries allowed per second from a single source address.
    pub per_source: u32,
    /// Queries allowed per second across an IPv4 /24 or IPv6 /64.
    pub per_prefix: u32,
    /// Hard cap on tracked sources, to bound memory during a spoofed flood.
    pub max_tracked: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_source: 100,
            per_prefix: 1_000,
            max_tracked: 50_000,
        }
    }
}

impl RateLimitConfig {
    /// A zero `per_source` disables limiting entirely.
    pub fn is_disabled(&self) -> bool {
        self.per_source == 0
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: u32,
    window_start: Instant,
}

impl Bucket {
    fn new(capacity: u32, now: Instant) -> Self {
        Self {
            tokens: capacity,
            window_start: now,
        }
    }

    /// Consume one token if available, refilling a full window at a time.
    fn try_take(&mut self, capacity: u32, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= WINDOW {
            self.window_start = now;
            self.tokens = capacity;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

pub struct RateLimiter {
    cfg: RateLimitConfig,
    sources: HashMap<IpAddr, Bucket>,
    prefixes: HashMap<String, Bucket>,
    last_sweep: Instant,
    rejected: u64,
}

impl RateLimiter {
    pub fn new(cfg: RateLimitConfig) -> Self {
        Self {
            cfg,
            sources: HashMap::new(),
            prefixes: HashMap::new(),
            last_sweep: Instant::now(),
            rejected: 0,
        }
    }

    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Coarse key used for the aggregate bucket.
    ///
    /// IPv4 collapses to /24 and IPv6 to /64, matching how a single host or small
    /// allocation can rotate addresses cheaply.
    fn prefix_key(ip: IpAddr) -> String {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
            }
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                format!(
                    "{:x}:{:x}:{:x}:{:x}::/64",
                    segments[0], segments[1], segments[2], segments[3]
                )
            }
        }
    }

    /// Returns true when this query may be served.
    ///
    /// Loopback is never limited: the local resolver and health checks depend on
    /// it, and it cannot be spoofed from off the machine.
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        if self.cfg.is_disabled() || is_loopback(ip) {
            return true;
        }
        self.sweep(now);

        // Capacity of 0 would block everything, which is never intended; treat
        // it as "no aggregate limit" and rely on the per-source bucket.
        if !self.take_source(ip, now) {
            self.rejected += 1;
            return false;
        }
        if self.cfg.per_prefix > 0 && !self.take_prefix(ip, now) {
            self.rejected += 1;
            return false;
        }
        true
    }

    fn take_source(&mut self, ip: IpAddr, now: Instant) -> bool {
        let capacity = self.cfg.per_source;
        if self.sources.len() >= self.cfg.max_tracked && !self.sources.contains_key(&ip) {
            // Table is full: drop the query rather than grow without bound.
            // A spoofed flood hits this instead of exhausting memory.
            return false;
        }
        self.sources
            .entry(ip)
            .or_insert_with(|| Bucket::new(capacity, now))
            .try_take(capacity, now)
    }

    fn take_prefix(&mut self, ip: IpAddr, now: Instant) -> bool {
        let capacity = self.cfg.per_prefix;
        let key = Self::prefix_key(ip);
        if self.prefixes.len() >= self.cfg.max_tracked && !self.prefixes.contains_key(&key) {
            return false;
        }
        self.prefixes
            .entry(key)
            .or_insert_with(|| Bucket::new(capacity, now))
            .try_take(capacity, now)
    }

    /// Drop buckets that have been idle for a full window.
    ///
    /// Runs at most once per second so the hot path stays cheap, and it is what
    /// keeps the table from growing without bound across normal operation.
    fn sweep(&mut self, now: Instant) {
        if now.duration_since(self.last_sweep) < WINDOW {
            return;
        }
        self.last_sweep = now;
        self.sources
            .retain(|_, b| now.duration_since(b.window_start) < WINDOW * 4);
        self.prefixes
            .retain(|_, b| now.duration_since(b.window_start) < WINDOW * 4);
    }
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cfg(per_source: u32, per_prefix: u32) -> RateLimitConfig {
        RateLimitConfig {
            per_source,
            per_prefix,
            max_tracked: 8,
        }
    }

    #[test]
    fn allows_up_to_the_bucket_then_blocks() {
        let mut rl = RateLimiter::new(cfg(3, 1_000));
        let now = Instant::now();
        let src = ip("203.0.113.9");
        assert!(rl.allow(src, now));
        assert!(rl.allow(src, now));
        assert!(rl.allow(src, now));
        assert!(!rl.allow(src, now), "fourth query must be limited");
        assert_eq!(rl.rejected(), 1);
    }

    #[test]
    fn bucket_refills_after_a_window() {
        let mut rl = RateLimiter::new(cfg(2, 1_000));
        let start = Instant::now();
        let src = ip("203.0.113.9");
        assert!(rl.allow(src, start));
        assert!(rl.allow(src, start));
        assert!(!rl.allow(src, start));
        assert!(rl.allow(src, start + WINDOW));
        assert!(rl.allow(src, start + WINDOW));
    }

    /// A spoofed flood rotating individual addresses must still hit a limit.
    #[test]
    fn prefix_bucket_limits_address_rotation() {
        let mut rl = RateLimiter::new(cfg(100, 5));
        let now = Instant::now();
        let allowed = (1..=10)
            .filter(|last| rl.allow(ip(&format!("198.51.100.{last}")), now))
            .count();
        assert_eq!(allowed, 5, "only the prefix budget may pass");
    }

    #[test]
    fn ipv6_prefix_bucket_groups_by_slash_64() {
        let mut rl = RateLimiter::new(cfg(100, 3));
        let now = Instant::now();
        let allowed = (0..6)
            .filter(|i| rl.allow(ip(&format!("2001:db8::{:x}", i)), now))
            .count();
        assert_eq!(allowed, 3);
        // A different /64 is unaffected.
        assert!(rl.allow(ip("2001:db8:1::1"), now));
    }

    #[test]
    fn loopback_is_never_limited() {
        let mut rl = RateLimiter::new(cfg(1, 1));
        let now = Instant::now();
        for _ in 0..10 {
            assert!(rl.allow(ip("127.0.0.1"), now));
            assert!(rl.allow(ip("::1"), now));
        }
    }

    #[test]
    fn zero_per_source_disables_limiting() {
        let mut rl = RateLimiter::new(cfg(0, 1));
        let now = Instant::now();
        for _ in 0..100 {
            assert!(rl.allow(ip("203.0.113.9"), now));
        }
    }

    /// A spoofed-source flood must not grow the table without bound.
    #[test]
    fn table_is_bounded_under_spoofed_flood() {
        let mut rl = RateLimiter::new(RateLimitConfig {
            per_source: 10,
            per_prefix: 0,
            max_tracked: 16,
        });
        let now = Instant::now();
        for i in 0..200u32 {
            let addr = Ipv4Addr::from(i.to_be_bytes());
            rl.allow(IpAddr::V4(addr), now);
        }
        assert!(rl.sources.len() <= 16, "table grew past max_tracked");
    }

    #[test]
    fn idle_buckets_are_swept() {
        let mut rl = RateLimiter::new(cfg(5, 1_000));
        let start = Instant::now();
        for i in 0..5u32 {
            rl.allow(IpAddr::V4(Ipv4Addr::new(203, 0, 113, i as u8)), start);
        }
        assert_eq!(rl.sources.len(), 5);
        // A later query from another source triggers the sweep.
        rl.allow(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            start + WINDOW * 10,
        );
        assert!(
            rl.sources.len() < 5,
            "stale buckets should have been dropped"
        );
    }

    #[test]
    fn prefix_key_is_stable() {
        assert_eq!(
            RateLimiter::prefix_key(ip("198.51.100.7")),
            "198.51.100.0/24"
        );
        assert_eq!(
            RateLimiter::prefix_key(ip("2001:db8::1")),
            "2001:db8:0:0::/64"
        );
    }

    #[test]
    fn ipv6_loopback_detected() {
        assert!(is_loopback(ip("::1")));
        assert!(!is_loopback(ip("2001:db8::1")));
    }
}
