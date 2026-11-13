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
    /// Whether both limits are off, so nothing is ever rejected.
    ///
    /// This used to be `per_source == 0` alone, and `allow` short-circuits on it.
    /// An operator who set `DNS_RATE_LIMIT_PER_SOURCE=0` intending "no per-client
    /// cap, just the per-prefix one" therefore turned off *all* limiting, including
    /// the aggregate bucket that protects against a distributed flood — while the
    /// config comment only warned that zero was "for use behind a scrubber".
    /// `allow` already guards the prefix check with `per_prefix > 0`, so a zero on
    /// one axis now means exactly that axis is off.
    pub fn is_disabled(&self) -> bool {
        self.per_source == 0 && self.per_prefix == 0
    }

    /// Which limits are inactive, for the startup warning.
    pub fn disabled_axes(&self) -> Vec<&'static str> {
        let mut off = Vec::new();
        if self.per_source == 0 {
            off.push("per-source");
        }
        if self.per_prefix == 0 {
            off.push("per-prefix");
        }
        off
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
    /// Where the incremental sweep stopped last time, so the next call resumes
    /// instead of always starting from the beginning.
    sweep_cursor_sources: Option<IpAddr>,
    sweep_cursor_prefixes: Option<String>,
    rejected: u64,
}

impl RateLimiter {
    pub fn new(cfg: RateLimitConfig) -> Self {
        Self {
            cfg,
            sources: HashMap::new(),
            prefixes: HashMap::new(),
            last_sweep: Instant::now(),
            sweep_cursor_sources: None,
            sweep_cursor_prefixes: None,
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

        // Each axis is honoured independently: a zero on one means that axis is
        // off, not that limiting is off. `is_disabled` above already covers the
        // both-zero case.
        if self.cfg.per_source > 0 && !self.take_source(ip, now) {
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

    /// Drop idle buckets incrementally.
    ///
    /// This used to be a full `retain` over both tables once per second, on the
    /// thread that receives packets. At `max_tracked` (50k each) that is a ~600 µs
    /// stall once a second — small on average, but a latency spike on the hot path
    /// exactly when the table is largest, which is when queries are already under
    /// pressure.
    ///
    /// Instead a bounded number of entries is examined per call, walking the map
    /// from where the previous call stopped. The work is spread across normal
    /// traffic, so no single query pays for the whole table. Removing entries only
    /// ever adds free space, so a resize cannot invalidate the cursor in a harmful
    /// way — it is reset whenever the map has shrunk below it.
    fn sweep(&mut self, now: Instant) {
        if now.duration_since(self.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        self.last_sweep = now;
        sweep_incremental(&mut self.sources, &mut self.sweep_cursor_sources, now);
        sweep_incremental(&mut self.prefixes, &mut self.sweep_cursor_prefixes, now);
    }
}

/// How many map entries one sweep call examines at most.
///
/// 256 entries is a few microseconds even in the worst case, and at typical query
/// rates it clears a full 50k-entry table well within the 4 s idle horizon the
/// entries are kept for.
const SWEEP_BATCH: usize = 256;

/// Minimum gap between sweep batches.
const SWEEP_INTERVAL: Duration = Duration::from_millis(50);

/// Examine the next [`SWEEP_BATCH`] entries, dropping idle ones.
///
/// The map is walked in an arbitrary but repeatable order; deleting entries never
/// adds keys, so resuming from a remembered key cannot skip live entries. If the
/// remembered key is gone, the walk restarts from the beginning.
fn sweep_incremental<K: std::hash::Hash + Eq + Clone>(
    map: &mut std::collections::HashMap<K, Bucket>,
    cursor: &mut Option<K>,
    now: Instant,
) {
    let horizon = WINDOW * 4;
    let mut expired: Vec<K> = Vec::new();
    let mut seen = 0usize;
    let mut last = None;
    let mut past_cursor = cursor.is_none();

    for (ip, bucket) in map.iter() {
        if seen >= SWEEP_BATCH {
            break;
        }
        if !past_cursor {
            if Some(ip) == cursor.as_ref() {
                past_cursor = true;
            }
            continue;
        }
        seen += 1;
        last = Some(ip.clone());
        if now.duration_since(bucket.window_start) >= horizon {
            expired.push(ip.clone());
        }
    }

    for ip in expired {
        map.remove(&ip);
    }
    // Restart on the next call if this pass reached the end, so cycles stay fair.
    *cursor = if seen < SWEEP_BATCH { None } else { last };
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
        // This used to run against `cfg(0, 1)` and expect 100 allows, i.e. it
        // encoded the old rule that a zero per-source cap disabled *everything*.
        // That rule was the bug: it silently turned off the per-prefix bucket too.
        // Disabling both axes is now what disables limiting, so the fixture has to
        // say so.
        let mut rl = RateLimiter::new(cfg(0, 0));
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
        rl.allow(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), start + WINDOW * 10);
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
    /// The incremental sweep must eventually remove every idle bucket.
    ///
    /// It examines a bounded number of entries per call, so correctness is "all
    /// expired entries are gone after enough batches", not "gone after one".
    #[test]
    fn incremental_sweep_clears_the_whole_table() {
        let mut map: HashMap<IpAddr, Bucket> = HashMap::new();
        let start = Instant::now();
        for i in 0..5_000u32 {
            map.insert(
                IpAddr::V4(std::net::Ipv4Addr::from(0x0A00_0000 + i)),
                Bucket::new(10, start),
            );
        }
        let mut cursor = None;
        // Past the 4-window horizon.
        let now = start + WINDOW * 8;
        // 5000 / 256 rounded up, with room for the cursor restart.
        for _ in 0..64 {
            sweep_incremental(&mut map, &mut cursor, now);
        }
        assert!(
            map.is_empty(),
            "expected every idle bucket to be removed, {} left",
            map.len()
        );
    }

    /// Live buckets survive the sweep.
    #[test]
    fn incremental_sweep_keeps_live_buckets() {
        let mut map: HashMap<IpAddr, Bucket> = HashMap::new();
        let start = Instant::now();
        for i in 0..1_000u32 {
            map.insert(
                IpAddr::V4(std::net::Ipv4Addr::from(0x0A00_0000 + i)),
                Bucket::new(10, start),
            );
        }
        let mut cursor = None;
        // Within the 4-window horizon, so nothing is idle.
        let now = start + WINDOW * 2;
        for _ in 0..16 {
            sweep_incremental(&mut map, &mut cursor, now);
        }
        assert_eq!(map.len(), 1_000, "live buckets must not be swept");
    }

    /// A sweep call examines a bounded number of entries, not the whole table.
    #[test]
    fn one_sweep_call_is_bounded() {
        let mut map: HashMap<IpAddr, Bucket> = HashMap::new();
        let start = Instant::now();
        for i in 0..10_000u32 {
            map.insert(
                IpAddr::V4(std::net::Ipv4Addr::from(0x0A00_0000 + i)),
                Bucket::new(10, start),
            );
        }
        let mut cursor = None;
        let now = start + WINDOW * 8;
        sweep_incremental(&mut map, &mut cursor, now);
        let removed = 10_000 - map.len();
        assert!(
            removed <= SWEEP_BATCH,
            "one call removed {removed}, more than the {SWEEP_BATCH} batch size"
        );
        assert!(removed > 0, "an expired table must lose at least one entry");
    }
    /// A zero on one axis must not disable the other.
    ///
    /// `is_disabled` used to test `per_source == 0` alone and `allow`
    /// short-circuits on it, so an operator who set `per_source = 0` meaning "no
    /// per-client cap, keep the aggregate one" turned off every check — including
    /// the per-prefix bucket that guards against a distributed flood.
    #[test]
    fn disabling_one_axis_keeps_the_other_active() {
        // per_source off, per_prefix on: the aggregate limit still applies.
        let cfg = RateLimitConfig {
            per_source: 0,
            per_prefix: 10,
            max_tracked: 1_000,
        };
        assert!(!cfg.is_disabled());
        assert_eq!(cfg.disabled_axes(), vec!["per-source"]);

        let mut rl = RateLimiter::new(cfg);
        let start = Instant::now();
        // One /24, many distinct sources: only the prefix bucket can stop them.
        let mut allowed = 0;
        for i in 0..50u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0A00_0000 + i));
            if rl.allow(ip, start) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 10, "the per-prefix limit must still apply");
    }

    /// The mirror case: per_prefix off, per_source on.
    #[test]
    fn disabling_the_prefix_axis_keeps_the_source_axis() {
        let cfg = RateLimitConfig {
            per_source: 3,
            per_prefix: 0,
            max_tracked: 1_000,
        };
        assert!(!cfg.is_disabled());
        assert_eq!(cfg.disabled_axes(), vec!["per-prefix"]);

        let mut rl = RateLimiter::new(cfg);
        let start = Instant::now();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(rl.allow(ip, start));
        assert!(rl.allow(ip, start));
        assert!(rl.allow(ip, start));
        assert!(
            !rl.allow(ip, start),
            "the per-source limit must still apply"
        );
    }

    /// Both zero is the only case that disables everything.
    #[test]
    fn both_axes_zero_disables_everything() {
        let cfg = RateLimitConfig {
            per_source: 0,
            per_prefix: 0,
            max_tracked: 1_000,
        };
        assert!(cfg.is_disabled());
        assert_eq!(cfg.disabled_axes().len(), 2);

        let mut rl = RateLimiter::new(cfg);
        let start = Instant::now();
        for i in 0..1_000u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0A00_0000 + i));
            assert!(rl.allow(ip, start), "nothing may be rejected");
        }
    }
}
