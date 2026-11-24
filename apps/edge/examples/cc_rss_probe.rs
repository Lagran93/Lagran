//! Real-RSS measurement for PERF-NEW-01.
//!
//! A measurement harness, not part of the shipped binary. It drives the real
//! `CcProtector` the way the edge data plane does and reports the process
//! resident set as the client-state table grows.
//!
//! Build: cargo build --release -p edge --example cc_rss_probe
//! Run:   ./target/release/examples/cc_rss_probe <fixed|legacy> <clients>
//!
//! `fixed`  — what ships: idle entries are swept every second on a background
//!            task and the table is capped at `CC_STATE_HARD_CAP`.
//! `legacy` — the pre-fix behaviour: the predicate only removes an entry after
//!            `STATE_TTL` (600 s) of silence and nothing bounds the table.
//!
//! Both modes submit exactly the same workload, so the RSS difference at the end
//! is attributable to eviction rather than to differing traffic.

use edge::server::cc::{CcConfig, CcDecision, CcMode, CcProtector};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

fn rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .trim()
                .trim_end_matches(" kB")
                .trim()
                .parse::<u64>()
                .unwrap_or(0);
        }
    }
    0
}

fn cfg() -> CcConfig {
    CcConfig {
        enabled: true,
        // No client is ever banned: the finding's scenario is a fleet that never
        // trips the threshold, only the per-client accounting.
        rps: 1_000_000,
        burst: 1_000_000,
        ban_after: 0,
        ban_seconds: 0,
        mode: CcMode::Monitor,
        allow_ips: Vec::new(),
        global_rps: 0,
        global_burst: 0,
    }
}

/// A distinct /24 per client.
///
/// CC aggregates IPv4 by /24, so the third octet is what distinguishes two
/// clients. Varying only the last octet would put every 256th client in one
/// entry: the first version of this probe did that and reported 782 tracked
/// clients for 200_000 requests, which measures nothing.
fn client(i: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(
        12 + (i / 65_536) as u8,
        ((i / 256) % 256) as u8,
        (i % 256) as u8,
        1,
    ))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "fixed".into());
    let clients: u32 = args.next().and_then(|s| s.parse().ok()).unwrap_or(200_000);
    let legacy = mode == "legacy";

    // Fail loudly rather than silently measuring collisions.
    for i in [0u32, 1, 255, 256, clients.saturating_sub(1)] {
        assert_ne!(
            edge::server::cc::client_group(client(i)),
            edge::server::cc::client_group(client((i + 1) % clients.max(2))),
            "client generator produced colliding groups at {i}"
        );
    }

    let mut cc = CcProtector::new();
    if legacy {
        // Reproduce the pre-fix world exactly: legacy predicate, no capacity cap,
        // and no background sweep.
        cc.set_legacy_eviction_for_measurement(true);
    } else {
        cc.spawn_maintenance();
    }

    let baseline = rss_kib();
    println!("mode={mode} clients={clients} rss_baseline_kib={baseline}");

    let config = cfg();
    let started = Instant::now();
    const REPORT_EVERY: u32 = 50_000;
    for i in 0..clients {
        let _ = cc.check("flood.test", "/", client(i), &config, false).await;
        if (i + 1) % REPORT_EVERY == 0 {
            println!(
                "  after {:>7} clients: rss_kib={:<8} tracked={:<8} elapsed_ms={}",
                i + 1,
                rss_kib(),
                cc.tracked_clients(),
                started.elapsed().as_millis()
            );
        }
    }

    let tracked_end = cc.tracked_clients();
    let rss_end = rss_kib();

    // Let whichever sweep is in play catch up. With the shipped rule every idle
    // entry is reclaimed; with the legacy rule the same sweep removes nothing,
    // because every entry is younger than STATE_TTL.
    if legacy {
        // Run the sweep the old code would have run: it removes nothing here,
        // because no entry has been idle for STATE_TTL.
        cc.run_maintenance_now_for_measurement();
    } else {
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    let final_rss = rss_kib();
    let tracked = cc.tracked_clients();
    println!(
        "mode={mode} tracked_end={tracked_end} rss_end_kib={rss_end} \
         tracked_final={tracked} rss_final_kib={final_rss} \
         rss_delta_kib={} total_ms={}",
        final_rss.saturating_sub(baseline),
        started.elapsed().as_millis()
    );

    // Per-entry cost: the number that explains the finding.
    if tracked > 0 {
        println!(
            "mode={mode} bytes_per_retained_client={}",
            ((final_rss.saturating_sub(baseline)) * 1024) / tracked as u64
        );
    }

    // The sweep must not break decision-making.
    let probe: IpAddr = "203.0.113.250".parse().unwrap();
    let decision = cc.check("flood.test", "/", probe, &config, false).await;
    assert!(
        matches!(decision, CcDecision::Allow | CcDecision::Limit { .. }),
        "CC must still answer after maintenance"
    );
    println!("cc_still_functional=true");
}
