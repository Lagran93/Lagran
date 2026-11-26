// Minimal dependency-free authoritative-DNS load generator (std only).
//
//   rustc -O tools/load-test/dns_load.rs -o /tmp/dns_load
//   /tmp/dns_load <server_ip> <port> <qname> <duration_secs> <threads>
//
// Each thread opens its own UDP socket, fires A-record queries back-to-back and
// records round-trip latency. It reports aggregate QPS and latency percentiles
// so the DNS service can be measured the same way the HTTP edges are.

use std::env;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn encode_qname(qname: &str, out: &mut Vec<u8>) {
    for label in qname.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
}

fn build_query(id: u16, qname: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(64);
    p.extend_from_slice(&id.to_be_bytes()); // transaction id
    p.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    p.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    p.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    p.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    p.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_qname(qname, &mut p);
    p.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    p.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    p
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 6 {
        eprintln!("usage: dns_load <ip> <port> <qname> <duration_secs> <threads>");
        std::process::exit(2);
    }
    let ip = args[1].clone();
    let port: u16 = args[2].parse().expect("port");
    let qname = args[3].clone();
    let duration: u64 = args[4].parse().expect("duration");
    let threads: usize = args[5].parse().expect("threads");

    let sent = Arc::new(AtomicU64::new(0));
    let ok = Arc::new(AtomicU64::new(0));
    let timeouts = Arc::new(AtomicU64::new(0));

    let start = Instant::now();
    let deadline = start + Duration::from_secs(duration);

    let mut handles = Vec::new();
    for t in 0..threads {
        let ip = ip.clone();
        let qname = qname.clone();
        let sent = Arc::clone(&sent);
        let ok = Arc::clone(&ok);
        let timeouts = Arc::clone(&timeouts);
        handles.push(thread::spawn(move || {
            let sock = UdpSocket::bind("0.0.0.0:0").expect("bind udp");
            sock.connect((ip.as_str(), port)).expect("connect udp");
            sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
            let mut lat: Vec<u64> = Vec::with_capacity(1_000_000);
            let mut id: u16 = (t as u16).wrapping_mul(7919);
            let mut buf = [0u8; 1500];
            while Instant::now() < deadline {
                id = id.wrapping_add(1);
                let q = build_query(id, &qname);
                sent.fetch_add(1, Ordering::Relaxed);
                let ts = Instant::now();
                if sock.send(&q).is_err() {
                    continue;
                }
                match sock.recv(&mut buf) {
                    Ok(n) if n >= 12 => {
                        ok.fetch_add(1, Ordering::Relaxed);
                        lat.push(ts.elapsed().as_micros() as u64);
                    }
                    _ => {
                        timeouts.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            lat
        }));
    }

    let mut all: Vec<u64> = Vec::new();
    for h in handles {
        if let Ok(mut v) = h.join() {
            all.append(&mut v);
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    let total_sent = sent.load(Ordering::Relaxed);
    let total_ok = ok.load(Ordering::Relaxed);
    let total_to = timeouts.load(Ordering::Relaxed);
    all.sort_unstable();
    let pct = |p: f64| -> u64 {
        if all.is_empty() {
            return 0;
        }
        let idx = ((all.len() as f64) * p / 100.0) as usize;
        all[idx.min(all.len() - 1)]
    };
    let avg = if all.is_empty() { 0 } else { all.iter().sum::<u64>() / all.len() as u64 };
    let qps = total_ok as f64 / elapsed;

    println!(
        "threads={} duration={:.1}s sent={} ok={} timeouts={} qps={:.1} avg_us={} p50_us={} p90_us={} p99_us={}",
        threads, elapsed, total_sent, total_ok, total_to, qps, avg, pct(50.0), pct(90.0), pct(99.0)
    );
}
