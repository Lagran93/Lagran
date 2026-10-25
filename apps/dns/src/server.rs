//! Authoritative DNS service: zone checks, scheduling lookups and caching.

use crate::config::DnsConfig;
use crate::control::ControlClient;
use crate::wire::{
    a_record, aaaa_record, encode_response, ns_record, parse_query, soa_record, Query, Record,
    RCODE_NOERROR, RCODE_REFUSED, RCODE_SERVFAIL, TYPE_A, TYPE_AAAA, TYPE_ANY, TYPE_NS, TYPE_SOA,
};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct CacheEntry {
    ip: Option<IpAddr>,
    ttl: u32,
    at: Instant,
}

pub struct Service {
    cfg: DnsConfig,
    control: ControlClient,
    cache: Mutex<HashMap<String, CacheEntry>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl Service {
    pub fn new(cfg: DnsConfig, control: ControlClient) -> Self {
        Self {
            cfg,
            control,
            cache: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    fn in_zone(&self, name: &str) -> bool {
        name == self.cfg.zone || name.ends_with(&format!(".{}", self.cfg.zone))
    }

    fn soa(&self) -> Record {
        let serial = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| (d.as_secs() / 3600) as u32)
            .unwrap_or(1);
        soa_record(
            &self.cfg.zone,
            &self.cfg.soa_mname,
            &self.cfg.soa_rname,
            serial,
            300,
        )
    }

    fn ns(&self) -> Record {
        ns_record(&self.cfg.zone, &self.cfg.ns_name, 300)
    }

    fn fallback_ip(&self) -> Option<IpAddr> {
        self.cfg
            .fallback_ip
            .as_deref()
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
    }

    fn lookup(
        &self,
        key: &str,
        qname: &str,
        subnet: Option<&str>,
        client_ip: IpAddr,
    ) -> Option<(IpAddr, u32)> {
        let now = Instant::now();
        {
            let cache = self.cache.lock().ok()?;
            if let Some(entry) = cache.get(key) {
                let age = now.duration_since(entry.at).as_secs();
                if age <= self.cfg.cache_secs {
                    if let Some(ip) = entry.ip {
                        self.hits.fetch_add(1, Ordering::Relaxed);
                        return Some((ip, entry.ttl));
                    }
                }
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        match self.control.schedule(qname, subnet, Some(client_ip)) {
            Ok(reply) => {
                let ip = reply.ip.or(reply.backup);
                if let Ok(mut cache) = self.cache.lock() {
                    cache.insert(
                        key.to_string(),
                        CacheEntry {
                            ip,
                            ttl: reply.ttl,
                            at: now,
                        },
                    );
                    if cache.len() > 20_000 {
                        cache.retain(|_, e| now.duration_since(e.at).as_secs() <= self.cfg.stale_secs);
                    }
                }
                ip.map(|ip| (ip, reply.ttl))
            }
            Err(e) => {
                tracing::warn!(error = %e, qname, "scheduler lookup failed");
                if let Ok(cache) = self.cache.lock() {
                    if let Some(entry) = cache.get(key) {
                        let age = now.duration_since(entry.at).as_secs();
                        if age <= self.cfg.stale_secs {
                            if let Some(ip) = entry.ip {
                                tracing::warn!(qname, age, "serving stale scheduling result");
                                return Some((ip, entry.ttl.max(5)));
                            }
                        }
                    }
                }
                self.fallback_ip().map(|ip| (ip, self.cfg.ttl))
            }
        }
    }

    fn resolve(&self, q: &Query, client_ip: IpAddr) -> (u8, Vec<Record>, Vec<Record>) {
        let qname = q.qname.as_str();
        if q.qclass != 1 {
            return (RCODE_REFUSED, vec![], vec![]);
        }
        if !self.in_zone(qname) {
            return (RCODE_REFUSED, vec![], vec![]);
        }
        if q.qtype == TYPE_ANY {
            return (RCODE_REFUSED, vec![], vec![]);
        }
        if qname == self.cfg.zone {
            match q.qtype {
                TYPE_SOA => return (RCODE_NOERROR, vec![self.soa()], vec![]),
                TYPE_NS => return (RCODE_NOERROR, vec![self.ns()], vec![]),
                _ => {}
            }
        }
        // NS host itself is glue, not a scheduled CDN record.
        if qname == self.cfg.ns_name && q.qtype == TYPE_A {
            if let Ok(ip) = self.cfg.ns_ip.parse::<Ipv4Addr>() {
                return (RCODE_NOERROR, vec![a_record(qname, ip, 300)], vec![]);
            }
        }
        if q.qtype != TYPE_A && q.qtype != TYPE_AAAA {
            return (RCODE_NOERROR, vec![], vec![self.soa()]);
        }

        let subnet = q
            .ecs
            .as_ref()
            .map(|e| format!("{}/{}", e.addr, e.source_prefix));
        let subnet_key = subnet.clone().unwrap_or_else(|| client_ip.to_string());
        let key = format!("{}|{}|{}", qname, q.qtype, subnet_key);
        let Some((ip, ttl)) = self.lookup(&key, qname, subnet.as_deref(), client_ip) else {
            return (RCODE_SERVFAIL, vec![], vec![]);
        };
        let ttl = ttl.min(self.cfg.ttl).max(5);
        let answers = match (q.qtype, ip) {
            (TYPE_A, IpAddr::V4(v4)) => vec![a_record(qname, v4, ttl)],
            (TYPE_AAAA, IpAddr::V6(v6)) => vec![aaaa_record(qname, v6, ttl)],
            (TYPE_A, IpAddr::V6(_)) | (TYPE_AAAA, IpAddr::V4(_)) => {
                return (RCODE_NOERROR, vec![], vec![self.soa()]);
            }
            _ => vec![],
        };
        if answers.is_empty() {
            (RCODE_NOERROR, vec![], vec![self.soa()])
        } else {
            (RCODE_NOERROR, answers, vec![])
        }
    }

    pub fn handle(&self, buf: &[u8], client_ip: IpAddr, tcp: bool) -> Vec<u8> {
        let query = match parse_query(buf) {
            Ok(q) => q,
            Err(e) => {
                tracing::debug!(error = %e, "bad DNS query");
                if buf.len() >= 12 {
                    return formerr(&buf[..2]);
                }
                return Vec::new();
            }
        };
        let (rcode, answers, authority) = self.resolve(&query, client_ip);
        let limit = if tcp { 65_535 } else { query.udp_limit() };
        let resp = encode_response(&query, rcode, &answers, &authority, tcp, limit);
        tracing::debug!(
            qname = %query.qname,
            qtype = query.qtype,
            rcode,
            answers = answers.len(),
            client = %client_ip,
            "dns answer"
        );
        resp
    }

    pub fn stats(&self) -> (u64, u64, usize) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
            self.cache.lock().map(|c| c.len()).unwrap_or(0),
        )
    }
}

fn formerr(id: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(id);
    out.extend_from_slice(&0x8001u16.to_be_bytes()); // QR + FORMERR
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

struct Queue {
    items: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    cv: Condvar,
}

impl Queue {
    fn new() -> Self {
        Self {
            items: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
        }
    }
    fn push(&self, item: (Vec<u8>, SocketAddr)) {
        if let Ok(mut q) = self.items.lock() {
            if q.len() < 20_000 {
                q.push_back(item);
                self.cv.notify_one();
            }
        }
    }
    fn pop(&self) -> (Vec<u8>, SocketAddr) {
        let mut q = self.items.lock().expect("queue lock");
        loop {
            if let Some(item) = q.pop_front() {
                return item;
            }
            q = self.cv.wait(q).expect("queue wait");
        }
    }
}

fn handle_tcp(mut stream: TcpStream, service: Arc<Service>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let peer = stream.peer_addr().ok();
    let mut len_buf = [0u8; 2];
    if stream.read_exact(&mut len_buf).is_err() {
        return;
    }
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 4096 {
        return;
    }
    let mut buf = vec![0u8; len];
    if stream.read_exact(&mut buf).is_err() {
        return;
    }
    let client_ip = peer.map(|p| p.ip()).unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let resp = service.handle(&buf, client_ip, true);
    if resp.len() > 65_535 {
        return;
    }
    let mut out = Vec::with_capacity(2 + resp.len());
    out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
    out.extend_from_slice(&resp);
    let _ = stream.write_all(&out);
}

pub fn run(cfg: DnsConfig) -> anyhow::Result<()> {
    let control = ControlClient::new(&cfg.control_url, &cfg.agent_token, cfg.http_timeout())?;
    let service = Arc::new(Service::new(cfg.clone(), control));
    let udp = Arc::new(UdpSocket::bind(&cfg.listen)?);
    tracing::info!(
        listen = %cfg.listen,
        zone = %cfg.zone,
        ttl = cfg.ttl,
        control = %cfg.control_url,
        "authoritative DNS started"
    );

    if cfg.tcp_enabled {
        let tcp_service = service.clone();
        let listen = cfg.listen.clone();
        std::thread::spawn(move || match TcpListener::bind(&listen) {
            Ok(listener) => {
                tracing::info!(listen, "DNS TCP listener started");
                for stream in listener.incoming().flatten() {
                    let svc = tcp_service.clone();
                    std::thread::spawn(move || handle_tcp(stream, svc));
                }
            }
            Err(e) => tracing::error!(error = %e, "DNS TCP bind failed"),
        });
    }

    let queue = Arc::new(Queue::new());
    for _ in 0..cfg.workers {
        let q = queue.clone();
        let svc = service.clone();
        let sock = udp.clone();
        std::thread::spawn(move || loop {
            let (buf, peer) = q.pop();
            let client_ip = peer.ip();
            let resp = svc.handle(&buf, client_ip, false);
            if !resp.is_empty() {
                let _ = sock.send_to(&resp, peer);
            }
        });
    }

    // Periodic stats + cache hygiene.
    let stats_service = service.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(60));
        let (hits, misses, size) = stats_service.stats();
        tracing::info!(hits, misses, cache = size, "dns stats");
    });

    let mut buf = [0u8; 4096];
    loop {
        match udp.recv_from(&mut buf) {
            Ok((n, peer)) => {
                if n >= 12 {
                    queue.push((buf[..n].to_vec(), peer));
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "udp recv error");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
