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

    fn ns_records(&self) -> Vec<Record> {
        self.cfg
            .ns_names
            .iter()
            .map(|name| ns_record(&self.cfg.zone, name, 300))
            .collect()
    }

    fn ns_glue(&self, name: &str) -> Option<Record> {
        let index = self
            .cfg
            .ns_names
            .iter()
            .position(|n| n.eq_ignore_ascii_case(name))?;
        let ip = *self.cfg.ns_ips.get(index)?;
        Some(match ip {
            IpAddr::V4(v4) => a_record(name, v4, 300),
            IpAddr::V6(v6) => aaaa_record(name, v6, 300),
        })
    }

    fn ns_glue_records(&self) -> Vec<Record> {
        self.cfg
            .ns_names
            .iter()
            .filter_map(|name| self.ns_glue(name))
            .collect()
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
                        cache.retain(|_, e| {
                            now.duration_since(e.at).as_secs() <= self.cfg.stale_secs
                        });
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

    fn resolve(&self, q: &Query, client_ip: IpAddr) -> (u8, Vec<Record>, Vec<Record>, Vec<Record>) {
        let qname = q.qname.as_str();
        if q.qclass != 1 {
            return (RCODE_REFUSED, vec![], vec![], vec![]);
        }
        if !self.in_zone(qname) {
            return (RCODE_REFUSED, vec![], vec![], vec![]);
        }
        if q.qtype == TYPE_ANY {
            return (RCODE_REFUSED, vec![], vec![], vec![]);
        }
        if qname == self.cfg.zone {
            match q.qtype {
                TYPE_SOA => return (RCODE_NOERROR, vec![self.soa()], vec![], vec![]),
                TYPE_NS => {
                    return (
                        RCODE_NOERROR,
                        self.ns_records(),
                        vec![],
                        self.ns_glue_records(),
                    )
                }
                _ => {}
            }
        }
        // NS host itself is glue, not a scheduled CDN record.
        if q.qtype == TYPE_A || q.qtype == TYPE_AAAA {
            if let Some(glue) = self.ns_glue(qname) {
                if (q.qtype == TYPE_A && glue.rtype == TYPE_A)
                    || (q.qtype == TYPE_AAAA && glue.rtype == TYPE_AAAA)
                {
                    return (RCODE_NOERROR, vec![glue], vec![], vec![]);
                }
                return (RCODE_NOERROR, vec![], vec![self.soa()], vec![]);
            }
        }
        if q.qtype != TYPE_A && q.qtype != TYPE_AAAA {
            return (RCODE_NOERROR, vec![], vec![self.soa()], vec![]);
        }

        let subnet = q
            .ecs
            .as_ref()
            .map(|e| format!("{}/{}", e.addr, e.source_prefix));
        let subnet_key = subnet.clone().unwrap_or_else(|| client_ip.to_string());
        let key = format!("{}|{}|{}", qname, q.qtype, subnet_key);
        let Some((ip, ttl)) = self.lookup(&key, qname, subnet.as_deref(), client_ip) else {
            return (RCODE_SERVFAIL, vec![], vec![], vec![]);
        };
        let ttl = ttl.min(self.cfg.ttl).max(5);
        let answers = match (q.qtype, ip) {
            (TYPE_A, IpAddr::V4(v4)) => vec![a_record(qname, v4, ttl)],
            (TYPE_AAAA, IpAddr::V6(v6)) => vec![aaaa_record(qname, v6, ttl)],
            (TYPE_A, IpAddr::V6(_)) | (TYPE_AAAA, IpAddr::V4(_)) => {
                return (RCODE_NOERROR, vec![], vec![self.soa()], vec![]);
            }
            _ => vec![],
        };
        if answers.is_empty() {
            (RCODE_NOERROR, vec![], vec![self.soa()], vec![])
        } else {
            (RCODE_NOERROR, answers, vec![], vec![])
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
        let (rcode, answers, authority, additional) = self.resolve(&query, client_ip);
        let limit = if tcp { 65_535 } else { query.udp_limit() };
        let resp = encode_response(&query, rcode, &answers, &authority, &additional, tcp, limit);
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
        let mut q = self
            .items
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if q.len() < 20_000 {
            q.push_back(item);
            self.cv.notify_one();
        }
    }
    fn pop(&self) -> (Vec<u8>, SocketAddr) {
        // Recover from a poisoned mutex instead of panicking.
        //
        // `expect` here used to be the single most dangerous line in this
        // service: one panic while the guard was held poisoned the lock, and then
        // *every* worker panicked on its next `pop`. The process stayed up
        // (the listener thread is separate) so the supervisor saw a healthy DNS
        // process that answered nothing. The queue only holds query bytes and
        // source addresses, which stay valid regardless of what the panicking
        // worker did, so reusing the inner data is safe.
        let mut q = self
            .items
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if let Some(item) = q.pop_front() {
                return item;
            }
            q = self
                .cv
                .wait(q)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

/// Read granularity for TCP DNS messages.
///
/// The length prefix is honoured up to the protocol maximum, but memory grows with
/// what actually arrives instead of with what was announced.
const TCP_READ_CHUNK: usize = 4096;

/// Read exactly `len` bytes without pre-allocating the announced size.
///
/// A client may announce 65535 bytes and then send nothing; committing that up
/// front would hold the memory for the whole read timeout on every connection
/// thread. Growth follows what actually arrives.
fn read_framed_body(stream: &mut dyn Read, len: usize) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(len.min(TCP_READ_CHUNK));
    let mut remaining = len;
    let mut chunk = [0u8; TCP_READ_CHUNK];
    while remaining > 0 {
        let want = remaining.min(TCP_READ_CHUNK);
        stream.read_exact(&mut chunk[..want]).ok()?;
        buf.extend_from_slice(&chunk[..want]);
        remaining -= want;
    }
    Some(buf)
}

/// Outcome of reading one TCP-framed DNS message.
#[derive(Debug, PartialEq, Eq)]
enum FramedRead {
    /// A complete message of the announced length.
    Body(Vec<u8>),
    /// Nothing to answer: zero-length or a failed/short read.
    Drop,
}

/// Read one length-prefixed message, applying the acceptance policy.
///
/// Kept separate from `handle_tcp` so the policy is testable: the previous
/// version rejected anything over 4096 bytes here, which silently closed the
/// connection for queries the protocol allows.
fn read_framed_message(stream: &mut dyn Read, announced: usize) -> FramedRead {
    if announced == 0 {
        return FramedRead::Drop;
    }
    match read_framed_body(stream, announced) {
        Some(body) => FramedRead::Body(body),
        None => FramedRead::Drop,
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
    // A TCP DNS message is length-prefixed with a 16-bit field, and RFC 7766
    // expects the server to read what the client announced. The previous 4096
    // cap silently dropped larger queries: the connection was closed without a
    // response, so the client saw a timeout rather than an error, and a resolver
    // retrying over TCP (which is what a truncated UDP answer leads to) never got
    // an answer at all. `Service::handle` already treats TCP as good for 65535
    // bytes, so the two limits disagreed.
    if len == 0 {
        // Zero-length is not a message; nothing to answer with an ID.
        return;
    }
    // Read into a fixed-size stack buffer in chunks rather than pre-allocating
    // `len` up front: a client may announce 65535 bytes and then send nothing, and
    // `vec![0u8; len]` would have committed that memory for the whole 5 s read
    // timeout on every one of the (default 512) connection threads.
    let buf = match read_framed_message(&mut stream, len) {
        FramedRead::Body(body) => body,
        FramedRead::Drop => return,
    };
    let client_ip = peer
        .map(|p| p.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let resp = service.handle(&buf, client_ip, true);
    if resp.len() > 65_535 {
        // The response cannot be framed in a 16-bit length field. Answer with
        // FORMERR echoing the original ID instead of closing silently, so the
        // client can distinguish "refused" from "server unreachable".
        let id = &buf[..buf.len().min(2)];
        let formerr = formerr(id);
        let mut out = Vec::with_capacity(2 + formerr.len());
        out.extend_from_slice(&(formerr.len() as u16).to_be_bytes());
        out.extend_from_slice(&formerr);
        let _ = stream.write_all(&out);
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
        ns = %cfg.ns_names.join(","),
        ttl = cfg.ttl,
        control = %cfg.control_url,
        "authoritative DNS started"
    );

    if cfg.tcp_enabled {
        let tcp_service = service.clone();
        let listen = cfg.listen.clone();
        // One thread per connection: without a cap a client can exhaust threads
        // and file descriptors just by opening sockets.
        let max_conns = cfg.max_tcp_connections;
        let active = Arc::new(AtomicU64::new(0));
        std::thread::spawn(move || match TcpListener::bind(&listen) {
            Ok(listener) => {
                tracing::info!(listen, max_conns, "DNS TCP listener started");
                for stream in listener.incoming().flatten() {
                    if active.load(Ordering::Relaxed) >= max_conns as u64 {
                        // Dropping the stream closes the connection immediately.
                        tracing::debug!("TCP connection limit reached, dropping");
                        continue;
                    }
                    let svc = tcp_service.clone();
                    let active = active.clone();
                    active.fetch_add(1, Ordering::Relaxed);
                    std::thread::spawn(move || {
                        handle_tcp(stream, svc);
                        active.fetch_sub(1, Ordering::Relaxed);
                    });
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

    // Rate limit at the receive edge so a flood never reaches the worker pool.
    // Loopback is exempt and a zero `per_source` disables the limiter.
    let mut limiter = crate::ratelimit::RateLimiter::new(cfg.rate_limit);
    let mut last_report = Instant::now();
    let mut buf = [0u8; 4096];
    loop {
        match udp.recv_from(&mut buf) {
            Ok((n, peer)) => {
                if n >= 12 && limiter.allow(peer.ip(), Instant::now()) {
                    queue.push((buf[..n].to_vec(), peer));
                }
                if last_report.elapsed() >= Duration::from_secs(30) {
                    let rejected = limiter.rejected();
                    if rejected > 0 {
                        tracing::warn!(rejected, "dropped rate-limited DNS queries");
                    }
                    last_report = Instant::now();
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "udp recv error");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[cfg(test)]
mod queue_tests {
    use super::*;
    use std::sync::Arc;

    fn addr() -> SocketAddr {
        "127.0.0.1:9".parse().unwrap()
    }

    /// A poisoned queue must keep working.
    ///
    /// `pop` used to `expect` the lock. Once any worker panicked while holding it
    /// the mutex was poisoned, so every worker panicked on its next pop, the queue
    /// drained nothing, and DNS stopped answering while the process stayed up.
    #[test]
    fn poisoned_queue_still_pops() {
        let queue = Arc::new(Queue::new());
        queue.push((b"first".to_vec(), addr()));

        // Poison the mutex by panicking while holding the guard.
        let poisoner = queue.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.items.lock().unwrap();
            panic!("poison the queue");
        })
        .join();

        // Pushing and popping must both recover rather than panic.
        queue.push((b"second".to_vec(), addr()));
        let (first, _) = queue.pop();
        let (second, _) = queue.pop();
        assert_eq!(first, b"first".to_vec());
        assert_eq!(second, b"second".to_vec());
    }

    /// The queue stays bounded so a flood cannot exhaust memory.
    #[test]
    fn queue_is_bounded() {
        let queue = Queue::new();
        for i in 0..20_010 {
            queue.push((format!("q{i}").into_bytes(), addr()));
        }
        let mut popped = 0;
        while let Ok(q) = queue.items.try_lock() {
            if q.is_empty() {
                break;
            }
            drop(q);
            queue.pop();
            popped += 1;
            if popped > 20_010 {
                break;
            }
        }
        assert!(popped <= 20_000, "queue accepted {popped} items");
    }
    /// A query larger than the old 4096 cap must be accepted.
    ///
    /// The length prefix allows 65535 bytes and RFC 7766 expects the server to
    /// read what was announced. The previous 4096 limit closed the connection
    /// without a response, so a resolver retrying over TCP after a truncated UDP
    /// answer got a timeout instead of an answer.
    #[test]
    fn tcp_reads_queries_larger_than_the_old_cap() {
        for size in [4097usize, 8192, 65_535] {
            let payload = vec![0xABu8; size];
            let mut cursor = std::io::Cursor::new(payload.clone());
            match read_framed_message(&mut cursor, size) {
                FramedRead::Body(body) => assert_eq!(body.len(), size),
                FramedRead::Drop => panic!("{size}-byte query must be read, not dropped"),
            }
        }
    }

    /// The announced size is not pre-allocated: a client that announces 65535 and
    /// sends nothing must not cause a 64 KiB allocation.
    #[test]
    fn tcp_read_does_not_preallocate_the_announced_size() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        assert_eq!(
            read_framed_message(&mut cursor, 65_535),
            FramedRead::Drop,
            "a short body must be dropped, not padded"
        );
    }

    /// A body that stops mid-message is rejected rather than returned truncated.
    #[test]
    fn tcp_read_rejects_a_truncated_body() {
        let mut cursor = std::io::Cursor::new(vec![1u8; 100]);
        assert_eq!(read_framed_message(&mut cursor, 200), FramedRead::Drop);
    }

    /// A zero-length frame has no ID to answer, so it is dropped.
    #[test]
    fn tcp_read_drops_zero_length_frames() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        assert_eq!(read_framed_message(&mut cursor, 0), FramedRead::Drop);
    }

    /// Small bodies round-trip unchanged.
    #[test]
    fn tcp_read_handles_small_bodies() {
        let payload = b"hello".to_vec();
        let mut cursor = std::io::Cursor::new(payload.clone());
        assert_eq!(
            read_framed_message(&mut cursor, payload.len()),
            FramedRead::Body(payload)
        );
    }
}
