//! Authoritative DNS service: zone checks, scheduling lookups and caching.

use crate::config::DnsConfig;
use crate::control::ControlClient;
use crate::wire::{
    a_record, aaaa_record, encode_response, ns_record, parse_query, soa_record, Query, Record,
    RCODE_NOERROR, RCODE_REFUSED, RCODE_SERVFAIL, TYPE_A, TYPE_AAAA, TYPE_ANY, TYPE_NS, TYPE_SOA,
};
use std::collections::{HashMap, HashSet, VecDeque};
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
    /// Keys currently being fetched from the control plane.
    ///
    /// A hot name missed by every worker at once used to produce one control-plane
    /// call per worker. The set makes the first caller the leader and the rest wait
    /// for its result.
    in_flight: Mutex<HashSet<String>>,
    /// Signalled whenever an in-flight fetch finishes, so waiters re-check the
    /// cache instead of polling.
    flight_done: Condvar,
    hits: AtomicU64,
    misses: AtomicU64,
}

/// Mark `key` as being fetched. Returns true when this caller is the leader.
///
/// A poisoned mutex returns true: falling through as the leader costs a duplicate
/// fetch, while refusing would leave the query unanswered.
fn claim_flight(in_flight: &Mutex<HashSet<String>>, key: &str) -> bool {
    match in_flight.lock() {
        Ok(mut set) => set.insert(key.to_string()),
        Err(_) => true,
    }
}

/// Clear the in-flight marker for `key` and wake anyone waiting on it.
fn release_flight(in_flight: &Mutex<HashSet<String>>, done: &Condvar, key: &str) {
    if let Ok(mut set) = in_flight.lock() {
        set.remove(key);
    }
    done.notify_all();
}

impl Service {
    pub fn new(cfg: DnsConfig, control: ControlClient) -> Self {
        Self {
            cfg,
            control,
            cache: Mutex::new(HashMap::new()),
            in_flight: Mutex::new(HashSet::new()),
            flight_done: Condvar::new(),
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

    /// Evict up to `budget` expired entries with a single bounded pass.
    ///
    /// HashMap iteration order is arbitrary but stable while nothing is inserted,
    /// which is enough here: the goal is to keep the table near the cap, not to
    /// sweep it exactly. Anything still live that this pass misses is caught on the
    /// next insert.
    fn evict_expired(
        cache: &mut HashMap<String, CacheEntry>,
        now: Instant,
        stale_secs: u64,
        budget: usize,
    ) {
        let mut expired: Vec<String> = Vec::new();
        for (key, entry) in cache.iter() {
            if expired.len() >= budget {
                break;
            }
            if now.duration_since(entry.at).as_secs() > stale_secs {
                expired.push(key.clone());
            }
        }
        for key in expired {
            cache.remove(&key);
        }
    }

    fn fallback_ip(&self) -> Option<IpAddr> {
        self.cfg
            .fallback_ip
            .as_deref()
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
    }

    /// Wait until the in-flight fetch for `key` finishes, or a short deadline.
    ///
    /// Bounded on purpose: if the leader is wedged (a hung read, a panic before it
    /// cleared the marker) a waiter must still answer the query rather than hold
    /// the worker thread. On timeout the caller fetches for itself, which is the
    /// pre-single-flight behaviour — degraded, not stuck.
    /// A fresh cached answer for `key`, if there is one.
    fn cached_answer(&self, key: &str, now: Instant) -> Option<Option<(IpAddr, u32)>> {
        let cache = self.cache.lock().ok()?;
        let entry = cache.get(key)?;
        if now.duration_since(entry.at).as_secs() > self.cfg.cache_secs {
            return None;
        }
        Some(entry.ip.map(|ip| (ip, entry.ttl)))
    }

    fn wait_for_flight(&self, key: &str, _now: Instant) {
        let deadline = Instant::now() + self.cfg.http_timeout().max(Duration::from_millis(100));
        let Ok(mut set) = self.in_flight.lock() else {
            return;
        };
        while set.contains(key) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return;
            }
            match self.flight_done.wait_timeout(set, remaining) {
                Ok((guard, _)) => set = guard,
                Err(_) => return,
            }
        }
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

        // Single-flight: the first caller for this key fetches, the rest wait for
        // its result. Without this, eight workers missing the same hot name at the
        // same moment produced eight control-plane calls, and when the control
        // plane was slow all eight blocked on the read timeout together while the
        // UDP queue drained.
        //
        // The lock is only held for the set bookkeeping. The fetch itself runs
        // unlocked — holding it across `control.schedule` would serialise every
        // query on the server, which is worse than the duplicate fetches.
        let leader = claim_flight(&self.in_flight, key);
        if !leader {
            self.wait_for_flight(key, now);
            // The leader is done. Its answer — or its failure — is already in the
            // cache; re-reading is the whole point of waiting. Falling through to a
            // fetch here would keep the duplicate origin calls the wait exists to
            // avoid, so only a still-empty cache sends us to the control plane.
            if let Some(now_cached) = self.cached_answer(key, now) {
                return now_cached;
            }
        }

        let fetched = self.control.schedule(qname, subnet, Some(client_ip));

        if leader {
            // Publish and wake waiters before doing anything else, so a slow
            // write-back cannot extend their wait.
            release_flight(&self.in_flight, &self.flight_done, key);
        }

        match fetched {
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
                    // Bound the table without a full sweep under the write lock.
                    //
                    // The old `retain` walked every entry the moment the map passed
                    // 20k — a millisecond-scale stall on the worker thread, repeated
                    // every time a random-subdomain flood refilled the table. Here a
                    // bounded number of expired entries is evicted per insert
                    // instead, so no single query pays for the whole map.
                    if cache.len() > 20_000 {
                        Self::evict_expired(&mut cache, now, self.cfg.stale_secs, 256);
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
    /// Queries dropped because the queue was full. Non-zero means the workers are
    /// not draining fast enough and clients are getting silence.
    dropped: std::sync::atomic::AtomicU64,
}

impl Queue {
    fn new() -> Self {
        Self {
            items: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
            dropped: std::sync::atomic::AtomicU64::new(0),
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
        } else {
            // A full queue means the workers are not keeping up — a stalled worker
            // or a burst above capacity. Dropping silently made that invisible.
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    /// Queries dropped since start.
    fn dropped(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
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

/// Best-effort text for a panic payload.
///
/// Most panics carry `&str` or `String`; anything else is reported by type so the
/// log line is still useful.
fn panic_reason(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "non-string panic payload".to_string()
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
                    // Claim a slot and test the limit in one atomic step. The
                    // previous check-then-increment was safe only because this
                    // accept loop is single-threaded — an invariant nothing states
                    // and any future second acceptor would silently break.
                    let claimed = active
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                            (current < max_conns as u64).then_some(current + 1)
                        })
                        .is_ok();
                    if !claimed {
                        // Dropping the stream closes the connection immediately.
                        tracing::debug!("TCP connection limit reached, dropping");
                        continue;
                    }
                    let svc = tcp_service.clone();
                    let active = active.clone();
                    std::thread::spawn(move || {
                        handle_tcp(stream, svc);
                        active.fetch_sub(1, Ordering::AcqRel);
                    });
                }
            }
            Err(e) => tracing::error!(error = %e, "DNS TCP bind failed"),
        });
    }

    let queue = Arc::new(Queue::new());
    for index in 0..cfg.workers {
        let q = queue.clone();
        let svc = service.clone();
        let sock = udp.clone();
        // A worker that dies takes a slice of the server's capacity with it, and
        // nothing else notices: `run()` keeps receiving and enqueuing, the process
        // stays up, and the supervisor sees a healthy DNS service that answers
        // fewer and fewer queries as workers drop out. Catching a panic here keeps
        // one malformed request from costing a worker forever.
        std::thread::spawn(move || {
            let mut restarts: u64 = 0;
            loop {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| loop {
                    let (buf, peer) = q.pop();
                    let client_ip = peer.ip();
                    let resp = svc.handle(&buf, client_ip, false);
                    if !resp.is_empty() {
                        let _ = sock.send_to(&resp, peer);
                    }
                }));
                // `catch_unwind` only returns on a panic or a `panic = "abort"`
                // build; reaching here means this worker unwound.
                let Err(payload) = outcome else {
                    continue;
                };
                restarts = restarts.saturating_add(1);
                let reason = panic_reason(payload.as_ref());
                tracing::error!(
                    worker = index,
                    restarts,
                    reason,
                    "DNS worker panicked; restarting"
                );
                // A tight panic loop would spin a core; back off a little.
                std::thread::sleep(Duration::from_millis(50 * restarts.min(20)));
            }
        });
    }

    // Periodic stats + cache hygiene.
    let stats_service = service.clone();
    let stats_queue = queue.clone();
    // Named so a panic here shows up as "dns-stats" rather than an unnamed thread,
    // and so the process listing makes it obvious the reporter is alive.
    std::thread::Builder::new()
        .name("dns-stats".into())
        .spawn(move || {
            let mut last_dropped = 0_u64;
            loop {
                std::thread::sleep(Duration::from_secs(60));
                let (hits, misses, size) = stats_service.stats();
                // A healthy second is unremarkable, so it stays at debug. Only drops —
                // which mean clients are getting silence — are worth a warn, and then
                // only when the count moved since the last report.
                let dropped = stats_queue.dropped();
                if dropped > last_dropped {
                    tracing::warn!(
                        hits,
                        misses,
                        cache = size,
                        dropped,
                        since_last = dropped - last_dropped,
                        "dns stats: queries dropped, queue full"
                    );
                    last_dropped = dropped;
                } else {
                    tracing::debug!(hits, misses, cache = size, "dns stats");
                }
            }
        })
        .ok();

    // Shutdown flag set by the signal handler below. The receive loop is
    // synchronous, so a read timeout is what makes `recv_from` interruptible;
    // without it SIGTERM would sit in the queue until the next packet arrived.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let stop = stop.clone();
        // The handler runs on its own thread for the life of the process; an error
        // installing it means shutdown stays best-effort rather than failing startup.
        if let Err(e) = ctrlc::set_handler(move || {
            tracing::info!("shutdown signal received; stopping the DNS listener");
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
        }) {
            tracing::warn!(error = %e, "cannot install shutdown handler");
        }
    }
    // A short timeout keeps shutdown responsive without waking a core in a tight
    // loop: 200 ms costs ~5 wakeups a second on an idle resolver.
    let _ = udp.set_read_timeout(Some(Duration::from_millis(200)));

    // Rate limit at the receive edge so a flood never reaches the worker pool.
    // Loopback is exempt and a zero `per_source` disables the limiter.
    let mut limiter = crate::ratelimit::RateLimiter::new(cfg.rate_limit);
    let mut last_report = Instant::now();
    let mut buf = [0u8; 4096];
    loop {
        if stop.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
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
                // A read timeout is the normal idle case, not an error: it exists so
                // the loop can check the shutdown flag.
                //
                // `Interrupted` is also normal — `ctrlc` interrupts the blocking
                // `recv_from` when the signal lands, which is exactly how the loop
                // learns to stop. Logging it as an error made every clean shutdown
                // print a spurious WARN.
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) {
                    continue;
                }
                tracing::warn!(error = %e, "udp recv error");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    tracing::info!("DNS listener stopped; exiting");
    Ok(())
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
    /// A panicking request handler must not permanently lose a worker.
    ///
    /// `catch_unwind` is what the worker loop wraps around `handle`. If it did
    /// not, one malformed request would kill a worker thread silently: the listener
    /// keeps enqueuing, the process stays up, and the service answers fewer queries
    /// with every panic.
    #[test]
    fn a_panicking_handler_is_caught_and_the_loop_continues() {
        let mut handled = 0;
        let mut panics = 0;
        for i in 0..5 {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if i == 2 {
                    panic!("simulated handler panic");
                }
                i
            }));
            match outcome {
                Ok(_) => handled += 1,
                Err(payload) => {
                    panics += 1;
                    // The payload must still be describable for the log line.
                    assert!(!panic_reason(payload.as_ref()).is_empty());
                }
            }
        }
        assert_eq!(panics, 1, "the panic must be caught, not propagated");
        assert_eq!(handled, 4, "the loop must keep processing after a panic");
    }

    /// `panic_reason` copes with the payload types a panic can carry.
    #[test]
    fn panic_reason_handles_both_payload_types() {
        let str_panic = std::panic::catch_unwind(|| panic!("literal reason")).unwrap_err();
        assert_eq!(panic_reason(str_panic.as_ref()), "literal reason");

        let string_panic =
            std::panic::catch_unwind(|| panic!("{}", String::from("owned reason"))).unwrap_err();
        assert_eq!(panic_reason(string_panic.as_ref()), "owned reason");
    }

    /// The slot claim never exceeds the limit.
    ///
    /// This checks the *counting* behaviour of the claim, not its atomicity: a
    /// single-threaded loop cannot distinguish `fetch_update` from a read-then-write
    /// pair, and forcing that distinction would need a real concurrent acceptor.
    /// The atomicity itself rests on `fetch_update` being a single operation, which
    /// is what removes the check-then-act window the old code relied on an implicit
    /// single-acceptor invariant to close.
    #[test]
    fn connection_slots_never_exceed_the_limit() {
        let active = std::sync::atomic::AtomicU64::new(0);
        let max = 3u64;
        let mut claimed = 0;
        for _ in 0..10 {
            let got = active
                .fetch_update(
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                    |current| (current < max).then_some(current + 1),
                )
                .is_ok();
            if got {
                claimed += 1;
            }
        }
        assert_eq!(claimed, 3, "exactly `max` slots may be claimed");
        assert_eq!(active.load(std::sync::atomic::Ordering::Acquire), 3);
    }
    /// Only one caller may lead the fetch for a key.
    ///
    /// Before single-flight, eight workers missing the same hot name produced eight
    /// control-plane calls, and a slow control plane blocked all of them at once
    /// while the UDP queue drained.
    #[test]
    fn only_the_first_caller_leads() {
        let in_flight = Mutex::new(HashSet::new());
        assert!(claim_flight(&in_flight, "GET:a.test"), "first caller leads");
        assert!(!claim_flight(&in_flight, "GET:a.test"), "second waits");
        assert!(!claim_flight(&in_flight, "GET:a.test"), "third waits");
        // A different key is independent.
        assert!(claim_flight(&in_flight, "GET:b.test"), "other key leads");
    }

    /// Releasing the marker lets the next caller lead again.
    #[test]
    fn release_allows_a_new_leader() {
        let in_flight = Mutex::new(HashSet::new());
        let done = Condvar::new();
        assert!(claim_flight(&in_flight, "GET:a.test"));
        assert!(!claim_flight(&in_flight, "GET:a.test"));
        release_flight(&in_flight, &done, "GET:a.test");
        assert!(
            claim_flight(&in_flight, "GET:a.test"),
            "after release the next caller leads"
        );
    }

    /// A waiter is woken by the release rather than sleeping out its deadline.
    #[test]
    fn release_wakes_a_waiter_promptly() {
        let in_flight = Arc::new(Mutex::new(HashSet::new()));
        let done = Arc::new(Condvar::new());
        assert!(claim_flight(&in_flight, "GET:a.test"));

        let waiter = {
            let in_flight = in_flight.clone();
            let done = done.clone();
            std::thread::spawn(move || {
                let set = in_flight.lock().unwrap();
                let (set, _) = done
                    .wait_timeout(set, Duration::from_secs(5))
                    .expect("wait");
                !set.contains("GET:a.test")
            })
        };

        // Let the waiter block, then release.
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        release_flight(&in_flight, &done, "GET:a.test");
        let cleared = waiter.join().expect("waiter thread");
        assert!(cleared, "the waiter must observe the marker cleared");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the waiter must wake on the signal, not the timeout"
        );
    }

    /// A poisoned in-flight mutex falls back to leading rather than refusing.
    #[test]
    fn poisoned_flight_mutex_still_answers() {
        let in_flight = Arc::new(Mutex::new(HashSet::new()));
        let poisoner = in_flight.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("poison the flight mutex");
        })
        .join();
        assert!(
            claim_flight(&in_flight, "GET:a.test"),
            "a duplicate fetch beats no answer"
        );
    }
}
