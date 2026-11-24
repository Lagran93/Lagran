//! Authoritative DNS service: zone checks, scheduling lookups and caching.

use crate::config::DnsConfig;
use crate::control::ControlClient;
use crate::wire::{
    a_record, aaaa_record, encode_response, ns_record, parse_query, soa_record, Query, Record,
    RCODE_NOERROR, RCODE_REFUSED, RCODE_SERVFAIL, TYPE_A, TYPE_AAAA, TYPE_ANY, TYPE_NS, TYPE_SOA,
};
use lru::LruCache;
use std::collections::hash_map::RandomState;
use std::collections::{HashSet, VecDeque};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

struct CacheEntry {
    ip: Option<IpAddr>,
    ttl: u32,
    at: Instant,
}

/// Hard cap on cached names. A PRSD flood must not be able to grow this map
/// without bound; when full, the least-recently-used entry is evicted in O(1)
/// by the LRU implementation.
const MAX_CACHE_ENTRIES: usize = 20_000;

struct DnsCache {
    // `RandomState` matters here: the default `lru` hasher is deterministic,
    // and PRSD clients choose the keys. Randomised hashing keeps a crafted
    // collision set from turning cache lookups into linear scans.
    inner: LruCache<String, CacheEntry, RandomState>,
}

impl DnsCache {
    fn new() -> Self {
        Self::with_capacity(MAX_CACHE_ENTRIES)
    }

    fn with_capacity(capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity.max(1)).expect("cache capacity is non-zero");
        Self {
            inner: LruCache::with_hasher(capacity, RandomState::new()),
        }
    }

    /// A hit updates recency; a miss does not insert.
    fn get(&mut self, key: &str) -> Option<&CacheEntry> {
        self.inner.get(key)
    }

    /// Inserts and, when at capacity, evicts the least-recently-used entry.
    fn insert(&mut self, key: String, entry: CacheEntry) {
        self.inner.put(key, entry);
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}

pub struct Service {
    cfg: DnsConfig,
    control: ControlClient,
    cache: Mutex<DnsCache>,
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
            cache: Mutex::new(DnsCache::new()),
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
        let mut cache = self.cache.lock().ok()?;
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

    /// `None` means "no usable answer" (SERVFAIL); `Some(None)` means the name
    /// has a fresh negative cache entry (NODATA).
    fn lookup(
        &self,
        key: &str,
        qname: &str,
        subnet: Option<&str>,
        client_ip: IpAddr,
    ) -> Option<Option<(IpAddr, u32)>> {
        let now = Instant::now();
        {
            let mut cache = self.cache.lock().ok()?;
            if let Some(entry) = cache.get(key) {
                let age = now.duration_since(entry.at).as_secs();
                if age <= self.cfg.cache_secs {
                    // Cache negative answers too. Requiring `Some(ip)` here meant
                    // an empty answer was fetched again on every query, so the
                    // negative cache existed but never took effect.
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(entry.ip.map(|ip| (ip, entry.ttl)));
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
                return Some(now_cached);
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
                    // `put` is O(1) and evicts the least-recently-used entry
                    // when the hard cap is reached, so a random-subdomain flood
                    // cannot grow memory or trigger a map-wide scan.
                    cache.insert(
                        key.to_string(),
                        CacheEntry {
                            ip,
                            ttl: reply.ttl,
                            at: now,
                        },
                    );
                }
                Some(ip.map(|ip| (ip, reply.ttl)))
            }
            Err(e) => {
                tracing::warn!(error = %e, qname, "scheduler lookup failed");
                if let Ok(mut cache) = self.cache.lock() {
                    if let Some(entry) = cache.get(key) {
                        let age = now.duration_since(entry.at).as_secs();
                        if age <= self.cfg.stale_secs {
                            if let Some(ip) = entry.ip {
                                tracing::warn!(qname, age, "serving stale scheduling result");
                                return Some(Some((ip, entry.ttl.max(5))));
                            }
                        }
                    }
                }
                self.fallback_ip()
                    .map(|ip| Some((ip, self.cfg.ttl)))
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
        let Some(answer) = self.lookup(&key, qname, subnet.as_deref(), client_ip) else {
            return (RCODE_SERVFAIL, vec![], vec![], vec![]);
        };
        let Some((ip, ttl)) = answer else {
            // A fresh negative cache entry: answer NODATA with our SOA rather
            // than hitting the control plane again.
            return (RCODE_NOERROR, vec![], vec![self.soa()], vec![]);
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

/// Answering a cache miss blocks on the control plane (HTTP timeout plus
/// single-flight waiting), so it runs on `spawn_blocking`. This caps how many
/// such jobs may be queued: without it, 65k accepted connections could enqueue
/// 65k blocking jobs at once.
const TCP_MAX_BLOCKING: usize = 256;

/// Read exactly `len` bytes without pre-allocating the announced size.
///
/// A client may announce 65535 bytes and then send nothing; committing that up
/// front would hold the memory for the whole idle timeout on every connection.
/// Growth follows what actually arrives.
async fn read_framed_body<R>(reader: &mut R, len: usize) -> Option<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(len.min(TCP_READ_CHUNK));
    let mut remaining = len;
    let mut chunk = [0u8; TCP_READ_CHUNK];
    while remaining > 0 {
        let want = remaining.min(TCP_READ_CHUNK);
        reader.read_exact(&mut chunk[..want]).await.ok()?;
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
/// Kept separate from the connection loop so the policy is testable: the
/// previous version rejected anything over 4096 bytes here, which silently
/// closed the connection for queries the protocol allows.
async fn read_framed_message<R>(reader: &mut R, announced: usize) -> FramedRead
where
    R: AsyncRead + Unpin,
{
    if announced == 0 {
        return FramedRead::Drop;
    }
    match read_framed_body(reader, announced).await {
        Some(body) => FramedRead::Body(body),
        None => FramedRead::Drop,
    }
}

/// Write one length-prefixed DNS message.
///
/// The response must fit the 16-bit length field; an oversized body is reported
/// as an error so the caller can answer FORMERR instead of writing a truncated
/// frame the client would parse as a shorter message.
async fn write_framed_message<W>(writer: &mut W, body: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let len = u16::try_from(body.len()).map_err(|_| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            "DNS/TCP response exceeds the 65535-byte frame limit",
        )
    })?;
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    writer.write_all(&out).await
}

/// Serve DNS-over-TCP messages on one connection until it ends.
///
/// This is the RFC 7766 connection-management rule: the server must not close
/// the connection after answering one query, it should keep it open for further
/// queries until the client closes it or the idle timeout expires. The previous
/// implementation read exactly one frame, wrote one answer and dropped the
/// stream, so every query after a truncated-UDP (`TC`) fallback paid for a fresh
/// three-way handshake and a resolver could not pipeline at all.
///
/// `handle` is a closure rather than a direct `Service` call so the loop can be
/// driven without a control plane in tests. Returning `None` closes the
/// connection (the handler could not produce an answer).
async fn serve_messages<S, H, Fut>(stream: &mut S, idle: Duration, mut handle: H) -> usize
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: FnMut(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Option<Vec<u8>>>,
{
    let mut answered = 0usize;
    let mut len_buf = [0u8; 2];
    loop {
        // The idle timer applies only while waiting for the *next* message: a
        // client that keeps querying is never disconnected mid-stream.
        match timeout(idle, stream.read_exact(&mut len_buf)).await {
            Err(_) => break,
            Ok(Err(error)) => {
                // EOF at a message boundary is the normal end of a kept-alive
                // connection; anything else is a broken or hostile peer.
                if error.kind() != ErrorKind::UnexpectedEof {
                    tracing::debug!(%error, "TCP DNS connection ended");
                }
                break;
            }
            Ok(Ok(_)) => {}
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        let buf = match timeout(idle, read_framed_message(stream, len)).await {
            // A stalled body must not hold the connection (or its slot) open.
            Err(_) => break,
            Ok(FramedRead::Drop) => break,
            Ok(FramedRead::Body(body)) => body,
        };
        // Keep the query ID for the FORMERR fallback below: the handler takes
        // ownership of the buffer.
        let id = (buf.len() >= 2).then(|| [buf[0], buf[1]]);
        let Some(resp) = handle(buf).await else {
            break;
        };
        // Cannot be framed in a 16-bit length field: answer FORMERR echoing the
        // original ID rather than closing silently, and keep the connection
        // usable for the next query.
        let resp = if resp.len() > 65_535 {
            formerr(&id.unwrap_or_default())
        } else {
            resp
        };
        match timeout(idle, write_framed_message(stream, &resp)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::debug!(%error, "TCP DNS write failed");
                break;
            }
            // A client that stops reading must not pin the connection.
            Err(_) => break,
        }
        answered += 1;
    }
    answered
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

/// One claimed TCP connection slot.
///
/// The claim is a single `fetch_update`, so the check-then-increment window the
/// old code closed by relying on a single-threaded accept loop cannot reappear.
/// Dropping the guard returns the slot, whatever path ends the connection.
struct ConnectionSlot(Arc<AtomicU64>);

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Claim a connection slot, or `None` when the limit is reached.
fn claim_slot(active: &Arc<AtomicU64>, max: usize) -> Option<ConnectionSlot> {
    active
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < max as u64).then_some(current + 1)
        })
        .ok()
        .map(|_| ConnectionSlot(active.clone()))
}

/// Answer one query for a TCP connection.
///
/// `Service::handle` blocks (control-plane HTTP, single-flight `Condvar`), so it
/// must not run on a runtime worker: a few slow lookups would stall every other
/// connection. The semaphore bounds how many blocking jobs can be queued.
async fn answer_on_blocking(
    service: Arc<Service>,
    body: Vec<u8>,
    client_ip: IpAddr,
    blocking: Arc<tokio::sync::Semaphore>,
) -> Option<Vec<u8>> {
    let permit = blocking.acquire_owned().await.ok()?;
    let joined = tokio::task::spawn_blocking(move || {
        let resp = service.handle(&body, client_ip, true);
        // The permit is released when the job finishes, not when the caller
        // wakes: holding it across the join is what bounds the pool's queue.
        drop(permit);
        resp
    })
    .await;
    joined.ok()
}

async fn serve_connection(
    stream: tokio::net::TcpStream,
    service: Arc<Service>,
    idle: Duration,
    blocking: Arc<tokio::sync::Semaphore>,
) {
    // DNS responses are small and latency-sensitive; Nagle plus delayed ACK adds
    // ~40 ms to a request/response pair every so often.
    let _ = stream.set_nodelay(true);
    let client_ip = stream
        .peer_addr()
        .map(|peer| peer.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut stream = stream;
    let answered = serve_messages(&mut stream, idle, |body| {
        answer_on_blocking(service.clone(), body, client_ip, blocking.clone())
    })
    .await;
    tracing::debug!(client = %client_ip, answered, "TCP DNS connection closed");
}

/// Accept and serve persistent DNS/TCP connections until the listener fails.
///
/// Each connection is a task, not an OS thread: a resolver keeping hundreds of
/// mostly-idle connections open costs a few kilobytes per task instead of a
/// thread stack each, which is what makes the RFC 7766 keep-alive affordable.
async fn serve_tcp(
    listener: tokio::net::TcpListener,
    max_conns: usize,
    idle: Duration,
    service: Arc<Service>,
) {
    let active = Arc::new(AtomicU64::new(0));
    let blocking = Arc::new(tokio::sync::Semaphore::new(max_conns.min(TCP_MAX_BLOCKING)));
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _peer)) => stream,
            Err(error) => {
                // `EMFILE` or a transient accept failure would otherwise spin a
                // core; the listener stays up and the next accept retries.
                tracing::warn!(%error, "DNS TCP accept failed");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let Some(slot) = claim_slot(&active, max_conns) else {
            // Dropping the stream closes the connection immediately.
            tracing::debug!("TCP connection limit reached, dropping");
            continue;
        };
        let service = service.clone();
        let blocking = blocking.clone();
        tokio::spawn(async move {
            let _slot = slot;
            serve_connection(stream, service, idle, blocking).await;
        });
    }
}

/// Bind and run the TCP listener on its own async runtime.
fn spawn_tcp_listener(cfg: &DnsConfig, service: Arc<Service>) {
    let listen = cfg.listen.clone();
    let max_conns = cfg.max_tcp_connections;
    let idle = Duration::from_secs(cfg.tcp_idle_secs);
    // Two workers are enough: connections are mostly idle, and every blocking
    // piece of work leaves the runtime via `spawn_blocking`.
    let spawned = std::thread::Builder::new()
        .name("dns-tcp".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("dns-tcp-worker")
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    tracing::error!(%error, "cannot build the DNS TCP runtime");
                    return;
                }
            };
            runtime.block_on(async move {
                match tokio::net::TcpListener::bind(&listen).await {
                    Ok(listener) => {
                        tracing::info!(
                            listen,
                            max_conns,
                            idle_secs = idle.as_secs(),
                            "DNS TCP listener started (persistent connections, RFC 7766)"
                        );
                        serve_tcp(listener, max_conns, idle, service).await;
                    }
                    Err(error) => tracing::error!(%error, listen, "DNS TCP bind failed"),
                }
            });
        });
    if let Err(error) = spawned {
        tracing::error!(%error, "cannot start the DNS TCP thread");
    }
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
        // TCP runs on its own small async runtime: persistent, mostly-idle
        // connections need an event loop, not one OS thread each. UDP below keeps
        // its synchronous socket and worker pool.
        spawn_tcp_listener(&cfg, service.clone());
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
    // EDNS0 lets a client advertise up to 65535 bytes, and a 4096-byte stack
    // buffer truncated larger UDP datagrams; the truncated tail then parsed as a
    // malformed query and the client got FORMERR. One datagram is never larger
    // than 64 KiB, so size the buffer for the protocol maximum.
    let mut buf = [0u8; 65_535];
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
        // The overflow count is what makes a stalled worker visible; the bound
        // alone does not tell anyone the queue is full.
        assert_eq!(
            queue.dropped(),
            10,
            "10 pushes past the 20_000 cap must be counted as dropped"
        );
    }

    /// A queue below the cap drops nothing.
    #[test]
    fn queue_below_cap_records_no_drops() {
        let queue = Queue::new();
        for i in 0..100 {
            queue.push((format!("q{i}").into_bytes(), addr()));
        }
        assert_eq!(queue.dropped(), 0);
    }
    /// A query larger than the old 4096 cap must be accepted.
    ///
    /// The length prefix allows 65535 bytes and RFC 7766 expects the server to
    /// read what was announced. The previous 4096 limit closed the connection
    /// without a response, so a resolver retrying over TCP after a truncated UDP
    /// answer got a timeout instead of an answer.
    #[tokio::test]
    async fn tcp_reads_queries_larger_than_the_old_cap() {
        for size in [4097usize, 8192, 65_535] {
            let payload = vec![0xABu8; size];
            let body = framed_body(payload, size).await;
            match body {
                FramedRead::Body(body) => assert_eq!(body.len(), size),
                FramedRead::Drop => panic!("{size}-byte query must be read, not dropped"),
            }
        }
    }

    /// Feed `bytes` to `read_framed_message` through an async pipe.
    async fn framed_body(bytes: Vec<u8>, announced: usize) -> FramedRead {
        let (mut writer, mut reader) = tokio::io::duplex(bytes.len().max(1));
        tokio::spawn(async move {
            let _ = writer.write_all(&bytes).await;
        });
        read_framed_message(&mut reader, announced).await
    }

    /// The announced size is not pre-allocated: a client that announces 65535 and
    /// sends nothing must not produce a padded body.
    #[tokio::test]
    async fn tcp_read_does_not_preallocate_the_announced_size() {
        assert_eq!(
            framed_body(Vec::new(), 65_535).await,
            FramedRead::Drop,
            "a short body must be dropped, not padded"
        );
    }

    /// A body that stops mid-message is rejected rather than returned truncated.
    #[tokio::test]
    async fn tcp_read_rejects_a_truncated_body() {
        assert_eq!(framed_body(vec![1u8; 100], 200).await, FramedRead::Drop);
    }

    /// A zero-length frame has no ID to answer, so it is dropped.
    #[tokio::test]
    async fn tcp_read_drops_zero_length_frames() {
        assert_eq!(framed_body(Vec::new(), 0).await, FramedRead::Drop);
    }

    /// Small bodies round-trip unchanged.
    #[tokio::test]
    async fn tcp_read_handles_small_bodies() {
        let payload = b"hello".to_vec();
        assert_eq!(
            framed_body(payload.clone(), payload.len()).await,
            FramedRead::Body(payload)
        );
    }

    /// Write one length-prefixed frame from a test client.
    async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, body: &[u8]) {
        writer
            .write_all(&(body.len() as u16).to_be_bytes())
            .await
            .expect("write length");
        writer.write_all(body).await.expect("write body");
    }

    /// Read one length-prefixed frame from a test client.
    async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Vec<u8> {
        let mut len = [0u8; 2];
        reader.read_exact(&mut len).await.expect("read length");
        let len = u16::from_be_bytes(len) as usize;
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).await.expect("read body");
        body
    }

    /// THE RFC 7766 regression: two queries on *one* connection must both be
    /// answered on that same connection.
    ///
    /// The old `handle_tcp` read one frame, wrote one answer and dropped the
    /// stream, so a second query hit a closed socket. A resolver that fell back to
    /// TCP after a truncated UDP answer had to re-handshake for every query and
    /// could not pipeline.
    #[tokio::test]
    async fn two_queries_on_one_connection_are_both_answered() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let served = tokio::spawn(async move {
            serve_messages(&mut server, Duration::from_secs(5), |body| async move {
                Some(body)
            })
            .await
        });

        for query in [b"first-query".to_vec(), b"second-query".to_vec()] {
            write_frame(&mut client, &query).await;
            let answer = read_frame(&mut client).await;
            assert_eq!(answer, query, "each query must be answered in place");
        }
        // Closing the write half is the normal end of a kept-alive connection.
        drop(client);

        assert_eq!(served.await.expect("connection task"), 2);
    }

    /// An idle connection is closed by the server after the idle timeout instead
    /// of pinning its slot forever.
    #[tokio::test]
    async fn idle_connection_is_closed_after_the_timeout() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let started = Instant::now();
        let served = tokio::spawn(async move {
            serve_messages(
                &mut server,
                Duration::from_millis(100),
                |body| async move { Some(body) },
            )
            .await
        });

        write_frame(&mut client, b"only-query").await;
        assert_eq!(read_frame(&mut client).await, b"only-query");

        // No second query: the loop must end on the idle timer, not hang.
        let answered = served.await.expect("connection task");
        assert_eq!(answered, 1);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the idle timeout must close the connection promptly"
        );
    }

    /// A response that cannot fit the 16-bit length field becomes FORMERR with the
    /// query's ID, and the connection stays usable afterwards.
    ///
    /// The old code answered FORMERR and then closed the connection; keeping it
    /// open is the RFC 7766 behaviour.
    #[tokio::test]
    async fn oversized_answer_becomes_formerr_and_the_connection_survives() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn(async move {
            serve_messages(&mut server, Duration::from_secs(5), |body| async move {
                // The first query asks for an impossible answer; the second is a
                // normal one and must still be answered on this connection.
                if body.len() == 4 {
                    Some(vec![0u8; 70_000])
                } else {
                    Some(body)
                }
            })
            .await
        });

        // Query ID 0x1234 plus two more bytes.
        write_frame(&mut client, &[0x12, 0x34, 0x01, 0x02]).await;
        let answer = read_frame(&mut client).await;
        assert_eq!(answer.len(), 12, "FORMERR is a bare 12-byte header");
        assert_eq!(&answer[..2], &[0x12, 0x34], "the query ID must be echoed");
        assert_eq!(
            u16::from_be_bytes([answer[2], answer[3]]) & 0x000F,
            1,
            "rcode must be FORMERR"
        );

        write_frame(&mut client, b"still-alive").await;
        assert_eq!(read_frame(&mut client).await, b"still-alive");
        drop(client);
        assert_eq!(served.await.expect("connection task"), 2);
    }

    /// A zero-length frame is not a message: the connection ends instead of being
    /// answered with bytes that belong to no query.
    #[tokio::test]
    async fn zero_length_frame_ends_the_connection() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let served = tokio::spawn(async move {
            serve_messages(&mut server, Duration::from_secs(5), |body| async move {
                Some(body)
            })
            .await
        });

        client
            .write_all(&0u16.to_be_bytes())
            .await
            .expect("write frame");
        assert_eq!(served.await.expect("connection task"), 0);
    }

    /// A handler that cannot answer closes the connection instead of writing a
    /// frame with stale bytes.
    #[tokio::test]
    async fn a_failing_handler_closes_the_connection() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let served = tokio::spawn(async move {
            serve_messages(&mut server, Duration::from_secs(5), |_body| async move {
                None
            })
            .await
        });

        write_frame(&mut client, b"query").await;
        assert_eq!(served.await.expect("connection task"), 0);
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

    /// The slot claim never exceeds the limit, and releasing a guard returns the
    /// slot.
    ///
    /// This checks the *counting* behaviour of the claim, not its atomicity: a
    /// single-threaded loop cannot distinguish `fetch_update` from a read-then-write
    /// pair, and forcing that distinction would need a real concurrent acceptor.
    /// The atomicity itself rests on `fetch_update` being a single operation, which
    /// is what removes the check-then-act window the old code relied on an implicit
    /// single-acceptor invariant to close.
    #[test]
    fn connection_slots_never_exceed_the_limit() {
        let active = Arc::new(AtomicU64::new(0));
        let max = 3usize;
        // Hold the guards: dropping them is what releases a slot, so collecting
        // them into a `Vec` is what makes the limit observable at all.
        let mut held = Vec::new();
        for _ in 0..10 {
            if let Some(slot) = claim_slot(&active, max) {
                held.push(slot);
            }
        }
        assert_eq!(held.len(), 3, "exactly `max` slots may be claimed");
        assert_eq!(active.load(Ordering::Acquire), 3);
        assert!(claim_slot(&active, max).is_none(), "still at the limit");

        // Dropping one guard must free exactly one slot: a connection that ends
        // (idle timeout, reset, error) must not leak capacity.
        held.pop();
        assert_eq!(active.load(Ordering::Acquire), 2);
        let reclaimed = claim_slot(&active, max);
        assert!(
            reclaimed.is_some(),
            "a released slot must be reusable"
        );
        drop(reclaimed);
        assert_eq!(
            active.load(Ordering::Acquire),
            2,
            "dropping the reclaimed guard must free that slot again"
        );
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

    fn cache_entry(ip: &str) -> CacheEntry {
        CacheEntry {
            ip: Some(ip.parse().expect("valid test IP")),
            ttl: 30,
            at: Instant::now(),
        }
    }

    /// A PRSD flood must not be able to grow the answer cache past its cap.
    #[test]
    fn cache_stays_hard_bounded_under_many_inserts() {
        let mut cache = DnsCache::with_capacity(8);
        for i in 0..1_000 {
            cache.insert(format!("rand-{i}.example.test"), cache_entry("192.0.2.1"));
        }
        assert_eq!(cache.len(), 8);
        assert!(cache.get("rand-0.example.test").is_none());
        assert!(cache.get("rand-999.example.test").is_some());
    }

    /// A hit refreshes recency; the true least-recently-used entry is evicted.
    #[test]
    fn cache_evicts_the_least_recently_used_entry() {
        let mut cache = DnsCache::with_capacity(2);
        cache.insert("a".into(), cache_entry("192.0.2.1"));
        cache.insert("b".into(), cache_entry("192.0.2.2"));
        assert!(cache.get("a").is_some(), "touch a so b becomes LRU");
        cache.insert("c".into(), cache_entry("192.0.2.3"));
        assert_eq!(cache.len(), 2);
        assert!(cache.get("a").is_some());
        assert!(cache.get("c").is_some());
        assert!(cache.get("b").is_none());
    }
}
