//! Shared application state for the edge.
//!
//! `AppState` used to live in `server::handler`. It is the only piece of that
//! module the Pingora data plane and the management / agent handlers need, so it
//! moved here when the legacy in-process engine was deleted (阶段 6).

use crate::agent::origin_health::OriginHealthMap;
use crate::agent::{ControlClient, NodeControl};
use crate::cache::flight::RedisFlight;
use crate::cache::policy::RuleSet;
use crate::cache::{LargeCache, SharedCache};
use crate::config::registry::DomainRegistry;
use crate::metrics::EdgeMetrics;
use crate::origin::OriginClient;
use crate::server::access_log::AccessLog;
use crate::server::acme_challenge::ChallengeStore;
use crate::server::cc::CcProtector;
use crate::server::cert_store::CertStore;
use crate::server::inflight::Inflight;
use crate::server::rate_limit::RateLimiter;
use crate::server::waf_log::WafLog;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    /// This edge's node id, used in the CDN-Loop chain.
    ///
    /// This is the *loop* identity (node id + per-machine instance token), not
    /// the control-plane name. Two hosts that share a `NODE_ID` still get distinct
    /// values here, so neither mistakes the other's stamp for its own.
    pub node_id: String,
    /// Peers whose loop headers are trusted (`TRUSTED_EDGES`).
    ///
    /// Empty by default. An unlisted peer's `CDN-Loop` / `X-Lagran-Shield-Hops`
    /// are client input and are stripped before the loop guard runs.
    pub trusted_edges: crate::security::trusted_proxy::TrustedProxies,
    /// Random token attached to internal prefetch requests. The loopback peer
    /// check is necessary but not sufficient when a local reverse proxy accepts
    /// public traffic; this token prevents a client from claiming the internal
    /// prefetch marker.
    pub prefetch_token: String,
    pub cache: SharedCache,
    /// Cross-node cold-miss coalescing; None when Redis L2 is disabled.
    pub flight: Option<Arc<RedisFlight>>,
    /// Cap on how long a follower waits for the flight leader before fetching
    /// the object itself (`EdgeConfig::cache_flight_wait_ms`).
    pub cache_flight_wait_ms: u64,
    /// Caps concurrent background revalidations.
    ///
    /// A stale hit spawns a detached origin fetch. When a whole cache expires at
    /// once — a config release purges everything — that is one spawn per request,
    /// each holding an origin connection for its full timeout, which starves normal
    /// traffic and can trip the origin health check. Overflow requests keep being
    /// served stale instead.
    pub revalidate_permits: Arc<tokio::sync::Semaphore>,
    /// Separate streaming disk cache for large objects; disabled when None.
    pub large_cache: Option<Arc<LargeCache>>,
    pub origin: OriginClient,
    pub default_ttl_secs: u64,
    pub rules: RuleSet,
    pub metrics: Arc<EdgeMetrics>,
    pub challenges: ChallengeStore,
    pub certs: Arc<CertStore>,
    pub domains: DomainRegistry,
    pub access_log: AccessLog,
    pub rate_limiter: RateLimiter,
    pub cc: CcProtector,
    pub control: ControlClient,
    pub origin_health: OriginHealthMap,
    pub agent_token: String,
    /// Dedicated Prometheus scrape credential for `/__lagran/metrics`
    /// (empty falls back to `agent_token`; see `server::agent_auth`).
    pub metrics_token: String,
    pub inflight: Inflight,
    pub waf_log: WafLog,
    /// Trust X-Forwarded-For when determining the client IP (WAF ACLs).
    pub trust_proxy_headers: bool,
    /// Networks whose `X-Forwarded-*` headers may be believed.
    pub trusted_proxies: crate::security::trusted_proxy::TrustedProxies,
    /// HMAC secret for challenge nonces and clearance cookies.
    pub challenge_secret: String,
    /// MaxMind-backed country/ASN lookup for the WAF Geo/ASN lists.
    pub geo: Arc<crate::waf::geo::GeoLookup>,
    /// Set from the heartbeat reply; disabled nodes answer 503 and keep serving
    /// management/health endpoints.
    pub node_control: NodeControl,
    /// Port used when redirecting HTTP to HTTPS (None = 443).
    pub https_redirect_port: Option<u16>,
    /// Responses larger than this are proxied but not stored in cache.
    pub max_cacheable_body: usize,
    /// Pre-compressed response variants, keyed by identity cache key + ETag.
    /// Keeps gzip out of the per-request path for repeat hits.
    pub compressed: Arc<lagran_cache::MemoryCache>,
    /// Header names intentionally excluded from the shared-cache key.
    pub cache_key_ignore_headers: Vec<String>,
    /// Idle origin read timeout; separate from per-domain connect timeout.
    pub origin_read_timeout_ms: u64,
    pub origin_stream_read_timeout_ms: u64,
    pub range_fill_max_bytes: u64,
    pub large_cache_fill_max_bytes: u64,
    pub large_cache_chunk_bytes: u64,
    pub large_cache_fill_queue_bytes: u64,
    pub downstream_keepalive_secs: u64,
    pub downstream_h2_idle_secs: u64,
    pub downstream_keepalive_requests: u32,
    pub websocket_idle_secs: u64,
    /// Loopback address of the public Pingora HTTP listener, used by internal
    /// prefetch so it goes through the native cache/large-cache data plane.
    pub local_http_addr: SocketAddr,
}
