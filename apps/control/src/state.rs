//! Shared application state

use crate::config::AppConfig;
use crate::middleware::agent_token_cache::SharedAgentTokenCache;
use crate::middleware::client_ip::ClientIpResolver;
use crate::middleware::login_limit::LoginLimiter;
use sqlx::PgPool;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<AppConfig>,
    /// CIDR → geo table used by the scheduler.
    pub geo: crate::scheduler::GeoTable,
    pub schedule_ttl: u64,
    /// Short-lived snapshot of the node table used by GeoDNS scheduling.
    pub nodes: Arc<crate::scheduler::NodeSnapshotCache>,
    /// Monotonic ticket used to rotate among equally-scored nodes.
    /// Per control process: multiple replicas rotate independently.
    pub schedule_rotation: Arc<AtomicU64>,
    /// Trusted reverse-proxy chain used for login/register client IPs.
    pub client_ip_resolver: Arc<ClientIpResolver>,
    /// Cached per-node agent token -> node name mapping.
    pub agent_tokens: SharedAgentTokenCache,
    pub login_limiter: Arc<LoginLimiter>,
    pub captcha: Arc<crate::service::captcha::CaptchaStore>,
    pub config_cache: Arc<crate::service::config_cache::ConfigCache>,
    /// In-flight certificate issuances (see `service::cert_jobs`).
    ///
    /// ACME issuance takes tens of seconds, so `POST /certs/issue` queues a job
    /// here and answers `202`; the caller polls `/certs/jobs/:id`.
    pub cert_jobs: Arc<crate::service::cert_jobs::CertJobs>,
    pub redis: Option<Arc<crate::service::redis::RedisService>>,
}

impl AppState {
    pub fn new(
        pool: PgPool,
        config: AppConfig,
        redis: Option<Arc<crate::service::redis::RedisService>>,
    ) -> Self {
        let geo =
            crate::scheduler::GeoTable::load_with_ipv6(&config.geoip_path, &config.geoip_ipv6_path);
        let schedule_ttl = config.schedule_ttl;
        let config_cache_ttl_secs = config.config_cache_ttl_secs;
        let nodes = Arc::new(crate::scheduler::NodeSnapshotCache::new(
            config.schedule_node_cache_secs,
        ));
        let client_ip_resolver = Arc::new(ClientIpResolver::from_config(&config.trusted_proxies));
        Self {
            pool,
            config: Arc::new(config),
            geo,
            schedule_ttl,
            nodes,
            schedule_rotation: Arc::new(AtomicU64::new(0)),
            client_ip_resolver,
            agent_tokens: Arc::new(crate::middleware::agent_token_cache::AgentTokenCache::new()),
            login_limiter: Arc::new(LoginLimiter::new()),
            captcha: Arc::new(crate::service::captcha::CaptchaStore::new()),
            config_cache: Arc::new(crate::service::config_cache::ConfigCache::new(
                config_cache_ttl_secs,
            )),
            cert_jobs: Arc::new(crate::service::cert_jobs::CertJobs::new()),
            redis,
        }
    }
}
