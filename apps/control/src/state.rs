//! Shared application state

use crate::config::AppConfig;
use crate::middleware::login_limit::LoginLimiter;
use sqlx::PgPool;
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
    pub login_limiter: Arc<LoginLimiter>,
    pub captcha: Arc<crate::service::captcha::CaptchaStore>,
    pub config_cache: Arc<crate::service::config_cache::ConfigCache>,
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
        Self {
            pool,
            config: Arc::new(config),
            geo,
            schedule_ttl,
            nodes,
            login_limiter: Arc::new(LoginLimiter::new()),
            captcha: Arc::new(crate::service::captcha::CaptchaStore::new()),
            config_cache: Arc::new(crate::service::config_cache::ConfigCache::new(
                config_cache_ttl_secs,
            )),
            redis,
        }
    }
}
