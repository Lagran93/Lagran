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
    pub login_limiter: Arc<LoginLimiter>,
    pub captcha: Arc<crate::service::captcha::CaptchaStore>,
    pub config_cache: Arc<crate::service::config_cache::ConfigCache>,
}

impl AppState {
    pub fn new(pool: PgPool, config: AppConfig) -> Self {
        let geo = crate::scheduler::GeoTable::load(&config.geoip_path);
        let schedule_ttl = config.schedule_ttl;
        let config_cache_ttl_secs = config.config_cache_ttl_secs;
        Self {
            pool,
            config: Arc::new(config),
            geo,
            schedule_ttl,
            login_limiter: Arc::new(LoginLimiter::new()),
            captcha: Arc::new(crate::service::captcha::CaptchaStore::new()),
            config_cache: Arc::new(crate::service::config_cache::ConfigCache::new(
                config_cache_ttl_secs,
            )),
        }
    }
}
