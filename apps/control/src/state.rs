//! Shared application state

use crate::config::AppConfig;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<AppConfig>,
    /// CIDR → geo table used by the scheduler.
    pub geo: crate::scheduler::GeoTable,
    pub schedule_ttl: u64,
}

impl AppState {
    pub fn new(pool: PgPool, config: AppConfig) -> Self {
        let geo = crate::scheduler::GeoTable::load(&config.geoip_json_path);
        let schedule_ttl = config.schedule_ttl;
        Self {
            pool,
            config: Arc::new(config),
            geo,
            schedule_ttl,
        }
    }
}
