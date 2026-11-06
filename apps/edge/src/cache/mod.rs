//! Edge cache layer

pub mod disk;
pub mod flight;
pub mod l2;
pub mod large;
pub mod policy;

pub use disk::{DiskCache, HybridCache};
pub use large::LargeCache;
pub use lagran_cache::{CacheBackend, CacheEntry, CacheGetResult, MemoryCache, SharedCache};

use crate::config::EdgeConfig;
use std::sync::Arc;

/// Build cache backend from EDGE config: memory | disk | hybrid
pub async fn build_cache(config: &EdgeConfig) -> anyhow::Result<SharedCache> {
    match config.cache_backend.as_str() {
        "redis" | "l2" => {
            let local = Arc::new(MemoryCache::with_max_bytes(
                config.cache_capacity,
                config.cache_max_bytes,
            )) as SharedCache;
            let url = if config.cache_redis_url.trim().is_empty() {
                config.redis_url.clone()
            } else {
                config.cache_redis_url.clone()
            };
            if url.trim().is_empty() {
                tracing::warn!("CACHE_BACKEND=redis but CACHE_REDIS_URL/REDIS_URL is empty; using local cache");
                return Ok(local);
            }
            match l2::RedisL2Cache::connect(
                local.clone(),
                &url,
                config.cache_redis_prefix.clone(),
                config.cache_l2_max_body,
            )
            .await
            {
                Ok(cache) => {
                    tracing::info!(prefix = %config.cache_redis_prefix, "Redis L2 cache enabled");
                    Ok(Arc::new(cache) as SharedCache)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Redis L2 cache unavailable; using local cache");
                    Ok(local)
                }
            }
        }
        "disk" => {
            let disk = DiskCache::new(&config.disk_cache_dir, config.disk_cache_max_bytes).await?;
            Ok(Arc::new(disk) as SharedCache)
        }
        "hybrid" => {
            let mem = Arc::new(MemoryCache::with_max_bytes(
                config.cache_capacity,
                config.cache_max_bytes,
            ));
            let disk = Arc::new(
                DiskCache::new(&config.disk_cache_dir, config.disk_cache_max_bytes).await?,
            );
            Ok(Arc::new(HybridCache::new(mem, disk)) as SharedCache)
        }
        _ => Ok(Arc::new(MemoryCache::with_max_bytes(
            config.cache_capacity,
            config.cache_max_bytes,
        )) as SharedCache),
    }
}
