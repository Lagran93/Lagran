//! Edge cache layer

pub mod disk;
pub mod policy;

pub use disk::{DiskCache, HybridCache};
pub use lagran_cache::{CacheBackend, CacheEntry, CacheGetResult, MemoryCache, SharedCache};

use crate::config::EdgeConfig;
use std::sync::Arc;

/// Build cache backend from EDGE config: memory | disk | hybrid
pub async fn build_cache(config: &EdgeConfig) -> anyhow::Result<SharedCache> {
    match config.cache_backend.as_str() {
        "disk" => {
            let disk = DiskCache::new(&config.disk_cache_dir, config.disk_cache_max_bytes).await?;
            Ok(Arc::new(disk) as SharedCache)
        }
        "hybrid" => {
            let mem = Arc::new(MemoryCache::new(config.cache_capacity)) as SharedCache;
            let disk = Arc::new(
                DiskCache::new(&config.disk_cache_dir, config.disk_cache_max_bytes).await?,
            ) as SharedCache;
            Ok(Arc::new(HybridCache::new(mem, disk)) as SharedCache)
        }
        _ => Ok(Arc::new(MemoryCache::new(config.cache_capacity)) as SharedCache),
    }
}
