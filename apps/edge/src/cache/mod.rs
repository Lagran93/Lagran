//! Edge cache layer

pub mod disk;
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
