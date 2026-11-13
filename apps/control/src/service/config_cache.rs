//! Short-lived process cache for the bulk edge configuration document.
//!
//! Configuration changes are infrequent and every edge polls the same
//! document. A small TTL cache removes the repeated multi-query build without
//! turning Redis/PostgreSQL into a hard dependency for config delivery.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 256;

#[derive(Clone, Serialize, Deserialize)]
pub struct SharedConfig {
    pub etag: String,
    pub body: String,
}

#[derive(Clone)]
pub struct CachedConfig {
    pub etag: String,
    pub body: Bytes,
}

struct Entry {
    cached: CachedConfig,
    expires: Instant,
}

pub struct ConfigCache {
    ttl: Duration,
    entries: RwLock<HashMap<String, Entry>>,
}

impl ConfigCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            ttl: Duration::from_secs(ttl_secs.clamp(1, 60)),
            entries: RwLock::new(HashMap::new()),
        }
    }

    pub fn get(&self, key: &str) -> Option<CachedConfig> {
        let now = Instant::now();
        let entries = self.entries.read().ok()?;
        let entry = entries.get(key)?;
        if entry.expires <= now {
            return None;
        }
        Some(entry.cached.clone())
    }

    pub fn put(&self, key: String, etag: String, body: Bytes) {
        let now = Instant::now();
        let Ok(mut entries) = self.entries.write() else {
            return;
        };
        // Evict expired entries only when the map is actually near its cap, and then
        // only enough to make room — the old code ran a full `retain` on **every**
        // insert and then threw the whole map away at 256 entries, which also discards
        // entries that were still valid. A config release purges this cache on every
        // sweep, so "everything vanished" was a normal thing to observe.
        if entries.len() >= MAX_ENTRIES {
            entries.retain(|_, entry| entry.expires > now);
            // Still full after dropping the expired ones: evict the entry closest to
            // expiry. That is the cheapest approximation of LRU available without
            // extra bookkeeping, and the cache is small enough to scan when we do.
            while entries.len() >= MAX_ENTRIES {
                let oldest = entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires)
                    .map(|(key, _)| key.clone());
                match oldest {
                    Some(key) => {
                        entries.remove(&key);
                    }
                    None => break,
                }
            }
        }
        entries.insert(
            key,
            Entry {
                cached: CachedConfig { etag, body },
                expires: now + self.ttl,
            },
        );
    }

    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caches_and_expires() {
        let cache = ConfigCache::new(1);
        cache.put("edge-1".into(), "\"v1\"".into(), Bytes::from_static(b"{}"));
        assert_eq!(cache.get("edge-1").unwrap().etag, "\"v1\"");
        std::thread::sleep(Duration::from_millis(1100));
        assert!(cache.get("edge-1").is_none());
    }
}
