//! Edge cache layer

pub mod disk;
pub mod memory;
pub mod policy;

pub use lagran_cache::{CacheBackend, CacheEntry, MemoryCache, SharedCache};
