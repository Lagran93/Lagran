//! pingora-cache storage backed by the existing `SharedCache`.
//!
//! The native Pingora path uses the same cache key string as the legacy
//! handler (`METHOD:host:path[?query]`), so admin purge/prefix invalidation
//! keeps working unchanged. `CacheMeta` is serialized into a private response
//! header that is stripped before the response reaches the client; this keeps
//! disk/hybrid persistence working without a separate metadata sidecar.

use crate::cache::policy::compute_etag;
use crate::cache::{CacheEntry, CacheGetResult, SharedCache};
use async_trait::async_trait;
use axum::http::{HeaderName, HeaderValue};
use base64::Engine;
use bytes::{Bytes, BytesMut};
use pingora_cache::meta::CacheMeta;
use pingora_cache::storage::{
    HandleHit, HandleMiss, HitHandler, MissFinishType, MissHandler, PurgeOutcome, PurgeTarget,
    PurgeType, Storage,
};
use pingora_cache::trace::SpanHandle;
use pingora_cache::CacheKey;

pub const META_HEADER: &str = "x-lagran-pingora-meta";

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub struct NativeStorage {
    cache: SharedCache,
}

impl NativeStorage {
    pub fn new(cache: SharedCache) -> Self {
        Self { cache }
    }

    fn key_str(key: &CacheKey) -> Option<&str> {
        key.primary_key_str()
    }
}

fn encode_meta(meta: &CacheMeta) -> pingora::Result<String> {
    let (internal, header) = meta.serialize()?;
    Ok(encode_meta_parts(&internal, &header))
}

fn encode_meta_parts(internal: &[u8], header: &[u8]) -> String {
    let mut raw = Vec::with_capacity(4 + internal.len() + header.len());
    raw.extend_from_slice(&(internal.len() as u32).to_be_bytes());
    raw.extend_from_slice(internal);
    raw.extend_from_slice(header);
    B64.encode(raw)
}

fn decode_meta(encoded: &str) -> Option<CacheMeta> {
    let raw = B64.decode(encoded).ok()?;
    if raw.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes(raw[0..4].try_into().ok()?) as usize;
    if raw.len() < 4 + len {
        return None;
    }
    CacheMeta::deserialize(&raw[4..4 + len], &raw[4 + len..]).ok()
}

struct EntryHit {
    body: Bytes,
    pos: usize,
}

#[async_trait]
impl HandleHit for EntryHit {
    async fn read_body(&mut self) -> pingora::Result<Option<Bytes>> {
        if self.pos >= self.body.len() {
            return Ok(None);
        }
        let chunk = self.body.slice(self.pos..);
        self.pos = self.body.len();
        Ok(Some(chunk))
    }

    fn can_seek(&self) -> bool {
        true
    }

    fn seek(&mut self, start: usize, end: Option<usize>) -> pingora::Result<()> {
        let end = end.unwrap_or(self.body.len()).min(self.body.len());
        self.pos = start.min(end);
        Ok(())
    }

    async fn finish(
        self: Box<Self>,
        _storage: &'static (dyn Storage + Sync),
        _key: &CacheKey,
        _trace: &SpanHandle,
    ) -> pingora::Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync + 'static) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn std::any::Any + Send + Sync + 'static) {
        self
    }
}

struct EntryMiss {
    cache: SharedCache,
    key: String,
    status: u16,
    headers: Vec<(String, String)>,
    encoded_meta: String,
    body: BytesMut,
    fresh_secs: u64,
    swr_secs: u64,
    too_large: bool,
}

#[async_trait]
impl HandleMiss for EntryMiss {
    async fn write_body(&mut self, data: Bytes, _eof: bool) -> pingora::Result<()> {
        if self.body.len() + data.len() > 8 * 1024 * 1024 {
            self.too_large = true;
        }
        if !self.too_large {
            self.body.extend_from_slice(&data);
        }
        Ok(())
    }

    async fn finish(self: Box<Self>) -> pingora::Result<MissFinishType> {
        let len = self.body.len();
        if self.too_large {
            return Ok(MissFinishType::Created(0));
        }
        let mut headers = self.headers;
        headers.push((META_HEADER.to_string(), self.encoded_meta));
        let mut entry = CacheEntry {
            status: self.status,
            headers,
            body: self.body.freeze(),
            stored_at_epoch_secs: now_epoch_secs(),
        };
        if entry.header("etag").is_none() {
            let etag = compute_etag(&entry);
            entry.headers.push(("etag".to_string(), etag));
        }
        self.cache
            .set_with_swr(&self.key, entry, self.fresh_secs, self.swr_secs)
            .await;
        Ok(MissFinishType::Created(len))
    }
}

use std::time::{Duration, SystemTime};

fn derive_meta(entry: &CacheEntry) -> pingora::Result<CacheMeta> {
    let mut header = pingora::http::ResponseHeader::build(entry.status, Some(entry.body.len()))?;
    for (name, value) in &entry.headers {
        if name.eq_ignore_ascii_case(META_HEADER) || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            header.append_header(name, value)?;
        }
    }
    header.insert_header("content-length", entry.body.len().to_string())?;
    let now = SystemTime::now();
    Ok(CacheMeta::new(
        now + Duration::from_secs(3600),
        now,
        0,
        0,
        header,
    ))
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn headers_vec(headers: &pingora::http::ResponseHeader) -> Vec<(String, String)> {
    headers
        .headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_string(), v.to_string()))
        })
        .collect()
}

#[async_trait]
impl Storage for NativeStorage {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &SpanHandle,
    ) -> pingora::Result<Option<(CacheMeta, HitHandler)>> {
        let Some(key) = Self::key_str(key) else {
            return Ok(None);
        };
        let entry = match self.cache.get_result(key).await {
            CacheGetResult::Hit(entry) | CacheGetResult::Stale(entry) => entry,
            CacheGetResult::Expired | CacheGetResult::Miss => return Ok(None),
        };
        let mut meta = if let Some(encoded) = entry
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(META_HEADER))
            .map(|(_, v)| v.as_str())
        {
            let Some(meta) = decode_meta(encoded) else {
                return Ok(None);
            };
            meta
        } else {
            // HEAD entries are written through the legacy SharedCache path and
            // intentionally have no encoded CacheMeta. Derive a metadata record
            // so GET can reuse the body and HEAD can reuse GET entries.
            derive_meta(&entry)?
        };
        if let Some(etag) = entry.header("etag") {
            if !meta.response_header().headers.contains_key("etag") {
                meta.response_header_mut().insert_header("etag", etag)?;
            }
        }
        Ok(Some((
            meta,
            Box::new(EntryHit {
                body: entry.body,
                pos: 0,
            }) as HitHandler,
        )))
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> pingora::Result<MissHandler> {
        let key = Self::key_str(key).unwrap_or_default().to_string();
        let encoded_meta = encode_meta(meta)?;
        Ok(Box::new(EntryMiss {
            cache: self.cache.clone(),
            key,
            status: meta.response_header().status.as_u16(),
            headers: headers_vec(meta.response_header()),
            encoded_meta,
            body: BytesMut::new(),
            fresh_secs: meta.fresh_sec(),
            swr_secs: u64::from(meta.stale_while_revalidate_sec()),
            too_large: false,
        }) as MissHandler)
    }

    async fn purge(
        &'static self,
        _target: PurgeTarget<'_>,
        _purge_type: PurgeType,
        _trace: &SpanHandle,
    ) -> pingora::Result<PurgeOutcome> {
        // The admin purge path uses `SharedCache::purge_matching` with the same
        // key strings, so Pingora-level purges are not needed there.
        Ok(PurgeOutcome::NotFound)
    }

    async fn update_meta(
        &'static self,
        _key: &CacheKey,
        _meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> pingora::Result<bool> {
        Ok(false)
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync + 'static) {
        self
    }
}

pub fn leak_storage(cache: SharedCache) -> &'static NativeStorage {
    Box::leak(Box::new(NativeStorage::new(cache)))
}
