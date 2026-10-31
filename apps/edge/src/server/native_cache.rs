//! pingora-cache storage backed by the existing `SharedCache`.
//!
//! The native Pingora path uses the same cache key string as the legacy
//! handler (`METHOD:host:path[?query]`), so admin purge/prefix invalidation
//! keeps working unchanged. `CacheMeta` is serialized into a private response
//! header that is stripped before the response reaches the client; this keeps
//! disk/hybrid persistence working without a separate metadata sidecar.

use crate::cache::policy::compute_etag;
use crate::cache::large::{LargeCache, LargeEntry, LargeWriter};
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
use std::sync::Arc;

pub const META_HEADER: &str = "x-lagran-pingora-meta";

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub struct NativeStorage {
    cache: SharedCache,
    max_body: usize,
    large: Option<Arc<LargeCache>>,
}

impl NativeStorage {
    pub fn new(cache: SharedCache) -> Self {
        Self::with_max_body(cache, 8 * 1024 * 1024)
    }

    pub fn with_max_body(cache: SharedCache, max_body: usize) -> Self {
        Self::with_large(cache, max_body, None)
    }

    pub fn with_large(
        cache: SharedCache,
        max_body: usize,
        large: Option<Arc<LargeCache>>,
    ) -> Self {
        Self {
            cache,
            max_body: max_body.clamp(64 * 1024, 64 * 1024 * 1024),
            large,
        }
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

struct LargeEntryHit {
    entry: LargeEntry,
    pos: u64,
    end: u64,
}

#[async_trait]
impl HandleHit for LargeEntryHit {
    async fn read_body(&mut self) -> pingora::Result<Option<Bytes>> {
        if self.pos >= self.end {
            return Ok(None);
        }
        let want = (self.end - self.pos).min(8 * 1024 * 1024) as usize;
        let chunk = self
            .entry
            .read_at(self.pos, want)
            .await
            .map_err(|e| pingora::Error::because(
                pingora::ErrorType::InternalError,
                "large cache read",
                e,
            ))?;
        if let Some(chunk) = chunk {
            self.pos += chunk.len() as u64;
            Ok(Some(chunk))
        } else {
            Ok(None)
        }
    }

    fn can_seek(&self) -> bool {
        true
    }

    fn seek(&mut self, start: usize, end: Option<usize>) -> pingora::Result<()> {
        let total = self.entry.content_length() as usize;
        let end = end.unwrap_or(total).min(total);
        self.pos = start.min(end) as u64;
        self.end = end as u64;
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
    max_body: usize,
    too_large: bool,
}

#[async_trait]
impl HandleMiss for EntryMiss {
    async fn write_body(&mut self, data: Bytes, _eof: bool) -> pingora::Result<()> {
        if self.body.len() + data.len() > self.max_body {
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

struct LargeMiss {
    writer: LargeWriter,
    written: u64,
}

#[async_trait]
impl HandleMiss for LargeMiss {
    async fn write_body(&mut self, data: Bytes, _eof: bool) -> pingora::Result<()> {
        if !self.writer.failed() {
            self.writer.write_all(&data).await;
            self.written += data.len() as u64;
        }
        Ok(())
    }

    async fn finish(self: Box<Self>) -> pingora::Result<MissFinishType> {
        let len = self.written;
        if self.writer.commit().await {
            Ok(MissFinishType::Created(len as usize))
        } else {
            Ok(MissFinishType::Created(0))
        }
    }
}

/// Discards oversized/unknown-size bodies without buffering them.
struct NoopMiss;

#[async_trait]
impl HandleMiss for NoopMiss {
    async fn write_body(&mut self, _data: Bytes, _eof: bool) -> pingora::Result<()> {
        Ok(())
    }

    async fn finish(self: Box<Self>) -> pingora::Result<MissFinishType> {
        Ok(MissFinishType::Created(0))
    }
}

fn header_content_length(headers: &[(String, String)]) -> Option<u64> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
}

use std::time::{Duration, SystemTime};

fn derive_meta(entry: &CacheEntry) -> pingora::Result<CacheMeta> {
    derive_meta_parts(entry.status, &entry.headers, entry.body.len())
}

fn derive_meta_parts(
    status: u16,
    headers: &[(String, String)],
    content_length: usize,
) -> pingora::Result<CacheMeta> {
    let mut header = pingora::http::ResponseHeader::build(status, Some(content_length))?;
    for (name, value) in headers {
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
    header.insert_header("content-length", content_length.to_string())?;
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
        if let Some(large) = self.large.as_ref() {
            if let Some(entry) = large.get(key).await {
                let len = entry.content_length() as usize;
                let mut meta = if let Some(encoded) = entry
                    .meta
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(META_HEADER))
                    .map(|(_, v)| v.as_str())
                {
                    decode_meta(encoded)
                        .unwrap_or(derive_meta_parts(entry.meta.status, &entry.meta.headers, len)?)
                } else {
                    derive_meta_parts(entry.meta.status, &entry.meta.headers, len)?
                };
                if let Some(etag) = entry
                    .meta
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("etag"))
                    .map(|(_, v)| v)
                {
                    if !meta.response_header().headers.contains_key("etag") {
                        meta.response_header_mut().insert_header("etag", etag)?;
                    }
                }
                return Ok(Some((
                    meta,
                    Box::new(LargeEntryHit {
                        entry,
                        pos: 0,
                        end: len as u64,
                    }) as HitHandler,
                )));
            }
        }
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
        let status = meta.response_header().status.as_u16();
        let headers = headers_vec(meta.response_header());
        let content_length = header_content_length(&headers);
        let fresh_secs = meta.fresh_sec();
        let swr_secs = u64::from(meta.stale_while_revalidate_sec());

        if status == 200 {
            if let (Some(large), Some(len)) = (self.large.as_ref(), content_length) {
                if large.accepts(len) {
                    let mut stored_headers = headers.clone();
                    stored_headers.push((META_HEADER.to_string(), encoded_meta.clone()));
                    if let Some(writer) = large
                        .begin(&key, status, stored_headers, len, fresh_secs, swr_secs)
                        .await
                    {
                        return Ok(Box::new(LargeMiss {
                            writer,
                            written: 0,
                        }) as MissHandler);
                    }
                }
            }
        }

        // Do not accumulate an object larger than the small-object limit in
        // memory when the large cache is disabled or the object is too big.
        if content_length.is_some_and(|len| len > self.max_body as u64) {
            return Ok(Box::new(NoopMiss) as MissHandler);
        }

        Ok(Box::new(EntryMiss {
            cache: self.cache.clone(),
            key,
            status,
            headers,
            encoded_meta,
            body: BytesMut::new(),
            fresh_secs,
            swr_secs,
            max_body: self.max_body,
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
    leak_storage_with_limit(cache, 8 * 1024 * 1024)
}

pub fn leak_storage_with_limit(cache: SharedCache, max_body: usize) -> &'static NativeStorage {
    Box::leak(Box::new(NativeStorage::with_max_body(cache, max_body)))
}

pub fn leak_storage_with_large(
    cache: SharedCache,
    max_body: usize,
    large: Option<Arc<LargeCache>>,
) -> &'static NativeStorage {
    Box::leak(Box::new(NativeStorage::with_large(cache, max_body, large)))
}
