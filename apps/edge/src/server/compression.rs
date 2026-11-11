//! Transparent downstream compression.
//!
//! Cacheable origin fetches force `Accept-Encoding: identity` so the shared
//! cache stores exactly one reusable representation. Compression therefore
//! happens on the way to the client, after the response has been written to
//! the cache: one identity object serves gzip and non-gzip clients alike.
//!
//! Only gzip is produced. Brotli would shave another ~15% but needs a new
//! dependency and is markedly more expensive to compress; gzip is understood
//! by every client and by every intermediary.

use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use http::{header, HeaderMap, Method, Version};
use std::io::Write;

#[derive(Debug, Clone, Copy)]
pub struct CompressionConfig {
    pub enabled: bool,
    /// Bodies below this size are not worth the CPU; `Content-Length` is used
    /// when present.
    pub min_bytes: usize,
    /// gzip level, 1 (fastest) to 9 (smallest).
    pub level: u32,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_bytes: 1024,
            level: 4,
        }
    }
}

/// Whether the client accepts `gzip` with a non-zero quality.
///
/// Handles `q=0`, `x-gzip` and `*`, and ignores unknown codings. A missing
/// `Accept-Encoding` header is handled by the caller (it means identity only).
pub fn accepts_gzip(value: &str) -> bool {
    let mut gzip: Option<bool> = None;
    let mut star: Option<bool> = None;
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut pieces = part.split(';');
        let coding = pieces.next().unwrap_or("").trim().to_ascii_lowercase();
        let quality = pieces
            .find_map(|p| {
                let p = p.trim();
                p.strip_prefix("q=")
                    .or_else(|| p.strip_prefix("Q="))
                    .and_then(|v| v.trim().parse::<f32>().ok())
            })
            .unwrap_or(1.0);
        let allowed = quality > 0.0;
        match coding.as_str() {
            "gzip" | "x-gzip" => gzip = Some(allowed),
            "*" => star = Some(allowed),
            _ => {}
        }
    }
    gzip.or(star).unwrap_or(false)
}

/// Content types that benefit from compression.
///
/// Already-compressed formats (images, video, archives, fonts) are excluded:
/// running gzip over them costs CPU and usually makes the body slightly larger.
pub fn is_compressible_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if media_type.is_empty() {
        return false;
    }
    if media_type.starts_with("text/") {
        return true;
    }
    matches!(
        media_type.as_str(),
        "application/json"
            | "application/javascript"
            | "application/x-javascript"
            | "application/ecmascript"
            | "application/xml"
            | "application/xhtml+xml"
            | "application/rss+xml"
            | "application/atom+xml"
            | "application/manifest+json"
            | "application/ld+json"
            | "application/graphql"
            | "image/svg+xml"
            | "application/wasm"
    ) || media_type.ends_with("+json")
        || media_type.ends_with("+xml")
}

fn cache_control_forbids_transform(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value
                .split(',')
                .any(|directive| directive.trim().eq_ignore_ascii_case("no-transform"))
        })
}

/// Whether this response should be gzip-encoded for this client.
pub fn should_compress(
    cfg: &CompressionConfig,
    http_version: Version,
    method: &Method,
    status: u16,
    response: &HeaderMap,
    request: &HeaderMap,
) -> bool {
    if !cfg.enabled {
        return false;
    }
    // HEAD carries no body; HTTP/1.0 downstream cannot do chunked framing.
    if method == Method::HEAD || http_version == Version::HTTP_10 {
        return false;
    }
    // 204 has no body; 206 is a byte range of an already-framed object.
    if !(200..300).contains(&status) || status == 204 || status == 206 {
        return false;
    }
    // Anything already encoded (origin gzip, or a previous filter) must not be
    // encoded twice.
    if let Some(encoding) = response.get(header::CONTENT_ENCODING) {
        let already_identity = encoding
            .to_str()
            .map(|value| {
                let value = value.trim();
                value.is_empty() || value.eq_ignore_ascii_case("identity")
            })
            .unwrap_or(false);
        if !already_identity {
            return false;
        }
    }
    if response.contains_key(header::CONTENT_RANGE) || cache_control_forbids_transform(response) {
        return false;
    }
    let content_type = response
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !is_compressible_content_type(content_type) {
        return false;
    }
    if let Some(length) = response
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        if length < cfg.min_bytes as u64 {
            return false;
        }
    }
    response_accepts_gzip(request)
}

fn response_accepts_gzip(request: &HeaderMap) -> bool {
    match request
        .get(header::ACCEPT_ENCODING)
        .and_then(|value| value.to_str().ok())
    {
        Some(value) => accepts_gzip(value),
        // No Accept-Encoding header at all: the client asked for identity.
        None => false,
    }
}

/// Streaming gzip encoder.
///
/// Each [`GzipEncoder::write`] flushes the encoder so the bytes produced so far
/// form a decodable prefix; otherwise a slow client would wait for the
/// encoder's internal buffer to fill before receiving anything.
pub struct GzipEncoder {
    inner: GzEncoder<Vec<u8>>,
}

impl GzipEncoder {
    pub fn new(level: u32) -> Self {
        Self {
            inner: GzEncoder::new(Vec::new(), Compression::new(level.clamp(1, 9))),
        }
    }

    /// Feed one upstream chunk and return the encoded bytes produced so far.
    pub fn write(&mut self, data: &[u8]) -> Bytes {
        if self.inner.write_all(data).is_err() || self.inner.flush().is_err() {
            return Bytes::new();
        }
        std::mem::take(self.inner.get_mut()).into()
    }

    /// Finish the stream and return the gzip trailer.
    pub fn finish(self) -> Bytes {
        match self.inner.finish() {
            Ok(buffer) => buffer.into(),
            Err(_) => Bytes::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

    fn config() -> CompressionConfig {
        CompressionConfig::default()
    }

    #[test]
    fn accept_encoding_quality_is_respected() {
        assert!(accepts_gzip("gzip"));
        assert!(accepts_gzip("br, gzip;q=0.5"));
        assert!(accepts_gzip("x-gzip"));
        assert!(accepts_gzip("*"));
        assert!(accepts_gzip("*;q=0.1"));
        assert!(!accepts_gzip("gzip;q=0"));
        assert!(!accepts_gzip("br"));
        assert!(!accepts_gzip(""));
        assert!(!accepts_gzip("identity"));
        // An explicit refusal wins over a wildcard.
        assert!(!accepts_gzip("gzip;q=0, *"));
    }

    #[test]
    fn compressible_content_types() {
        assert!(is_compressible_content_type("text/html; charset=utf-8"));
        assert!(is_compressible_content_type("text/css"));
        assert!(is_compressible_content_type("application/javascript"));
        assert!(is_compressible_content_type("application/json"));
        assert!(is_compressible_content_type("application/ld+json"));
        assert!(is_compressible_content_type("image/svg+xml"));
        assert!(!is_compressible_content_type("image/png"));
        assert!(!is_compressible_content_type("video/mp4"));
        assert!(!is_compressible_content_type("application/zip"));
        assert!(!is_compressible_content_type(""));
    }

    fn response(headers: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.insert(
                header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                header::HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn decision_respects_encoding_and_method() {
        let cfg = config();
        let request = response(&[("accept-encoding", "gzip")]);
        let ok = response(&[
            ("content-type", "text/html"),
            ("content-length", "8192"),
        ]);
        assert!(should_compress(
            &cfg,
            Version::HTTP_11,
            &Method::GET,
            200,
            &ok,
            &request
        ));

        // Small bodies are skipped.
        let small = response(&[("content-type", "text/html"), ("content-length", "12")]);
        assert!(!should_compress(
            &cfg,
            Version::HTTP_11,
            &Method::GET,
            200,
            &small,
            &request
        ));

        // HEAD, 206, already-encoded, no-transform, binary types.
        assert!(!should_compress(
            &cfg,
            Version::HTTP_11,
            &Method::HEAD,
            200,
            &ok,
            &request
        ));
        assert!(!should_compress(
            &cfg,
            Version::HTTP_11,
            &Method::GET,
            206,
            &ok,
            &request
        ));
        let encoded = response(&[
            ("content-type", "text/html"),
            ("content-length", "8192"),
            ("content-encoding", "br"),
        ]);
        assert!(!should_compress(
            &cfg,
            Version::HTTP_11,
            &Method::GET,
            200,
            &encoded,
            &request
        ));
        let no_transform = response(&[
            ("content-type", "text/html"),
            ("content-length", "8192"),
            ("cache-control", "no-transform"),
        ]);
        assert!(!should_compress(
            &cfg,
            Version::HTTP_11,
            &Method::GET,
            200,
            &no_transform,
            &request
        ));
        let binary = response(&[("content-type", "video/mp4"), ("content-length", "8192")]);
        assert!(!should_compress(
            &cfg,
            Version::HTTP_11,
            &Method::GET,
            200,
            &binary,
            &request
        ));
        // HTTP/1.0 downstream cannot use chunked framing.
        assert!(!should_compress(
            &cfg,
            Version::HTTP_10,
            &Method::GET,
            200,
            &ok,
            &request
        ));
        // Client did not ask for gzip.
        let identity = response(&[("accept-encoding", "identity")]);
        assert!(!should_compress(
            &cfg,
            Version::HTTP_11,
            &Method::GET,
            200,
            &ok,
            &identity
        ));
    }

    /// The streaming encoder must produce a valid gzip stream across arbitrary
    /// chunk boundaries.
    #[test]
    fn streaming_encoder_roundtrips() {
        let mut encoder = GzipEncoder::new(4);
        let mut encoded = Vec::new();
        let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        for chunk in payload.chunks(997) {
            encoded.extend_from_slice(&encoder.write(chunk));
        }
        encoded.extend_from_slice(&encoder.finish());

        let mut decoder = GzDecoder::new(&encoded[..]);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, payload);
    }
}
