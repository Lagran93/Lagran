//! Transparent downstream compression.
//!
//! Cacheable origin fetches force `Accept-Encoding: identity` so the shared
//! cache stores exactly one reusable representation. Compression therefore
//! happens on the way to the client, after the response has been written to
//! the cache: one identity object serves gzip, zstd, deflate and identity
//! clients alike.
//!
//! Supported codings: gzip, zstd and deflate (zlib-wrapped, RFC 1950). gzip is
//! enabled by default; zstd/deflate are opt-in through
//! `EDGE_COMPRESSION_ALGORITHMS`.

use bytes::Bytes;
use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression;
use http::{header, HeaderMap, Method, Version};
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Gzip,
    Zstd,
    Deflate,
}

impl Encoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
            Self::Deflate => "deflate",
        }
    }

    fn preference(self) -> u8 {
        match self {
            Self::Zstd => 3,
            Self::Gzip => 2,
            Self::Deflate => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Algorithms {
    pub gzip: bool,
    pub zstd: bool,
    pub deflate: bool,
}

impl Default for Algorithms {
    fn default() -> Self {
        Self {
            gzip: true,
            zstd: false,
            deflate: false,
        }
    }
}

impl Algorithms {
    pub fn from_csv(input: &str) -> Self {
        let mut out = Self {
            gzip: false,
            zstd: false,
            deflate: false,
        };
        for item in input.split(',') {
            match item.trim().to_ascii_lowercase().as_str() {
                "gzip" | "x-gzip" => out.gzip = true,
                "zstd" => out.zstd = true,
                "deflate" => out.deflate = true,
                _ => {}
            }
        }
        // gzip is the compatibility fallback; an empty/invalid list keeps the
        // previous default rather than silently disabling compression.
        if !out.gzip && !out.zstd && !out.deflate {
            out.gzip = true;
        }
        out
    }

    pub fn enabled(self, encoding: Encoding) -> bool {
        match encoding {
            Encoding::Gzip => self.gzip,
            Encoding::Zstd => self.zstd,
            Encoding::Deflate => self.deflate,
        }
    }

    fn enabled_encodings(self) -> impl Iterator<Item = Encoding> {
        [Encoding::Zstd, Encoding::Gzip, Encoding::Deflate]
            .into_iter()
            .filter(move |encoding| self.enabled(*encoding))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CompressionConfig {
    pub enabled: bool,
    pub algorithms: Algorithms,
    /// Bodies below this size are not worth the CPU; `Content-Length` is used
    /// when present.
    pub min_bytes: usize,
    /// gzip level, 1 (fastest) to 9 (smallest).
    pub level: u32,
    /// zstd level, 1..=19.
    pub zstd_level: i32,
    /// deflate level, 1..=9.
    pub deflate_level: u32,
    /// Largest object retained as a pre-compressed variant. 0 disables reuse.
    pub variant_max_object_bytes: usize,
    /// Variant lifetime used when the identity entry's remaining TTL is
    /// unknown.
    pub variant_ttl_secs: u64,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithms: Algorithms::default(),
            min_bytes: 1024,
            level: 4,
            zstd_level: 3,
            deflate_level: 4,
            variant_max_object_bytes: 4 * 1024 * 1024,
            variant_ttl_secs: 300,
        }
    }
}

#[derive(Debug, Default)]
struct AcceptEncoding {
    gzip: Option<f32>,
    zstd: Option<f32>,
    deflate: Option<f32>,
    wildcard: Option<f32>,
}

impl AcceptEncoding {
    fn parse(value: &str) -> Self {
        let mut out = Self::default();
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
                .unwrap_or(1.0)
                .clamp(0.0, 1.0);
            match coding.as_str() {
                "gzip" | "x-gzip" => out.gzip = Some(quality),
                "zstd" => out.zstd = Some(quality),
                "deflate" => out.deflate = Some(quality),
                "*" => out.wildcard = Some(quality),
                _ => {}
            }
        }
        out
    }

    fn quality(&self, encoding: Encoding) -> f32 {
        let explicit = match encoding {
            Encoding::Gzip => self.gzip,
            Encoding::Zstd => self.zstd,
            Encoding::Deflate => self.deflate,
        };
        explicit.or(self.wildcard).unwrap_or(0.0)
    }
}

/// Whether the client accepts `gzip` with a non-zero quality.
pub fn accepts_gzip(value: &str) -> bool {
    AcceptEncoding::parse(value).quality(Encoding::Gzip) > 0.0
}

/// Choose the best coding for this response and client, or `None` for identity.
pub fn select_encoding(
    cfg: &CompressionConfig,
    http_version: Version,
    method: &Method,
    status: u16,
    response: &HeaderMap,
    request: &HeaderMap,
) -> Option<Encoding> {
    if !cfg.enabled {
        return None;
    }
    // HEAD carries no body; HTTP/1.0 downstream cannot do chunked framing.
    if method == Method::HEAD || http_version == Version::HTTP_10 {
        return None;
    }
    // 204 has no body; 206 is a byte range of an already-framed object.
    if !(200..300).contains(&status) || status == 204 || status == 206 {
        return None;
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
            return None;
        }
    }
    if response.contains_key(header::CONTENT_RANGE) || cache_control_forbids_transform(response) {
        return None;
    }
    let content_type = response
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !is_compressible_content_type(content_type) {
        return None;
    }
    if let Some(length) = response
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        if length < cfg.min_bytes as u64 {
            return None;
        }
    }

    let accept = request
        .get(header::ACCEPT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(AcceptEncoding::parse)?;
    let mut best: Option<(f32, Encoding)> = None;
    for encoding in cfg.algorithms.enabled_encodings() {
        let quality = accept.quality(encoding);
        if quality <= 0.0 {
            continue;
        }
        let replace = match best {
            None => true,
            Some((best_q, best_encoding)) => {
                quality > best_q
                    || (quality == best_q && encoding.preference() > best_encoding.preference())
            }
        };
        if replace {
            best = Some((quality, encoding));
        }
    }
    best.map(|(_, encoding)| encoding)
}

/// Backwards-compatible predicate: any enabled encoding would be selected.
pub fn should_compress(
    cfg: &CompressionConfig,
    http_version: Version,
    method: &Method,
    status: u16,
    response: &HeaderMap,
    request: &HeaderMap,
) -> bool {
    select_encoding(cfg, http_version, method, status, response, request).is_some()
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

/// Content types that benefit from compression.
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

/// Take the next slice of a pre-compressed body.
pub fn replay_chunk(replay: &mut Bytes, input_len: usize, end_of_stream: bool) -> Bytes {
    const MIN_EMIT: usize = 16 * 1024;
    const MAX_EMIT: usize = 256 * 1024;
    let take = if end_of_stream {
        replay.len()
    } else {
        input_len.clamp(MIN_EMIT, MAX_EMIT).min(replay.len())
    };
    if take == 0 {
        Bytes::new()
    } else {
        replay.split_to(take)
    }
}

/// Streaming encoder for one response.
///
/// Each `write` flushes the encoder so the bytes produced so far form a
/// decodable prefix; otherwise a slow client would wait for the encoder's
/// internal buffer to fill before receiving anything.
pub enum StreamEncoder {
    Gzip(GzEncoder<Vec<u8>>),
    Zstd(zstd::stream::write::Encoder<'static, Vec<u8>>),
    Deflate(ZlibEncoder<Vec<u8>>),
}

impl StreamEncoder {
    pub fn new(encoding: Encoding, cfg: &CompressionConfig) -> Self {
        match encoding {
            Encoding::Gzip => Self::Gzip(GzEncoder::new(
                Vec::new(),
                Compression::new(cfg.level.clamp(1, 9)),
            )),
            Encoding::Zstd => Self::Zstd(
                zstd::stream::write::Encoder::new(Vec::new(), cfg.zstd_level.clamp(1, 19))
                    .expect("zstd encoder"),
            ),
            Encoding::Deflate => Self::Deflate(ZlibEncoder::new(
                Vec::new(),
                Compression::new(cfg.deflate_level.clamp(1, 9)),
            )),
        }
    }

    /// Feed one upstream chunk and return the encoded bytes produced so far.
    pub fn write(&mut self, data: &[u8]) -> Bytes {
        match self {
            Self::Gzip(encoder) => {
                if encoder.write_all(data).is_err() || encoder.flush().is_err() {
                    return Bytes::new();
                }
                std::mem::take(encoder.get_mut()).into()
            }
            Self::Zstd(encoder) => {
                if encoder.write_all(data).is_err() || encoder.flush().is_err() {
                    return Bytes::new();
                }
                std::mem::take(encoder.get_mut()).into()
            }
            Self::Deflate(encoder) => {
                if encoder.write_all(data).is_err() || encoder.flush().is_err() {
                    return Bytes::new();
                }
                std::mem::take(encoder.get_mut()).into()
            }
        }
    }

    /// Finish the stream and return the encoder trailer.
    pub fn finish(self) -> Bytes {
        match self {
            Self::Gzip(encoder) => encoder.finish().unwrap_or_default().into(),
            Self::Zstd(encoder) => encoder.finish().unwrap_or_default().into(),
            Self::Deflate(encoder) => encoder.finish().unwrap_or_default().into(),
        }
    }

    /// One-shot encode, used by the engine path.
    pub fn encode_all(encoding: Encoding, cfg: &CompressionConfig, body: &[u8]) -> Bytes {
        let mut encoder = Self::new(encoding, cfg);
        let mut out = bytes::BytesMut::with_capacity(body.len() / 2);
        out.extend_from_slice(&encoder.write(body));
        out.extend_from_slice(&encoder.finish());
        out.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::{GzDecoder, ZlibDecoder};
    use std::io::Read;

    fn config() -> CompressionConfig {
        CompressionConfig::default()
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

    fn decode(encoding: Encoding, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        match encoding {
            Encoding::Gzip => GzDecoder::new(bytes).read_to_end(&mut out).unwrap(),
            Encoding::Deflate => ZlibDecoder::new(bytes).read_to_end(&mut out).unwrap(),
            Encoding::Zstd => zstd::stream::read::Decoder::new(bytes)
                .unwrap()
                .read_to_end(&mut out)
                .unwrap(),
        };
        out
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
        assert!(!accepts_gzip("gzip;q=0, *"));
    }

    #[test]
    fn selection_prefers_best_quality_then_zstd() {
        let mut cfg = config();
        cfg.algorithms = Algorithms {
            gzip: true,
            zstd: true,
            deflate: true,
        };
        let request = |value: &str| response(&[("accept-encoding", value)]);
        let ok = response(&[("content-type", "text/html"), ("content-length", "8192")]);
        let pick = |value: &str| {
            select_encoding(
                &cfg,
                Version::HTTP_11,
                &Method::GET,
                200,
                &ok,
                &request(value),
            )
        };
        assert_eq!(pick("gzip, zstd, deflate"), Some(Encoding::Zstd));
        assert_eq!(pick("gzip;q=0.9, deflate;q=0.5"), Some(Encoding::Gzip));
        assert_eq!(pick("deflate"), Some(Encoding::Deflate));
        assert_eq!(pick("gzip;q=0, *"), Some(Encoding::Zstd));
        assert_eq!(pick("identity"), None);
        assert_eq!(pick("zstd;q=0, gzip;q=0"), None);

        let gzip_only = config();
        assert_eq!(
            select_encoding(
                &gzip_only,
                Version::HTTP_11,
                &Method::GET,
                200,
                &ok,
                &request("zstd")
            ),
            None
        );
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

    #[test]
    fn decision_respects_encoding_and_method() {
        let cfg = config();
        let request = response(&[("accept-encoding", "gzip")]);
        let ok = response(&[("content-type", "text/html"), ("content-length", "8192")]);
        assert!(should_compress(
            &cfg,
            Version::HTTP_11,
            &Method::GET,
            200,
            &ok,
            &request
        ));

        let small = response(&[("content-type", "text/html"), ("content-length", "12")]);
        assert!(!should_compress(
            &cfg,
            Version::HTTP_11,
            &Method::GET,
            200,
            &small,
            &request
        ));
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
        let binary = response(&[("content-type", "image/png"), ("content-length", "8192")]);
        assert!(!should_compress(
            &cfg,
            Version::HTTP_11,
            &Method::GET,
            200,
            &binary,
            &request
        ));
        assert!(!should_compress(
            &cfg,
            Version::HTTP_10,
            &Method::GET,
            200,
            &ok,
            &request
        ));
        assert!(!should_compress(
            &cfg,
            Version::HTTP_11,
            &Method::GET,
            200,
            &ok,
            &HeaderMap::new()
        ));
    }

    #[test]
    fn all_streaming_encoders_roundtrip() {
        let cfg = config();
        for encoding in [Encoding::Gzip, Encoding::Zstd, Encoding::Deflate] {
            let payload = b"hello downstream compression";
            let compressed = StreamEncoder::encode_all(encoding, &cfg, payload);
            assert_eq!(decode(encoding, &compressed), payload, "{encoding:?}");
        }
    }

    #[test]
    fn streaming_encoder_emits_usable_prefix_after_flush() {
        let cfg = config();
        for encoding in [Encoding::Gzip, Encoding::Zstd, Encoding::Deflate] {
            let mut encoder = StreamEncoder::new(encoding, &cfg);
            let first = encoder.write(b"first chunk ");
            assert!(!first.is_empty(), "{encoding:?} should emit after flush");
            let second = encoder.write(b"second chunk");
            let tail = encoder.finish();
            let mut all = Vec::new();
            all.extend_from_slice(&first);
            all.extend_from_slice(&second);
            all.extend_from_slice(&tail);
            assert_eq!(decode(encoding, &all), b"first chunk second chunk");
        }
    }
}
