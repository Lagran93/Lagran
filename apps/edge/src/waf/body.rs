//! Request-body inspection policy and decoding for the WAF.
//!
//! The proxy can only inspect a body it can replay to the origin. Pingora's
//! retry buffer is 64 KiB, so [`HARD_MAX_BYTES`] is the hard ceiling: a body
//! above it (or one whose length is not known in advance) is handled by the
//! configured policy instead of being buffered.

use axum::http::HeaderMap;
use serde_json::Value;
use std::time::Duration;

/// Pingora's `BODY_BUF_LIMIT`: larger bodies cannot be replayed upstream after
/// a pre-read, so body inspection must never buffer beyond this.
pub const HARD_MAX_BYTES: usize = 64 * 1024;
/// Default inspection ceiling. Reading 32 KiB keeps the latency/memory cost
/// predictable while covering normal JSON/form login payloads.
pub const DEFAULT_MAX_BYTES: usize = 32 * 1024;
/// Decoded text can be several times larger than the wire bytes (percent or
/// JSON escapes). Cap the scan so decoding cannot become a memory amplifier.
const MAX_SCAN_BYTES: usize = HARD_MAX_BYTES * 3;

/// What to do when a body cannot be inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BodyPolicy {
    /// Forward the request without body inspection (only an access-log hint).
    Allow,
    /// Forward, but record a warning/metric so operators can see the gap.
    #[default]
    Log,
    /// Reject the request instead of letting an uninspected body through.
    Block,
}

impl BodyPolicy {
    pub fn parse(input: &str) -> Self {
        match input.trim().to_ascii_lowercase().as_str() {
            "allow" | "off" | "pass" => Self::Allow,
            "block" | "deny" | "reject" => Self::Block,
            _ => Self::Log,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Log => "log",
            Self::Block => "block",
        }
    }

    pub fn blocks(self) -> bool {
        self == Self::Block
    }
}

/// Per-domain body-inspection settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyInspection {
    pub enabled: bool,
    pub max_bytes: usize,
    /// Uppercase HTTP methods whose bodies are inspected.
    pub methods: Vec<String>,
    /// Lowercase media types; `text/*` and `*/*` wildcards are supported.
    pub content_types: Vec<String>,
    /// Policy when `Content-Length` exceeds [`Self::max_bytes`].
    pub oversize: BodyPolicy,
    /// Policy for bodies we cannot inspect: missing length, unsupported
    /// content type/encoding, `Expect: 100-continue`, or upgrade requests.
    pub uninspectable: BodyPolicy,
    pub timeout_ms: u64,
    /// Inspect chunked / HTTP/2 bodies without `Content-Length` by reading up to
    /// [`Self::max_bytes`]. Bodies over the cap are rejected with 413 because
    /// they can no longer be replayed.
    pub inspect_unknown_length: bool,
    /// Decompress `Content-Encoding: gzip` (bounded) before scanning.
    pub decompress_gzip: bool,
    /// Decompress `Content-Encoding: br` (bounded) before scanning.
    pub decompress_brotli: bool,
    /// Decompress `Content-Encoding: zstd` (bounded) before scanning.
    pub decompress_zstd: bool,
    /// Decompress `Content-Encoding: deflate` (zlib-wrapped) before scanning.
    pub decompress_deflate: bool,
}

impl Default for BodyInspection {
    fn default() -> Self {
        Self {
            enabled: false,
            max_bytes: DEFAULT_MAX_BYTES,
            methods: default_methods(),
            content_types: default_content_types(),
            oversize: BodyPolicy::Log,
            uninspectable: BodyPolicy::Log,
            timeout_ms: 1000,
            inspect_unknown_length: false,
            decompress_gzip: false,
            decompress_brotli: false,
            decompress_zstd: false,
            decompress_deflate: false,
        }
    }
}

fn default_methods() -> Vec<String> {
    ["POST", "PUT", "PATCH"]
        .iter()
        .map(|m| (*m).to_string())
        .collect()
}

fn default_content_types() -> Vec<String> {
    [
        "application/json",
        "application/x-www-form-urlencoded",
        "text/*",
    ]
    .iter()
    .map(|m| (*m).to_string())
    .collect()
}

impl BodyInspection {
    /// Clamp/validate values once at config construction time so the request
    /// path never has to check ranges.
    pub fn finalize(&mut self) {
        self.max_bytes = self.max_bytes.clamp(1024, HARD_MAX_BYTES);
        self.timeout_ms = self.timeout_ms.clamp(100, 5000);
        if self.methods.is_empty() {
            self.methods = default_methods();
        }
        self.methods = self
            .methods
            .iter()
            .map(|m| m.trim().to_ascii_uppercase())
            .filter(|m| !m.is_empty())
            .collect();
        self.methods.dedup();
        if self.content_types.is_empty() {
            self.content_types = default_content_types();
        }
        self.content_types = self
            .content_types
            .iter()
            .map(|c| c.trim().to_ascii_lowercase())
            .filter(|c| !c.is_empty())
            .collect();
        self.content_types.dedup();
    }

    pub fn method_allowed(&self, method: &str) -> bool {
        self.methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method.trim()))
    }

    /// Match the media type (parameters such as `; charset=utf-8` ignored).
    pub fn content_type_allowed(&self, content_type: &str) -> bool {
        let media = media_type(content_type);
        self.content_types.iter().any(|pattern| {
            if pattern == "*/*" {
                true
            } else if let Some(prefix) = pattern.strip_suffix('*') {
                media.starts_with(prefix)
            } else {
                media == *pattern
            }
        })
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.max(1))
    }
}

/// Extract the lowercase media type from a `Content-Type` header value.
pub fn media_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// Decode a body into the lowercase text the managed signatures and custom
/// rules scan. JSON/form payloads are decoded so `\u003c`, `%27` and `+` do
/// not hide a payload from the WAF. Multipart bodies are split into text parts;
/// binary file parts are skipped.
pub fn decode_for_scan(content_type: &str, body: &[u8]) -> String {
    let media = media_type(content_type);
    let text = if media == "multipart/form-data" {
        decode_multipart(content_type, body)
    } else {
        decode_content(&media, body)
    };
    let mut lowered = text.to_lowercase();
    truncate_scan_text(&mut lowered);
    lowered
}

fn decode_content(media: &str, body: &[u8]) -> String {
    if media == "application/json" || media.ends_with("+json") {
        decode_json(body)
    } else if media == "application/x-www-form-urlencoded" {
        decode_form(&String::from_utf8_lossy(body))
    } else {
        String::from_utf8_lossy(body).into_owned()
    }
}

fn multipart_boundary(content_type: &str) -> Option<&str> {
    content_type.split(';').skip(1).find_map(|param| {
        let (key, value) = param.split_once('=')?;
        if key.trim().eq_ignore_ascii_case("boundary") {
            Some(value.trim().trim_matches('"'))
        } else {
            None
        }
    })
}

fn part_is_scannable(content_type: &str) -> bool {
    let media = media_type(content_type);
    media.is_empty()
        || media == "application/json"
        || media.ends_with("+json")
        || media == "application/x-www-form-urlencoded"
        || media.starts_with("text/")
}

fn split_bytes<'a>(data: &'a [u8], needle: &[u8]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    while start <= data.len() {
        let Some(offset) = data[start..]
            .windows(needle.len())
            .position(|window| window == needle)
        else {
            break;
        };
        out.push(&data[start..start + offset]);
        start += offset + needle.len();
    }
    out.push(&data[start..]);
    out
}

fn header_value<'a>(headers: &'a [u8], name: &str) -> Option<&'a str> {
    for line in headers.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        if !line[..colon].eq_ignore_ascii_case(name.as_bytes()) {
            continue;
        }
        return std::str::from_utf8(&line[colon + 1..]).ok().map(str::trim);
    }
    None
}

fn decode_multipart(content_type: &str, body: &[u8]) -> String {
    let Some(boundary) = multipart_boundary(content_type).filter(|b| !b.is_empty()) else {
        return String::from_utf8_lossy(body).into_owned();
    };
    let delimiter = format!("--{boundary}");
    let mut out = String::new();
    for part in split_bytes(body, delimiter.as_bytes()) {
        if out.len() >= MAX_SCAN_BYTES {
            break;
        }
        let part = part.strip_prefix(b"\r\n").unwrap_or(part);
        let part = part.strip_suffix(b"\r\n").unwrap_or(part);
        if part.is_empty() || part.starts_with(b"--") {
            continue;
        }
        let Some(head_end) = part.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let headers = &part[..head_end];
        let content = &part[head_end + 4..];
        let part_type = header_value(headers, "content-type").unwrap_or("text/plain");
        if !part_is_scannable(part_type) {
            continue;
        }
        let media = media_type(part_type);
        out.push_str(&decode_content(&media, content));
        out.push(' ');
    }
    out
}

fn truncate_scan_text(text: &mut String) {
    if text.len() <= MAX_SCAN_BYTES {
        return;
    }
    let mut cut = MAX_SCAN_BYTES;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
}

fn decode_json(body: &[u8]) -> String {
    match serde_json::from_slice::<Value>(body) {
        Ok(value) => {
            let mut out = String::new();
            collect_json_strings(&value, &mut out);
            out
        }
        // Truncated/invalid JSON is still worth scanning: unescape the raw text
        // so `\u0027 or 1=1` does not slip through just because the document
        // was slightly malformed.
        Err(_) => unescape_json(&String::from_utf8_lossy(body)),
    }
}

fn collect_json_strings(value: &Value, out: &mut String) {
    if out.len() >= MAX_SCAN_BYTES {
        return;
    }
    match value {
        Value::String(s) => {
            out.push_str(s);
            out.push(' ');
        }
        Value::Array(items) => {
            for item in items {
                collect_json_strings(item, out);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                out.push_str(key);
                out.push(' ');
                collect_json_strings(item, out);
            }
        }
        _ => {}
    }
}

fn decode_form(input: &str) -> String {
    let plus = input.replace('+', " ");
    let once = percent_decode(&plus);
    if once.contains('%') {
        percent_decode(&once)
    } else {
        once
    }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Minimal JSON string unescaper used when the document does not parse.
fn unescape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('/') => out.push('/'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('u') => {
                let mut code = 0u32;
                let mut digits = 0;
                for _ in 0..4 {
                    match chars.next().and_then(|c| c.to_digit(16)) {
                        Some(digit) => {
                            code = (code << 4) | digit;
                            digits += 1;
                        }
                        None => break,
                    }
                }
                if digits == 4 {
                    // Combine a UTF-16 surrogate pair when present.
                    if (0xD800..=0xDBFF).contains(&code) {
                        let mut lookahead = chars.clone();
                        if lookahead.next() == Some('\\') && lookahead.next() == Some('u') {
                            let mut low = 0u32;
                            let mut low_digits = 0;
                            for _ in 0..4 {
                                match lookahead.next().and_then(|c| c.to_digit(16)) {
                                    Some(digit) => {
                                        low = (low << 4) | digit;
                                        low_digits += 1;
                                    }
                                    None => break,
                                }
                            }
                            if low_digits == 4 && (0xDC00..=0xDFFF).contains(&low) {
                                chars = lookahead;
                                code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                            }
                        }
                    }
                    if let Some(c) = char::from_u32(code) {
                        out.push(c);
                    }
                }
            }
            Some(other) => out.push(other),
            None => break,
        }
    }
    out
}

/// Body-inspection eligibility facts extracted once from the request headers.
#[derive(Debug, Clone, Copy)]
pub struct BodyFacts<'a> {
    pub method: &'a str,
    pub content_type: &'a str,
    pub content_encoding: Option<&'a str>,
    pub content_length: Option<usize>,
    pub expect_continue: bool,
    pub upgrade: bool,
}

impl<'a> BodyFacts<'a> {
    pub fn from_headers(method: &'a str, headers: &'a HeaderMap) -> Self {
        let content_type = headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let content_encoding = headers
            .get(axum::http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok());
        let content_length = headers
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<usize>().ok());
        let expect_continue = headers
            .get(axum::http::header::EXPECT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("100-continue"));
        let upgrade = headers.contains_key(axum::http::header::UPGRADE)
            || headers
                .get(axum::http::header::CONNECTION)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.to_ascii_lowercase().contains("upgrade"));
        Self {
            method,
            content_type,
            content_encoding,
            content_length,
            expect_continue,
            upgrade,
        }
    }

    /// `identity` or absent means the body is not compressed.
    pub fn is_identity(&self) -> bool {
        self.content_encoding
            .is_none_or(|v| v.trim().is_empty() || v.trim().eq_ignore_ascii_case("identity"))
    }

    pub fn is_gzip(&self) -> bool {
        self.content_encoding
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("gzip"))
    }

    pub fn is_brotli(&self) -> bool {
        self.content_encoding
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("br"))
    }

    pub fn is_zstd(&self) -> bool {
        self.content_encoding
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("zstd"))
    }

    pub fn is_deflate(&self) -> bool {
        self.content_encoding
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("deflate"))
    }
}

/// Decompressed bodies are scanned through a separate, larger cap; the wire
/// body itself still has to fit Pingora's retry buffer.
pub const MAX_DECOMPRESSED_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    TooLarge,
    Invalid,
}

/// Brotli-decompress a request body for scanning, bounded by `max`.
pub fn brotli_for_scan(input: &[u8], max: usize) -> Result<Vec<u8>, DecodeError> {
    use std::io::Read;
    let decoder = brotli::Decompressor::new(input, 4096);
    let mut out = Vec::new();
    decoder
        .take((max as u64).saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|_| DecodeError::Invalid)?;
    if out.len() > max {
        return Err(DecodeError::TooLarge);
    }
    Ok(out)
}

/// zstd-decompress a request body for scanning, bounded by `max`.
pub fn zstd_for_scan(input: &[u8], max: usize) -> Result<Vec<u8>, DecodeError> {
    use std::io::Read;
    let decoder = zstd::stream::read::Decoder::new(input).map_err(|_| DecodeError::Invalid)?;
    let mut out = Vec::new();
    decoder
        .take((max as u64).saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|_| DecodeError::Invalid)?;
    if out.len() > max {
        return Err(DecodeError::TooLarge);
    }
    Ok(out)
}

/// Inflate a zlib-wrapped (`Content-Encoding: deflate`) request body.
pub fn inflate_for_scan(input: &[u8], max: usize) -> Result<Vec<u8>, DecodeError> {
    use std::io::Read;
    let decoder = flate2::read::ZlibDecoder::new(input);
    let mut out = Vec::new();
    decoder
        .take((max as u64).saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|_| DecodeError::Invalid)?;
    if out.len() > max {
        return Err(DecodeError::TooLarge);
    }
    Ok(out)
}

/// Gunzip a request body for scanning, bounded by `max`.
pub fn gunzip_for_scan(input: &[u8], max: usize) -> Result<Vec<u8>, DecodeError> {
    use std::io::Read;
    let decoder = flate2::read::GzDecoder::new(input);
    let mut out = Vec::new();
    decoder
        .take((max as u64).saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|_| DecodeError::Invalid)?;
    if out.len() > max {
        return Err(DecodeError::TooLarge);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_form_escapes_twice() {
        assert!(
            decode_for_scan("application/x-www-form-urlencoded", b"q=%2527+or+1%253D1")
                .contains("' or 1=1")
        );
        assert!(decode_for_scan(
            "application/x-www-form-urlencoded; charset=utf-8",
            b"q=%27+or+1%3D1"
        )
        .contains("' or 1=1"));
    }

    #[test]
    fn decodes_json_string_values() {
        let text = decode_for_scan(
            "application/json",
            br#"{"q":"\u003cscript\u003ealert(1)\u003c/script\u003e","n":1}"#,
        );
        assert!(text.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn unescapes_malformed_json_fallback() {
        let text = decode_for_scan("application/json", br#"{"q":"\u0027 or 1=1""#);
        assert!(text.contains("' or 1=1"));
    }

    #[test]
    fn plain_text_is_lowercased() {
        assert_eq!(
            decode_for_scan("text/plain", b"Union SELECT"),
            "union select"
        );
    }

    #[test]
    fn content_type_matching_supports_wildcards() {
        let mut body = BodyInspection::default();
        body.finalize();
        assert!(body.content_type_allowed("application/json; charset=utf-8"));
        assert!(body.content_type_allowed("text/html"));
        assert!(!body.content_type_allowed("image/png"));
        assert!(!body.content_type_allowed("multipart/form-data; boundary=x"));
    }

    #[test]
    fn finalize_clamps_limits_and_methods() {
        let mut body = BodyInspection {
            max_bytes: 10,
            timeout_ms: 10,
            methods: vec!["post".into(), " POST ".into()],
            content_types: vec!["APPLICATION/JSON".into()],
            ..BodyInspection::default()
        };
        body.finalize();
        assert_eq!(body.max_bytes, 1024);
        assert_eq!(body.timeout_ms, 100);
        assert_eq!(body.methods, vec!["POST".to_string()]);
        assert_eq!(body.content_types, vec!["application/json".to_string()]);
        assert!(body.method_allowed("post"));
        assert!(!body.method_allowed("GET"));
    }

    #[test]
    fn brotli_is_bounded_and_decodes() {
        use std::io::Write;
        let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
        encoder.write_all(b"union select").unwrap();
        let compressed = encoder.into_inner();
        assert_eq!(brotli_for_scan(&compressed, 1024).unwrap(), b"union select");
        assert_eq!(
            brotli_for_scan(&compressed, 4).unwrap_err(),
            DecodeError::TooLarge
        );
        assert_eq!(
            brotli_for_scan(b"not brotli", 1024).unwrap_err(),
            DecodeError::Invalid
        );
    }

    #[test]
    fn zstd_and_deflate_are_bounded_and_decode() {
        use std::io::Write;
        let zstd = zstd::stream::encode_all(&b"union select"[..], 3).unwrap();
        assert_eq!(zstd_for_scan(&zstd, 1024).unwrap(), b"union select");
        assert_eq!(zstd_for_scan(&zstd, 4).unwrap_err(), DecodeError::TooLarge);
        assert_eq!(
            zstd_for_scan(b"not zstd", 1024).unwrap_err(),
            DecodeError::Invalid
        );

        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"union select").unwrap();
        let deflate = encoder.finish().unwrap();
        assert_eq!(inflate_for_scan(&deflate, 1024).unwrap(), b"union select");
        assert_eq!(
            inflate_for_scan(&deflate, 4).unwrap_err(),
            DecodeError::TooLarge
        );
        assert_eq!(
            inflate_for_scan(b"not deflate", 1024).unwrap_err(),
            DecodeError::Invalid
        );
    }

    #[test]
    fn multipart_scans_text_parts_only() {
        let body = b"--X\r\nContent-Disposition: form-data; name=\"q\"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nq=%27+or+1%3D1\r\n--X\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\nContent-Type: application/octet-stream\r\n\r\nbinary-data\r\n--X--\r\n";
        let text = decode_for_scan("multipart/form-data; boundary=X", body);
        assert!(text.contains("' or 1=1"), "{text}");
        assert!(!text.contains("binary-data"));
    }

    #[test]
    fn gunzip_is_bounded_and_decodes() {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"union select").unwrap();
        let compressed = encoder.finish().unwrap();
        assert_eq!(gunzip_for_scan(&compressed, 1024).unwrap(), b"union select");
        assert_eq!(
            gunzip_for_scan(&compressed, 4).unwrap_err(),
            DecodeError::TooLarge
        );
        assert_eq!(
            gunzip_for_scan(b"not gzip", 1024).unwrap_err(),
            DecodeError::Invalid
        );
    }

    #[test]
    fn body_facts_parse_expect_and_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::CONTENT_LENGTH, "12".parse().unwrap());
        headers.insert(axum::http::header::EXPECT, "100-continue".parse().unwrap());
        headers.insert(
            axum::http::header::CONTENT_ENCODING,
            "gzip".parse().unwrap(),
        );
        let facts = BodyFacts::from_headers("POST", &headers);
        assert_eq!(facts.content_length, Some(12));
        assert!(facts.expect_continue);
        assert!(!facts.is_identity());
    }
}
