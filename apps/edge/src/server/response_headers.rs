use axum::http::{HeaderMap, HeaderName, HeaderValue};
use std::sync::{Arc, OnceLock};

/// Validated response headers configured for one domain.
///
/// This is built when a domain snapshot is decoded and shared by all
/// responses, so the request path does not parse the same strings repeatedly.
#[derive(Debug, Clone, Default)]
pub struct ResponseHeaderOverrides {
    cors_origin: Option<HeaderValue>,
    custom: Vec<(HeaderName, HeaderValue)>,
}

impl ResponseHeaderOverrides {
    pub fn empty_arc() -> Arc<Self> {
        static EMPTY: OnceLock<Arc<ResponseHeaderOverrides>> = OnceLock::new();
        EMPTY
            .get_or_init(|| Arc::new(ResponseHeaderOverrides::default()))
            .clone()
    }

    pub fn parse(cors: &str, custom: &str) -> Self {
        let cors_origin = if cors.is_empty() {
            None
        } else {
            let origin = if cors.trim() == "*" {
                "*"
            } else {
                cors.split(',').next().map(str::trim).unwrap_or("*")
            };
            HeaderValue::from_str(origin).ok()
        };

        let custom = custom
            .lines()
            .filter_map(|line| {
                let (name, value) = line.trim().split_once(':')?;
                let name = HeaderName::from_bytes(name.trim().as_bytes()).ok()?;
                let value = HeaderValue::from_str(value.trim()).ok()?;
                Some((name, value))
            })
            .collect();

        Self {
            cors_origin,
            custom,
        }
    }

    pub fn apply(&self, headers: &mut HeaderMap) {
        if let Some(origin) = &self.cors_origin {
            headers.insert(
                HeaderName::from_static("access-control-allow-origin"),
                origin.clone(),
            );
        }
        for (name, value) in &self.custom {
            headers.insert(name.clone(), value.clone());
        }
    }

    pub fn cors_origin(&self) -> Option<&HeaderValue> {
        self.cors_origin.as_ref()
    }

    pub fn custom(&self) -> &[(HeaderName, HeaderValue)] {
        &self.custom
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsed_overrides_apply_same_valid_headers() {
        let overrides = ResponseHeaderOverrides::parse(
            "https://first.test, https://second.test",
            " X-Frame-Options: DENY\ninvalid header: ignored\nX-Trace: edge ",
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
        overrides.apply(&mut headers);

        assert_eq!(headers["access-control-allow-origin"], "https://first.test");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["x-trace"], "edge");
    }

    #[test]
    fn empty_or_invalid_values_are_ignored() {
        let overrides = ResponseHeaderOverrides::parse("", "X-Good: yes\nBad Header: ignored");
        let mut headers = HeaderMap::new();
        headers.insert(
            "access-control-allow-origin",
            HeaderValue::from_static("https://existing.test"),
        );
        overrides.apply(&mut headers);

        assert_eq!(
            headers["access-control-allow-origin"],
            "https://existing.test"
        );
        assert_eq!(headers["x-good"], "yes");
        assert!(!headers.contains_key("x-bad"));
    }
}
