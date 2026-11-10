//! MaxMind GeoLite2 lookups backing the per-domain Geo/ASN WAF lists.
//!
//! Both databases are optional. A missing or unreadable file disables only
//! that half of the lookup and logs a warning: the WAF keeps serving traffic
//! and the Geo/ASN rules simply never match, so an absent database can never
//! take the data plane down on its own.

use maxminddb::Reader;
use serde::Deserialize;
use std::net::IpAddr;

/// Country/ASN information resolved for one client address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeoInfo {
    /// ISO 3166-1 alpha-2 code, uppercase.
    pub country: Option<String>,
    /// Autonomous system number from GeoLite2-ASN.
    pub asn: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct CountryRecord {
    #[serde(default)]
    country: Option<CountryCode>,
}

#[derive(Debug, Deserialize)]
struct CountryCode {
    #[serde(default)]
    iso_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AsnRecord {
    #[serde(default)]
    autonomous_system_number: Option<u32>,
}

/// Loaded MaxMind databases shared by every request on this node.
pub struct GeoLookup {
    country: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

impl std::fmt::Debug for GeoLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoLookup")
            .field("country", &self.country.is_some())
            .field("asn", &self.asn.is_some())
            .finish()
    }
}

impl GeoLookup {
    /// A lookup with no databases loaded; every result is empty.
    pub fn disabled() -> Self {
        Self {
            country: None,
            asn: None,
        }
    }

    /// Load the configured databases once at startup.
    pub fn load(country_path: &str, asn_path: &str) -> Self {
        let country = open(country_path, "country");
        let asn = open(asn_path, "asn");
        if country.is_none() && asn.is_none() {
            tracing::warn!(
                country = %country_path,
                asn = %asn_path,
                "MaxMind databases unavailable; Geo/ASN WAF rules are inactive"
            );
        }
        Self { country, asn }
    }

    /// True when at least one database is loaded.
    pub fn is_enabled(&self) -> bool {
        self.country.is_some() || self.asn.is_some()
    }

    /// Resolve country and ASN for a client address. Lookup failures and
    /// private/unknown addresses both yield empty fields.
    pub fn lookup(&self, ip: Option<IpAddr>) -> GeoInfo {
        let Some(ip) = ip else {
            return GeoInfo::default();
        };
        let country =
            self.country
                .as_ref()
                .and_then(|reader| match reader.lookup::<CountryRecord>(ip) {
                    Ok(record) => record
                        .country
                        .and_then(|c| c.iso_code)
                        .map(|code| code.trim().to_ascii_uppercase())
                        .filter(|code| code.len() == 2),
                    Err(_) => None,
                });
        let asn = self
            .asn
            .as_ref()
            .and_then(|reader| match reader.lookup::<AsnRecord>(ip) {
                Ok(record) => record.autonomous_system_number.filter(|n| *n > 0),
                Err(_) => None,
            });
        GeoInfo { country, asn }
    }
}

fn open(path: &str, kind: &str) -> Option<Reader<Vec<u8>>> {
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    match Reader::open_readfile(path) {
        Ok(reader) => {
            tracing::info!(kind, path, "loaded MaxMind database");
            Some(reader)
        }
        Err(e) => {
            tracing::warn!(kind, path, error = %e, "cannot open MaxMind database");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn db(name: &str) -> String {
        format!("{}/../../data/maxmind/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn missing_database_yields_no_geo_data() {
        let lookup = GeoLookup::load("/nonexistent/country.mmdb", "/nonexistent/asn.mmdb");
        assert!(!lookup.is_enabled());
        let info = lookup.lookup(Some("1.1.1.1".parse().unwrap()));
        assert_eq!(info, GeoInfo::default());
        assert_eq!(lookup.lookup(None), GeoInfo::default());
    }

    #[test]
    fn resolves_real_addresses_when_the_project_databases_exist() {
        let country_path = db("GeoLite2-Country.mmdb");
        let asn_path = db("GeoLite2-ASN.mmdb");
        if !Path::new(&country_path).exists() || !Path::new(&asn_path).exists() {
            return;
        }
        let lookup = GeoLookup::load(&country_path, &asn_path);
        assert!(lookup.is_enabled());
        let info = lookup.lookup(Some("1.1.1.1".parse().unwrap()));
        if let Some(code) = info.country.as_deref() {
            assert_eq!(code.len(), 2);
            assert_eq!(code, code.to_ascii_uppercase());
        }
        assert!(info.country.is_some() || info.asn.is_some());
        // Reserved TEST-NET-1 space is not present in the databases.
        let reserved = lookup.lookup(Some("192.0.2.55".parse().unwrap()));
        assert_eq!(reserved.country, None);
    }

    #[test]
    fn ipv6_addresses_are_supported() {
        let country_path = db("GeoLite2-Country.mmdb");
        if !Path::new(&country_path).exists() {
            return;
        }
        let lookup = GeoLookup::load(&country_path, &db("GeoLite2-ASN.mmdb"));
        let info = lookup.lookup(Some("2606:4700:4700::1111".parse().unwrap()));
        assert!(info.country.is_some() || info.asn.is_some());
    }
}
