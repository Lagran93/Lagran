//! ip2region XDB v2/v3 reader (IPv4 and IPv6).
//!
//! XDB layout:
//!
//! ```text
//! 0..256           header
//! 256..524544      vector index (256 * 256 * 8 bytes)
//! start_index_ptr  segment index entries
//! data_ptr         region strings
//! ```
//!
//! Each segment index entry is:
//!
//! ```text
//! IPv4: start u32 LE | end u32 LE | data_len u16 LE | data_ptr u32 LE
//! IPv6: start 16 B  | end 16 B  | data_len u16 LE | data_ptr u32 LE
//! ```
//!
//! Region strings produced by ip2region v2 are normally:
//!
//! ```text
//! Country|Province|City|ISP|ISO-3166-alpha2
//! ```
//!
//! Older data uses:
//!
//! ```text
//! Country|Region|Province|City|ISP
//! ```
//!
//! Both are recognized.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const HEADER_LEN: usize = 256;
const VECTOR_INDEX_SIZE: usize = 256 * 256 * 8;
const SEGMENT_INDEX_V4: usize = 14;
const SEGMENT_INDEX_V6: usize = 38;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ip2RegionRecord {
    pub country: String,
    pub province: String,
    pub city: String,
    pub isp: String,
}

#[derive(Debug, Clone)]
pub struct Ip2RegionDb {
    raw: Vec<u8>,
    ip_version: u8,
    segment_index_size: usize,
}

impl Ip2RegionDb {
    pub fn parse(raw: Vec<u8>) -> Result<Self, String> {
        if raw.len() < HEADER_LEN + VECTOR_INDEX_SIZE {
            return Err("ip2region xdb is shorter than header + vector index".into());
        }
        let version = le_u16(&raw, 0).ok_or_else(|| "truncated ip2region header".to_string())?;
        if version != 2 && version != 3 {
            return Err(format!(
                "unsupported ip2region xdb version {version}; expected 2 or 3"
            ));
        }
        let ip_version = if version == 2 {
            4
        } else {
            le_u16(&raw, 16).ok_or_else(|| "truncated ip2region header".to_string())? as u8
        };
        if ip_version != 4 && ip_version != 6 {
            return Err(format!(
                "unsupported ip2region ip version {ip_version}; expected 4 or 6"
            ));
        }
        let pointer_bytes = if version >= 3 {
            le_u16(&raw, 18).ok_or_else(|| "truncated ip2region header".to_string())?
        } else {
            4
        };
        if pointer_bytes != 4 {
            return Err(format!(
                "unsupported ip2region pointer width {pointer_bytes}; expected 4"
            ));
        }
        let segment_size = if ip_version == 4 {
            SEGMENT_INDEX_V4
        } else {
            SEGMENT_INDEX_V6
        };
        let start_index =
            le_u32(&raw, 8).ok_or_else(|| "truncated ip2region header".to_string())? as usize;
        let end_index =
            le_u32(&raw, 12).ok_or_else(|| "truncated ip2region header".to_string())? as usize;
        if start_index < HEADER_LEN + VECTOR_INDEX_SIZE
            || end_index < start_index
            || end_index > raw.len()
        {
            return Err("ip2region segment index is outside the file".into());
        }
        Ok(Self {
            raw,
            ip_version,
            segment_index_size: segment_size,
        })
    }

    pub fn ip_version(&self) -> u8 {
        self.ip_version
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<Ip2RegionRecord> {
        match (self.ip_version, ip) {
            (4, IpAddr::V4(v4)) => self.lookup_v4(v4),
            (4, IpAddr::V6(v6)) => v6.to_ipv4_mapped().and_then(|v4| self.lookup_v4(v4)),
            (6, IpAddr::V6(v6)) => self.lookup_v6(v6),
            _ => None,
        }
    }

    fn lookup_v4(&self, ip: Ipv4Addr) -> Option<Ip2RegionRecord> {
        let ipno = u32::from(ip);
        let idx = (((ipno >> 24) as usize) * 256 + (((ipno >> 16) & 0xff) as usize)) * 8;
        let vector = HEADER_LEN + idx;
        let start_ptr = le_u32(&self.raw, vector)?;
        let end_ptr = le_u32(&self.raw, vector + 4)?;
        if start_ptr == 0 || end_ptr == 0 || end_ptr < start_ptr {
            return None;
        }
        let start_ptr = start_ptr as usize;
        let end_ptr = end_ptr as usize;
        if end_ptr
            .checked_add(self.segment_index_size)
            .map(|end| end > self.raw.len())
            .unwrap_or(true)
        {
            return None;
        }

        let mut low = 0_i64;
        let mut high = ((end_ptr - start_ptr) / self.segment_index_size) as i64;
        while low <= high {
            let mid = low + (high - low) / 2;
            let entry = start_ptr + mid as usize * self.segment_index_size;
            let from = le_u32(&self.raw, entry)?;
            let to = le_u32(&self.raw, entry + 4)?;
            if ipno < from {
                high = mid - 1;
            } else if ipno > to {
                low = mid + 1;
            } else {
                let len = le_u16(&self.raw, entry + 8)? as usize;
                let ptr = le_u32(&self.raw, entry + 10)? as usize;
                if len == 0 || ptr == 0 {
                    return None;
                }
                let data = self.raw.get(ptr..ptr.checked_add(len)?)?;
                return Some(parse_region(&String::from_utf8_lossy(data)));
            }
        }
        None
    }

    fn lookup_v6(&self, ip: Ipv6Addr) -> Option<Ip2RegionRecord> {
        let ipno = u128::from(ip);
        let bytes = ip.octets();
        let idx = (bytes[0] as usize * 256 + bytes[1] as usize) * 8;
        let vector = HEADER_LEN + idx;
        let start_ptr = le_u32(&self.raw, vector)?;
        let end_ptr = le_u32(&self.raw, vector + 4)?;
        if start_ptr == 0 || end_ptr == 0 || end_ptr < start_ptr {
            return None;
        }
        let start_ptr = start_ptr as usize;
        let end_ptr = end_ptr as usize;
        if end_ptr
            .checked_add(self.segment_index_size)
            .map(|end| end > self.raw.len())
            .unwrap_or(true)
        {
            return None;
        }

        let mut low = 0_i64;
        let mut high = ((end_ptr - start_ptr) / self.segment_index_size) as i64;
        while low <= high {
            let mid = low + (high - low) / 2;
            let entry = start_ptr + mid as usize * self.segment_index_size;
            let from = u128_be(&self.raw, entry)?;
            let to = u128_be(&self.raw, entry + 16)?;
            if ipno < from {
                high = mid - 1;
            } else if ipno > to {
                low = mid + 1;
            } else {
                let len = le_u16(&self.raw, entry + 32)? as usize;
                let ptr = le_u32(&self.raw, entry + 34)? as usize;
                if len == 0 || ptr == 0 {
                    return None;
                }
                let data = self.raw.get(ptr..ptr.checked_add(len)?)?;
                return Some(parse_region(&String::from_utf8_lossy(data)));
            }
        }
        None
    }
}

fn parse_region(region: &str) -> Ip2RegionRecord {
    let fields: Vec<&str> = region.split('|').map(str::trim).collect();
    let get = |index: usize| fields.get(index).copied().unwrap_or_default();

    // New format: Country|Province|City|ISP|ISO-alpha2. A missing ISO
    // field is represented by `0`, so treat that as the new layout too.
    let iso_or_missing = is_iso_code(get(4)) || {
        let value = clean(get(4));
        value.is_empty()
    };
    if fields.len() >= 5 && iso_or_missing {
        let country = country_code(get(4));
        return Ip2RegionRecord {
            country: if country.is_empty() {
                country_code(get(0))
            } else {
                country
            },
            province: clean(get(1)),
            city: clean(get(2)),
            isp: clean(get(3)),
        };
    }

    // Old format: Country|Region|Province|City|ISP.
    if fields.len() >= 5 {
        return Ip2RegionRecord {
            country: country_code(get(0)),
            province: clean(get(2)),
            city: clean(get(3)),
            isp: clean(get(4)),
        };
    }

    // Degenerate/custom data: preserve what is available.
    Ip2RegionRecord {
        country: country_code(get(0)),
        province: clean(get(1)),
        city: clean(get(2)),
        isp: clean(get(3)),
    }
}

fn is_iso_code(value: &str) -> bool {
    let value = value.trim();
    value.len() == 2 && value.bytes().all(|b| b.is_ascii_alphabetic())
}

fn clean(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() || value == "0" || value == "-" {
        String::new()
    } else {
        value.to_string()
    }
}

fn country_code(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() || value == "0" {
        return String::new();
    }
    if is_iso_code(value) {
        let value = value.to_ascii_uppercase();
        return if value == "UK" { "GB".into() } else { value };
    }
    match value {
        "中国" => "CN".into(),
        "香港" => "HK".into(),
        "澳门" => "MO".into(),
        "台湾" => "TW".into(),
        "美国" => "US".into(),
        "日本" => "JP".into(),
        "韩国" => "KR".into(),
        "新加坡" => "SG".into(),
        "英国" => "GB".into(),
        "德国" => "DE".into(),
        "法国" => "FR".into(),
        "俄罗斯" => "RU".into(),
        "加拿大" => "CA".into(),
        "澳大利亚" => "AU".into(),
        "印度" => "IN".into(),
        "巴西" => "BR".into(),
        "荷兰" => "NL".into(),
        "United States" => "US".into(),
        "United Kingdom" => "GB".into(),
        "Australia" => "AU".into(),
        "Germany" => "DE".into(),
        "France" => "FR".into(),
        "Russia" => "RU".into(),
        "Canada" => "CA".into(),
        "Japan" => "JP".into(),
        "South Korea" => "KR".into(),
        "Singapore" => "SG".into(),
        "India" => "IN".into(),
        "Brazil" => "BR".into(),
        "Netherlands" => "NL".into(),
        "Hong Kong" => "HK".into(),
        "Taiwan" => "TW".into(),
        "Macau" => "MO".into(),
        _ => value.to_ascii_uppercase(),
    }
}

fn le_u16(raw: &[u8], offset: usize) -> Option<u16> {
    let bytes = raw.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(raw: &[u8], offset: usize) -> Option<u32> {
    let bytes = raw.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u128_be(raw: &[u8], offset: usize) -> Option<u128> {
    let bytes: [u8; 16] = raw.get(offset..offset + 16)?.try_into().ok()?;
    Some(u128::from_be_bytes(bytes))
}

/// Detect XDB by extension first, then by a plausible version-2/3 header.
pub fn is_xdb_file(path: &str, raw: &[u8]) -> bool {
    if let Some(ext) = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
    {
        if ext.eq_ignore_ascii_case("xdb") {
            return true;
        }
        if ext.eq_ignore_ascii_case("dat") || ext.eq_ignore_ascii_case("json") {
            return false;
        }
    }
    if raw.len() < HEADER_LEN + VECTOR_INDEX_SIZE {
        return false;
    }
    let version = u16::from_le_bytes([raw[0], raw[1]]);
    version == 2 || version == 3
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn xdb_fixture() -> Vec<u8> {
        let segment_start = HEADER_LEN + VECTOR_INDEX_SIZE;
        let region = "中国|广东省|深圳市|电信|CN";
        let data_ptr = segment_start + SEGMENT_INDEX_V4;
        let mut raw = vec![0_u8; data_ptr + region.len()];
        put_u16(&mut raw, 0, 3); // structure 3
        put_u16(&mut raw, 2, 1); // vector index policy
        put_u32(&mut raw, 4, 1_700_000_000);
        put_u32(&mut raw, 8, segment_start as u32);
        put_u32(&mut raw, 12, segment_start as u32);
        put_u16(&mut raw, 16, 4);
        put_u16(&mut raw, 18, 4);

        // Vector bucket for 1.2.x.x
        let vector = HEADER_LEN + (256 + 2) * 8;
        put_u32(&mut raw, vector, segment_start as u32);
        put_u32(&mut raw, vector + 4, segment_start as u32);

        // One segment: 1.2.3.4 .. 1.2.3.5
        put_u32(
            &mut raw,
            segment_start,
            u32::from(Ipv4Addr::new(1, 2, 3, 4)),
        );
        put_u32(
            &mut raw,
            segment_start + 4,
            u32::from(Ipv4Addr::new(1, 2, 3, 5)),
        );
        put_u16(&mut raw, segment_start + 8, region.len() as u16);
        put_u32(&mut raw, segment_start + 10, data_ptr as u32);
        raw[data_ptr..].copy_from_slice(region.as_bytes());
        raw
    }

    fn xdb_v6_fixture() -> Vec<u8> {
        let segment_start = HEADER_LEN + VECTOR_INDEX_SIZE;
        let region = "中国|北京市|北京市|联通";
        let data_ptr = segment_start + SEGMENT_INDEX_V6;
        let mut raw = vec![0_u8; data_ptr + region.len()];
        put_u16(&mut raw, 0, 3);
        put_u16(&mut raw, 2, 1);
        put_u32(&mut raw, 4, 1_700_000_000);
        put_u32(&mut raw, 8, segment_start as u32);
        put_u32(&mut raw, 12, segment_start as u32);
        put_u16(&mut raw, 16, 6);
        put_u16(&mut raw, 18, 4);

        let vector = HEADER_LEN + (0x20 * 256 + 0x01) * 8;
        put_u32(&mut raw, vector, segment_start as u32);
        put_u32(&mut raw, vector + 4, segment_start as u32);

        let start: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let end: Ipv6Addr = "2001:db8::2".parse().unwrap();
        raw[segment_start..segment_start + 16].copy_from_slice(&start.octets());
        raw[segment_start + 16..segment_start + 32].copy_from_slice(&end.octets());
        put_u16(&mut raw, segment_start + 32, region.len() as u16);
        put_u32(&mut raw, segment_start + 34, data_ptr as u32);
        raw[data_ptr..].copy_from_slice(region.as_bytes());
        raw
    }

    #[test]
    fn parses_ipv6_xdb() {
        let db = Ip2RegionDb::parse(xdb_v6_fixture()).expect("parse xdb v6");
        assert_eq!(
            db.lookup("2001:db8::1".parse().unwrap()),
            Some(Ip2RegionRecord {
                country: "CN".into(),
                province: "北京市".into(),
                city: "北京市".into(),
                isp: "联通".into(),
            })
        );
        assert_eq!(db.lookup("2001:db8::3".parse().unwrap()), None);
    }

    #[test]
    fn parses_ipv4_xdb() {
        let db = Ip2RegionDb::parse(xdb_fixture()).expect("parse xdb");
        assert_eq!(
            db.lookup("1.2.3.4".parse().unwrap()),
            Some(Ip2RegionRecord {
                country: "CN".into(),
                province: "广东省".into(),
                city: "深圳市".into(),
                isp: "电信".into(),
            })
        );
        assert_eq!(db.lookup("9.9.9.9".parse().unwrap()), None);
    }

    #[test]
    fn parses_old_and_new_region_formats() {
        assert_eq!(
            parse_region("美国|加利福尼亚州|洛杉矶|ISP|US"),
            Ip2RegionRecord {
                country: "US".into(),
                province: "加利福尼亚州".into(),
                city: "洛杉矶".into(),
                isp: "ISP".into(),
            }
        );
        assert_eq!(
            parse_region("中国|0|广东省|深圳市|电信"),
            Ip2RegionRecord {
                country: "CN".into(),
                province: "广东省".into(),
                city: "深圳市".into(),
                isp: "电信".into(),
            }
        );
        assert_eq!(
            parse_region("中国|福建省|福州市|电信"),
            Ip2RegionRecord {
                country: "CN".into(),
                province: "福建省".into(),
                city: "福州市".into(),
                isp: "电信".into(),
            }
        );
    }
}
