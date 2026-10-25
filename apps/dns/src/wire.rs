//! Minimal DNS wire format: query parsing (EDNS0/ECS) and authoritative
//! response encoding. Only the record types a CDN zone needs are supported.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_ANY: u16 = 255;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_REFUSED: u8 = 5;

#[derive(Debug)]
pub enum WireError {
    Short,
    BadName,
    BadMessage,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Short => write!(f, "short DNS message"),
            WireError::BadName => write!(f, "invalid DNS name"),
            WireError::BadMessage => write!(f, "invalid DNS message"),
        }
    }
}

impl std::error::Error for WireError {}

#[derive(Debug, Clone)]
pub struct Edns {
    pub udp_size: u16,
}

#[derive(Debug, Clone)]
pub struct Ecs {
    pub source_prefix: u8,
    pub addr: IpAddr,
}

#[derive(Debug, Clone)]
pub struct Query {
    pub id: u16,
    pub flags: u16,
    /// Lower-case, no trailing dot; root is empty.
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Raw question bytes (from offset 12 to the end of QNAME/QTYPE/QCLASS).
    pub question: Vec<u8>,
    pub edns: Option<Edns>,
    pub ecs: Option<Ecs>,
}

impl Query {
    pub fn udp_limit(&self) -> usize {
        self.edns
            .as_ref()
            .map(|e| (e.udp_size as usize).clamp(512, 4096))
            .unwrap_or(512)
    }
}

fn be16(buf: &[u8], pos: usize) -> Result<u16, WireError> {
    if pos + 2 > buf.len() {
        return Err(WireError::Short);
    }
    Ok(u16::from_be_bytes([buf[pos], buf[pos + 1]]))
}

fn be32(buf: &[u8], pos: usize) -> Result<u32, WireError> {
    if pos + 4 > buf.len() {
        return Err(WireError::Short);
    }
    Ok(u32::from_be_bytes([
        buf[pos],
        buf[pos + 1],
        buf[pos + 2],
        buf[pos + 3],
    ]))
}

/// Returns (name, offset after the name in the original message).
fn read_name(buf: &[u8], start: usize) -> Result<(String, usize), WireError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end = start;
    let mut jumped = false;
    let mut hops = 0usize;
    loop {
        if pos >= buf.len() {
            return Err(WireError::BadName);
        }
        let len = buf[pos];
        if len == 0 {
            if !jumped {
                end = pos + 1;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return Err(WireError::BadName);
            }
            let ptr = (((len & 0x3F) as usize) << 8) | buf[pos + 1] as usize;
            if !jumped {
                end = pos + 2;
                jumped = true;
            }
            if ptr >= buf.len() {
                return Err(WireError::BadName);
            }
            pos = ptr;
            hops += 1;
            if hops > 32 {
                return Err(WireError::BadName);
            }
            continue;
        }
        if len & 0xC0 != 0 {
            return Err(WireError::BadName);
        }
        let l = len as usize;
        if l > 63 || pos + 1 + l > buf.len() {
            return Err(WireError::BadName);
        }
        let label = std::str::from_utf8(&buf[pos + 1..pos + 1 + l])
            .map_err(|_| WireError::BadName)?
            .to_ascii_lowercase();
        labels.push(label);
        pos += 1 + l;
        if labels.len() > 127 {
            return Err(WireError::BadName);
        }
    }
    Ok((labels.join("."), end))
}

fn skip_rr(buf: &[u8], pos: usize) -> Result<usize, WireError> {
    let (_, mut p) = read_name(buf, pos)?;
    p += 8; // type, class, ttl
    if p + 2 > buf.len() {
        return Err(WireError::Short);
    }
    let rdlen = be16(buf, p)? as usize;
    p += 2 + rdlen;
    if p > buf.len() {
        return Err(WireError::Short);
    }
    Ok(p)
}

fn parse_opt(buf: &[u8], pos: usize) -> Result<(Edns, Option<Ecs>), WireError> {
    let (_name, p) = read_name(buf, pos)?;
    let rtype = be16(buf, p)?;
    if rtype != TYPE_OPT {
        return Err(WireError::BadMessage);
    }
    let class = be16(buf, p + 2)?;
    let _ttl = be32(buf, p + 4)?;
    let rdlen = be16(buf, p + 8)? as usize;
    let mut rdata = p + 10;
    let end = rdata + rdlen;
    if end > buf.len() {
        return Err(WireError::Short);
    }
    let edns = Edns { udp_size: class };
    let mut ecs = None;
    while rdata + 4 <= end {
        let code = be16(buf, rdata)?;
        let len = be16(buf, rdata + 2)? as usize;
        rdata += 4;
        if rdata + len > end {
            return Err(WireError::BadMessage);
        }
        if code == 8 && len >= 4 {
            let family = be16(buf, rdata)?;
            let source = buf[rdata + 2];
            let _scope = buf[rdata + 3];
            let addr_bytes = match family {
                1 => 4,
                2 => 16,
                _ => 0,
            };
            if addr_bytes > 0 && len >= 4 + addr_bytes {
                let mut octets = [0u8; 16];
                octets[..addr_bytes].copy_from_slice(&buf[rdata + 4..rdata + 4 + addr_bytes]);
                let addr = if family == 1 {
                    IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
                } else {
                    IpAddr::V6(Ipv6Addr::from(octets))
                };
                ecs = Some(Ecs {
                    source_prefix: source.min(if family == 1 { 32 } else { 128 }),
                    addr: mask_addr(addr, source.min(if family == 1 { 32 } else { 128 })),
                });
            }
        }
        rdata += len;
    }
    Ok((edns, ecs))
}

pub fn mask_addr(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(ip) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix.min(32))
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(ip) & mask))
        }
        IpAddr::V6(ip) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix.min(128))
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(ip) & mask))
        }
    }
}

pub fn parse_query(buf: &[u8]) -> Result<Query, WireError> {
    if buf.len() < 12 {
        return Err(WireError::Short);
    }
    let id = be16(buf, 0)?;
    let flags = be16(buf, 2)?;
    let qd = be16(buf, 4)?;
    let an = be16(buf, 6)?;
    let ns = be16(buf, 8)?;
    let ar = be16(buf, 10)?;
    if qd != 1 {
        return Err(WireError::BadMessage);
    }
    let (qname, mut pos) = read_name(buf, 12)?;
    let qtype = be16(buf, pos)?;
    let qclass = be16(buf, pos + 2)?;
    pos += 4;
    let question = buf[12..pos].to_vec();

    for _ in 0..an + ns {
        pos = skip_rr(buf, pos)?;
    }
    let mut edns = None;
    let mut ecs = None;
    for _ in 0..ar {
        let (_, p) = read_name(buf, pos)?;
        if p + 10 > buf.len() {
            return Err(WireError::Short);
        }
        let rtype = be16(buf, p)?;
        if rtype == TYPE_OPT {
            let (e, c) = parse_opt(buf, pos)?;
            edns = Some(e);
            ecs = c;
        }
        pos = skip_rr(buf, pos)?;
    }

    Ok(Query {
        id,
        flags,
        qname,
        qtype,
        qclass,
        question,
        edns,
        ecs,
    })
}

#[derive(Debug, Clone)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

fn put_name(out: &mut Vec<u8>, name: &str) {
    let name = name.trim_end_matches('.');
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            let bytes = label.as_bytes();
            let len = bytes.len().min(63);
            out.push(len as u8);
            out.extend_from_slice(&bytes[..len]);
        }
    }
    out.push(0);
}

pub fn a_record(name: &str, ip: Ipv4Addr, ttl: u32) -> Record {
    Record {
        name: name.into(),
        rtype: TYPE_A,
        ttl,
        rdata: ip.octets().to_vec(),
    }
}

pub fn aaaa_record(name: &str, ip: Ipv6Addr, ttl: u32) -> Record {
    Record {
        name: name.into(),
        rtype: TYPE_AAAA,
        ttl,
        rdata: ip.octets().to_vec(),
    }
}

pub fn ns_record(name: &str, target: &str, ttl: u32) -> Record {
    let mut rdata = Vec::new();
    put_name(&mut rdata, target);
    Record {
        name: name.into(),
        rtype: TYPE_NS,
        ttl,
        rdata,
    }
}

pub fn soa_record(name: &str, mname: &str, rname: &str, serial: u32, ttl: u32) -> Record {
    let mut rdata = Vec::new();
    put_name(&mut rdata, mname);
    put_name(&mut rdata, rname);
    rdata.extend_from_slice(&serial.to_be_bytes());
    rdata.extend_from_slice(&3600u32.to_be_bytes()); // refresh
    rdata.extend_from_slice(&600u32.to_be_bytes()); // retry
    rdata.extend_from_slice(&86400u32.to_be_bytes()); // expire
    rdata.extend_from_slice(&60u32.to_be_bytes()); // minimum
    Record {
        name: name.into(),
        rtype: TYPE_SOA,
        ttl,
        rdata,
    }
}

fn write_record(out: &mut Vec<u8>, rec: &Record) {
    put_name(out, &rec.name);
    out.extend_from_slice(&rec.rtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&rec.ttl.to_be_bytes());
    out.extend_from_slice(&(rec.rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rec.rdata);
}

fn write_opt(out: &mut Vec<u8>, query: &Query) {
    out.push(0); // root
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&1232u16.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    let mut rdata = Vec::new();
    if let Some(ecs) = &query.ecs {
        let (bytes, family) = match ecs.addr {
            IpAddr::V4(ip) => (ip.octets().to_vec(), 1u16),
            IpAddr::V6(ip) => (ip.octets().to_vec(), 2u16),
        };
        let len = 4 + bytes.len();
        rdata.extend_from_slice(&8u16.to_be_bytes());
        rdata.extend_from_slice(&(len as u16).to_be_bytes());
        rdata.extend_from_slice(&family.to_be_bytes());
        rdata.push(ecs.source_prefix);
        rdata.push(ecs.source_prefix.min(if family == 1 { 32 } else { 128 }));
        rdata.extend_from_slice(&bytes);
    }
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
}

fn encode_with(
    query: &Query,
    rcode: u8,
    answers: &[Record],
    authority: &[Record],
    additional: &[Record],
    truncated: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    let mut flags = 0x8000u16 | 0x0400u16 | (query.flags & 0x0100) | (rcode as u16 & 0x000F);
    if truncated {
        flags |= 0x0200;
    }
    out.extend_from_slice(&query.id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&(authority.len() as u16).to_be_bytes());
    let ar = additional.len() as u16 + u16::from(query.edns.is_some());
    out.extend_from_slice(&ar.to_be_bytes());
    out.extend_from_slice(&query.question);
    for rec in answers {
        write_record(&mut out, rec);
    }
    for rec in authority {
        write_record(&mut out, rec);
    }
    for rec in additional {
        write_record(&mut out, rec);
    }
    if query.edns.is_some() {
        write_opt(&mut out, query);
    }
    out
}

/// Encode a response; truncates over UDP when it exceeds the client's limit.
pub fn encode_response(
    query: &Query,
    rcode: u8,
    answers: &[Record],
    authority: &[Record],
    additional: &[Record],
    tcp: bool,
    udp_limit: usize,
) -> Vec<u8> {
    let full = encode_with(query, rcode, answers, authority, additional, false);
    if !tcp && full.len() > udp_limit {
        return encode_with(query, rcode, &[], &[], &[], true);
    }
    full
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_query(name: &str, qtype: u16, ecs: Option<(IpAddr, u8)>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x1234u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        let ar = if ecs.is_some() { 1u16 } else { 0 };
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&ar.to_be_bytes());
        put_name(&mut out, name);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        if let Some((ip, prefix)) = ecs {
            out.push(0);
            out.extend_from_slice(&TYPE_OPT.to_be_bytes());
            out.extend_from_slice(&1232u16.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
            let (bytes, family) = match ip {
                IpAddr::V4(v) => (v.octets().to_vec(), 1u16),
                IpAddr::V6(v) => (v.octets().to_vec(), 2u16),
            };
            let mut rdata = Vec::new();
            rdata.extend_from_slice(&8u16.to_be_bytes());
            rdata.extend_from_slice(&((4 + bytes.len()) as u16).to_be_bytes());
            rdata.extend_from_slice(&family.to_be_bytes());
            rdata.push(prefix);
            rdata.push(0);
            rdata.extend_from_slice(&bytes);
            out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(&rdata);
        }
        out
    }

    #[test]
    fn parses_question_and_ecs() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let buf = build_query("cdn.edge.lagran.net", TYPE_A, Some((ip, 24)));
        let q = parse_query(&buf).unwrap();
        assert_eq!(q.qname, "cdn.edge.lagran.net");
        assert_eq!(q.qtype, TYPE_A);
        let ecs = q.ecs.unwrap();
        assert_eq!(ecs.source_prefix, 24);
        assert_eq!(ecs.addr, "203.0.113.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn encodes_a_and_roundtrips() {
        let buf = build_query("cdn.edge.lagran.net", TYPE_A, None);
        let q = parse_query(&buf).unwrap();
        let resp = encode_response(
            &q,
            RCODE_NOERROR,
            &[a_record(&q.qname, "203.0.113.10".parse().unwrap(), 30)],
            &[],
            &[],
            false,
            512,
        );
        assert_eq!(be16(&resp, 6).unwrap(), 1, "one answer");
        let mut pos = 12 + q.question.len();
        let (_, p) = read_name(&resp, pos).unwrap();
        pos = p;
        let rtype = be16(&resp, pos).unwrap();
        let ttl = be32(&resp, pos + 4).unwrap();
        let rdlen = be16(&resp, pos + 8).unwrap();
        assert_eq!(rtype, TYPE_A);
        assert_eq!(ttl, 30);
        assert_eq!(rdlen, 4);
        let ip = &resp[pos + 10..pos + 14];
        assert_eq!(ip, [203, 0, 113, 10]);
    }

    #[test]
    fn truncates_oversize_udp() {
        let buf = build_query("cdn.edge.lagran.net", TYPE_A, None);
        let q = parse_query(&buf).unwrap();
        let big: Vec<Record> = (0..80)
            .map(|i| a_record(&q.qname, Ipv4Addr::new(10, 0, 0, i), 30))
            .collect();
        let resp = encode_response(&q, RCODE_NOERROR, &big, &[], &[], false, 512);
        assert!(resp.len() <= 512);
        assert_ne!(be16(&resp, 2).unwrap() & 0x0200, 0, "TC bit set");
    }
}
