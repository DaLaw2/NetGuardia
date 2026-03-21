use std::collections::HashSet;

use common::model::dns_name::DnsName;
use parking_lot::RwLock;

use crate::model::error::misc::MiscError;
use crate::model::error::Error;

pub struct DnsFilter {
    blacklist: RwLock<HashSet<DnsName>>,
}

impl DnsFilter {
    pub fn new() -> Self {
        Self {
            blacklist: RwLock::new(HashSet::new()),
        }
    }

    pub fn add_domain(&self, domain: &str) -> Result<(), Error> {
        let name = domain_to_wire_format(domain)?;
        self.blacklist.write().insert(name);
        Ok(())
    }

    pub fn remove_domain(&self, domain: &str) -> Result<(), Error> {
        let name = domain_to_wire_format(domain)?;
        self.blacklist.write().remove(&name);
        Ok(())
    }

    pub fn list_domains(&self) -> Vec<String> {
        self.blacklist
            .read()
            .iter()
            .filter_map(wire_format_to_domain)
            .collect()
    }

    /// Check if a DNS query name (in wire format) or any of its parent domains is blacklisted.
    pub fn is_blacklisted(&self, name: &DnsName, name_len: usize) -> bool {
        let bl = self.blacklist.read();
        if bl.is_empty() {
            return false;
        }
        // Check exact match
        if bl.contains(name) {
            return true;
        }
        // Check parent domains
        let mut offset: usize = 0;
        loop {
            if offset >= name_len || offset >= 128 {
                break;
            }
            let lbl = name.data[offset] as usize;
            if lbl == 0 {
                break;
            }
            offset += 1 + lbl;
            if offset >= name_len || offset >= 128 {
                break;
            }
            if name.data[offset] == 0 {
                break;
            }

            let mut parent = DnsName::zeroed();
            let remaining = name_len - offset;
            parent.data[..remaining.min(128)]
                .copy_from_slice(&name.data[offset..offset + remaining.min(128)]);
            if bl.contains(&parent) {
                return true;
            }
        }
        false
    }

    /// Parse DNS query name from raw packet bytes.
    /// Returns the DNS name in wire format and the name length, or None if not a DNS query.
    pub fn parse_query_name(raw: &[u8]) -> Option<(DnsName, usize)> {
        if raw.len() < 14 {
            return None;
        }

        let eth_type = u16::from_be_bytes([raw[12], raw[13]]);
        let l3_header_len = match eth_type {
            0x0800 => {
                // IPv4
                if raw.len() < 24 {
                    return None;
                }
                let ihl = (raw[14] & 0x0F) as usize * 4;
                // Check protocol is UDP (17)
                if raw[14 + 9] != 17 {
                    return None;
                }
                ihl
            }
            0x86DD => {
                // IPv6
                if raw.len() < 54 + 8 {
                    return None;
                }
                // Check next header is UDP (17)
                if raw[14 + 6] != 17 {
                    return None;
                }
                40
            }
            _ => return None,
        };

        let udp_start = 14 + l3_header_len;
        if udp_start + 8 > raw.len() {
            return None;
        }

        // Check destination port is 53
        let dst_port = u16::from_be_bytes([raw[udp_start + 2], raw[udp_start + 3]]);
        if dst_port != 53 {
            return None;
        }

        let dns_header_offset = udp_start + 8;
        if dns_header_offset + 12 > raw.len() {
            return None;
        }

        // QR bit must be 0 (query, not response)
        if raw[dns_header_offset + 2] & 0x80 != 0 {
            return None;
        }

        // QDCOUNT must be > 0
        if raw[dns_header_offset + 4] == 0 && raw[dns_header_offset + 5] == 0 {
            return None;
        }

        let dns_qname_offset = dns_header_offset + 12;
        if dns_qname_offset >= raw.len() {
            return None;
        }

        let mut name = DnsName::zeroed();
        let mut pos = dns_qname_offset;
        let mut out: usize = 0;
        for _ in 0..32 {
            if pos >= raw.len() {
                return None;
            }
            let ll = raw[pos] as usize;
            if ll == 0 {
                if out < 128 {
                    name.data[out] = 0;
                }
                return Some((name, out + 1));
            }
            if ll >= 64 {
                return None;
            }
            if out + 1 + ll >= 128 {
                return None;
            }
            if pos + 1 + ll > raw.len() {
                return None;
            }
            name.data[out] = ll as u8;
            out += 1;
            for j in 0..ll {
                let mut b = raw[pos + 1 + j];
                if b.is_ascii_uppercase() {
                    b += 32;
                }
                name.data[out] = b;
                out += 1;
            }
            pos += 1 + ll;
        }
        None
    }
}

/// Convert a human-readable domain name (e.g., "example.com") to DNS wire format.
/// The result is a DnsName with lowercase, length-prefixed labels, zero-terminated and zero-padded.
fn domain_to_wire_format(domain: &str) -> Result<DnsName, Error> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    let mut name = DnsName::zeroed();
    let mut pos: usize = 0;

    for label in domain.split('.') {
        let label_bytes = label.as_bytes();
        let label_len = label_bytes.len();
        if label_len == 0 || label_len >= 64 {
            return Err(MiscError::InvalidDnsName {
                reason: format!("invalid label length: {}", label_len),
            }
            .into());
        }
        if pos + 1 + label_len >= 128 {
            return Err(MiscError::InvalidDnsName {
                reason: format!("domain name too long: {}", domain),
            }
            .into());
        }
        name.data[pos] = label_len as u8;
        pos += 1;
        name.data[pos..pos + label_len].copy_from_slice(label_bytes);
        pos += label_len;
    }

    // Terminating zero byte
    if pos < 128 {
        name.data[pos] = 0;
    }

    Ok(name)
}

/// Convert DNS wire format back to a human-readable domain name.
fn wire_format_to_domain(name: &DnsName) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos: usize = 0;

    loop {
        if pos >= 128 {
            break;
        }
        let label_len = name.data[pos] as usize;
        if label_len == 0 {
            break;
        }
        if label_len >= 64 || pos + 1 + label_len > 128 {
            return None;
        }
        pos += 1;
        let label = core::str::from_utf8(&name.data[pos..pos + label_len]).ok()?;
        labels.push(label.to_string());
        pos += label_len;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}
