use core::str;

use dashmap::DashSet;
use net_guardia_abi::model::dns_name::DnsName;

use crate::common::error::Error;
use crate::domain::data_plane::error::EbpfError;
use crate::interface::data_plane::dns_filter_api::DnsFilterPort;
use crate::interface::data_plane::dns_query_filter::DnsQueryFilter;

const ETH_HEADER_LEN: usize = 14;
const ETH_TYPE_IPV4: u16 = 0x0800;
const ETH_TYPE_IPV6: u16 = 0x86DD;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const UDP_PROTOCOL_NUMBER: u8 = 17;
const DNS_PORT: u16 = 53;
const DNS_HEADER_LEN: usize = 12;
const DNS_RESPONSE_FLAG: u8 = 0x80;
const DNS_NAME_CAPACITY: usize = 128;
const DNS_LABEL_CAPACITY: usize = 64;
const DNS_MAX_LABELS: usize = 32;

pub struct DnsFilter {
    blacklist: DashSet<DnsName>,
}

impl DnsFilter {
    pub fn new() -> Self {
        Self {
            blacklist: DashSet::new(),
        }
    }

    pub fn add_domain(&self, domain: &str) -> Result<(), Error> {
        let name = domain_to_wire_format(domain)?;
        self.blacklist.insert(name);
        Ok(())
    }

    pub fn validate_domain(&self, domain: &str) -> Result<(), Error> {
        domain_to_wire_format(domain).map(|_| ())
    }

    pub fn remove_domain(&self, domain: &str) -> Result<(), Error> {
        let name = domain_to_wire_format(domain)?;
        self.blacklist.remove(&name);
        Ok(())
    }

    pub fn list_domains(&self) -> Vec<String> {
        self.blacklist
            .iter()
            .filter_map(|entry| wire_format_to_domain(&entry))
            .collect()
    }

    pub fn is_query_blacklisted(&self, raw: &[u8]) -> bool {
        match Self::parse_query_name(raw) {
            Some((name, name_len)) => self.is_blacklisted(&name, name_len),
            None => false,
        }
    }

    pub fn is_blacklisted(&self, name: &DnsName, name_len: usize) -> bool {
        if self.blacklist.is_empty() {
            return false;
        }
        if self.blacklist.contains(name) {
            return true;
        }
        let mut offset: usize = 0;
        loop {
            if offset >= name_len || offset >= DNS_NAME_CAPACITY {
                break;
            }
            let lbl = name.data[offset] as usize;
            if lbl == 0 {
                break;
            }
            offset += 1 + lbl;
            if offset >= name_len || offset >= DNS_NAME_CAPACITY {
                break;
            }
            if name.data[offset] == 0 {
                break;
            }

            let mut parent = DnsName::zeroed();
            let remaining = name_len - offset;
            parent.data[..remaining.min(DNS_NAME_CAPACITY)]
                .copy_from_slice(&name.data[offset..offset + remaining.min(DNS_NAME_CAPACITY)]);
            if self.blacklist.contains(&parent) {
                return true;
            }
        }
        false
    }

    pub fn parse_query_name(raw: &[u8]) -> Option<(DnsName, usize)> {
        if raw.len() < ETH_HEADER_LEN {
            return None;
        }

        let eth_type = u16::from_be_bytes([raw[12], raw[13]]);
        let (l3_header_len, l3_payload_end) = match eth_type {
            ETH_TYPE_IPV4 => {
                if raw.len() < ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN {
                    return None;
                }
                let ihl = (raw[14] & 0x0F) as usize * 4;
                if ihl < IPV4_MIN_HEADER_LEN {
                    return None;
                }
                let total_len = u16::from_be_bytes([raw[16], raw[17]]) as usize;
                if total_len < ihl || raw.len() < ETH_HEADER_LEN + total_len {
                    return None;
                }
                if raw[ETH_HEADER_LEN + 9] != UDP_PROTOCOL_NUMBER {
                    return None;
                }
                (ihl, ETH_HEADER_LEN + total_len)
            }
            ETH_TYPE_IPV6 => {
                if raw.len() < ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN {
                    return None;
                }
                if raw[ETH_HEADER_LEN + 6] != UDP_PROTOCOL_NUMBER {
                    return None;
                }
                let payload_len = u16::from_be_bytes([raw[18], raw[19]]) as usize;
                if raw.len() < ETH_HEADER_LEN + IPV6_HEADER_LEN + payload_len {
                    return None;
                }
                (IPV6_HEADER_LEN, ETH_HEADER_LEN + IPV6_HEADER_LEN + payload_len)
            }
            _ => return None,
        };

        let udp_start = ETH_HEADER_LEN + l3_header_len;
        if udp_start + UDP_HEADER_LEN > l3_payload_end {
            return None;
        }

        let dst_port = u16::from_be_bytes([raw[udp_start + 2], raw[udp_start + 3]]);
        if dst_port != DNS_PORT {
            return None;
        }

        let udp_len = u16::from_be_bytes([raw[udp_start + 4], raw[udp_start + 5]]) as usize;
        if udp_len < UDP_HEADER_LEN || udp_start + udp_len > l3_payload_end {
            return None;
        }
        let udp_payload_end = udp_start + udp_len;

        let dns_header_offset = udp_start + UDP_HEADER_LEN;
        if dns_header_offset + DNS_HEADER_LEN > udp_payload_end {
            return None;
        }

        if raw[dns_header_offset + 2] & DNS_RESPONSE_FLAG != 0 {
            return None;
        }

        if raw[dns_header_offset + 4] == 0 && raw[dns_header_offset + 5] == 0 {
            return None;
        }

        let dns_qname_offset = dns_header_offset + DNS_HEADER_LEN;
        if dns_qname_offset >= udp_payload_end {
            return None;
        }

        let mut name = DnsName::zeroed();
        let mut pos = dns_qname_offset;
        let mut out: usize = 0;
        for _ in 0..DNS_MAX_LABELS {
            if pos >= udp_payload_end {
                return None;
            }
            let ll = raw[pos] as usize;
            if ll == 0 {
                if out < DNS_NAME_CAPACITY {
                    name.data[out] = 0;
                }
                return Some((name, out + 1));
            }
            if ll >= DNS_LABEL_CAPACITY {
                return None;
            }
            if out + 1 + ll >= DNS_NAME_CAPACITY {
                return None;
            }
            if pos + 1 + ll > udp_payload_end {
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

impl DnsFilterPort for DnsFilter {
    fn list_domains(&self) -> Vec<String> {
        self.list_domains()
    }

    fn validate_domain(&self, domain: &str) -> Result<(), Error> {
        self.validate_domain(domain)
    }

    fn add_domain(&self, domain: &str) -> Result<(), Error> {
        self.add_domain(domain)
    }

    fn remove_domain(&self, domain: &str) -> Result<(), Error> {
        self.remove_domain(domain)
    }
}

impl DnsQueryFilter for DnsFilter {
    fn is_query_blacklisted(&self, raw: &[u8]) -> bool {
        self.is_query_blacklisted(raw)
    }
}

fn domain_to_wire_format(domain: &str) -> Result<DnsName, Error> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    let mut name = DnsName::zeroed();
    let mut pos: usize = 0;

    for label in domain.split('.') {
        let label_bytes = label.as_bytes();
        let label_len = label_bytes.len();
        if label_len == 0 || label_len >= 64 {
            return Err(EbpfError::DnsLabelOutOfRange(label_len).into());
        }
        if !is_valid_domain_label(label_bytes) {
            return Err(EbpfError::InvalidDnsDomain(format!("invalid label '{label}'")).into());
        }
        if pos + 1 + label_len >= 128 {
            return Err(EbpfError::DnsDomainTooLong(domain).into());
        }
        name.data[pos] = label_len as u8;
        pos += 1;
        name.data[pos..pos + label_len].copy_from_slice(label_bytes);
        pos += label_len;
    }
    if pos < 128 {
        name.data[pos] = 0;
    }

    Ok(name)
}

fn is_valid_domain_label(label: &[u8]) -> bool {
    label.first().is_some_and(|byte| byte.is_ascii_alphanumeric())
        && label.last().is_some_and(|byte| byte.is_ascii_alphanumeric())
        && label.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn wire_format_to_domain(name: &DnsName) -> Option<String> {
    let mut domain = String::new();
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
        let label = str::from_utf8(&name.data[pos..pos + label_len]).ok()?;
        if !domain.is_empty() {
            domain.push('.');
        }
        domain.push_str(label);
        pos += label_len;
    }

    if domain.is_empty() { None } else { Some(domain) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn append_dns_query(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a', b'm', b'p',
            b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ]);
    }

    fn ipv4_dns_query_frame() -> Vec<u8> {
        let mut frame = vec![0_u8; 14];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x00, 64, 17, 0x00, 0x00, 192, 0, 2, 1, 198, 51, 100, 53,
        ]);
        frame.extend_from_slice(&[0xc0, 0x00, 0x00, 0x35, 0x00, 0x25, 0x00, 0x00]);
        append_dns_query(&mut frame);
        frame
    }

    fn malformed_short_ihl_frame_that_looks_like_dns_at_wrong_offset() -> Vec<u8> {
        let mut frame = vec![0_u8; 64];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x40;
        frame[23] = 17;
        frame[16] = 0x00;
        frame[17] = 0x35;
        frame[26] = 0x00;
        frame[27] = 0x01;
        let mut dns = Vec::new();
        append_dns_query(&mut dns);
        frame[22..22 + dns.len()].copy_from_slice(&dns);
        frame
    }

    fn ipv4_dns_query_with_ip_total_len(total_len: u16) -> Vec<u8> {
        let mut frame = ipv4_dns_query_frame();
        frame[16..18].copy_from_slice(&total_len.to_be_bytes());
        frame
    }

    fn ipv4_dns_query_with_udp_len(udp_len: u16) -> Vec<u8> {
        let mut frame = ipv4_dns_query_frame();
        let udp_start = 14 + 20;
        frame[udp_start + 4..udp_start + 6].copy_from_slice(&udp_len.to_be_bytes());
        frame
    }

    fn ipv6_dns_query_frame() -> Vec<u8> {
        let mut frame = vec![0_u8; 14];
        frame[12] = 0x86;
        frame[13] = 0xdd;
        frame.extend_from_slice(&[
            0x60, 0x00, 0x00, 0x00, 0x00, 0x25, 17, 64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ]);
        frame.extend_from_slice(&[0xc0, 0x00, 0x00, 0x35, 0x00, 0x25, 0x00, 0x00]);
        append_dns_query(&mut frame);
        frame
    }

    fn ipv6_dns_query_with_payload_len(payload_len: u16) -> Vec<u8> {
        let mut frame = ipv6_dns_query_frame();
        frame[18..20].copy_from_slice(&payload_len.to_be_bytes());
        frame
    }

    #[test]
    fn parse_query_name_accepts_ipv4_dns_query() {
        let frame = ipv4_dns_query_frame();

        let (name, len) = DnsFilter::parse_query_name(&frame).expect("valid DNS query");

        assert_eq!(wire_format_to_domain(&name).as_deref(), Some("example.com"));
        assert_eq!(len, 13);
    }

    #[test]
    fn parse_query_name_rejects_ipv4_ihl_shorter_than_minimum() {
        let frame = malformed_short_ihl_frame_that_looks_like_dns_at_wrong_offset();

        assert!(DnsFilter::parse_query_name(&frame).is_none());
    }

    #[test]
    fn parse_query_name_rejects_dns_beyond_ipv4_total_length() {
        let frame = ipv4_dns_query_with_ip_total_len(28);

        assert!(DnsFilter::parse_query_name(&frame).is_none());
    }

    #[test]
    fn parse_query_name_rejects_dns_beyond_udp_length() {
        let frame = ipv4_dns_query_with_udp_len(8);

        assert!(DnsFilter::parse_query_name(&frame).is_none());
    }

    #[test]
    fn parse_query_name_rejects_dns_beyond_ipv6_payload_length() {
        let frame = ipv6_dns_query_with_payload_len(8);

        assert!(DnsFilter::parse_query_name(&frame).is_none());
    }

    #[test]
    fn validate_domain_rejects_non_hostname_labels() {
        let filter = DnsFilter::new();

        for domain in ["bad domain.test", "bad_domain.test", "-bad.test", "bad-.test"] {
            assert!(
                matches!(
                    filter.validate_domain(domain),
                    Err(Error::Ebpf(EbpfError::InvalidDnsDomain { .. }))
                ),
                "{domain} should be rejected"
            );
        }
    }

    #[test]
    fn validate_domain_accepts_canonical_and_punycode_labels() {
        let filter = DnsFilter::new();

        filter.validate_domain("Example.COM.").expect("canonical domain");
        filter
            .validate_domain("xn--bcher-kva.example")
            .expect("punycode domain");
    }
}
