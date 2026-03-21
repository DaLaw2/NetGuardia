use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use common::define::offset::*;
use common::define::setting::MAX_RULES;
use common::model::dns_name::DnsName;
use common::model::parsed_packet::ParsedPacket;
use common::model::placeholder::PlaceHolder;
use network_types::ip::IpProto;

const DNS_PORT: u16 = 53;
const DNS_HEADER_SIZE: usize = 12;
const DNS_MAX_NAME_LEN: usize = 128;
const DNS_MAX_LABELS: usize = 32;

#[map]
static DNS_BLACKLIST: HashMap<DnsName, PlaceHolder> = HashMap::with_max_entries(MAX_RULES as u32, 0);

/// Check if a packet is a DNS query to a blacklisted domain.
/// Works for both IPv4 and IPv6 UDP packets destined to port 53.
#[inline(always)]
pub fn is_dns_blacklisted(start: usize, end: usize, pkt: &ParsedPacket) -> bool {
    // Must be UDP protocol
    if !matches!(pkt.protocol, IpProto::Udp) {
        return false;
    }

    // Must be destined to DNS port 53
    if pkt.dst_port != DNS_PORT {
        return false;
    }

    // Determine UDP header start based on IP version
    let udp_header_start = match pkt.ip_version {
        4 => IPV4_UDP_HEADER_START,
        6 => IPV6_UDP_HEADER_START,
        _ => return false,
    };

    // DNS payload starts after UDP header (8 bytes) + DNS header (12 bytes)
    let dns_header_offset = udp_header_start + 8;
    let dns_payload_offset = dns_header_offset + DNS_HEADER_SIZE;

    // Bounds check: ensure we can read the DNS header
    if start + dns_header_offset + 3 > end {
        return false;
    }

    // Check QR bit (byte 2 of DNS header, bit 7) - must be 0 (query)
    let flags_byte = unsafe { *((start + dns_header_offset + 2) as *const u8) };
    if flags_byte & 0x80 != 0 {
        return false;
    }

    // Bounds check: ensure DNS payload starts within packet
    if start + dns_payload_offset >= end {
        return false;
    }

    // Extract DNS query name into DnsName buffer
    let mut name = DnsName::zeroed();
    let mut name_len: usize = 0;

    // Parse DNS wire format labels (bounded loop)
    let mut offset = dns_payload_offset;
    let mut i: usize = 0;
    while i < DNS_MAX_LABELS {
        // Bounds check for label length byte
        if start + offset >= end {
            return false;
        }

        let label_len = unsafe { *((start + offset) as *const u8) } as usize;

        // Zero-length label marks end of name
        if label_len == 0 {
            // Store the terminating zero
            if name_len < DNS_MAX_NAME_LEN {
                name.data[name_len] = 0;
                name_len += 1;
            }
            break;
        }

        // Reject compression pointers (top 2 bits set) and oversized labels
        if label_len >= 64 {
            return false;
        }

        // Check if adding this label would exceed our buffer
        // We need: label_len_byte (1) + label_data (label_len) + at least terminator (1)
        if name_len + 1 + label_len >= DNS_MAX_NAME_LEN {
            return false;
        }

        // Bounds check for the full label in the packet
        if start + offset + 1 + label_len > end {
            return false;
        }

        // Store label length byte
        name.data[name_len] = label_len as u8;
        name_len += 1;

        // Copy label bytes, converting to lowercase
        let mut j: usize = 0;
        while j < label_len {
            if name_len >= DNS_MAX_NAME_LEN {
                return false;
            }
            let mut b = unsafe { *((start + offset + 1 + j) as *const u8) };
            // ASCII uppercase to lowercase
            if b >= b'A' && b <= b'Z' {
                b += 32;
            }
            name.data[name_len] = b;
            name_len += 1;
            j += 1;
        }

        offset += 1 + label_len;
        i += 1;
    }

    // Check exact domain match
    if unsafe { DNS_BLACKLIST.get(&name).is_some() } {
        return true;
    }

    // Check parent domains for subdomain matching.
    // For "sub.example.com" (\x03sub\x07example\x03com\x00),
    // we also check "example.com" (\x07example\x03com\x00).
    // We do this by advancing past successive labels.
    let mut parent_offset: usize = 0;
    let mut k: usize = 0;
    while k < DNS_MAX_LABELS {
        if parent_offset >= name_len {
            break;
        }
        let lbl = name.data[parent_offset] as usize;
        if lbl == 0 {
            break;
        }
        // Skip past this label: length byte + label bytes
        parent_offset += 1 + lbl;

        if parent_offset >= name_len {
            break;
        }

        // If the next byte is the terminator, no parent domain to check
        if name.data[parent_offset] == 0 {
            break;
        }

        // Build a parent DnsName from parent_offset onward
        let mut parent = DnsName::zeroed();
        let remaining = name_len - parent_offset;
        let mut m: usize = 0;
        while m < remaining && m < DNS_MAX_NAME_LEN {
            parent.data[m] = name.data[parent_offset + m];
            m += 1;
        }

        if unsafe { DNS_BLACKLIST.get(&parent).is_some() } {
            return true;
        }

        k += 1;
    }

    false
}
