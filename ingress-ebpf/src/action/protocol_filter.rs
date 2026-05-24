use core::slice;

use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap};
use net_guardia_abi::define::setting::MAX_RULES;
use net_guardia_abi::define::tcp_flags::*;
use net_guardia_abi::model::empty::EmptyMapValue;
use net_guardia_abi::model::http_method::HttpMethodBitmap;
use net_guardia_abi::model::ip_address::*;
use net_guardia_abi::model::parsed_packet::ParsedPacket;
use network_types::ip::IpProto;

#[map]
static IPV4_HTTP_SERVICE: HashMap<AddrPortV4, HttpMethodBitmap> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV6_HTTP_SERVICE: HashMap<AddrPortV6, HttpMethodBitmap> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static SSH_WHITE_LIST_ENABLE: Array<EmptyMapValue> = Array::with_max_entries(1, 0);
#[map]
static IPV4_SSH_SERVICE: HashMap<AddrPortV4, EmptyMapValue> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV6_SSH_SERVICE: HashMap<AddrPortV6, EmptyMapValue> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV4_SSH_WHITE_LIST: HashMap<IPv4, EmptyMapValue> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV6_SSH_WHITE_LIST: HashMap<IPv6, EmptyMapValue> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV4_SSH_BLACK_LIST: HashMap<IPv4, EmptyMapValue> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV6_SSH_BLACK_LIST: HashMap<IPv6, EmptyMapValue> = HashMap::with_max_entries(MAX_RULES as u32, 0);

pub fn ipv4_service_rule_violation(start: usize, end: usize, pkt: &ParsedPacket) -> bool {
    let source = pkt.src_addr_v4();
    let destination = pkt.dst_addr_v4();
    http_service_violation(start, end, pkt, &IPV4_HTTP_SERVICE, &destination)
        || ipv4_ssh_service_violation(&source, &destination)
}

pub fn ipv6_service_rule_violation(start: usize, end: usize, pkt: &ParsedPacket) -> bool {
    let source = pkt.src_addr_v6();
    let destination = pkt.dst_addr_v6();
    http_service_violation(start, end, pkt, &IPV6_HTTP_SERVICE, &destination)
        || ipv6_ssh_service_violation(&source, &destination)
}

#[inline(always)]
fn http_service_violation<K>(
    start: usize,
    end: usize,
    pkt: &ParsedPacket,
    map: &HashMap<K, HttpMethodBitmap>,
    destination: &K,
) -> bool {
    match map.get_ptr_mut(destination) {
        Some(allow_method) => {
            if pkt.protocol != IpProto::Tcp as u8 {
                return false;
            }
            if pkt.tcp_flags & (TCP_SYN | TCP_RST | TCP_FIN) != 0 {
                return false;
            }
            if pkt.tcp_flags & (TCP_PSH | TCP_ACK) != (TCP_PSH | TCP_ACK) {
                return false;
            }
            if start + 15 > end {
                return false;
            }
            let l4_offset = match pkt.ip_version {
                value if value == IpVersion::V4.as_u8() => {
                    14 + ((unsafe { *((start + 14) as *const u8) } & 0x0F) as usize) * 4
                }
                value if value == IpVersion::V6.as_u8() => 14 + 40,
                _ => return false,
            };
            if start + l4_offset + 13 > end {
                return false;
            }
            let doff = (unsafe { *((start + l4_offset + 12) as *const u8) } >> 4) as usize;
            if !(5..=15).contains(&doff) {
                return false;
            }
            let payload_offset = l4_offset + doff * 4;
            match get_http_request_method(start, end, payload_offset) {
                Some(http_method) => unsafe { *allow_method & http_method == 0 },
                None => false,
            }
        }
        None => false,
    }
}

#[inline(always)]
fn get_http_request_method(start: usize, end: usize, offset: usize) -> Option<HttpMethodBitmap> {
    if start + offset + 8 > end {
        return None;
    }
    let data = unsafe { slice::from_raw_parts((start + offset) as *const u8, 8) };
    match &data[..4] {
        b"GET " => Some(1 << 0),
        b"POST" if &data[4..5] == b" " => Some(1 << 1),
        b"PUT " => Some(1 << 2),
        b"DELE" if &data[4..7] == b"TE " => Some(1 << 3),
        b"HEAD" if &data[4..5] == b" " => Some(1 << 4),
        b"OPTI" if &data[4..8] == b"ONS " => Some(1 << 5),
        b"PATC" if &data[4..6] == b"H " => Some(1 << 6),
        b"TRAC" if &data[4..6] == b"E " => Some(1 << 7),
        b"CONN" if &data[4..8] == b"ECT " => Some(1 << 8),
        _ => None,
    }
}

#[inline(always)]
fn ipv4_ssh_service_violation(source: &AddrPortV4, destination: &AddrPortV4) -> bool {
    unsafe {
        if IPV4_SSH_SERVICE.get(destination).is_some() {
            if matches!(SSH_WHITE_LIST_ENABLE.get(0), Some(&v) if v != 0) {
                IPV4_SSH_WHITE_LIST.get(&source.ip()).is_none()
            } else {
                IPV4_SSH_BLACK_LIST.get(&source.ip()).is_some()
            }
        } else {
            false
        }
    }
}

#[inline(always)]
fn ipv6_ssh_service_violation(source: &AddrPortV6, destination: &AddrPortV6) -> bool {
    unsafe {
        if IPV6_SSH_SERVICE.get(destination).is_some() {
            if matches!(SSH_WHITE_LIST_ENABLE.get(0), Some(&v) if v != 0) {
                IPV6_SSH_WHITE_LIST.get(&source.ip()).is_none()
            } else {
                IPV6_SSH_BLACK_LIST.get(&source.ip()).is_some()
            }
        } else {
            false
        }
    }
}
