use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap};
use common::define::offset::*;
use common::define::setting::MAX_RULES;
use common::model::event::{IPv4Event, IPv6Event};
use common::model::http_method::HttpMethodBitmap;
use common::model::ip_address::*;
use common::model::placeholder::PlaceHolder;
use network_types::ip::IpProto;
use network_types::tcp::TcpHdr;

#[map]
static IPV4_HTTP_SERVICE: HashMap<AddrPortV4, HttpMethodBitmap> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV6_HTTP_SERVICE: HashMap<AddrPortV6, HttpMethodBitmap> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static SSH_WHITE_LIST_ENABLE: Array<PlaceHolder> = Array::with_max_entries(1, 0);
#[map]
static IPV4_SSH_SERVICE: HashMap<AddrPortV4, PlaceHolder> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV6_SSH_SERVICE: HashMap<AddrPortV6, PlaceHolder> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV4_SSH_WHITE_LIST: HashMap<IPv4, PlaceHolder> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV6_SSH_WHITE_LIST: HashMap<IPv6, PlaceHolder> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV4_SSH_BLACK_LIST: HashMap<IPv4, PlaceHolder> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV6_SSH_BLACK_LIST: HashMap<IPv6, PlaceHolder> = HashMap::with_max_entries(MAX_RULES as u32, 0);

pub fn ipv4_service_rule_violation(start: usize, end: usize, event: &IPv4Event) -> bool {
    let protocol = event.protocol;
    let source = event.source_addr();
    let destination = event.destination_addr();
    ipv4_http_service_violation(start, end, &protocol, &destination)
        || ipv4_ssh_service_violation(&source, &destination)
}

pub fn ipv6_service_rule_violation(start: usize, end: usize, event: &IPv6Event) -> bool {
    let protocol = event.protocol;
    let source = event.source_addr();
    let destination = event.destination_addr();
    ipv6_http_service_violation(start, end, &protocol, &destination)
        || ipv6_ssh_service_violation(&source, &destination)
}

#[inline(always)]
fn ipv4_http_service_violation(start: usize, end: usize, protocol: &IpProto, destination: &AddrPortV4) -> bool {
    match IPV4_HTTP_SERVICE.get_ptr_mut(destination) {
        Some(allow_method) => {
            if !matches!(protocol, IpProto::Tcp) {
                return false;
            }
            unsafe {
                if start + IPV4_TCP_HEADER_END > end {
                    return false;
                }
                let tcp_header = &*((start + IPV4_TCP_HEADER_START) as *const TcpHdr);
                if tcp_header.syn() != 0 || tcp_header.rst() != 0 || tcp_header.fin() != 0 {
                    return false;
                }
                if tcp_header.psh() == 0 || tcp_header.ack() == 0 {
                    return false;
                }
                let doff = tcp_header.doff();
                if doff < 5 || doff > 15 {
                    return false;
                }
                let tcp_header_len = (doff * 4) as usize;
                let tcp_payload_start = IPV4_TCP_HEADER_END + tcp_header_len;
                match get_http_request_method(start, end, tcp_payload_start) {
                    Some(http_method) => *allow_method & http_method == 0,
                    None => true,
                }
            }
        }
        None => false,
    }
}

#[inline(always)]
fn ipv6_http_service_violation(start: usize, end: usize, protocol: &IpProto, destination: &AddrPortV6) -> bool {
    match IPV6_HTTP_SERVICE.get_ptr_mut(destination) {
        Some(allow_method) => {
            if !matches!(protocol, IpProto::Tcp) {
                return false;
            }
            unsafe {
                if start + IPV6_TCP_HEADER_END > end {
                    return false;
                }
                let tcp_header = &*((start + IPV6_TCP_HEADER_START) as *const TcpHdr);
                if tcp_header.syn() != 0 || tcp_header.rst() != 0 || tcp_header.fin() != 0 {
                    return false;
                }
                if tcp_header.psh() == 0 || tcp_header.ack() == 0 {
                    return false;
                }
                let doff = tcp_header.doff();
                if doff < 5 || doff > 15 {
                    return false;
                }
                let tcp_header_len = (doff * 4) as usize;
                let tcp_payload_start = IPV6_TCP_HEADER_END + tcp_header_len;
                match get_http_request_method(start, end, tcp_payload_start) {
                    Some(http_method) => *allow_method & http_method == 0,
                    None => true,
                }
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
    let data = unsafe { core::slice::from_raw_parts((start + offset) as *const u8, 8) };
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
            if SSH_WHITE_LIST_ENABLE.get(0).is_some() {
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
fn ipv6_ssh_service_violation(source_ip: &AddrPortV6, destination: &AddrPortV6) -> bool {
    unsafe {
        if IPV6_SSH_SERVICE.get(destination).is_some() {
            if SSH_WHITE_LIST_ENABLE.get(0).is_some() {
                IPV6_SSH_WHITE_LIST.get(&source_ip.ip()).is_none()
            } else {
                IPV6_SSH_BLACK_LIST.get(&source_ip.ip()).is_some()
            }
        } else {
            false
        }
    }
}
