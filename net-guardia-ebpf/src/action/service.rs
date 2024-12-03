use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap};
use net_guardia_common::model::event::{IPv4Event, IPv6Event};
use net_guardia_common::model::http_method::EbpfHttpMethod;
use net_guardia_common::model::ip_address::{EbpfAddrPortV4, EbpfAddrPortV6, IPv4, IPv6};
use net_guardia_common::model::placeholder::PlaceHolder;
use net_guardia_common::MAX_RULES;
use network_types::eth::EthHdr;
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;

#[map]
static IPV4_HTTP_SERVICE: HashMap<EbpfAddrPortV4, EbpfHttpMethod> =
    HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static IPV6_HTTP_SERVICE: HashMap<EbpfAddrPortV6, EbpfHttpMethod> =
    HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static SSH_WHITE_LIST_ONLY: Array<PlaceHolder> = Array::with_max_entries(1, 0);
#[map]
static IPV4_SSH_SERVICE: HashMap<EbpfAddrPortV4, PlaceHolder> =
    HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static IPV6_SSH_SERVICE: HashMap<EbpfAddrPortV6, PlaceHolder> =
    HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static IPV4_SSH_WHITE_LIST: HashMap<IPv4, PlaceHolder> = HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static IPV6_SSH_WHITE_LIST: HashMap<IPv6, PlaceHolder> = HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static IPV4_SSH_BLACK_LIST: HashMap<IPv4, PlaceHolder> = HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static IPV6_SSH_BLACK_LIST: HashMap<IPv6, PlaceHolder> = HashMap::with_max_entries(MAX_RULES, 0);

pub fn ipv4_service_rule_violation(start: usize, end: usize, event: &IPv4Event) -> bool {
    let protocol = event.protocol;
    let source = event.get_source();
    let destination = event.get_destination();
    ipv4_http_service_violation(start, end, &protocol, &destination)
        || ipv4_ssh_service_violation(&source, &destination)
}

pub fn ipv6_service_rule_violation(start: usize, end: usize, event: &IPv6Event) -> bool {
    let protocol = event.protocol;
    let source = event.get_source();
    let destination = event.get_destination();
    ipv6_http_service_violation(start, end, &protocol, &destination)
        || ipv6_ssh_service_violation(&source, &destination)
}

#[inline(always)]
fn ipv4_http_service_violation(
    start: usize,
    end: usize,
    protocol: &IpProto,
    destination: &EbpfAddrPortV4,
) -> bool {
    match protocol {
        IpProto::Tcp => unsafe {
            let offset = size_of::<EthHdr>() + size_of::<Ipv4Hdr>();
            let tcp_header = &*((start + offset) as *const TcpHdr);
            if tcp_header.syn() != 0 || tcp_header.rst() != 0 || tcp_header.fin() != 0 {
                return false;
            }
            if tcp_header.psh() == 0 || tcp_header.ack() == 0 {
                return false;
            }
            match IPV4_HTTP_SERVICE.get_ptr_mut(destination) {
                Some(allow_method) => match get_http_request_method(start, end, offset) {
                    Some(http_method) => *allow_method & http_method == 0,
                    None => true,
                },
                None => false,
            }
        },
        _ => false,
    }
}

#[inline(always)]
fn ipv6_http_service_violation(
    start: usize,
    end: usize,
    protocol: &IpProto,
    destination: &EbpfAddrPortV6,
) -> bool {
    match protocol {
        IpProto::Tcp => unsafe {
            let offset = size_of::<EthHdr>() + size_of::<Ipv6Hdr>();
            let tcp_header = &*((start + offset) as *const TcpHdr);
            if tcp_header.syn() != 0 || tcp_header.rst() != 0 || tcp_header.fin() != 0 {
                return false;
            }
            if tcp_header.psh() == 0 || tcp_header.ack() == 0 {
                return false;
            }
            match IPV6_HTTP_SERVICE.get_ptr_mut(destination) {
                Some(allow_method) => match get_http_request_method(start, end, offset) {
                    Some(http_method) => *allow_method & http_method == 0,
                    None => true,
                },
                None => false,
            }
        },
        _ => false,
    }
}

#[inline(always)]
fn get_http_request_method(start: usize, end: usize, offset: usize) -> Option<EbpfHttpMethod> {
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
fn ipv4_ssh_service_violation(source: &EbpfAddrPortV4, destination: &EbpfAddrPortV4) -> bool {
    unsafe {
        if IPV4_SSH_SERVICE.get(destination).is_some() {
            if SSH_WHITE_LIST_ONLY.get(0).is_some() {
                IPV4_SSH_WHITE_LIST.get(&source[0]).is_none()
            } else {
                IPV4_SSH_BLACK_LIST.get(&source[0]).is_some()
            }
        } else {
            false
        }
    }
}

#[inline(always)]
fn ipv6_ssh_service_violation(source_ip: &EbpfAddrPortV6, destination: &EbpfAddrPortV6) -> bool {
    unsafe {
        if IPV6_SSH_SERVICE.get(destination).is_some() {
            if SSH_WHITE_LIST_ONLY.get(0).is_some() {
                IPV6_SSH_WHITE_LIST.get(&source_ip[0]).is_none()
            } else {
                IPV6_SSH_BLACK_LIST.get(&source_ip[0]).is_some()
            }
        } else {
            false
        }
    }
}
