use aya_ebpf::maps::{Array, HashMap};
use net_guardia_common::model::event::{IPv4Event, IPv6Event};
use net_guardia_common::model::http_method::EbpfHttpMethod;
use net_guardia_common::model::ip_address::{EbpfAddrPortV4, EbpfAddrPortV6, IPv4, IPv6};
use net_guardia_common::model::placeholder::PlaceHolder;
use net_guardia_common::MAX_RULES;

static HTTP_SERVICE_V4: HashMap<EbpfAddrPortV4, EbpfHttpMethod> =
    HashMap::with_max_entries(MAX_RULES, 0);
static HTTP_SERVICE_V6: HashMap<EbpfAddrPortV6, EbpfHttpMethod> =
    HashMap::with_max_entries(MAX_RULES, 0);

static SSH_WHITE_LIST_ONLY: Array<PlaceHolder> = Array::with_max_entries(1, 0);
static IPV4_SSH_SERVICE: HashMap<EbpfAddrPortV4, PlaceHolder> =
    HashMap::with_max_entries(MAX_RULES, 0);
static IPV6_SSH_SERVICE: HashMap<EbpfAddrPortV6, PlaceHolder> =
    HashMap::with_max_entries(MAX_RULES, 0);
static IPV4_SSH_WHITE_LIST: HashMap<IPv4, PlaceHolder> = HashMap::with_max_entries(MAX_RULES, 0);
static IPV6_SSH_WHITE_LIST: HashMap<IPv6, PlaceHolder> = HashMap::with_max_entries(MAX_RULES, 0);
static IPV4_SSH_BLACK_LIST: HashMap<IPv4, PlaceHolder> = HashMap::with_max_entries(MAX_RULES, 0);
static IPV6_SSH_BLACK_LIST: HashMap<IPv6, PlaceHolder> = HashMap::with_max_entries(MAX_RULES, 0);

pub fn ipv4_service_rule_violation(event: &IPv4Event, start: usize, end: usize, offset: usize) -> bool {
    let source = event.get_source();
    let destination = event.get_destination();
    ipv4_http_service_violation(&destination, start, end, offset) || ipv4_ssh_service_violation(&source, &destination)
}

pub fn ipv6_service_rule_violation(event: &IPv6Event, start: usize, end: usize, offset: usize) -> bool {
    let source = event.get_source();
    let destination = event.get_destination();
    ipv6_http_service_violation(&destination, start, end, offset) || ipv6_ssh_service_violation(&source, &destination)
}

#[inline(always)]
fn ipv4_http_service_violation(addr_port: &EbpfAddrPortV4, start: usize, end: usize, offset: usize) -> bool {
    match HTTP_SERVICE_V4.get_ptr_mut(addr_port) {
        Some(allow_method) => match get_http_request_method(start, end, offset) {
            Some(http_method) => unsafe { *allow_method & http_method == 0 },
            None => true,
        },
        None => false,
    }
}

#[inline(always)]
fn ipv6_http_service_violation(addr_port: &EbpfAddrPortV6, start: usize, end: usize, offset: usize) -> bool {
    match HTTP_SERVICE_V6.get_ptr_mut(addr_port) {
        Some(allow_method) => match get_http_request_method(start, end, offset) {
            Some(http_method) => unsafe { *allow_method & http_method == 0 },
            None => true,
        },
        None => false,
    }
}

#[inline(always)]
fn get_http_request_method(start: usize, end: usize, offset: usize) -> Option<EbpfHttpMethod> {
    if start + offset + 3 > end {
        return None;
    }
    let data = unsafe { core::slice::from_raw_parts((start + offset) as *const u8, 3) };
    match data {
        b"GET" => Some(1 << 0),
        b"POS" => Some(1 << 1),
        b"PUT" => Some(1 << 2),
        b"DEL" => Some(1 << 3),
        b"HEA" => Some(1 << 4),
        b"OPT" => Some(1 << 5),
        b"PAT" => Some(1 << 6),
        b"TRA" => Some(1 << 7),
        b"CON" => Some(1 << 8),
        _ => None,
    }
}

#[inline(always)]
fn ipv4_ssh_service_violation(source_ip: &EbpfAddrPortV4, destination: &EbpfAddrPortV4) -> bool {
    unsafe {
        if IPV4_SSH_SERVICE.get(destination).is_some() {
            if SSH_WHITE_LIST_ONLY.get(0).is_some() {
                IPV4_SSH_WHITE_LIST.get(&source_ip[0]).is_none()
            } else {
                IPV4_SSH_BLACK_LIST.get(&source_ip[0]).is_some()
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
