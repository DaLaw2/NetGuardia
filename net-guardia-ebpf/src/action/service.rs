use aya_ebpf::maps::HashMap;
use net_guardia_common::model::event::{IPv4Event, IPv6Event};
use net_guardia_common::model::http_method::EbpfHttpMethod;
use net_guardia_common::model::ip_address::{EbpfAddrPortV4, EbpfAddrPortV6};
use net_guardia_common::MAX_RULES;

static HTTP_SERVICE_V4: HashMap<EbpfAddrPortV4, EbpfHttpMethod> =
    HashMap::with_max_entries(MAX_RULES, 0);
static HTTP_SERVICE_V6: HashMap<EbpfAddrPortV6, EbpfHttpMethod> =
    HashMap::with_max_entries(MAX_RULES, 0);

pub fn ipv4_service_rule(event: &IPv4Event, start: usize, end: usize, offset: usize) -> bool {
    let destination = event.get_destination();
    ipv4_http_service(destination, start, end, offset)
}

pub fn ipv6_service_rule(event: &IPv6Event, start: usize, end: usize, offset: usize) -> bool {
    let destination = event.get_destination();
    ipv6_http_service(destination, start, end, offset)
}

#[inline(always)]
fn ipv4_http_service(addr_port: EbpfAddrPortV4, start: usize, end: usize, offset: usize) -> bool {
    match HTTP_SERVICE_V4.get_ptr_mut(&addr_port) {
        Some(allow_method) => match get_http_request_method(start, end, offset) {
            Some(http_method) => unsafe { *allow_method & http_method != 0 },
            None => false,
        },
        None => true,
    }
}

#[inline(always)]
fn ipv6_http_service(addr_port: EbpfAddrPortV6, start: usize, end: usize, offset: usize) -> bool {
    match HTTP_SERVICE_V6.get_ptr_mut(&addr_port) {
        Some(allow_method) => match get_http_request_method(start, end, offset) {
            Some(http_method) => unsafe { *allow_method & http_method != 0 },
            None => false,
        },
        None => true,
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
