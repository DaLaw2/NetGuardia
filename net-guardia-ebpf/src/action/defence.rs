use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, LruHashMap};
use net_guardia_common::model::ip_address::{EbpfAddrPortV4, EbpfAddrPortV6, IPv4, IPv6};
use net_guardia_common::{MAX_PORT_ACCESS, MAX_RULES};
use net_guardia_common::model::event::{IPv4Event, IPv6Event};
use net_guardia_common::model::placeholder::PlaceHolder;

#[map]
static PORT_SCAN_IPV4: LruHashMap<IPv4, [u16; MAX_PORT_ACCESS]> =
    LruHashMap::with_max_entries(1000, 0);
#[map]
static PORT_SCAN_IPV6: LruHashMap<IPv6, [u16; MAX_PORT_ACCESS]> =
    LruHashMap::with_max_entries(1000, 0);
#[map]
static LAST_UPDATE_IPV4: LruHashMap<IPv4, u64> = LruHashMap::with_max_entries(1000, 0);
#[map]
static LAST_UPDATE_IPV6: LruHashMap<IPv6, u64> = LruHashMap::with_max_entries(1000, 0);
#[map]
static SCANNER_IPV4: HashMap<IPv4, PlaceHolder> = HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static SCANNER_IPV6: HashMap<IPv6, PlaceHolder> = HashMap::with_max_entries(MAX_RULES, 0);

pub fn is_attack_ipv4(event: &IPv4Event) -> bool {
    port_scan_ipv4(event)
}

pub fn is_attack_ipv6(event: &IPv6Event) -> bool {
    port_scan_ipv6(event)
}

fn port_scan_ipv4(event: &IPv4Event) -> bool {
    unsafe {
        let ip = &event.source_ip;
        let port = &event.source_port;
        if SCANNER_IPV4.get(ip).is_some() {
            return true;
        }
        if let Some(last_update) = LAST_UPDATE_IPV4.get(ip) {
            if event.timestamp - *last_update > 60_000_000_000 {
                let _ = PORT_SCAN_IPV4.remove(ip);
            }
        }
        if let Some(ports) = PORT_SCAN_IPV4.get_ptr_mut(ip) {
            for i in 0..MAX_PORT_ACCESS {
                let ports = &mut *ports;
                if ports[i] == *port {
                    return false;
                }
                if ports[i] == 0 {
                    ports[i] = *port;
                    return false;
                }
            }
            let _ = SCANNER_IPV4.insert(&ip, &0_u8, 0);
            true
        } else {
            true
        }
    }
}

fn port_scan_ipv6(event: &IPv6Event) -> bool {
    unsafe {
        let ip = &event.source_ip;
        let port = &event.source_port;
        if SCANNER_IPV6.get(ip).is_some() {
            return true;
        }
        if let Some(last_update) = LAST_UPDATE_IPV6.get(ip) {
            if event.timestamp - *last_update > 60_000_000_000 {
                let _ = PORT_SCAN_IPV6.remove(ip);
            }
        }
        if let Some(ports) = PORT_SCAN_IPV6.get_ptr_mut(ip) {
            for i in 0..MAX_PORT_ACCESS {
                let ports = &mut *ports;
                if ports[i] == *port {
                    return false;
                }
                if ports[i] == 0 {
                    ports[i] = *port;
                    return false;
                }
            }
            let _ = SCANNER_IPV6.insert(&ip, &0_u8, 0);
            true
        } else {
            true
        }
    }
}