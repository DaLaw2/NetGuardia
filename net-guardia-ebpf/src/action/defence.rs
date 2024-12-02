use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, LruHashMap};
use net_guardia_common::model::ip_address::{IPv4, IPv6};
use net_guardia_common::{MAX_PORT_ACCESS, MAX_RULES};
use net_guardia_common::model::event::{IPv4Event, IPv6Event};
use net_guardia_common::model::placeholder::PlaceHolder;

#[map]
static IPV4_PORT_SCAN: LruHashMap<IPv4, [u16; MAX_PORT_ACCESS]> =
    LruHashMap::with_max_entries(1000, 0);
#[map]
static IPV6_PORT_SCAN: LruHashMap<IPv6, [u16; MAX_PORT_ACCESS]> =
    LruHashMap::with_max_entries(1000, 0);
#[map]
static IPV4_LAST_UPDATE: LruHashMap<IPv4, u64> = LruHashMap::with_max_entries(1000, 0);
#[map]
static IPV6_LAST_UPDATE: LruHashMap<IPv6, u64> = LruHashMap::with_max_entries(1000, 0);
#[map]
static IPV4_SCANNER_LIST: HashMap<IPv4, PlaceHolder> = HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static IPV6_SCANNER_LIST: HashMap<IPv6, PlaceHolder> = HashMap::with_max_entries(MAX_RULES, 0);

pub fn ipv4_is_attack(event: &IPv4Event) -> bool {
    ipv4_port_scan(event)
}

pub fn ipv6_is_attack(event: &IPv6Event) -> bool {
    ipv6_port_scan(event)
}

fn ipv4_port_scan(event: &IPv4Event) -> bool {
    unsafe {
        let ip = &event.source_ip;
        let port = &event.source_port;
        if IPV4_SCANNER_LIST.get(ip).is_some() {
            return true;
        }
        if let Some(last_update) = IPV4_LAST_UPDATE.get(ip) {
            if event.timestamp - *last_update > 60_000_000_000 {
                let _ = IPV4_PORT_SCAN.remove(ip);
            }
        }
        if let Some(ports) = IPV4_PORT_SCAN.get_ptr_mut(ip) {
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
            let _ = IPV4_SCANNER_LIST.insert(&ip, &0_u8, 0);
            true
        } else {
            true
        }
    }
}

fn ipv6_port_scan(event: &IPv6Event) -> bool {
    unsafe {
        let ip = &event.source_ip;
        let port = &event.source_port;
        if IPV6_SCANNER_LIST.get(ip).is_some() {
            return true;
        }
        if let Some(last_update) = IPV6_LAST_UPDATE.get(ip) {
            if event.timestamp - *last_update > 60_000_000_000 {
                let _ = IPV6_PORT_SCAN.remove(ip);
            }
        }
        if let Some(ports) = IPV6_PORT_SCAN.get_ptr_mut(ip) {
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
            let _ = IPV6_SCANNER_LIST.insert(&ip, &0_u8, 0);
            true
        } else {
            true
        }
    }
}