use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, LruHashMap};
use net_guardia_common::model::event::{IPv4Event, IPv6Event};
use net_guardia_common::model::ip_address::{IPv4, IPv6};
use net_guardia_common::model::placeholder::PlaceHolder;
use net_guardia_common::model::port_accesses::PortAccesses;
use net_guardia_common::{MAX_PORT_ACCESS, MAX_RULES};

const PORT_EXPIRE_TIME: u64 = 60_000_000_000;

#[map]
static IPV4_PORT_ACCESS: LruHashMap<IPv4, PortAccesses> = LruHashMap::with_max_entries(10000, 0);
#[map]
static IPV4_SCANNER_LIST: HashMap<IPv4, PlaceHolder> = HashMap::with_max_entries(MAX_RULES, 0);

#[map]
static IPV6_PORT_ACCESS: LruHashMap<IPv6, PortAccesses> = LruHashMap::with_max_entries(10000, 0);
#[map]
static IPV6_SCANNER_LIST: HashMap<IPv6, PlaceHolder> = HashMap::with_max_entries(MAX_RULES, 0);

pub fn ipv4_is_attack(event: &IPv4Event) -> bool {
    unsafe {
        let ip = &event.source_ip;
        let port = event.source_port;
        let current_time = event.timestamp;

        if IPV4_SCANNER_LIST.get(ip).is_some() {
            return true;
        }

        let mut access = IPV4_PORT_ACCESS.get(ip).map(|v| *v).unwrap_or_default();
        let expire_time = current_time - PORT_EXPIRE_TIME;
        let mut insert_index = MAX_PORT_ACCESS;

        for i in 0..MAX_PORT_ACCESS {
            let (stored_port, timestamp) = access.records[i];
            if timestamp > expire_time {
                if stored_port == port {
                    access.records[i] = (port, current_time);
                    let _ = IPV4_PORT_ACCESS.insert(ip, &access, 0);
                    return false;
                }
            } else if insert_index == MAX_PORT_ACCESS {
                insert_index = i;
            }
        }

        if insert_index == MAX_PORT_ACCESS {
            let _ = IPV4_SCANNER_LIST.insert(ip, &0_u8, 0);
            return true;
        }

        access.records[insert_index] = (port, current_time);
        let _ = IPV4_PORT_ACCESS.insert(ip, &access, 0);
        false
    }
}

pub fn ipv6_is_attack(event: &IPv6Event) -> bool {
    unsafe {
        let ip = &event.source_ip;
        let port = event.source_port;
        let current_time = event.timestamp;

        if IPV6_SCANNER_LIST.get(ip).is_some() {
            return true;
        }

        let mut access = IPV6_PORT_ACCESS.get(ip).map(|v| *v).unwrap_or_default();
        let expire_time = current_time - PORT_EXPIRE_TIME;
        let mut insert_index = MAX_PORT_ACCESS;

        for i in 0..MAX_PORT_ACCESS {
            let (stored_port, timestamp) = access.records[i];
            if timestamp > expire_time {
                if stored_port == port {
                    access.records[i] = (port, current_time);
                    let _ = IPV6_PORT_ACCESS.insert(ip, &access, 0);
                    return false;
                }
            } else if insert_index == MAX_PORT_ACCESS {
                insert_index = i;
            }
        }

        if insert_index == MAX_PORT_ACCESS {
            let _ = IPV6_SCANNER_LIST.insert(ip, &0_u8, 0);
            return true;
        }

        access.records[insert_index] = (port, current_time);
        let _ = IPV6_PORT_ACCESS.insert(ip, &access, 0);
        false
    }
}
