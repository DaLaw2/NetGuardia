use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, LruHashMap};
use net_guardia_common::model::event::{IPv4Event, IPv6Event};
use net_guardia_common::model::ip_address::{EbpfAddrPortV4, EbpfAddrPortV6, IPv4, IPv6};
use net_guardia_common::model::placeholder::PlaceHolder;
use net_guardia_common::{MAX_PORT_ACCESS, MAX_RULES};

const PORT_EXPIRE_TIME: u64 = 60_000_000_000;

#[map]
static IPV4_ACTIVE_PORTS: LruHashMap<IPv4, [u16; MAX_PORT_ACCESS]> = LruHashMap::with_max_entries(10000, 0);
#[map]
static IPV4_PORT_TIMESTAMPS: LruHashMap<EbpfAddrPortV4, u64> = LruHashMap::with_max_entries(10000, 0);
#[map]
static IPV4_SCANNER_LIST: HashMap<IPv4, PlaceHolder> = HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static IPV6_ACTIVE_PORTS: LruHashMap<IPv6, [u16; MAX_PORT_ACCESS]> = LruHashMap::with_max_entries(10000, 0);
#[map]
static IPV6_PORT_TIMESTAMPS: LruHashMap<EbpfAddrPortV6, u64> = LruHashMap::with_max_entries(10000, 0);
#[map]
static IPV6_SCANNER_LIST: HashMap<IPv6, PlaceHolder> = HashMap::with_max_entries(MAX_RULES, 0);

pub fn ipv4_is_attack(event: &IPv4Event) -> bool {
    unsafe {
        let ip = event.source_ip;
        let port = event.source_port;
        let current_time = event.timestamp;

        if IPV4_SCANNER_LIST.get(&ip).is_some() {
            return true;
        }

        let port_key = [ip, port as u32];
        let expire_time = current_time - PORT_EXPIRE_TIME;

        if let Some(ports) = IPV4_ACTIVE_PORTS.get_ptr_mut(&ip) {
            let mut active_count = 1;
            let mut found_port = false;
            let mut empty_index = MAX_PORT_ACCESS;
            let mut expired_index = MAX_PORT_ACCESS;

            for i in 0..MAX_PORT_ACCESS {
                let stored_port = (*ports)[i];
                if stored_port == port {
                    found_port = true;
                    let _ = IPV4_PORT_TIMESTAMPS.insert(&port_key, &current_time, 0);
                } else if stored_port == 0 {
                    empty_index = i;
                } else if stored_port != 0 {
                    let stored_key = [ip, stored_port as u32];
                    if let Some(&timestamp) = IPV4_PORT_TIMESTAMPS.get(&stored_key) {
                        if timestamp > expire_time {
                            active_count += 1;
                        } else {
                            (*ports)[i] = 0;
                            let _ = IPV4_PORT_TIMESTAMPS.remove(&stored_key);
                            expired_index = i;
                        }
                    } else {
                        (*ports)[i] = 0;
                        let _ = IPV4_PORT_TIMESTAMPS.remove(&stored_key);
                        expired_index = i;
                    }
                }
            }

            if !found_port {
                let insert_index = if empty_index != MAX_PORT_ACCESS {
                    empty_index
                } else if expired_index != MAX_PORT_ACCESS {
                    expired_index
                } else {
                    let _ = IPV4_SCANNER_LIST.insert(&ip, &0_u8, 0);
                    return true;
                };

                (*ports)[insert_index] = port;
                let _ = IPV4_PORT_TIMESTAMPS.insert(&port_key, &current_time, 0);
                active_count += 1;
            }

            if active_count == MAX_PORT_ACCESS {
                let _ = IPV4_SCANNER_LIST.insert(&ip, &0_u8, 0);
                return true;
            }
        } else {
            let mut new_ports = [0u16; MAX_PORT_ACCESS];
            new_ports[0] = port;
            let _ = IPV4_ACTIVE_PORTS.insert(&ip, &new_ports, 0);
            let _ = IPV4_PORT_TIMESTAMPS.insert(&port_key, &current_time, 0);
        }

        false
    }
}

pub fn ipv6_is_attack(event: &IPv6Event) -> bool {
    unsafe {
        let ip = event.source_ip;
        let port = event.source_port;
        let current_time = event.timestamp;

        if IPV6_SCANNER_LIST.get(&ip).is_some() {
            return true;
        }

        let port_key = [ip, port as u128];
        let expire_time = current_time - PORT_EXPIRE_TIME;

        if let Some(ports) = IPV6_ACTIVE_PORTS.get_ptr_mut(&ip) {
            let mut active_count = 1;
            let mut found_port = false;
            let mut empty_index = MAX_PORT_ACCESS;
            let mut expired_index = MAX_PORT_ACCESS;

            for i in 0..MAX_PORT_ACCESS {
                let stored_port = (*ports)[i];
                if stored_port == port {
                    found_port = true;
                    let _ = IPV6_PORT_TIMESTAMPS.insert(&port_key, &current_time, 0);
                } else if stored_port == 0 {
                    empty_index = i;
                } else if stored_port != 0 {
                    let stored_key = [ip, stored_port as u128];
                    if let Some(&timestamp) = IPV6_PORT_TIMESTAMPS.get(&stored_key) {
                        if timestamp > expire_time {
                            active_count += 1;
                        } else {
                            (*ports)[i] = 0;
                            let _ = IPV6_PORT_TIMESTAMPS.remove(&stored_key);
                            expired_index = i;
                        }
                    } else {
                        (*ports)[i] = 0;
                        let _ = IPV6_PORT_TIMESTAMPS.remove(&stored_key);
                        expired_index = i;
                    }
                }
            }

            if !found_port {
                let insert_index = if empty_index != MAX_PORT_ACCESS {
                    empty_index
                } else if expired_index != MAX_PORT_ACCESS {
                    expired_index
                } else {
                    let _ = IPV6_SCANNER_LIST.insert(&ip, &0_u8, 0);
                    return true;
                };

                (*ports)[insert_index] = port;
                let _ = IPV6_PORT_TIMESTAMPS.insert(&port_key, &current_time, 0);
                active_count += 1;
            }

            if active_count == MAX_PORT_ACCESS {
                let _ = IPV6_SCANNER_LIST.insert(&ip, &0_u8, 0);
                return true;
            }
        } else {
            let mut new_ports = [0u16; MAX_PORT_ACCESS];
            new_ports[0] = port;
            let _ = IPV6_ACTIVE_PORTS.insert(&ip, &new_ports, 0);
            let _ = IPV6_PORT_TIMESTAMPS.insert(&port_key, &current_time, 0);
        }

        false
    }
}
