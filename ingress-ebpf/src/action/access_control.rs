use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use common::define::setting::{MAX_RULES, MAX_RULES_PORT};
use common::model::event::{IPv4Event, IPv6Event};
use common::model::ip_address::{IPv4, IPv6, Port};

#[map]
static IPV4_SRC_WHITELIST: HashMap<IPv4, [Port; MAX_RULES_PORT]> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV6_SRC_WHITELIST: HashMap<IPv6, [Port; MAX_RULES_PORT]> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV4_DST_WHITELIST: HashMap<IPv4, [Port; MAX_RULES_PORT]> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV6_DST_WHITELIST: HashMap<IPv6, [Port; MAX_RULES_PORT]> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV4_SRC_BLACKLIST: HashMap<IPv4, [Port; MAX_RULES_PORT]> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV6_SRC_BLACKLIST: HashMap<IPv6, [Port; MAX_RULES_PORT]> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV4_DST_BLACKLIST: HashMap<IPv4, [Port; MAX_RULES_PORT]> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV6_DST_BLACKLIST: HashMap<IPv6, [Port; MAX_RULES_PORT]> = HashMap::with_max_entries(MAX_RULES as u32, 0);

pub fn ipv4_is_whitelisted(event: &IPv4Event) -> bool {
    unsafe {
        if let Some(ports) = IPV4_SRC_WHITELIST.get(&event.src_ip) {
            if is_port_exist(ports, event.src_port) {
                return true;
            }
        }
        if let Some(ports) = IPV4_DST_WHITELIST.get(&event.dst_ip) {
            if is_port_exist(ports, event.dst_port) {
                return true;
            }
        }
    }
    false
}

pub fn ipv6_is_whitelisted(event: &IPv6Event) -> bool {
    unsafe {
        if let Some(ports) = IPV6_SRC_WHITELIST.get(&event.src_ip) {
            if is_port_exist(ports, event.src_port) {
                return true;
            }
        }
        if let Some(ports) = IPV6_DST_WHITELIST.get(&event.dst_ip) {
            if is_port_exist(ports, event.dst_port) {
                return true;
            }
        }
    }
    false
}

pub fn ipv4_is_blacklisted(event: &IPv4Event) -> bool {
    unsafe {
        if let Some(ports) = IPV4_SRC_BLACKLIST.get(&event.src_ip) {
            if is_port_exist(ports, event.src_port) {
                return true;
            }
        }
        if let Some(ports) = IPV4_DST_BLACKLIST.get(&event.dst_ip) {
            if is_port_exist(ports, event.dst_port) {
                return true;
            }
        }
    }
    false
}

pub fn ipv6_is_blacklisted(event: &IPv6Event) -> bool {
    unsafe {
        if let Some(ports) = IPV6_SRC_BLACKLIST.get(&event.src_ip) {
            if is_port_exist(ports, event.src_port) {
                return true;
            }
        }
        if let Some(ports) = IPV6_DST_BLACKLIST.get(&event.dst_ip) {
            if is_port_exist(ports, event.dst_port) {
                return true;
            }
        }
    }
    false
}

#[inline(always)]
fn is_port_exist(ports: &[Port; MAX_RULES_PORT], target_port: Port) -> bool {
    if ports.get(0) == Some(&0) {
        return true;
    }
    for &port in ports.iter() {
        if port == 0 {
            break;
        }
        if port == target_port {
            return true;
        }
    }
    false
}
