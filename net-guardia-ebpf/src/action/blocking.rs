use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use net_guardia_common::model::event::{IPv4Event, IPv6Event};
use net_guardia_common::model::ip_address::{IPv4, IPv6, Port};
use net_guardia_common::{MAX_RULES, MAX_RULES_PORT};

#[map]
static IPV4_SRC_BLACKLIST: HashMap<IPv4, [Port; MAX_RULES_PORT]> =
    HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static IPV6_SRC_BLACKLIST: HashMap<IPv6, [Port; MAX_RULES_PORT]> =
    HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static IPV4_DST_BLACKLIST: HashMap<IPv4, [Port; MAX_RULES_PORT]> =
    HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static IPV6_DST_BLACKLIST: HashMap<IPv6, [Port; MAX_RULES_PORT]> =
    HashMap::with_max_entries(MAX_RULES, 0);

pub fn ipv4_should_block(event: &IPv4Event) -> bool {
    unsafe {
        if let Some(ports) = IPV4_SRC_BLACKLIST.get(&event.source_ip) {
            if is_port_blocked(ports, event.source_port) {
                return true;
            }
        }
        if let Some(ports) = IPV4_DST_BLACKLIST.get(&event.destination_ip) {
            if is_port_blocked(ports, event.destination_port) {
                return true;
            }
        }
    }
    false
}

pub fn ipv6_should_block(event: &IPv6Event) -> bool {
    unsafe {
        if let Some(ports) = IPV6_SRC_BLACKLIST.get(&event.source_ip) {
            if is_port_blocked(ports, event.source_port) {
                return true;
            }
        }
        if let Some(ports) = IPV6_DST_BLACKLIST.get(&event.destination_ip) {
            if is_port_blocked(ports, event.destination_port) {
                return true;
            }
        }
    }
    false
}

#[inline(always)]
fn is_port_blocked(ports: &[Port; MAX_RULES_PORT], target_port: Port) -> bool {
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
