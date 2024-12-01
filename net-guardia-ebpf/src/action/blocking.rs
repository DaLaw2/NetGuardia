use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use net_guardia_common::model::event::{IPv4Event, IPv6Event};
use net_guardia_common::model::ip_address::{IPv4, IPv6, Port};
use net_guardia_common::{MAX_RULES, MAX_RULES_PORT};

#[map]
static PERMANENT_BLACKLIST_IPV4: HashMap<IPv4, [Port; MAX_RULES_PORT]> =
    HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static PERMANENT_BLACKLIST_IPV6: HashMap<IPv6, [Port; MAX_RULES_PORT]> =
    HashMap::with_max_entries(MAX_RULES, 0);

pub fn should_block_ipv4(event: &IPv4Event) -> bool {
    unsafe {
        if let Some(ports) = PERMANENT_BLACKLIST_IPV4.get(&event.source_ip) {
            if is_port_blocked(ports, event.source_port) {
                return true;
            }
        }
    }
    false
}

pub fn should_block_ipv6(event: &IPv6Event) -> bool {
    unsafe {
        if let Some(ports) = PERMANENT_BLACKLIST_IPV6.get(&event.source_ip) {
            if is_port_blocked(ports, event.source_port) {
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
