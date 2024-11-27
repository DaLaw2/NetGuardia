use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use net_guardia_common::model::general::{AddrPortV4, AddrPortV6, IPv4, IPv6, Port, MAX_RULES};

#[map]
static FORWARD_RULES_IPV4: HashMap<AddrPortV4, AddrPortV4> = HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static FORWARD_RULES_IPV6: HashMap<AddrPortV6, AddrPortV6> = HashMap::with_max_entries(MAX_RULES, 0);

pub fn get_forward_rule_ipv4(source_ip: IPv4, source_port: Port) -> Option<AddrPortV4> {
    unsafe {
        let key: AddrPortV4 = [source_ip, source_port as u32];
        FORWARD_RULES_IPV4.get(&key).cloned()
    }
}

pub fn get_forward_rule_ipv6(source_ip: IPv6, source_port: Port) -> Option<AddrPortV6> {
    unsafe {
        let key: AddrPortV6 = [source_ip, source_port as u128];
        FORWARD_RULES_IPV6.get(&key).cloned()
    }
}
