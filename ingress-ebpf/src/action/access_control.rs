use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use common::define::setting::MAX_RULES;
use common::model::parsed_packet::ParsedPacket;
use common::model::ip_address::{IPv4, IPv6};
use common::model::port_rule::PortRule;

#[map]
static IPV4_SRC_WHITELIST: HashMap<IPv4, PortRule> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV6_SRC_WHITELIST: HashMap<IPv6, PortRule> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV4_DST_WHITELIST: HashMap<IPv4, PortRule> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV6_DST_WHITELIST: HashMap<IPv6, PortRule> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV4_SRC_BLACKLIST: HashMap<IPv4, PortRule> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV6_SRC_BLACKLIST: HashMap<IPv6, PortRule> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV4_DST_BLACKLIST: HashMap<IPv4, PortRule> = HashMap::with_max_entries(MAX_RULES as u32, 0);
#[map]
static IPV6_DST_BLACKLIST: HashMap<IPv6, PortRule> = HashMap::with_max_entries(MAX_RULES as u32, 0);

pub fn ipv4_is_whitelisted(pkt: &ParsedPacket) -> bool {
    let src_ip = pkt.src_ip_v4();
    let dst_ip = pkt.dst_ip_v4();
    unsafe {
        if let Some(rule) = IPV4_SRC_WHITELIST.get(&src_ip) {
            if rule.contains(pkt.src_port) {
                return true;
            }
        }
        if let Some(rule) = IPV4_DST_WHITELIST.get(&dst_ip) {
            if rule.contains(pkt.dst_port) {
                return true;
            }
        }
    }
    false
}

pub fn ipv6_is_whitelisted(pkt: &ParsedPacket) -> bool {
    let src_ip = pkt.src_ip_v6();
    let dst_ip = pkt.dst_ip_v6();
    unsafe {
        if let Some(rule) = IPV6_SRC_WHITELIST.get(&src_ip) {
            if rule.contains(pkt.src_port) {
                return true;
            }
        }
        if let Some(rule) = IPV6_DST_WHITELIST.get(&dst_ip) {
            if rule.contains(pkt.dst_port) {
                return true;
            }
        }
    }
    false
}

pub fn ipv4_is_blacklisted(pkt: &ParsedPacket) -> bool {
    let src_ip = pkt.src_ip_v4();
    let dst_ip = pkt.dst_ip_v4();
    unsafe {
        if let Some(rule) = IPV4_SRC_BLACKLIST.get(&src_ip) {
            if rule.contains(pkt.src_port) {
                return true;
            }
        }
        if let Some(rule) = IPV4_DST_BLACKLIST.get(&dst_ip) {
            if rule.contains(pkt.dst_port) {
                return true;
            }
        }
    }
    false
}

pub fn ipv6_is_blacklisted(pkt: &ParsedPacket) -> bool {
    let src_ip = pkt.src_ip_v6();
    let dst_ip = pkt.dst_ip_v6();
    unsafe {
        if let Some(rule) = IPV6_SRC_BLACKLIST.get(&src_ip) {
            if rule.contains(pkt.src_port) {
                return true;
            }
        }
        if let Some(rule) = IPV6_DST_BLACKLIST.get(&dst_ip) {
            if rule.contains(pkt.dst_port) {
                return true;
            }
        }
    }
    false
}
