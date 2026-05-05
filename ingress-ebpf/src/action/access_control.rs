use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::maps::LpmTrie;
use aya_ebpf::maps::lpm_trie::Key;
use common::define::setting::{MAX_GEO_ENTRIES, MAX_RULES};
use common::model::ip_address::{IPv4, IPv6};
use common::model::parsed_packet::ParsedPacket;
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
#[map]
static GEO_BLOCK_V4: LpmTrie<u32, u8> = LpmTrie::with_max_entries(MAX_GEO_ENTRIES, 0);
#[map]
static GEO_BLOCK_V6: LpmTrie<u128, u8> = LpmTrie::with_max_entries(MAX_GEO_ENTRIES, 0);

pub fn ipv4_is_geo_blocked(pkt: &ParsedPacket) -> bool {
    // from_ne_bytes so memory layout = raw packet bytes (network order).
    // Matches userspace insertion which uses to_bits().to_be() (same memory layout).
    let src_ip = u32::from_ne_bytes([pkt.src_ip[0], pkt.src_ip[1], pkt.src_ip[2], pkt.src_ip[3]]);
    let key = Key::new(32, src_ip);
    unsafe { GEO_BLOCK_V4.get(&key).is_some() }
}

pub fn ipv6_is_geo_blocked(pkt: &ParsedPacket) -> bool {
    let src_ip = u128::from_ne_bytes(pkt.src_ip);
    let key = Key::new(128, src_ip);
    unsafe { GEO_BLOCK_V6.get(&key).is_some() }
}

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
