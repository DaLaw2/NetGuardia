use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, LruHashMap};
use common::define::tcp_flags::*;
use common::model::ip_address::{IPv4, IPv6};
use common::model::parsed_packet::ParsedPacket;
use common::model::rate_limit::*;
use network_types::ip::IpProto;

const CFG_PACKET_RATE: u32 = 0;
const CFG_SYN_RATE: u32 = 1;
const CFG_UDP_RATE: u32 = 2;
const CFG_DNS_RATE: u32 = 3;
const CFG_WINDOW_NS: u32 = 4;

#[map]
static RATE_LIMIT_CONFIG: Array<u64> = Array::with_max_entries(5, 0);

#[map]
static IPV4_PACKET_RATE_MAP: LruHashMap<IPv4, RateState> = LruHashMap::with_max_entries(MAX_TRACKED_IPS, 0);
#[map]
static IPV6_PACKET_RATE_MAP: LruHashMap<IPv6, RateState> = LruHashMap::with_max_entries(MAX_TRACKED_IPS, 0);
#[map]
static IPV4_SYN_RATE_MAP: LruHashMap<IPv4, RateState> = LruHashMap::with_max_entries(MAX_TRACKED_IPS, 0);
#[map]
static IPV6_SYN_RATE_MAP: LruHashMap<IPv6, RateState> = LruHashMap::with_max_entries(MAX_TRACKED_IPS, 0);
#[map]
static IPV4_UDP_RATE_MAP: LruHashMap<IPv4, RateState> = LruHashMap::with_max_entries(MAX_TRACKED_IPS, 0);
#[map]
static IPV6_UDP_RATE_MAP: LruHashMap<IPv6, RateState> = LruHashMap::with_max_entries(MAX_TRACKED_IPS, 0);
#[map]
static IPV4_DNS_RATE_MAP: LruHashMap<IPv4, RateState> = LruHashMap::with_max_entries(MAX_TRACKED_IPS, 0);
#[map]
static IPV6_DNS_RATE_MAP: LruHashMap<IPv6, RateState> = LruHashMap::with_max_entries(MAX_TRACKED_IPS, 0);

pub fn should_drop(pkt: &ParsedPacket) -> bool {
    match pkt.ip_version {
        4 => ipv4_should_drop(pkt),
        6 => ipv6_should_drop(pkt),
        _ => false,
    }
}

#[inline(always)]
fn get_config(index: u32, default: u64) -> u64 {
    unsafe {
        RATE_LIMIT_CONFIG
            .get(index)
            .copied()
            .filter(|&v| v > 0)
            .unwrap_or(default)
    }
}

/// Returns true if the packet is a TCP SYN-only (no ACK) packet.
/// For non-TCP packets (e.g. UDP), tcp_flags is 0, so this safely returns false.
#[inline(always)]
fn is_syn_only(pkt: &ParsedPacket) -> bool {
    matches!(pkt.protocol, IpProto::Tcp)
        && (pkt.tcp_flags & TCP_SYN != 0)
        && (pkt.tcp_flags & TCP_ACK == 0)
}

#[inline(always)]
fn check_rate<K>(
    map: &LruHashMap<K, RateState>,
    key: &K,
    now: u64,
    window: u64,
    limit: u64,
) -> bool {
    unsafe {
        if let Some(state) = map.get_ptr_mut(key) {
            if now - (*state).window_start >= window {
                (*state).count = 1;
                (*state).window_start = now;
            } else {
                (*state).count += 1;
                if (*state).count > limit {
                    return true;
                }
            }
        } else {
            let new_state = RateState {
                count: 1,
                window_start: now,
            };
            let _ = map.insert(key, &new_state, 0);
        }
    }
    false
}

#[inline(always)]
fn ipv4_should_drop(pkt: &ParsedPacket) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    let window = get_config(CFG_WINDOW_NS, DEFAULT_WINDOW_NS);
    let src_ip = pkt.src_ip_v4();

    if check_rate(&IPV4_PACKET_RATE_MAP, &src_ip, now, window, get_config(CFG_PACKET_RATE, DEFAULT_PACKET_RATE)) {
        return true;
    }

    if is_syn_only(pkt) {
        if check_rate(&IPV4_SYN_RATE_MAP, &src_ip, now, window, get_config(CFG_SYN_RATE, DEFAULT_SYN_RATE)) {
            return true;
        }
    }

    if matches!(pkt.protocol, IpProto::Udp) {
        if check_rate(&IPV4_UDP_RATE_MAP, &src_ip, now, window, get_config(CFG_UDP_RATE, DEFAULT_UDP_RATE)) {
            return true;
        }
    }

    if pkt.dst_port == 53 {
        if check_rate(&IPV4_DNS_RATE_MAP, &src_ip, now, window, get_config(CFG_DNS_RATE, DEFAULT_DNS_RATE)) {
            return true;
        }
    }

    false
}

#[inline(always)]
fn ipv6_should_drop(pkt: &ParsedPacket) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    let window = get_config(CFG_WINDOW_NS, DEFAULT_WINDOW_NS);
    let src_ip = pkt.src_ip_v6();

    if check_rate(&IPV6_PACKET_RATE_MAP, &src_ip, now, window, get_config(CFG_PACKET_RATE, DEFAULT_PACKET_RATE)) {
        return true;
    }

    if is_syn_only(pkt) {
        if check_rate(&IPV6_SYN_RATE_MAP, &src_ip, now, window, get_config(CFG_SYN_RATE, DEFAULT_SYN_RATE)) {
            return true;
        }
    }

    if matches!(pkt.protocol, IpProto::Udp) {
        if check_rate(&IPV6_UDP_RATE_MAP, &src_ip, now, window, get_config(CFG_UDP_RATE, DEFAULT_UDP_RATE)) {
            return true;
        }
    }

    if pkt.dst_port == 53 {
        if check_rate(&IPV6_DNS_RATE_MAP, &src_ip, now, window, get_config(CFG_DNS_RATE, DEFAULT_DNS_RATE)) {
            return true;
        }
    }

    false
}
