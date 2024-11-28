use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::map;
use aya_ebpf::maps::LruHashMap;
use net_guardia_common::model::event::{IPv4Event, IPv6Event};
use net_guardia_common::model::flow_status::FlowStatus;
use net_guardia_common::model::ip_address::{AddrPortV4, AddrPortV6};
use net_guardia_common::MAX_STATS;

#[map]
static SRC_IPV4_1MIN: LruHashMap<AddrPortV4, FlowStatus> = LruHashMap::with_max_entries(MAX_STATS, 0);
#[map]
static SRC_IPV6_1MIN: LruHashMap<AddrPortV6, FlowStatus> = LruHashMap::with_max_entries(MAX_STATS, 0);
#[map]
static SRC_IPV4_10MIN: LruHashMap<AddrPortV4, FlowStatus> = LruHashMap::with_max_entries(MAX_STATS, 0);
#[map]
static SRC_IPV6_10MIN: LruHashMap<AddrPortV6, FlowStatus> = LruHashMap::with_max_entries(MAX_STATS, 0);
#[map]
static SRC_IPV4_1HOUR: LruHashMap<AddrPortV4, FlowStatus> = LruHashMap::with_max_entries(MAX_STATS, 0);
#[map]
static SRC_IPV6_1HOUR: LruHashMap<AddrPortV6, FlowStatus> = LruHashMap::with_max_entries(MAX_STATS, 0);
#[map]
static DST_IPV4_1MIN: LruHashMap<AddrPortV4, FlowStatus> = LruHashMap::with_max_entries(MAX_STATS, 0);
#[map]
static DST_IPV6_1MIN: LruHashMap<AddrPortV6, FlowStatus> = LruHashMap::with_max_entries(MAX_STATS, 0);
#[map]
static DST_IPV4_10MIN: LruHashMap<AddrPortV4, FlowStatus> = LruHashMap::with_max_entries(MAX_STATS, 0);
#[map]
static DST_IPV6_10MIN: LruHashMap<AddrPortV6, FlowStatus> = LruHashMap::with_max_entries(MAX_STATS, 0);
#[map]
static DST_IPV4_1HOUR: LruHashMap<AddrPortV4, FlowStatus> = LruHashMap::with_max_entries(MAX_STATS, 0);
#[map]
static DST_IPV6_1HOUR: LruHashMap<AddrPortV6, FlowStatus> = LruHashMap::with_max_entries(MAX_STATS, 0);

pub fn update_stats_ipv4(event: &IPv4Event) {
    unsafe {
        let now = bpf_ktime_get_ns();
        let source = [event.source_ip, event.source_port as u32];
        let destination = [event.destination_ip, event.destination_port as u32];
        update_flow_status_ipv4(&SRC_IPV4_1MIN, &source, event, now);
        update_flow_status_ipv4(&SRC_IPV4_10MIN, &source, event, now);
        update_flow_status_ipv4(&SRC_IPV4_1HOUR, &source, event, now);
        update_flow_status_ipv4(&DST_IPV4_1MIN, &destination, event, now);
        update_flow_status_ipv4(&DST_IPV4_10MIN, &destination, event, now);
        update_flow_status_ipv4(&DST_IPV4_1HOUR, &destination, event, now);
    }
}

pub fn update_stats_ipv6(event: &IPv6Event) {
    unsafe {
        let now = bpf_ktime_get_ns();
        let source = [event.source_ip, event.source_port as u128];
        let destination = [event.destination_ip, event.destination_port as u128];
        update_flow_status_ipv6(&SRC_IPV6_1MIN, &source, event, now);
        update_flow_status_ipv6(&SRC_IPV6_10MIN, &source, event, now);
        update_flow_status_ipv6(&SRC_IPV6_1HOUR, &source, event, now);
        update_flow_status_ipv6(&DST_IPV6_1MIN, &destination, event, now);
        update_flow_status_ipv6(&DST_IPV6_10MIN, &destination, event, now);
        update_flow_status_ipv6(&DST_IPV6_1HOUR, &destination, event, now);
    }
}

#[inline(always)]
unsafe fn update_flow_status_ipv4(
    map: &LruHashMap<AddrPortV4, FlowStatus>,
    key: &AddrPortV4,
    event: &IPv4Event,
    now: u64,
) {
    if let Some(status) = map.get_ptr_mut(key) {
        (*status)[0] += event.len as u64;
        (*status)[1] += 1;
        (*status)[2] = now;
    } else {
        let new_status = [event.len as u64, 1, now];
        let _ = map.insert(key, &new_status, 0);
    }
}

#[inline(always)]
unsafe fn update_flow_status_ipv6(
    map: &LruHashMap<AddrPortV6, FlowStatus>,
    key: &AddrPortV6,
    event: &IPv6Event,
    now: u64,
) {
    if let Some(status) = map.get_ptr_mut(key) {
        (*status)[0] += event.len as u64;
        (*status)[1] += 1;
        (*status)[2] = now;
    } else {
        let new_status = [event.len as u64, 1, now];
        let _ = map.insert(key, &new_status, 0);
    }
}
