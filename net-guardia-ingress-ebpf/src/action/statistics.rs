use aya_ebpf::macros::map;
use aya_ebpf::maps::LruHashMap;
use net_guardia_common::model::event::{IPv4Event, IPv6Event};
use net_guardia_common::model::flow_stats::FlowStats;
use net_guardia_common::model::ip_address::{AddrPortV4, AddrPortV6};
use net_guardia_common::define::setting::MAX_STATS;

#[map]
static IPV4_INGRESS_SRC_1MIN: LruHashMap<AddrPortV4, FlowStats> = LruHashMap::with_max_entries(MAX_STATS as u32, 0);
#[map]
static IPV4_INGRESS_SRC_10MIN: LruHashMap<AddrPortV4, FlowStats> = LruHashMap::with_max_entries(MAX_STATS as u32, 0);
#[map]
static IPV4_INGRESS_SRC_1HOUR: LruHashMap<AddrPortV4, FlowStats> = LruHashMap::with_max_entries(MAX_STATS as u32, 0);
#[map]
static IPV6_INGRESS_SRC_1MIN: LruHashMap<AddrPortV6, FlowStats> = LruHashMap::with_max_entries(MAX_STATS as u32, 0);
#[map]
static IPV6_INGRESS_SRC_10MIN: LruHashMap<AddrPortV6, FlowStats> = LruHashMap::with_max_entries(MAX_STATS as u32, 0);
#[map]
static IPV6_INGRESS_SRC_1HOUR: LruHashMap<AddrPortV6, FlowStats> = LruHashMap::with_max_entries(MAX_STATS as u32, 0);
#[map]
static IPV4_INGRESS_DST_1MIN: LruHashMap<AddrPortV4, FlowStats> = LruHashMap::with_max_entries(MAX_STATS as u32, 0);
#[map]
static IPV4_INGRESS_DST_10MIN: LruHashMap<AddrPortV4, FlowStats> = LruHashMap::with_max_entries(MAX_STATS as u32, 0);
#[map]
static IPV4_INGRESS_DST_1HOUR: LruHashMap<AddrPortV4, FlowStats> = LruHashMap::with_max_entries(MAX_STATS as u32, 0);
#[map]
static IPV6_INGRESS_DST_1MIN: LruHashMap<AddrPortV6, FlowStats> = LruHashMap::with_max_entries(MAX_STATS as u32, 0);
#[map]
static IPV6_INGRESS_DST_10MIN: LruHashMap<AddrPortV6, FlowStats> = LruHashMap::with_max_entries(MAX_STATS as u32, 0);
#[map]
static IPV6_INGRESS_DST_1HOUR: LruHashMap<AddrPortV6, FlowStats> = LruHashMap::with_max_entries(MAX_STATS as u32, 0);

pub fn ipv4_update_stats(event: &IPv4Event) {
    unsafe {
        let source = event.source_addr();
        let destination = event.destination_addr();
        ipv4_update_flow_stats(&IPV4_INGRESS_SRC_1MIN, &source, event);
        ipv4_update_flow_stats(&IPV4_INGRESS_SRC_10MIN, &source, event);
        ipv4_update_flow_stats(&IPV4_INGRESS_SRC_1HOUR, &source, event);
        ipv4_update_flow_stats(&IPV4_INGRESS_DST_1MIN, &destination, event);
        ipv4_update_flow_stats(&IPV4_INGRESS_DST_10MIN, &destination, event);
        ipv4_update_flow_stats(&IPV4_INGRESS_DST_1HOUR, &destination, event);
    }
}

pub fn ipv6_update_stats(event: &IPv6Event) {
    unsafe {
        let source = event.source_addr();
        let destination = event.destination_addr();
        ipv6_update_flow_status(&IPV6_INGRESS_SRC_1MIN, &source, event);
        ipv6_update_flow_status(&IPV6_INGRESS_SRC_10MIN, &source, event);
        ipv6_update_flow_status(&IPV6_INGRESS_SRC_1HOUR, &source, event);
        ipv6_update_flow_status(&IPV6_INGRESS_DST_1MIN, &destination, event);
        ipv6_update_flow_status(&IPV6_INGRESS_DST_10MIN, &destination, event);
        ipv6_update_flow_status(&IPV6_INGRESS_DST_1HOUR, &destination, event);
    }
}

#[inline(always)]
unsafe fn ipv4_update_flow_stats(
    map: &LruHashMap<AddrPortV4, FlowStats>,
    key: &AddrPortV4,
    event: &IPv4Event,
) {
    unsafe {
        if let Some(status) = map.get_ptr_mut(key) {
            (*status).bytes += event.len as u64;
            (*status).packets += 1;
            (*status).last_seen = event.timestamp;
        } else {
            let new_stats = FlowStats {
                bytes: event.len as u64,
                packets: 1,
                last_seen: event.timestamp,
            };
            let _ = map.insert(key, &new_stats, 0);
        }
    }
}

#[inline(always)]
unsafe fn ipv6_update_flow_status(
    map: &LruHashMap<AddrPortV6, FlowStats>,
    key: &AddrPortV6,
    event: &IPv6Event,
) {
    unsafe {
        if let Some(status) = map.get_ptr_mut(key) {
            (*status).bytes += event.len as u64;
            (*status).packets += 1;
            (*status).last_seen = event.timestamp;
        } else {
            let new_stats = FlowStats {
                bytes: event.len as u64,
                packets: 1,
                last_seen: event.timestamp,
            };
            let _ = map.insert(key, &new_stats, 0);
        }
    }
}
