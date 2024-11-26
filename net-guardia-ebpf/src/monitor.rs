use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::map;
use aya_ebpf::maps::LruHashMap;
use net_guardia_common::model::flow_status::FlowStatus;
use net_guardia_common::model::packet_info::PacketInfo;

#[map]
static mut SRC_STATS_1MIN: LruHashMap<[u32; 2], FlowStatus> = LruHashMap::with_max_entries(100000, 0);
#[map]
static mut SRC_STATS_10MIN: LruHashMap<[u32; 2], FlowStatus> = LruHashMap::with_max_entries(100000, 0);
#[map]
static mut SRC_STATS_1HOUR: LruHashMap<[u32; 2], FlowStatus> = LruHashMap::with_max_entries(100000, 0);
#[map]
static mut DST_STATS_1MIN: LruHashMap<[u32; 2], FlowStatus> = LruHashMap::with_max_entries(100000, 0);
#[map]
static mut DST_STATS_10MIN: LruHashMap<[u32; 2], FlowStatus> = LruHashMap::with_max_entries(100000, 0);
#[map]
static mut DST_STATS_1HOUR: LruHashMap<[u32; 2], FlowStatus> = LruHashMap::with_max_entries(100000, 0);

pub fn update_stats(packet: &PacketInfo) {
    unsafe {
        let now = bpf_ktime_get_ns();
        let source = [packet.source_ip, packet.source_port as u32];
        let destination = [packet.destination_ip, packet.destination_port as u32];
        update_flow_status(&mut SRC_STATS_1MIN, &source, packet, now);
        update_flow_status(&mut SRC_STATS_10MIN, &source, packet, now);
        update_flow_status(&mut SRC_STATS_1HOUR, &source, packet, now);
        update_flow_status(&mut DST_STATS_1MIN, &destination, packet, now);
        update_flow_status(&mut DST_STATS_10MIN, &destination, packet, now);
        update_flow_status(&mut DST_STATS_1HOUR, &destination, packet, now);
    }
}

unsafe fn update_flow_status(
    map: &mut LruHashMap<[u32; 2], FlowStatus>,
    key: &[u32; 2],
    packet: &PacketInfo,
    now: u64
) {
    if let Some(status) = map.get_ptr_mut(key) {
        (*status)[0] += packet.len as u64;
        (*status)[1] += 1;
        (*status)[2] = now;
    } else {
        let new_status = [packet.len as u64, 1, now];
        let _ = map.insert(key, &new_status, 0);
    }
}
