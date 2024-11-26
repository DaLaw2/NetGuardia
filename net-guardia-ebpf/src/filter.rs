use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use net_guardia_common::model::packet_info::PacketInfo;
use net_guardia_common::{MAX_RULES, MAX_RULES_PORT};

#[map]
static mut BLOCKED_IPV4: HashMap<u32, [u16; MAX_RULES_PORT]> = HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static mut BLOCKED_IPV6: HashMap<u128, [u16; MAX_RULES_PORT]> = HashMap::with_max_entries(MAX_RULES, 0);

pub fn should_block(packet: &PacketInfo) -> bool {
    unsafe {
        if let Some(list) = BLOCKED_IPV4.get(&packet.source_ip) {
            let port = packet.source_port;
            if list.get(0) == Some(&0_u16) {
                return true;
            }
            if list.iter().find(|&&value| value == port).is_some() {
                return true;
            }
        }
        if let Some(list) = BLOCKED_IPV4.get(&packet.destination_ip) {
            let port = packet.destination_port;
            if list.get(0) == Some(&0_u16) {
                return true;
            }
            if list.iter().find(|&&value| value == port).is_some() {
                return true;
            }
        }
    }
    false
}
