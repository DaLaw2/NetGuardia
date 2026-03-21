use crate::model::parsed_packet::ParsedPacket;

#[inline(always)]
pub fn symmetric_queue_id(pkt: &ParsedPacket, num_queues: u32) -> Option<u32> {
    if num_queues == 0 {
        return None;
    }

    let ip_hash = match pkt.ip_version {
        4 => pkt.src_ip_v4() ^ pkt.dst_ip_v4(),
        6 => {
            let s = pkt.src_ip_v6();
            let d = pkt.dst_ip_v6();
            let xor = s ^ d;
            (xor as u32) ^ ((xor >> 32) as u32) ^ ((xor >> 64) as u32) ^ ((xor >> 96) as u32)
        }
        _ => return None,
    };
    let port_hash = (pkt.src_port as u32) ^ (pkt.dst_port as u32);

    let h = (ip_hash ^ port_hash.rotate_left(16) ^ (pkt.protocol as u8 as u32)).wrapping_mul(2654435761);

    Some(h % num_queues)
}
