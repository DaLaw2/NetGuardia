use crate::model::parsed_packet::ParsedPacket;

/// Compute a symmetric queue ID from a parsed packet's 5-tuple.
/// Symmetric means hash(A->B) == hash(B->A), ensuring both directions
/// of a flow land on the same XSK queue.
#[inline(always)]
pub fn symmetric_queue_id(pkt: &ParsedPacket, num_queues: u32) -> Option<u32> {
    if num_queues == 0 {
        return None;
    }

    // XOR is inherently symmetric: a^b == b^a
    let ip_hash = match pkt.ip_version {
        4 => pkt.src_ip_v4() ^ pkt.dst_ip_v4(),
        _ => {
            // Fold 128-bit IPv6 into 32-bit via XOR
            let s = pkt.src_ip_v6();
            let d = pkt.dst_ip_v6();
            let xor = s ^ d;
            (xor as u32) ^ ((xor >> 32) as u32) ^ ((xor >> 64) as u32) ^ ((xor >> 96) as u32)
        }
    };
    let port_hash = (pkt.src_port as u32) ^ (pkt.dst_port as u32);

    // Knuth multiplicative hash for mixing
    let h = (ip_hash ^ port_hash.rotate_left(16) ^ (pkt.protocol as u8 as u32))
        .wrapping_mul(2654435761);

    Some(h % num_queues)
}
