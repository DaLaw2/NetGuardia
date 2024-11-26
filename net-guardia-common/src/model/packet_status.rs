#[repr(C)]
pub struct PacketStatus {
    pub packets_total: u64,
    pub bytes_total: u64,
    pub dropped_packets: u64,
    pub forwarded_packets: u64,
}
