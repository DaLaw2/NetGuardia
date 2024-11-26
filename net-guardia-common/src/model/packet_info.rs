#[repr(C)]
pub struct PacketInfo {
    pub protocol: u8,
    pub source_ip: u32,
    pub destination_ip: u32,
    pub source_port: u16,
    pub destination_port: u16,
    pub len: u32,
    pub timestamp: u64
}
