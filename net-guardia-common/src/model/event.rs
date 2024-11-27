pub enum PacketEvent {
    IPv4(IPv4Event),
    IPv6(IPv6Event),
}

#[repr(C)]
pub struct IPv4Event {
    pub protocol: u8,
    pub source_ip: u32,
    pub destination_ip: u32,
    pub source_port: u16,
    pub destination_port: u16,
    pub len: u32,
    pub timestamp: u64
}

#[repr(C)]
pub struct IPv6Event {
    pub protocol: u8,
    pub source_ip: u128,
    pub destination_ip: u128,
    pub source_port: u16,
    pub destination_port: u16,
    pub len: u32,
    pub timestamp: u64
}
