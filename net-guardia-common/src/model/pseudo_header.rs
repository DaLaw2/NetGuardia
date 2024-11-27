#[repr(C)]
#[derive(Clone, Copy)]
pub struct IPv4PseudoHeader {
    pub source_ip: u32,
    pub destination_ip: u32,
    pub zeros: u8,
    pub protocol: u8,
    pub length: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IPv6PseudoHeader {
    pub source_ip: u128,
    pub destination_ip: u128,
    pub length: u16,
    pub zeros: u8,
    pub next_header: u8,
}
