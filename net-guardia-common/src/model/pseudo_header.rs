#[repr(C)]
#[derive(Clone, Copy)]
pub struct PseudoHeader {
    pub source_ip: u32,
    pub destination_ip: u32,
    pub zeros: u8,
    pub protocol: u8,
    pub length: u16,
}
