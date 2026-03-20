#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct DropEvent {
    pub timestamp_ns: u64,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub reason: u8,
    pub ip_version: u8,
    pub _pad: u8,
}
