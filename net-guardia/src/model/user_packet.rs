pub struct UserPacket {
    #[allow(dead_code)]
    pub ip_version: u8,
    pub protocol: u8,
    pub tcp_flags: u8,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub packet_length: u32,
    pub payload_length: u32,
    pub header_length: u16,
    pub tcp_window_size: u16,
    pub timestamp_us: u64,
    pub is_forward: bool,
}
