use std::net::{Ipv4Addr, Ipv6Addr};

pub struct UserPacket {
    pub ip_version: u8,
    pub protocol: u8,
    pub tcp_flags: u8,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub packet_length: u32,
    pub payload_length: u32,
    pub header_length: u16,
    pub tcp_window_size: u16,
    pub timestamp_us: u64,
    pub is_forward: bool,
}

impl UserPacket {
    /// Format source IP as a human-readable string.
    pub fn src_ip_string(&self) -> String {
        Self::ip_bytes_to_string(self.ip_version, &self.src_ip)
    }

    /// Format destination IP as a human-readable string.
    pub fn dst_ip_string(&self) -> String {
        Self::ip_bytes_to_string(self.ip_version, &self.dst_ip)
    }

    fn ip_bytes_to_string(ip_version: u8, bytes: &[u8; 16]) -> String {
        if ip_version == 6 {
            Ipv6Addr::from(*bytes).to_string()
        } else {
            Ipv4Addr::from([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string()
        }
    }
}
