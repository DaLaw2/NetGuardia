use crate::model::ip_address::{AddrPortV4, AddrPortV6};

#[repr(C, align(8))]
pub struct ParsedPacket {
    pub timestamp_ns: u64,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub packet_length: u32,
    pub payload_length: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_version: u8,
    pub protocol: u8,
    pub tcp_flags: u8,
    pub _pad: u8,
}

impl ParsedPacket {
    #[inline(always)]
    pub fn src_ip_v4(&self) -> u32 {
        u32::from_ne_bytes([self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3]])
    }

    #[inline(always)]
    pub fn dst_ip_v4(&self) -> u32 {
        u32::from_ne_bytes([self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3]])
    }

    #[inline(always)]
    pub fn src_ip_v6(&self) -> u128 {
        u128::from_ne_bytes(self.src_ip)
    }

    #[inline(always)]
    pub fn dst_ip_v6(&self) -> u128 {
        u128::from_ne_bytes(self.dst_ip)
    }

    #[inline(always)]
    pub fn src_addr_v4(&self) -> AddrPortV4 {
        AddrPortV4::new(self.src_ip_v4(), self.src_port)
    }

    #[inline(always)]
    pub fn dst_addr_v4(&self) -> AddrPortV4 {
        AddrPortV4::new(self.dst_ip_v4(), self.dst_port)
    }

    #[inline(always)]
    pub fn src_addr_v6(&self) -> AddrPortV6 {
        AddrPortV6::new(self.src_ip_v6(), self.src_port)
    }

    #[inline(always)]
    pub fn dst_addr_v6(&self) -> AddrPortV6 {
        AddrPortV6::new(self.dst_ip_v6(), self.dst_port)
    }
}
