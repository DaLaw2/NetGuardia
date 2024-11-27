use crate::model::ip_address::{AddrPortV4, AddrPortV6};

pub struct IPv4Event {
    pub protocol: u8,
    pub source_ip: u32,
    pub destination_ip: u32,
    pub source_port: u16,
    pub destination_port: u16,
    pub len: u32,
    pub timestamp: u64
}

impl IPv4Event {
    #[inline(always)]
    pub fn get_source(&self) -> AddrPortV4 {
        [self.source_ip, self.source_port as u32]
    }

    #[inline(always)]
    pub fn get_destination(&self) -> AddrPortV4 {
        [self.destination_ip, self.destination_port as u32]
    }
}

pub struct IPv6Event {
    pub protocol: u8,
    pub source_ip: u128,
    pub destination_ip: u128,
    pub source_port: u16,
    pub destination_port: u16,
    pub len: u32,
    pub timestamp: u64
}

impl IPv6Event {
    #[inline(always)]
    pub fn get_source(&self) -> AddrPortV6 {
        [self.source_ip, self.source_port as u128]
    }

    #[inline(always)]
    pub fn get_destination(&self) -> AddrPortV6 {
        [self.destination_ip, self.destination_port as u128]
    }
}
