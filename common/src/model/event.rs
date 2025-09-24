use network_types::ip::IpProto;

use crate::model::ip_address::{AddrPortV4, AddrPortV6};

#[repr(C, align(8))]
#[derive(Clone)]
pub enum Event {
    IPv4(IPv4Event),
    IPv6(IPv6Event),
}

#[repr(C, align(8))]
#[derive(Clone)]
pub struct IPv4Event {
    pub protocol: IpProto,
    pub source_ip: u32,
    pub destination_ip: u32,
    pub source_port: u16,
    pub destination_port: u16,
    pub len: u32,
    pub timestamp: u64,
}

impl IPv4Event {
    #[inline(always)]
    pub fn source_addr(&self) -> AddrPortV4 {
        AddrPortV4::new(self.source_ip, self.source_port)
    }

    #[inline(always)]
    pub fn destination_addr(&self) -> AddrPortV4 {
        AddrPortV4::new(self.destination_ip, self.destination_port)
    }
}

#[repr(C, align(8))]
#[derive(Clone)]
pub struct IPv6Event {
    pub protocol: IpProto,
    pub source_ip: u128,
    pub destination_ip: u128,
    pub source_port: u16,
    pub destination_port: u16,
    pub len: u32,
    pub timestamp: u64,
}

impl IPv6Event {
    #[inline(always)]
    pub fn source_addr(&self) -> AddrPortV6 {
        AddrPortV6::new(self.source_ip, self.source_port)
    }

    #[inline(always)]
    pub fn destination_addr(&self) -> AddrPortV6 {
        AddrPortV6::new(self.destination_ip, self.destination_port)
    }
}
