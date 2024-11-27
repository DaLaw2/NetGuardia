use crate::model::general::{AddrPort, AddrPortV4, AddrPortV6};

pub enum PacketEvent {
    IPv4(IPv4Event),
    IPv6(IPv6Event),
}

impl PacketEvent {
    #[inline(always)]
    pub fn get_source(&self) -> AddrPort {
        match self {
            PacketEvent::IPv4(event) => AddrPort::IPv4(event.get_addr_port()),
            PacketEvent::IPv6(event) => AddrPort::IPv6(event.get_source())
        }
    }

    #[inline(always)]
    pub fn get_destination(&self) -> AddrPort {
        match self {
            PacketEvent::IPv4(event) => AddrPort::IPv4(event.get_destination()),
            PacketEvent::IPv6(event) => AddrPort::IPv6(event.get_destination())
        }
    }
}

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
    pub fn get_addr_port(&self) -> AddrPortV4 {
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
