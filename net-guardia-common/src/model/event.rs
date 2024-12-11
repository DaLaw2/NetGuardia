use network_types::eth::EtherType;
use crate::model::ip_address::{EbpfAddrPortV4, EbpfAddrPortV6};
use network_types::ip::IpProto;

pub struct Event {
    pub eth_type: EtherType,
    pub protocol: IpProto,
    pub source_ip: u128,
    pub destination_ip: u128,
    pub source_port: u16,
    pub destination_port: u16,
    pub len: u32,
    pub timestamp: u64
}

impl Event {
    #[inline(always)]
    pub fn to_ipv4_event(&self) -> IPv4Event {
        IPv4Event {
            protocol: self.protocol,
            source_ip: self.source_ip as u32,
            destination_ip: self.destination_ip as u32,
            source_port: self.source_port,
            destination_port: self.destination_port,
            len: self.len,
            timestamp: self.timestamp,
        }
    }

    #[inline(always)]
    pub fn to_ipv6_event(&self) -> IPv6Event {
        IPv6Event {
            protocol: self.protocol,
            source_ip: self.source_ip,
            destination_ip: self.destination_ip,
            source_port: self.source_port,
            destination_port: self.destination_port,
            len: self.len,
            timestamp: self.timestamp,
        }
    }

    #[inline(always)]
    pub fn into_ipv4_event(self) -> IPv4Event {
        IPv4Event {
            protocol: self.protocol,
            source_ip: self.source_ip as u32,
            destination_ip: self.destination_ip as u32,
            source_port: self.source_port,
            destination_port: self.destination_port,
            len: self.len,
            timestamp: self.timestamp,
        }
    }

    #[inline(always)]
    pub fn into_ipv6_event(self) -> IPv6Event {
        IPv6Event {
            protocol: self.protocol,
            source_ip: self.source_ip,
            destination_ip: self.destination_ip,
            source_port: self.source_port,
            destination_port: self.destination_port,
            len: self.len,
            timestamp: self.timestamp,
        }
    }
}

pub struct IPv4Event {
    pub protocol: IpProto,
    pub source_ip: u32,
    pub destination_ip: u32,
    pub source_port: u16,
    pub destination_port: u16,
    pub len: u32,
    pub timestamp: u64
}

impl IPv4Event {
    #[inline(always)]
    pub fn get_source(&self) -> EbpfAddrPortV4 {
        [self.source_ip, self.source_port as u32]
    }

    #[inline(always)]
    pub fn get_destination(&self) -> EbpfAddrPortV4 {
        [self.destination_ip, self.destination_port as u32]
    }
}

pub struct IPv6Event {
    pub protocol: IpProto,
    pub source_ip: u128,
    pub destination_ip: u128,
    pub source_port: u16,
    pub destination_port: u16,
    pub len: u32,
    pub timestamp: u64
}

impl IPv6Event {
    #[inline(always)]
    pub fn get_source(&self) -> EbpfAddrPortV6 {
        [self.source_ip, self.source_port as u128]
    }

    #[inline(always)]
    pub fn get_destination(&self) -> EbpfAddrPortV6 {
        [self.destination_ip, self.destination_port as u128]
    }
}
