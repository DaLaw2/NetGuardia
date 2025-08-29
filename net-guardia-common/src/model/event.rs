use crate::model::ip_address::{AddrPortV4, AddrPortV6};
use network_types::eth::EtherType;
use network_types::ip::IpProto;

pub struct Event {
    pub eth_type: EtherType,
    pub protocol: IpProto,
    pub source_ip: u128,
    pub destination_ip: u128,
    pub source_port: u16,
    pub destination_port: u16,
    pub len: u32,
    pub timestamp: u64,
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
    pub timestamp: u64,
}

impl IPv4Event {
    #[inline(always)]
    pub fn get_source(&self) -> AddrPortV4 {
        AddrPortV4 {
            ip: self.source_ip,
            port: self.source_port,
        }
    }

    #[inline(always)]
    pub fn get_destination(&self) -> AddrPortV4 {
        AddrPortV4 {
            ip: self.destination_ip,
            port: self.destination_port,
        }
    }
}

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
    pub fn get_source(&self) -> AddrPortV6 {
        AddrPortV6 {
            ip: self.source_ip,
            port: self.source_port,
        }
    }

    #[inline(always)]
    pub fn get_destination(&self) -> AddrPortV6 {
        AddrPortV6 {
            ip: self.destination_ip,
            port: self.destination_port,
        }
    }
}
