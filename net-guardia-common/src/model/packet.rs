use crate::define::other::STANDARD_MTU;
use crate::model::event::{Event, IPv4Event, IPv6Event};
use network_types::eth::EtherType;

#[repr(C, align(8))]
pub struct Packet {
    pub event: Event,
    pub raw_data: [u8; STANDARD_MTU],
}

impl Packet {
    pub fn new(event: Event, raw_data: [u8; STANDARD_MTU]) -> Self {
        Self {
            event,
            raw_data,
        }
    }

    pub fn ether_type(&self) -> EtherType {
        self.event.eth_type
    }

    pub fn into_ipv4_packet(self) -> IPv4Packet {
        IPv4Packet {
            event: self.event.into_ipv4_event(),
            raw_data: self.raw_data,
        }
    }

    pub fn into_ipv6_packet(self) -> IPv6Packet {
        IPv6Packet {
            event: self.event.into_ipv6_event(),
            raw_data: self.raw_data,
        }
    }
}

#[repr(C, align(8))]
pub struct IPv4Packet {
    pub event: IPv4Event,
    pub raw_data: [u8; STANDARD_MTU],
}

#[repr(C, align(8))]
pub struct IPv6Packet {
    pub event: IPv6Event,
    pub raw_data: [u8; STANDARD_MTU],
}
