use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use network_types::ip::IpProto;

use crate::model::ip_address::{AddrPortV4, AddrPortV6};

#[repr(C, align(8))]
#[derive(Clone)]
pub enum Event {
    IPv4(IPv4Event),
    IPv6(IPv6Event),
}

impl Event {
    pub fn timestamp_us(&self) -> u64 {
        match self {
            Event::IPv4(e) => e.timestamp_us,
            Event::IPv6(e) => e.timestamp_us,
        }
    }

    pub fn packet_length(&self) -> u32 {
        match self {
            Event::IPv4(e) => e.packet_length,
            Event::IPv6(e) => e.packet_length,
        }
    }

    pub fn header_length(&self) -> u16 {
        match self {
            Event::IPv4(e) => e.header_length,
            Event::IPv6(e) => e.header_length,
        }
    }

    pub fn payload_length(&self) -> u32 {
        match self {
            Event::IPv4(e) => e.payload_length,
            Event::IPv6(e) => e.payload_length,
        }
    }

    pub fn tcp_flags(&self) -> &TcpFlags {
        match self {
            Event::IPv4(e) => &e.tcp_flags,
            Event::IPv6(e) => &e.tcp_flags,
        }
    }

    pub fn tcp_window_size(&self) -> u16 {
        match self {
            Event::IPv4(e) => e.tcp_window_size,
            Event::IPv6(e) => e.tcp_window_size,
        }
    }

    pub fn is_forward(&self) -> bool {
        match self {
            Event::IPv4(e) => e.is_forward,
            Event::IPv6(e) => e.is_forward,
        }
    }

    pub fn protocol(&self) -> &IpProto {
        match self {
            Event::IPv4(e) => &e.protocol,
            Event::IPv6(e) => &e.protocol,
        }
    }

    pub fn src_ip(&self) -> IpAddr {
        match self {
            Event::IPv4(e) => {
                IpAddr::V4(Ipv4Addr::from(e.src_ip))
            }
            Event::IPv6(e) => {
                IpAddr::V6(Ipv6Addr::from(e.src_ip))
            }
        }
    }

    pub fn dst_ip(&self) -> IpAddr {
        match self {
            Event::IPv4(e) => {
                IpAddr::V4(Ipv4Addr::from(e.dst_ip))
            }
            Event::IPv6(e) => {
                IpAddr::V6(Ipv6Addr::from(e.dst_ip))
            }
        }
    }

    pub fn src_port(&self) -> u16 {
        match self {
            Event::IPv4(e) => e.src_port,
            Event::IPv6(e) => e.src_port,
        }
    }

    pub fn dst_port(&self) -> u16 {
        match self {
            Event::IPv4(e) => e.dst_port,
            Event::IPv6(e) => e.dst_port,
        }
    }

    pub fn set_is_forward(&mut self, value: bool) {
        match self {
            Event::IPv4(e) => e.is_forward = value,
            Event::IPv6(e) => e.is_forward = value,
        }
    }
}


#[repr(C, align(8))]
#[derive(Debug, Clone)]
pub struct IPv4Event {
    pub protocol: IpProto,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub packet_length: u32,
    pub payload_length: u32,
    pub header_length: u16,
    pub timestamp_us: u64,
    pub tcp_flags: TcpFlags,
    pub tcp_window_size: u16,
    pub is_forward: bool,
}

impl IPv4Event {
    #[inline(always)]
    pub fn source_addr(&self) -> AddrPortV4 {
        AddrPortV4::new(self.src_ip, self.src_port)
    }

    #[inline(always)]
    pub fn destination_addr(&self) -> AddrPortV4 {
        AddrPortV4::new(self.dst_ip, self.dst_port)
    }
}

#[repr(C, align(8))]
#[derive(Clone)]
pub struct IPv6Event {
    pub protocol: IpProto,
    pub src_ip: u128,
    pub dst_ip: u128,
    pub src_port: u16,
    pub dst_port: u16,
    pub packet_length: u32,
    pub payload_length: u32,
    pub header_length: u16,
    pub timestamp_us: u64,
    pub tcp_flags: TcpFlags,
    pub tcp_window_size: u16,
    pub is_forward: bool,
}

impl IPv6Event {
    #[inline(always)]
    pub fn source_addr(&self) -> AddrPortV6 {
        AddrPortV6::new(self.src_ip, self.src_port)
    }

    #[inline(always)]
    pub fn destination_addr(&self) -> AddrPortV6 {
        AddrPortV6::new(self.dst_ip, self.dst_port)
    }
}

#[derive(Debug, Clone, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    pub fn from_byte(flags: u8) -> Self {
        Self {
            fin: (flags & 0x01) != 0,
            syn: (flags & 0x02) != 0,
            rst: (flags & 0x04) != 0,
            psh: (flags & 0x08) != 0,
            ack: (flags & 0x10) != 0,
            urg: (flags & 0x20) != 0,
            ece: (flags & 0x40) != 0,
            cwr: (flags & 0x80) != 0,
        }
    }
}
