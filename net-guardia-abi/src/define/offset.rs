use core::mem::size_of;

use network_types::eth::EthHdr;
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

pub const ETHER_HEADER_START: usize = 0;
pub const ETHER_HEADER_END: usize = ETHER_HEADER_START + size_of::<EthHdr>();

pub const IPV4_HEADER_START: usize = ETHER_HEADER_END;
pub const IPV4_HEADER_END: usize = IPV4_HEADER_START + size_of::<Ipv4Hdr>();

pub const IPV6_HEADER_START: usize = ETHER_HEADER_END;
pub const IPV6_HEADER_END: usize = IPV6_HEADER_START + size_of::<Ipv6Hdr>();

pub const IPV4_TCP_HEADER_START: usize = IPV4_HEADER_END;
pub const IPV4_TCP_HEADER_END: usize = IPV4_TCP_HEADER_START + size_of::<TcpHdr>();

pub const IPV6_TCP_HEADER_START: usize = IPV6_HEADER_END;
pub const IPV6_TCP_HEADER_END: usize = IPV6_TCP_HEADER_START + size_of::<TcpHdr>();

pub const IPV4_UDP_HEADER_START: usize = IPV4_HEADER_END;
pub const IPV4_UDP_HEADER_END: usize = IPV4_UDP_HEADER_START + size_of::<UdpHdr>();

pub const IPV6_UDP_HEADER_START: usize = IPV6_HEADER_END;
pub const IPV6_UDP_HEADER_END: usize = IPV6_UDP_HEADER_START + size_of::<UdpHdr>();

#[cfg(not(feature = "user"))]
const _: () = {
    assert!(size_of::<EthHdr>() == 14);
    assert!(size_of::<Ipv4Hdr>() == 20);
    assert!(size_of::<Ipv6Hdr>() == 40);
};
