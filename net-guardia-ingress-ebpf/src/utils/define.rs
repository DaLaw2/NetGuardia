use network_types::eth::EthHdr;
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

pub const ETHER_HEADER_OFFSET: usize = size_of::<EthHdr>();
pub const IPV4_HEADER_OFFSET: usize = ETHER_HEADER_OFFSET + size_of::<Ipv4Hdr>();
pub const IPV6_HEADER_OFFSET: usize = ETHER_HEADER_OFFSET + size_of::<Ipv6Hdr>();
pub const IPV4_TCP_HEADER_OFFSET: usize = IPV4_HEADER_OFFSET + size_of::<TcpHdr>();
pub const IPV6_TCP_HEADER_OFFSET: usize = IPV6_HEADER_OFFSET + size_of::<TcpHdr>();
pub const IPV4_UDP_HEADER_OFFSET: usize = IPV4_HEADER_OFFSET + size_of::<UdpHdr>();
pub const IPV6_UDP_HEADER_OFFSET: usize = IPV6_HEADER_OFFSET + size_of::<UdpHdr>();
