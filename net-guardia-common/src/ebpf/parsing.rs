use crate::model::event::Event;
use crate::define::offset::*;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

pub fn parse_packet(start: usize, end: usize) -> Result<Event, ()> {
    unsafe {
        if start + ETHER_HEADER_END > end {
            return Err(());
        }
        let eth = &*((start + ETHER_HEADER_START) as *const EthHdr);
        let ether_type = eth.ether_type().map_err(|_| ())?;
        match ether_type {
            EtherType::Ipv4 => parse_ipv4_packet(start, end),
            EtherType::Ipv6 => parse_ipv6_packet(start, end),
            _ => Err(()),
        }
    }
}

#[inline(always)]
unsafe fn parse_ipv4_packet(start: usize, end: usize) -> Result<Event, ()> {
    unsafe {
        if start + IPV4_HEADER_END > end {
            return Err(());
        }
        let ipv4 = &*((start + IPV4_HEADER_START) as *const Ipv4Hdr);
        let protocol = ipv4.proto;
        let source_ip = u32::from_be_bytes(ipv4.src_addr);
        let destination_ip = u32::from_be_bytes(ipv4.dst_addr);

        let (source_port, destination_port) = match protocol {
            IpProto::Tcp => parse_tcp_port(start, end, IPV4_TCP_HEADER_START, IPV4_TCP_HEADER_END)?,
            IpProto::Udp => parse_udp_port(start, end, IPV4_UDP_HEADER_START, IPV4_UDP_HEADER_END)?,
            _ => return Err(()),
        };

        Ok(Event {
            eth_type: EtherType::Ipv4,
            protocol,
            source_ip: source_ip as u128,
            destination_ip: destination_ip as u128,
            source_port,
            destination_port,
            len: (end - start) as u32,
            timestamp: bpf_ktime_get_ns(),
        })
    }
}

#[inline(always)]
unsafe fn parse_ipv6_packet(start: usize, end: usize) -> Result<Event, ()> {
    unsafe {
        if start + IPV6_HEADER_END > end {
            return Err(());
        }
        let ipv6 = &*((start + IPV6_HEADER_START) as *const Ipv6Hdr);
        let protocol = ipv6.next_hdr;
        let source_ip = u128::from_be_bytes(ipv6.src_addr);
        let destination_ip = u128::from_be_bytes(ipv6.dst_addr);

        let (source_port, destination_port) = match protocol {
            IpProto::Tcp => parse_tcp_port(start, end, IPV6_TCP_HEADER_START, IPV6_TCP_HEADER_END)?,
            IpProto::Udp => parse_udp_port(start, end, IPV6_UDP_HEADER_START, IPV6_UDP_HEADER_END)?,
            _ => return Err(()),
        };

        Ok(Event {
            eth_type: EtherType::Ipv6,
            protocol,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            len: (end - start) as u32,
            timestamp: bpf_ktime_get_ns(),
        })
    }
}

#[inline(always)]
unsafe fn parse_tcp_port(start: usize, end: usize, tcp_start: usize, tcp_end: usize) -> Result<(u16, u16), ()> {
    unsafe {
        if start + tcp_end > end {
            return Err(());
        }
        let tcp = &*((start + tcp_start) as *const TcpHdr);
        Ok((u16::from_be_bytes(tcp.source), u16::from_be_bytes(tcp.dest)))
    }
}

#[inline(always)]
unsafe fn parse_udp_port(start: usize, end: usize, udp_start: usize, udp_end: usize) -> Result<(u16, u16), ()> {
    unsafe {
        if start + udp_end > end {
            return Err(());
        }
        let udp = &*((start + udp_start) as *const UdpHdr);
        Ok((udp.src_port(), udp.dst_port()))
    }
}
