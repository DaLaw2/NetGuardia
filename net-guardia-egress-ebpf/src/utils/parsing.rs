use aya_ebpf::helpers::bpf_ktime_get_ns;
use net_guardia_common::model::event::Event;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

pub fn parse_packet(start: usize, end: usize) -> Result<Event, ()> {
    if start + size_of::<EthHdr>() > end {
        return Err(());
    }
    let eth = unsafe { &*(start as *const EthHdr) };
    match eth.ether_type {
        EtherType::Ipv4 => parse_ipv4_packet(start, end),
        EtherType::Ipv6 => parse_ipv6_packet(start, end),
        _ => Err(())
    }
}

#[inline(always)]
pub fn parse_ipv4_packet(start: usize, end: usize) -> Result<Event, ()> {
    let mut offset = size_of::<EthHdr>();
    if start + offset + size_of::<Ipv4Hdr>() > end {
        return Err(());
    }
    let ipv4 = unsafe { &*((start + offset) as *const Ipv4Hdr) };
    offset += size_of::<Ipv4Hdr>();

    let protocol = ipv4.proto;
    let source_ip = u32::from_be(ipv4.src_addr);
    let destination_ip = u32::from_be(ipv4.dst_addr);

    let (source_port, destination_port) = match protocol {
        IpProto::Tcp => parse_tcp_port(start, end, offset)?,
        IpProto::Udp => parse_udp_port(start, end, offset)?,
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
        timestamp: unsafe { bpf_ktime_get_ns() },
    })
}

#[inline(always)]
pub fn parse_ipv6_packet(start: usize, end: usize) -> Result<Event, ()> {
    let mut offset = size_of::<EthHdr>();
    if start + offset + size_of::<Ipv6Hdr>() > end {
        return Err(());
    }
    let ipv6 = unsafe { &*((start + offset) as *const Ipv6Hdr) };
    offset += size_of::<Ipv6Hdr>();

    let protocol = ipv6.next_hdr;
    let source_ip = u128::from_be_bytes(unsafe { ipv6.src_addr.in6_u.u6_addr8 });
    let destination_ip = u128::from_be_bytes(unsafe { ipv6.dst_addr.in6_u.u6_addr8 });

    let (source_port, destination_port) = match protocol {
        IpProto::Tcp => parse_tcp_port(start, end, offset)?,
        IpProto::Udp => parse_udp_port(start, end, offset)?,
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
        timestamp: unsafe { bpf_ktime_get_ns() },
    })
}

#[inline(always)]
fn parse_tcp_port(start: usize, end: usize, offset: usize) -> Result<(u16, u16), ()> {
    let tcp: *const TcpHdr = (start + offset) as *const TcpHdr;
    if start + offset + size_of::<TcpHdr>() > end {
        return Err(());
    }
    Ok((
        u16::from_be(unsafe { (*tcp).source }),
        u16::from_be(unsafe { (*tcp).dest }),
    ))
}

#[inline(always)]
fn parse_udp_port(start: usize, end: usize, offset: usize) -> Result<(u16, u16), ()> {
    let udp: *const UdpHdr = (start + offset) as *const UdpHdr;
    if start + offset + size_of::<UdpHdr>() > end {
        return Err(());
    }
    Ok((
        u16::from_be(unsafe { (*udp).source }),
        u16::from_be(unsafe { (*udp).dest }),
    ))
}
