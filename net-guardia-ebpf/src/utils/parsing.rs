use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::programs::XdpContext;
use net_guardia_common::model::event::{IPv4Event, IPv6Event, PacketEvent};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

pub fn parse_packet(ctx: &XdpContext) -> Result<PacketEvent, ()> {
    let mut offset = 0;
    let start = ctx.data();
    let end = ctx.data_end();

    if start + offset + size_of::<EthHdr>() > end {
        return Err(());
    }
    let eth = unsafe { &*(start as *const EthHdr) };
    offset += size_of::<EthHdr>();

    match eth.ether_type {
        EtherType::Ipv4 => parse_ipv4_packet(start, end, offset)
            .map(PacketEvent::IPv4),
        EtherType::Ipv6 => parse_ipv6_packet(start, end, offset)
            .map(PacketEvent::IPv6),
        _ => Err(())
    }
}

pub fn parse_ipv4_packet(start: usize, end: usize, mut offset: usize) -> Result<IPv4Event, ()> {
    if start + offset + size_of::<Ipv4Hdr>() > end {
        return Err(());
    }
    let ipv4 = unsafe { &*((start + offset) as *const Ipv4Hdr) };
    offset += size_of::<Ipv4Hdr>();

    let protocol = ipv4.proto;
    let source_ip = ipv4.src_addr;
    let destination_ip = ipv4.dst_addr;

    let (source_port, destination_port) = match protocol {
        IpProto::Tcp => {
            let tcp: *const TcpHdr = (start + offset) as *const TcpHdr;
            if start + offset + size_of::<TcpHdr>() > end {
                return Err(());
            }
            (u16::from_be(unsafe { (*tcp).source }), u16::from_be(unsafe { (*tcp).dest }))
        }
        IpProto::Udp => {
            let udp: *const UdpHdr = (start + offset) as *const UdpHdr;
            if start + offset + size_of::<UdpHdr>() > end {
                return Err(());
            }
            (u16::from_be(unsafe { (*udp).source }), u16::from_be(unsafe { (*udp).dest }))
        }
        _ => return Err(()),
    };
    Ok(IPv4Event {
        protocol: protocol as u8,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        len: (end - start) as u32,
        timestamp: unsafe { bpf_ktime_get_ns() }
    })
}

pub fn parse_ipv6_packet(start: usize, end: usize, mut offset: usize) -> Result<IPv6Event, ()> {
    Err(())
}
