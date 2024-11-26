use crate::utils::{ipv4_checksum, transport_checksum};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::programs::XdpContext;
use net_guardia_common::model::packet_info::PacketInfo;
use network_types::ip::IpProto;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};

pub fn parse_packet(ctx: &XdpContext) -> Result<PacketInfo, ()> {
    let mut offset = 0;
    let start = ctx.data();
    let end = ctx.data_end();

    if start + offset + size_of::<EthHdr>() > end {
        return Err(());
    }
    let eth = unsafe { &*(start as *const EthHdr) };
    offset += size_of::<EthHdr>();

    match (*eth).ether_type {
        EtherType::Ipv4 => {
            if start + offset + size_of::<Ipv4Hdr>() > end {
                return Err(());
            }
            let ipv4 = unsafe { &*((start + offset) as *const Ipv4Hdr) };
            offset += size_of::<Ipv4Hdr>();

            let source_ip = (*ipv4).src_addr;
            let destination_ip = (*ipv4).dst_addr;
            let protocol = ipv4.proto;

            let (source_port, destination_port) = match protocol {
                IpProto::Tcp => {
                    let tcp: *const TcpHdr = (start + offset) as *const TcpHdr;
                    if start + offset + size_of::<TcpHdr>() > end {
                        return Err(());
                    }
                    (
                        u16::from_be(unsafe { (*tcp).source }),
                        u16::from_be(unsafe { (*tcp).dest }),
                    )
                }
                IpProto::Udp => {
                    let udp: *const UdpHdr = (start + offset) as *const UdpHdr;
                    if start + offset + size_of::<UdpHdr>() > end {
                        return Err(());
                    }
                    (
                        u16::from_be(unsafe { (*udp).source }),
                        u16::from_be(unsafe { (*udp).dest }),
                    )
                }
                _ => return Err(()),
            };
            Ok(PacketInfo {
                protocol: protocol as u8,
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                len: (end - start) as u32,
                timestamp: unsafe { bpf_ktime_get_ns() },
            })
        },
        _ => Err(()),
    }
}

pub fn modify_packet_destination(ctx: &XdpContext, new_ip: u32, new_port: u16) -> Result<(), ()> {
    let mut offset = 0;
    let start = ctx.data();
    let end = ctx.data_end();

    if start + offset + size_of::<EthHdr>() > end {
        return Err(());
    }
    let eth = unsafe { &mut *(start as *mut EthHdr) };
    offset += size_of::<EthHdr>();

    if { (*eth).ether_type } == EtherType::Ipv4 {
        if start + offset + size_of::<Ipv4Hdr>() > end {
            return Err(());
        }
        let ipv4 = unsafe { &mut *((start + offset) as *mut Ipv4Hdr) };
        offset += size_of::<Ipv4Hdr>();

        (*ipv4).dst_addr = u32::to_be(new_ip);
        (*ipv4).check = 0;
        (*ipv4).check = ipv4_checksum(ipv4);

        match (*ipv4).proto {
            IpProto::Tcp => {
                if start + offset + size_of::<TcpHdr>() > end {
                    return Err(());
                }
                let tcp = unsafe { &mut *((start + offset) as *mut TcpHdr) };
                tcp.dest = u16::to_be(new_port);
                tcp.check = 0;
                tcp.check = transport_checksum(
                    ipv4.src_addr,
                    ipv4.dst_addr,
                    IpProto::Tcp as u8,
                    tcp as *const _ as *const u8,
                    size_of::<TcpHdr>() as u16,
                );
            }
            IpProto::Udp => {
                if start + offset + size_of::<UdpHdr>() > end {
                    return Err(());
                }
                let udp = unsafe { &mut *((start + offset) as *mut UdpHdr) };
                udp.dest = u16::to_be(new_port);
                udp.check = 0;
                udp.check = transport_checksum(
                    ipv4.src_addr,
                    ipv4.dst_addr,
                    IpProto::Udp as u8,
                    udp as *const _ as *const u8,
                    size_of::<UdpHdr>() as u16,
                );
            }
            _ => return Err(()),
        }
        Ok(())
    } else {
        Err(())
    }
}
