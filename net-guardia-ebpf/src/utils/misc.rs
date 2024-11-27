use network_types::ip::{IpProto, Ipv4Hdr};
use aya_ebpf::programs::XdpContext;
use net_guardia_common::model::pseudo_header::PseudoHeader;
use network_types::eth::{EthHdr, EtherType};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

#[inline(always)]
pub fn ipv4_checksum(ipv4: *const Ipv4Hdr) -> u16 {
    let mut sum = 0u32;
    let header = unsafe { core::slice::from_raw_parts(ipv4 as *const u16, size_of::<Ipv4Hdr>() / 2) };
    for &word in header {
        sum += u32::from(u16::from_be(word));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

#[inline(always)]
pub fn transport_checksum(source_ip: u32, destination_ip: u32, protocol: u8, transport_data: *const u8, length: u16) -> u16 {
    let mut sum = 0u32;

    let pseudo_header = PseudoHeader {
        source_ip,
        destination_ip,
        zeros: 0,
        protocol,
        length,
    };

    let pseudo_ptr = &pseudo_header as *const _ as *const u16;
    for i in 0..(size_of::<PseudoHeader>() / 2) {
        unsafe {
            sum += u32::from(u16::from_be(*pseudo_ptr.add(i)));
        }
    }

    let trans_ptr = transport_data as *const u16;
    let words = (length as usize) / 2;
    for i in 0..words {
        unsafe {
            sum += u32::from(u16::from_be(*trans_ptr.add(i)));
        }
    }

    if length % 2 == 1 {
        unsafe {
            let last_byte = *transport_data.add(length as usize - 1);
            sum += u32::from(last_byte) << 8;
        }
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
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