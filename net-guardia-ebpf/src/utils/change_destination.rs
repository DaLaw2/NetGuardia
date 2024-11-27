use aya_ebpf::programs::XdpContext;
use net_guardia_common::model::ip_address::{AddrPortV4, AddrPortV6};
use net_guardia_common::model::pseudo_header::{IPv4PseudoHeader, IPv6PseudoHeader};
use network_types::eth::EthHdr;
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

pub fn modify_ipv4_packet_destination(ctx: &XdpContext, new_address: AddrPortV4) -> Result<(), ()> {
    let new_ip = new_address[0];
    let new_port = new_address[1] as u16;

    let mut offset = 0;
    let start = ctx.data();
    let end = ctx.data_end();

    if start + offset + size_of::<EthHdr>() > end {
        return Err(());
    }
    offset += size_of::<EthHdr>();

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
            tcp.check = ipv4_transport_checksum(
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
            udp.check = ipv4_transport_checksum(
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
}

pub fn modify_ipv6_packet_destination(ctx: &XdpContext, new_address: AddrPortV6) -> Result<(), ()> {
    let new_ip = new_address[0];
    let new_port = new_address[1] as u16;

    let mut offset = 0;
    let start = ctx.data();
    let end = ctx.data_end();

    if start + offset + size_of::<EthHdr>() > end {
        return Err(());
    }
    offset += size_of::<EthHdr>();

    if start + offset + size_of::<Ipv6Hdr>() > end {
        return Err(());
    }
    let ipv6 = unsafe { &mut *((start + offset) as *mut Ipv6Hdr) };
    offset += size_of::<Ipv6Hdr>();

    let src_bytes = unsafe { (*ipv6).src_addr.in6_u.u6_addr8 };
    let src_addr = u128::from_be_bytes(src_bytes);
    let new_ip_bytes = new_ip.to_be_bytes();
    (*ipv6).dst_addr.in6_u.u6_addr8 = new_ip_bytes;

    match ipv6.next_hdr {
        IpProto::Tcp => {
            if start + offset + size_of::<TcpHdr>() > end {
                return Err(());
            }
            let tcp = unsafe { &mut *((start + offset) as *mut TcpHdr) };
            tcp.dest = u16::to_be(new_port);
            tcp.check = 0;
            tcp.check = ipv6_transport_checksum(
                src_addr,
                new_ip,
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
            udp.check = ipv6_transport_checksum(
                src_addr,
                new_ip,
                IpProto::Udp as u8,
                udp as *const _ as *const u8,
                size_of::<UdpHdr>() as u16,
            );
        }
        _ => return Err(()),
    }
    Ok(())
}

#[inline(always)]
fn ipv4_checksum(ipv4: *const Ipv4Hdr) -> u16 {
    let mut sum = 0u32;
    let header =
        unsafe { core::slice::from_raw_parts(ipv4 as *const u16, size_of::<Ipv4Hdr>() / 2) };
    for &word in header {
        sum += u32::from(u16::from_be(word));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

#[inline(always)]
fn ipv4_transport_checksum(
    source_ip: u32,
    destination_ip: u32,
    protocol: u8,
    transport_data: *const u8,
    length: u16,
) -> u16 {
    let mut sum = 0_u32;

    let pseudo_header = IPv4PseudoHeader {
        source_ip,
        destination_ip,
        zeros: 0,
        protocol,
        length,
    };

    let pseudo_header = &pseudo_header as *const _ as *const u16;
    for i in 0..(size_of::<IPv4PseudoHeader>() / 2) {
        unsafe {
            sum += u32::from(u16::from_be(*pseudo_header.add(i)));
        }
    }

    let transport_data = transport_data as *const u16;
    let words = (length as usize) / 2;
    for i in 0..words {
        unsafe {
            sum += u32::from(u16::from_be(*transport_data.add(i)));
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

#[inline(always)]
fn ipv6_transport_checksum(
    source_ip: u128,
    destination_ip: u128,
    protocol: u8,
    transport_data: *const u8,
    length: u16,
) -> u16 {
    let mut sum = 0_u32;

    let pseudo_header = IPv6PseudoHeader {
        source_ip,
        destination_ip,
        length,
        zeros: 0,
        next_header: protocol,
    };

    let pseudo_header = &pseudo_header as *const _ as *const u16;
    for i in 0..(size_of::<IPv6PseudoHeader>() / 2) {
        unsafe {
            sum += u32::from(u16::from_be(*pseudo_header.add(i)));
        }
    }

    let transport_data = transport_data as *const u16;
    let words = (length as usize) / 2;
    for i in 0..words {
        unsafe {
            sum += u32::from(u16::from_be(*transport_data.add(i)));
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
