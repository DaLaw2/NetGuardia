use core::mem::size_of;
use core::ptr;

use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

use crate::define::offset::*;
use crate::model::ip_address::IpVersion;
use crate::model::parsed_packet::ParsedPacket;

pub unsafe fn parse_packet(start: usize, end: usize, target: *mut ParsedPacket) -> Option<()> {
    unsafe {
        if start + ETHER_HEADER_END > end {
            return None;
        }
        let eth = &*((start + ETHER_HEADER_START) as *const EthHdr);
        let ether_type = eth.ether_type().ok()?;
        match ether_type {
            EtherType::Ipv4 => parse_ipv4_packet(start, end, target),
            EtherType::Ipv6 => parse_ipv6_packet(start, end, target),
            _ => None,
        }
    }
}

#[inline(always)]
unsafe fn parse_ipv4_packet(start: usize, end: usize, target: *mut ParsedPacket) -> Option<()> {
    if start + IPV4_HEADER_END > end {
        return None;
    }

    unsafe {
        let ipv4 = &*((start + IPV4_HEADER_START) as *const Ipv4Hdr);
        let ipv4_header_len = parse_ipv4_header_len(start, end)?;
        let l4_start = IPV4_HEADER_START + ipv4_header_len;
        let ip_total_len = read_be_u16(start, end, IPV4_HEADER_START + 2)? as usize;
        if ip_total_len < ipv4_header_len {
            return None;
        }
        let transport_len = ip_total_len - ipv4_header_len;
        let packet_length = ip_total_len as u32;

        let t = &mut *target;
        ptr::copy_nonoverlapping(ipv4.src_addr.as_ptr(), t.src_ip.as_mut_ptr(), 4);
        ptr::copy_nonoverlapping(ipv4.dst_addr.as_ptr(), t.dst_ip.as_mut_ptr(), 4);
        t.packet_length = packet_length;
        t.ip_version = IpVersion::V4.as_u8();
        t.protocol = ipv4.proto;

        let (src_port, dst_port, tcp_flags, l4_header_len, transport_len) = match ipv4.proto {
            value if value == IpProto::Tcp as u8 => parse_tcp(start, end, l4_start, transport_len)?,
            value if value == IpProto::Udp as u8 => parse_udp(start, end, l4_start, transport_len)?,
            _ => (0, 0, 0, 0, 0),
        };

        t.payload_length = (transport_len as u32).saturating_sub(l4_header_len as u32);
        t.src_port = src_port;
        t.dst_port = dst_port;
        t.tcp_flags = tcp_flags;
    }

    Some(())
}

#[inline(always)]
unsafe fn parse_ipv6_packet(start: usize, end: usize, target: *mut ParsedPacket) -> Option<()> {
    if start + IPV6_HEADER_END > end {
        return None;
    }

    unsafe {
        let ipv6 = &*((start + IPV6_HEADER_START) as *const Ipv6Hdr);
        let payload_len = read_be_u16(start, end, IPV6_HEADER_START + 4)? as usize;
        let packet_length = (IPV6_HEADER_END - IPV6_HEADER_START + payload_len) as u32;

        let t = &mut *target;
        ptr::copy_nonoverlapping(ipv6.src_addr.as_ptr(), t.src_ip.as_mut_ptr(), 16);
        ptr::copy_nonoverlapping(ipv6.dst_addr.as_ptr(), t.dst_ip.as_mut_ptr(), 16);
        t.packet_length = packet_length;
        t.ip_version = IpVersion::V6.as_u8();
        t.protocol = ipv6.next_hdr;

        let (src_port, dst_port, tcp_flags, l4_header_len, transport_len) = match ipv6.next_hdr {
            value if value == IpProto::Tcp as u8 => parse_tcp(start, end, IPV6_TCP_HEADER_START, payload_len)?,
            value if value == IpProto::Udp as u8 => parse_udp(start, end, IPV6_UDP_HEADER_START, payload_len)?,
            _ => (0, 0, 0, 0, 0),
        };

        t.payload_length = (transport_len as u32).saturating_sub(l4_header_len as u32);
        t.src_port = src_port;
        t.dst_port = dst_port;
        t.tcp_flags = tcp_flags;
    }

    Some(())
}

#[inline(always)]
unsafe fn parse_ipv4_header_len(start: usize, end: usize) -> Option<usize> {
    if start + IPV4_HEADER_START + 1 > end {
        return None;
    }

    let version_ihl = unsafe { *((start + IPV4_HEADER_START) as *const u8) };
    let version = version_ihl >> 4;
    let ihl = (version_ihl & 0x0f) as usize;
    if version != 4 || !(5..=15).contains(&ihl) {
        return None;
    }

    let header_len = ihl * 4;
    if start + IPV4_HEADER_START + header_len > end {
        return None;
    }

    Some(header_len)
}

#[inline(always)]
unsafe fn parse_tcp(
    start: usize,
    end: usize,
    tcp_start: usize,
    transport_len: usize,
) -> Option<(u16, u16, u8, usize, usize)> {
    if start + tcp_start + size_of::<TcpHdr>() > end {
        return None;
    }
    if transport_len < size_of::<TcpHdr>() {
        return None;
    }

    unsafe {
        let tcp = &*((start + tcp_start) as *const TcpHdr);
        let data_offset = (*((start + tcp_start + 12) as *const u8) >> 4) as usize;
        if !(5..=15).contains(&data_offset) {
            return None;
        }
        let header_len = data_offset * 4;
        if header_len > transport_len || start + tcp_start + header_len > end {
            return None;
        }
        let flags = *((start + tcp_start + 13) as *const u8);
        Some((
            u16::from_be_bytes(tcp.source),
            u16::from_be_bytes(tcp.dest),
            flags,
            header_len,
            transport_len,
        ))
    }
}

#[inline(always)]
unsafe fn parse_udp(
    start: usize,
    end: usize,
    udp_start: usize,
    transport_len: usize,
) -> Option<(u16, u16, u8, usize, usize)> {
    if start + udp_start + size_of::<UdpHdr>() > end {
        return None;
    }
    if transport_len < size_of::<UdpHdr>() {
        return None;
    }

    let udp = unsafe { &*((start + udp_start) as *const UdpHdr) };
    let udp_len = udp.len() as usize;
    if udp_len < size_of::<UdpHdr>() || udp_len > transport_len {
        return None;
    }
    Some((udp.src_port(), udp.dst_port(), 0u8, 8usize, udp_len))
}

#[inline(always)]
fn read_be_u16(start: usize, end: usize, offset: usize) -> Option<u16> {
    if start + offset + 2 > end {
        return None;
    }
    let hi = unsafe { *((start + offset) as *const u8) };
    let lo = unsafe { *((start + offset + 1) as *const u8) };
    Some(u16::from_be_bytes([hi, lo]))
}
