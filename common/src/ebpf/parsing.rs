use core::mem::size_of;

use aya_ebpf::helpers::bpf_ktime_get_ns;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

use crate::define::offset::*;
use crate::model::parsed_packet::ParsedPacket;

#[allow(clippy::result_unit_err, clippy::not_unsafe_ptr_arg_deref)]
pub fn parse_packet(start: usize, end: usize, target: *mut ParsedPacket) -> Result<(), ()> {
    unsafe {
        if start + ETHER_HEADER_END > end {
            return Err(());
        }
        let eth = &*((start + ETHER_HEADER_START) as *const EthHdr);
        let ether_type = eth.ether_type().map_err(|_| ())?;
        match ether_type {
            EtherType::Ipv4 => parse_ipv4_packet(start, end, target),
            EtherType::Ipv6 => parse_ipv6_packet(start, end, target),
            _ => Err(()),
        }
    }
}

#[inline(always)]
unsafe fn parse_ipv4_packet(start: usize, end: usize, target: *mut ParsedPacket) -> Result<(), ()> {
    if start + IPV4_HEADER_END > end {
        return Err(());
    }

    unsafe {
        let ipv4 = &*((start + IPV4_HEADER_START) as *const Ipv4Hdr);
        let ipv4_header_len = parse_ipv4_header_len(start, end)?;
        let l4_start = IPV4_HEADER_START + ipv4_header_len;
        let packet_length = (end - start) as u32;

        let t = &mut *target;
        t.timestamp_ns = bpf_ktime_get_ns();
        core::ptr::copy_nonoverlapping(ipv4.src_addr.as_ptr(), t.src_ip.as_mut_ptr(), 4);
        core::ptr::copy_nonoverlapping(ipv4.dst_addr.as_ptr(), t.dst_ip.as_mut_ptr(), 4);
        t.packet_length = packet_length;
        t.ip_version = 4;
        t.protocol = ipv4.proto;

        let (src_port, dst_port, tcp_flags, l4_header_len) = match ipv4.proto {
            IpProto::Tcp => parse_tcp(start, end, l4_start)?,
            IpProto::Udp => parse_udp(start, end, l4_start)?,
            _ => (0, 0, 0, 0),
        };

        t.payload_length = packet_length.saturating_sub((l4_start + l4_header_len) as u32);
        t.src_port = src_port;
        t.dst_port = dst_port;
        t.tcp_flags = tcp_flags;
    }

    Ok(())
}

#[inline(always)]
unsafe fn parse_ipv6_packet(start: usize, end: usize, target: *mut ParsedPacket) -> Result<(), ()> {
    if start + IPV6_HEADER_END > end {
        return Err(());
    }

    unsafe {
        let ipv6 = &*((start + IPV6_HEADER_START) as *const Ipv6Hdr);
        let packet_length = (end - start) as u32;

        let t = &mut *target;
        t.timestamp_ns = bpf_ktime_get_ns();
        core::ptr::copy_nonoverlapping(ipv6.src_addr.as_ptr(), t.src_ip.as_mut_ptr(), 16);
        core::ptr::copy_nonoverlapping(ipv6.dst_addr.as_ptr(), t.dst_ip.as_mut_ptr(), 16);
        t.packet_length = packet_length;
        t.ip_version = 6;
        t.protocol = ipv6.next_hdr;

        let (src_port, dst_port, tcp_flags, l4_header_len) = match ipv6.next_hdr {
            IpProto::Tcp => parse_tcp(start, end, IPV6_TCP_HEADER_START)?,
            IpProto::Udp => parse_udp(start, end, IPV6_UDP_HEADER_START)?,
            _ => (0, 0, 0, 0),
        };

        t.payload_length = packet_length.saturating_sub((IPV6_HEADER_END + l4_header_len) as u32);
        t.src_port = src_port;
        t.dst_port = dst_port;
        t.tcp_flags = tcp_flags;
    }

    Ok(())
}

#[inline(always)]
#[allow(clippy::manual_range_contains)]
unsafe fn parse_ipv4_header_len(start: usize, end: usize) -> Result<usize, ()> {
    if start + IPV4_HEADER_START + 1 > end {
        return Err(());
    }

    let version_ihl = unsafe { *((start + IPV4_HEADER_START) as *const u8) };
    let version = version_ihl >> 4;
    let ihl = (version_ihl & 0x0f) as usize;
    if version != 4 || ihl < 5 || ihl > 15 {
        return Err(());
    }

    let header_len = ihl * 4;
    if start + IPV4_HEADER_START + header_len > end {
        return Err(());
    }

    Ok(header_len)
}

#[inline(always)]
#[allow(clippy::manual_range_contains)]
unsafe fn parse_tcp(start: usize, end: usize, tcp_start: usize) -> Result<(u16, u16, u8, usize), ()> {
    if start + tcp_start + size_of::<TcpHdr>() > end {
        return Err(());
    }

    unsafe {
        let tcp = &*((start + tcp_start) as *const TcpHdr);
        let data_offset = (*((start + tcp_start + 12) as *const u8) >> 4) as usize;
        if data_offset < 5 || data_offset > 15 {
            return Err(());
        }
        let header_len = data_offset * 4;
        if start + tcp_start + header_len > end {
            return Err(());
        }
        let flags = *((start + tcp_start + 13) as *const u8);
        Ok((
            u16::from_be_bytes(tcp.source),
            u16::from_be_bytes(tcp.dest),
            flags,
            header_len,
        ))
    }
}

#[inline(always)]
unsafe fn parse_udp(start: usize, end: usize, udp_start: usize) -> Result<(u16, u16, u8, usize), ()> {
    if start + udp_start + size_of::<UdpHdr>() > end {
        return Err(());
    }

    let udp = unsafe { &*((start + udp_start) as *const UdpHdr) };
    Ok((udp.src_port(), udp.dst_port(), 0u8, 8usize))
}
