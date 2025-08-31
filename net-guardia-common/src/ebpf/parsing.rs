use aya_ebpf::helpers::bpf_ktime_get_ns;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::{
    define::offset::*,
    model::event::{Event, IPv4Event, IPv6Event},
};

pub fn parse_packet(start: usize, end: usize, target: *mut Event) -> Result<(), ()> {
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
unsafe fn parse_ipv4_packet(start: usize, end: usize, target: *mut Event) -> Result<(), ()> {
    unsafe {
        if start + IPV4_HEADER_END > end {
            return Err(());
        }

        let ipv4 = &*((start + IPV4_HEADER_START) as *const Ipv4Hdr);

        let (source_port, destination_port) = match ipv4.proto {
            IpProto::Tcp => parse_tcp_port(start, end, IPV4_TCP_HEADER_START, IPV4_TCP_HEADER_END)?,
            IpProto::Udp => parse_udp_port(start, end, IPV4_UDP_HEADER_START, IPV4_UDP_HEADER_END)?,
            _ => return Err(()),
        };

        *(target as *mut u32) = 0;

        let ipv4_data_ptr = (target as *mut u8).add(16);

        core::ptr::write(ipv4_data_ptr as *mut IpProto, ipv4.proto);
        core::ptr::copy_nonoverlapping(
            ipv4.src_addr.as_ptr(),
            ipv4_data_ptr.add(core::mem::offset_of!(IPv4Event, source_ip)),
            4,
        );
        core::ptr::copy_nonoverlapping(
            ipv4.dst_addr.as_ptr(),
            ipv4_data_ptr.add(core::mem::offset_of!(IPv4Event, destination_ip)),
            4,
        );
        core::ptr::write(
            ipv4_data_ptr.add(core::mem::offset_of!(IPv4Event, source_port)) as *mut u16,
            source_port,
        );
        core::ptr::write(
            ipv4_data_ptr.add(core::mem::offset_of!(IPv4Event, destination_port)) as *mut u16,
            destination_port,
        );
        core::ptr::write(
            ipv4_data_ptr.add(core::mem::offset_of!(IPv4Event, len)) as *mut u32,
            (end - start) as u32,
        );
        core::ptr::write(
            ipv4_data_ptr.add(core::mem::offset_of!(IPv4Event, timestamp)) as *mut u64,
            bpf_ktime_get_ns(),
        );

        Ok(())
    }
}

#[inline(always)]
unsafe fn parse_ipv6_packet(start: usize, end: usize, target: *mut Event) -> Result<(), ()> {
    unsafe {
        if start + IPV6_HEADER_END > end {
            return Err(());
        }

        let ipv6 = &*((start + IPV6_HEADER_START) as *const Ipv6Hdr);

        let (source_port, destination_port) = match ipv6.next_hdr {
            IpProto::Tcp => parse_tcp_port(start, end, IPV6_TCP_HEADER_START, IPV6_TCP_HEADER_END)?,
            IpProto::Udp => parse_udp_port(start, end, IPV6_UDP_HEADER_START, IPV6_UDP_HEADER_END)?,
            _ => return Err(()),
        };

        *(target as *mut u32) = 1;

        let ipv6_data_ptr = (target as *mut u8).add(16);

        core::ptr::write(ipv6_data_ptr as *mut IpProto, ipv6.next_hdr);
        core::ptr::copy_nonoverlapping(
            ipv6.src_addr.as_ptr(),
            ipv6_data_ptr.add(core::mem::offset_of!(IPv6Event, source_ip)),
            16,
        );
        core::ptr::copy_nonoverlapping(
            ipv6.dst_addr.as_ptr(),
            ipv6_data_ptr.add(core::mem::offset_of!(IPv6Event, destination_ip)),
            16,
        );
        core::ptr::write(
            ipv6_data_ptr.add(core::mem::offset_of!(IPv6Event, source_port)) as *mut u16,
            source_port,
        );
        core::ptr::write(
            ipv6_data_ptr.add(core::mem::offset_of!(IPv6Event, destination_port)) as *mut u16,
            destination_port,
        );
        core::ptr::write(
            ipv6_data_ptr.add(core::mem::offset_of!(IPv6Event, len)) as *mut u32,
            (end - start) as u32,
        );
        core::ptr::write(
            ipv6_data_ptr.add(core::mem::offset_of!(IPv6Event, timestamp)) as *mut u64,
            bpf_ktime_get_ns(),
        );

        Ok(())
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
