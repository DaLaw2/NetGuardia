use std::mem;
use std::time;

use common::model::event::{Event, IPv4Event, IPv6Event, TcpFlags};
use network_types::ip::IpProto;

pub fn parse_packet(packet_data: &[u8]) -> Option<(Event, usize)> {
    if packet_data.len() < 14 {
        return None;
    }

    let eth_type = u16::from_be_bytes([packet_data[12], packet_data[13]]);

    let timestamp_us = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .ok()?
        .as_micros() as u64;

    match eth_type {
        0x0800 => parse_ipv4(packet_data, timestamp_us),
        0x86DD => parse_ipv6(packet_data, timestamp_us),
        _ => None,
    }
}

fn parse_ipv4(packet_data: &[u8], timestamp_us: u64) -> Option<(Event, usize)> {
    if packet_data.len() < 34 {
        return None;
    }

    let ip_header = &packet_data[14..];

    let protocol_byte = ip_header[9];
    let protocol = unsafe { mem::transmute::<u8, IpProto>(protocol_byte) };

    let src_ip = u32::from_be_bytes([ip_header[12], ip_header[13], ip_header[14], ip_header[15]]);
    let dst_ip = u32::from_be_bytes([ip_header[16], ip_header[17], ip_header[18], ip_header[19]]);

    if protocol_byte != 6 && protocol_byte != 17 {
        return None;
    }

    let ihl = (ip_header[0] & 0x0F) as usize * 4;
    let total_len = u16::from_be_bytes([ip_header[2], ip_header[3]]) as u32;

    if packet_data.len() < 14 + ihl + 4 {
        return None;
    }

    let transport_header = &ip_header[ihl..];
    let src_port = u16::from_be_bytes([transport_header[0], transport_header[1]]);
    let dst_port = u16::from_be_bytes([transport_header[2], transport_header[3]]);

    let (tcp_flags, tcp_window_size, header_length) = if protocol_byte == 6 {
        if packet_data.len() < 14 + ihl + 20 {
            return None;
        }

        let data_offset = (transport_header[12] >> 4) as u16 * 4;
        let flags = TcpFlags::from_byte(transport_header[13]);
        let window = u16::from_be_bytes([transport_header[14], transport_header[15]]);

        (flags, window, data_offset)
    } else if protocol_byte == 17 {
        (TcpFlags::default(), 0, 8)
    } else {
        (TcpFlags::default(), 0, 0)
    };

    let payload_length = total_len.saturating_sub(ihl as u32 + header_length as u32);
    let payload_start = 14 + ihl + header_length as usize;

    let event = IPv4Event {
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        packet_length: total_len,
        payload_length,
        header_length,
        timestamp_us,
        tcp_flags,
        tcp_window_size,
        is_forward: false,
    };

    Some((Event::IPv4(event), payload_start))
}

fn parse_ipv6(packet_data: &[u8], timestamp_us: u64) -> Option<(Event, usize)> {
    if packet_data.len() < 54 {
        return None;
    }

    let ip_header = &packet_data[14..];

    let protocol_byte = ip_header[6];
    let protocol = unsafe { mem::transmute::<u8, IpProto>(protocol_byte) };

    let mut source_ip_bytes = [0u8; 16];
    source_ip_bytes.copy_from_slice(&ip_header[8..24]);
    let src_ip = u128::from_be_bytes(source_ip_bytes);

    let mut dest_ip_bytes = [0u8; 16];
    dest_ip_bytes.copy_from_slice(&ip_header[24..40]);
    let dst_ip = u128::from_be_bytes(dest_ip_bytes);

    if protocol_byte != 6 && protocol_byte != 17 {
        return None;
    }

    let payload_len = u16::from_be_bytes([ip_header[4], ip_header[5]]) as u32;
    let total_len = payload_len + 40;

    if packet_data.len() < 54 + 4 {
        return None;
    }

    let transport_header = &ip_header[40..];
    let src_port = u16::from_be_bytes([transport_header[0], transport_header[1]]);
    let dst_port = u16::from_be_bytes([transport_header[2], transport_header[3]]);

    let (tcp_flags, tcp_window_size, header_length) = if protocol_byte == 6 {
        if packet_data.len() < 54 + 20 {
            return None;
        }

        let data_offset = (transport_header[12] >> 4) as u16 * 4;
        let flags = TcpFlags::from_byte(transport_header[13]);
        let window = u16::from_be_bytes([transport_header[14], transport_header[15]]);

        (flags, window, data_offset)
    } else if protocol_byte == 17 {
        (TcpFlags::default(), 0, 8)
    } else {
        (TcpFlags::default(), 0, 0)
    };

    let payload_length = total_len.saturating_sub(40 + header_length as u32);
    let payload_start = 14 + 40 + header_length as usize;

    let event = IPv6Event {
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        packet_length: total_len,
        payload_length,
        header_length,
        timestamp_us,
        tcp_flags,
        tcp_window_size,
        is_forward: false,
    };

    Some((Event::IPv6(event), payload_start))
}

pub fn format_ipv4(addr: u32) -> String {
    let bytes = addr.to_be_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3],)
}

pub fn format_ipv6(addr: u128) -> String {
    let bytes = addr.to_be_bytes();
    format!(
        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}
