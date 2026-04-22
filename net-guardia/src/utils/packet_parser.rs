use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::data_plane::user_packet::UserPacket;

pub fn parse_packet(packet_data: &[u8]) -> Option<(UserPacket, usize)> {
    if packet_data.len() < 14 {
        return None;
    }

    let eth_type = u16::from_be_bytes([packet_data[12], packet_data[13]]);

    let timestamp_us = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_micros() as u64;

    match eth_type {
        0x0800 => parse_ipv4(packet_data, timestamp_us),
        0x86DD => parse_ipv6(packet_data, timestamp_us),
        _ => None,
    }
}

fn parse_ipv4(packet_data: &[u8], timestamp_us: u64) -> Option<(UserPacket, usize)> {
    if packet_data.len() < 34 {
        return None;
    }

    let ip_header = &packet_data[14..];

    let protocol_byte = ip_header[9];

    let mut src_ip = [0u8; 16];
    src_ip[..4].copy_from_slice(&ip_header[12..16]);
    let mut dst_ip = [0u8; 16];
    dst_ip[..4].copy_from_slice(&ip_header[16..20]);

    let ihl = (ip_header[0] & 0x0F) as usize * 4;
    let total_len = u16::from_be_bytes([ip_header[2], ip_header[3]]) as u32;

    if protocol_byte != 6 && protocol_byte != 17 {
        return None;
    }

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
        let flags = transport_header[13];
        let window = u16::from_be_bytes([transport_header[14], transport_header[15]]);

        (flags, window, data_offset)
    } else if protocol_byte == 17 {
        (0u8, 0, 8)
    } else {
        (0u8, 0, 0)
    };

    let payload_length = total_len.saturating_sub(ihl as u32 + header_length as u32);
    let payload_start = 14 + ihl + header_length as usize;

    let packet = UserPacket {
        ip_version: 4,
        protocol: protocol_byte,
        tcp_flags,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        packet_length: total_len,
        payload_length,
        header_length,
        tcp_window_size,
        timestamp_us,
        is_forward: false,
    };

    Some((packet, payload_start))
}

fn parse_ipv6(packet_data: &[u8], timestamp_us: u64) -> Option<(UserPacket, usize)> {
    if packet_data.len() < 54 {
        return None;
    }

    let ip_header = &packet_data[14..];

    let protocol_byte = ip_header[6];

    let mut src_ip = [0u8; 16];
    src_ip.copy_from_slice(&ip_header[8..24]);

    let mut dst_ip = [0u8; 16];
    dst_ip.copy_from_slice(&ip_header[24..40]);

    let payload_len = u16::from_be_bytes([ip_header[4], ip_header[5]]) as u32;
    let total_len = payload_len + 40;

    if protocol_byte != 6 && protocol_byte != 17 {
        return None;
    }

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
        let flags = transport_header[13];
        let window = u16::from_be_bytes([transport_header[14], transport_header[15]]);

        (flags, window, data_offset)
    } else if protocol_byte == 17 {
        (0u8, 0, 8)
    } else {
        (0u8, 0, 0)
    };

    let payload_length = total_len.saturating_sub(40 + header_length as u32);
    let payload_start = 14 + 40 + header_length as usize;

    let packet = UserPacket {
        ip_version: 6,
        protocol: protocol_byte,
        tcp_flags,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        packet_length: total_len,
        payload_length,
        header_length,
        tcp_window_size,
        timestamp_us,
        is_forward: false,
    };

    Some((packet, payload_start))
}
