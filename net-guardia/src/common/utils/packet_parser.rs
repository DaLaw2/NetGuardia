use crate::domain::data_plane::ip_version::IpVersion;
use crate::domain::data_plane::user_packet::UserPacket;

const ETH_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_MIN_HEADER_LEN: u16 = 20;
const UDP_HEADER_LEN: u16 = 8;

pub fn parse_packet_at(packet_data: &[u8], timestamp_us: u64) -> Option<(UserPacket, usize)> {
    if packet_data.len() < ETH_HEADER_LEN {
        return None;
    }

    let eth_type = u16::from_be_bytes([packet_data[12], packet_data[13]]);

    match eth_type {
        0x0800 => parse_ipv4(packet_data, timestamp_us),
        0x86DD => parse_ipv6(packet_data, timestamp_us),
        _ => None,
    }
}

fn parse_ipv4(packet_data: &[u8], timestamp_us: u64) -> Option<(UserPacket, usize)> {
    if packet_data.len() < ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN {
        return None;
    }

    let ip_header = &packet_data[ETH_HEADER_LEN..];
    if ip_header[0] >> 4 != 4 {
        return None;
    }

    let protocol_byte = ip_header[9];
    let ihl = (ip_header[0] & 0x0F) as usize * 4;
    let total_len = u16::from_be_bytes([ip_header[2], ip_header[3]]) as u32;
    let total_len_usize = total_len as usize;

    if ihl < IPV4_MIN_HEADER_LEN || total_len_usize < ihl || packet_data.len() < ETH_HEADER_LEN + total_len_usize {
        return None;
    }

    let mut src_ip = [0u8; 16];
    src_ip[..4].copy_from_slice(&ip_header[12..16]);
    let mut dst_ip = [0u8; 16];
    dst_ip[..4].copy_from_slice(&ip_header[16..20]);

    if total_len_usize < ihl + 4 {
        return None;
    }

    let transport_header = &ip_header[ihl..];
    let src_port = u16::from_be_bytes([transport_header[0], transport_header[1]]);
    let dst_port = u16::from_be_bytes([transport_header[2], transport_header[3]]);

    let (tcp_flags, tcp_window_size, header_length, transport_len) = match protocol_byte {
        6 => {
            if total_len_usize < ihl + TCP_MIN_HEADER_LEN as usize {
                return None;
            }

            let data_offset = (transport_header[12] >> 4) as u16 * 4;
            if data_offset < TCP_MIN_HEADER_LEN || total_len_usize < ihl + data_offset as usize {
                return None;
            }
            let flags = transport_header[13];
            let window = u16::from_be_bytes([transport_header[14], transport_header[15]]);

            (flags, window, data_offset, total_len.saturating_sub(ihl as u32))
        }
        17 => {
            if total_len_usize < ihl + UDP_HEADER_LEN as usize {
                return None;
            }
            let udp_len = u16::from_be_bytes([transport_header[4], transport_header[5]]) as u32;
            if udp_len < UDP_HEADER_LEN as u32 || total_len < ihl as u32 + udp_len {
                return None;
            }
            (0u8, 0, UDP_HEADER_LEN, udp_len)
        }
        _ => return None,
    };

    let payload_length = transport_len.saturating_sub(header_length as u32);
    let payload_start = ETH_HEADER_LEN + ihl + header_length as usize;

    let packet = UserPacket {
        ip_version: IpVersion::V4,
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
    if packet_data.len() < ETH_HEADER_LEN + IPV6_HEADER_LEN {
        return None;
    }

    let ip_header = &packet_data[ETH_HEADER_LEN..];
    if ip_header[0] >> 4 != 6 {
        return None;
    }

    let protocol_byte = ip_header[6];

    let mut src_ip = [0u8; 16];
    src_ip.copy_from_slice(&ip_header[8..24]);

    let mut dst_ip = [0u8; 16];
    dst_ip.copy_from_slice(&ip_header[24..40]);

    let payload_len = u16::from_be_bytes([ip_header[4], ip_header[5]]) as u32;
    let total_len = payload_len + IPV6_HEADER_LEN as u32;
    let total_len_usize = total_len as usize;

    if packet_data.len() < ETH_HEADER_LEN + total_len_usize || payload_len < 4 {
        return None;
    }

    let transport_header = &ip_header[IPV6_HEADER_LEN..];
    let src_port = u16::from_be_bytes([transport_header[0], transport_header[1]]);
    let dst_port = u16::from_be_bytes([transport_header[2], transport_header[3]]);

    let (tcp_flags, tcp_window_size, header_length, transport_len) = match protocol_byte {
        6 => {
            if payload_len < TCP_MIN_HEADER_LEN as u32 {
                return None;
            }

            let data_offset = (transport_header[12] >> 4) as u16 * 4;
            if data_offset < TCP_MIN_HEADER_LEN || payload_len < data_offset as u32 {
                return None;
            }
            let flags = transport_header[13];
            let window = u16::from_be_bytes([transport_header[14], transport_header[15]]);

            (flags, window, data_offset, payload_len)
        }
        17 => {
            if payload_len < UDP_HEADER_LEN as u32 {
                return None;
            }
            let udp_len = u16::from_be_bytes([transport_header[4], transport_header[5]]) as u32;
            if udp_len < UDP_HEADER_LEN as u32 || udp_len > payload_len {
                return None;
            }
            (0u8, 0, UDP_HEADER_LEN, udp_len)
        }
        _ => return None,
    };

    let payload_length = transport_len.saturating_sub(header_length as u32);
    let payload_start = ETH_HEADER_LEN + IPV6_HEADER_LEN + header_length as usize;

    let packet = UserPacket {
        ip_version: IpVersion::V6,
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TIMESTAMP_US: u64 = 1_700_000_000_000_000;

    fn parse_packet(packet_data: &[u8]) -> Option<(UserPacket, usize)> {
        parse_packet_at(packet_data, TEST_TIMESTAMP_US)
    }

    fn ipv4_tcp_frame(ihl_words: u8, total_len: u16, tcp_offset_words: u8, frame_len: usize) -> Vec<u8> {
        let mut frame = vec![0u8; frame_len];
        frame[12] = 0x08;
        frame[13] = 0x00;

        let ip_start = ETH_HEADER_LEN;
        frame[ip_start] = 0x40 | ihl_words;
        frame[ip_start + 2..ip_start + 4].copy_from_slice(&total_len.to_be_bytes());
        frame[ip_start + 9] = 6;
        frame[ip_start + 12..ip_start + 16].copy_from_slice(&[192, 0, 2, 1]);
        frame[ip_start + 16..ip_start + 20].copy_from_slice(&[198, 51, 100, 2]);

        let tcp_start = ip_start + usize::from(ihl_words) * 4;
        if frame.len() >= tcp_start + 20 {
            frame[tcp_start..tcp_start + 2].copy_from_slice(&443u16.to_be_bytes());
            frame[tcp_start + 2..tcp_start + 4].copy_from_slice(&8443u16.to_be_bytes());
            frame[tcp_start + 12] = tcp_offset_words << 4;
            frame[tcp_start + 13] = 0x18;
            frame[tcp_start + 14..tcp_start + 16].copy_from_slice(&1024u16.to_be_bytes());
        }
        frame
    }

    fn ipv4_udp_frame(total_len: u16, udp_len: u16, frame_len: usize) -> Vec<u8> {
        let mut frame = vec![0u8; frame_len];
        frame[12] = 0x08;
        frame[13] = 0x00;

        let ip_start = ETH_HEADER_LEN;
        frame[ip_start] = 0x45;
        frame[ip_start + 2..ip_start + 4].copy_from_slice(&total_len.to_be_bytes());
        frame[ip_start + 9] = 17;
        frame[ip_start + 12..ip_start + 16].copy_from_slice(&[192, 0, 2, 1]);
        frame[ip_start + 16..ip_start + 20].copy_from_slice(&[198, 51, 100, 2]);

        let udp_start = ip_start + IPV4_MIN_HEADER_LEN;
        if frame.len() >= udp_start + UDP_HEADER_LEN as usize {
            frame[udp_start..udp_start + 2].copy_from_slice(&53u16.to_be_bytes());
            frame[udp_start + 2..udp_start + 4].copy_from_slice(&5353u16.to_be_bytes());
            frame[udp_start + 4..udp_start + 6].copy_from_slice(&udp_len.to_be_bytes());
        }
        frame
    }

    fn ipv6_udp_frame(payload_len: u16, udp_len: u16, frame_len: usize) -> Vec<u8> {
        let mut frame = vec![0u8; frame_len];
        frame[12] = 0x86;
        frame[13] = 0xdd;

        let ip_start = ETH_HEADER_LEN;
        frame[ip_start] = 0x60;
        frame[ip_start + 4..ip_start + 6].copy_from_slice(&payload_len.to_be_bytes());
        frame[ip_start + 6] = 17;
        frame[ip_start + 7] = 64;
        frame[ip_start + 8..ip_start + 24]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        frame[ip_start + 24..ip_start + 40]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        let udp_start = ip_start + IPV6_HEADER_LEN;
        if frame.len() >= udp_start + UDP_HEADER_LEN as usize {
            frame[udp_start..udp_start + 2].copy_from_slice(&53u16.to_be_bytes());
            frame[udp_start + 2..udp_start + 4].copy_from_slice(&5353u16.to_be_bytes());
            frame[udp_start + 4..udp_start + 6].copy_from_slice(&udp_len.to_be_bytes());
        }
        frame
    }

    #[test]
    fn rejects_ipv4_header_shorter_than_minimum() {
        let frame = ipv4_tcp_frame(4, 40, 5, ETH_HEADER_LEN + 40);

        assert!(parse_packet(&frame).is_none());
    }

    #[test]
    fn rejects_ipv4_total_length_beyond_received_frame() {
        let frame = ipv4_tcp_frame(5, 64, 5, ETH_HEADER_LEN + 40);

        assert!(parse_packet(&frame).is_none());
    }

    #[test]
    fn rejects_tcp_data_offset_shorter_than_minimum() {
        let frame = ipv4_tcp_frame(5, 40, 4, ETH_HEADER_LEN + 40);

        assert!(parse_packet(&frame).is_none());
    }

    #[test]
    fn parses_valid_ipv4_tcp_frame() {
        let frame = ipv4_tcp_frame(5, 44, 5, ETH_HEADER_LEN + 44);
        let (packet, payload_start) = parse_packet(&frame).expect("valid IPv4 TCP packet");

        assert_eq!(packet.ip_version, IpVersion::V4);
        assert_eq!(packet.protocol, 6);
        assert_eq!(packet.src_port, 443);
        assert_eq!(packet.dst_port, 8443);
        assert_eq!(packet.packet_length, 44);
        assert_eq!(packet.payload_length, 4);
        assert_eq!(
            payload_start,
            ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + TCP_MIN_HEADER_LEN as usize
        );
    }

    #[test]
    fn parses_ipv4_udp_payload_from_udp_length() {
        let frame = ipv4_udp_frame(40, 12, ETH_HEADER_LEN + 40);
        let (packet, payload_start) = parse_packet(&frame).expect("valid IPv4 UDP packet");

        assert_eq!(packet.protocol, 17);
        assert_eq!(packet.payload_length, 4);
        assert_eq!(
            payload_start,
            ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN as usize
        );
    }

    #[test]
    fn rejects_ipv4_udp_length_beyond_ip_payload() {
        let frame = ipv4_udp_frame(32, 20, ETH_HEADER_LEN + 32);

        assert!(parse_packet(&frame).is_none());
    }

    #[test]
    fn parses_ipv6_udp_payload_from_udp_length() {
        let frame = ipv6_udp_frame(20, 12, ETH_HEADER_LEN + IPV6_HEADER_LEN + 20);
        let (packet, payload_start) = parse_packet(&frame).expect("valid IPv6 UDP packet");

        assert_eq!(packet.ip_version, IpVersion::V6);
        assert_eq!(packet.protocol, 17);
        assert_eq!(packet.payload_length, 4);
        assert_eq!(
            payload_start,
            ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN as usize
        );
    }

    #[test]
    fn rejects_ipv6_udp_length_beyond_payload() {
        let frame = ipv6_udp_frame(12, 20, ETH_HEADER_LEN + IPV6_HEADER_LEN + 12);

        assert!(parse_packet(&frame).is_none());
    }
}
