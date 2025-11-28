use common::model::event::{Event, IPv4Event, IPv6Event};
use network_types::ip::IpProto;

/// Parse raw packet bytes into an Event
pub fn parse_packet(packet_data: &[u8]) -> Option<Event> {
    // Minimum ethernet header size
    if packet_data.len() < 14 {
        tracing::trace!("Packet too small: {} bytes", packet_data.len());
        return None;
    }

    // Get ethernet type
    let eth_type = u16::from_be_bytes([packet_data[12], packet_data[13]]);

    // Get current timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();

    match eth_type {
        // IPv4
        0x0800 => {
            tracing::trace!("Parsing IPv4 packet, {} bytes", packet_data.len());
            parse_ipv4(packet_data, timestamp)
        }
        // IPv6
        0x86DD => {
            tracing::trace!("Parsing IPv6 packet, {} bytes", packet_data.len());
            parse_ipv6(packet_data, timestamp)
        }
        // Not IP packet
        _ => {
            tracing::debug!("Skipping non-IP packet: EtherType=0x{:04x}, {} bytes", eth_type, packet_data.len());
            None
        }
    }
}

fn parse_ipv4(packet_data: &[u8], timestamp: u64) -> Option<Event> {
    // Ethernet header (14) + minimum IPv4 header (20) = 34 bytes
    if packet_data.len() < 34 {
        return None;
    }

    let ip_header = &packet_data[14..];

    // Parse IPv4 header
    let protocol = ip_header[9];
    let source_ip = u32::from_be_bytes([
        ip_header[12],
        ip_header[13],
        ip_header[14],
        ip_header[15],
    ]);
    let destination_ip = u32::from_be_bytes([
        ip_header[16],
        ip_header[17],
        ip_header[18],
        ip_header[19],
    ]);

    // Get IP header length
    let ihl = (ip_header[0] & 0x0F) as usize * 4;

    // Total length
    let total_len = u16::from_be_bytes([ip_header[2], ip_header[3]]) as u32;

    // Parse transport layer (TCP/UDP)
    let (source_port, destination_port) = if packet_data.len() >= 14 + ihl + 4 {
        let transport_header = &ip_header[ihl..];
        let src_port = u16::from_be_bytes([transport_header[0], transport_header[1]]);
        let dst_port = u16::from_be_bytes([transport_header[2], transport_header[3]]);
        (src_port, dst_port)
    } else {
        (0, 0)
    };

    let event = IPv4Event {
        protocol: unsafe { std::mem::transmute::<u8, IpProto>(protocol) },
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        len: total_len,
        timestamp,
    };

    Some(Event::IPv4(event))
}

fn parse_ipv6(packet_data: &[u8], timestamp: u64) -> Option<Event> {
    // Ethernet header (14) + minimum IPv6 header (40) = 54 bytes
    if packet_data.len() < 54 {
        return None;
    }

    let ip_header = &packet_data[14..];

    // Parse IPv6 header
    let protocol = ip_header[6];

    // Source IPv6 address (16 bytes starting at offset 8)
    let mut source_ip_bytes = [0u8; 16];
    source_ip_bytes.copy_from_slice(&ip_header[8..24]);
    let source_ip = u128::from_be_bytes(source_ip_bytes);

    // Destination IPv6 address (16 bytes starting at offset 24)
    let mut dest_ip_bytes = [0u8; 16];
    dest_ip_bytes.copy_from_slice(&ip_header[24..40]);
    let destination_ip = u128::from_be_bytes(dest_ip_bytes);

    // Payload length
    let payload_len = u16::from_be_bytes([ip_header[4], ip_header[5]]) as u32;
    let total_len = payload_len + 40; // IPv6 header is always 40 bytes

    // Parse transport layer (TCP/UDP)
    let (source_port, destination_port) = if packet_data.len() >= 54 + 4 {
        let transport_header = &ip_header[40..];
        let src_port = u16::from_be_bytes([transport_header[0], transport_header[1]]);
        let dst_port = u16::from_be_bytes([transport_header[2], transport_header[3]]);
        (src_port, dst_port)
    } else {
        (0, 0)
    };

    let event = IPv6Event {
        protocol: unsafe { std::mem::transmute::<u8, IpProto>(protocol) },
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        len: total_len,
        timestamp,
    };

    Some(Event::IPv6(event))
}
