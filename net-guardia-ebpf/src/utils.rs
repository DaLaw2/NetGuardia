use network_types::ip::Ipv4Hdr;
use net_guardia_common::model::pseudo_header::PseudoHeader;

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
