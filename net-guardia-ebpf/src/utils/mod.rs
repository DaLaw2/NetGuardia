use network_types::eth::EthHdr;
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};

pub mod change_destination;
pub mod parsing;

#[inline(always)]
pub fn validate_packet_bounds(start: usize, end: usize) -> Result<bool, ()> {
    let eth_size = size_of::<EthHdr>();
    if start + eth_size > end {
        return Ok(false);
    }
    Ok(true)
}

#[inline(always)]
pub fn validate_ipv4_bounds(start: usize, end: usize) -> Result<bool, ()> {
    let eth_size = size_of::<EthHdr>();
    let ipv4_size = size_of::<Ipv4Hdr>();
    if start + eth_size + ipv4_size > end {
        return Ok(false);
    }
    Ok(true)
}

#[inline(always)]
pub fn validate_ipv6_bounds(start: usize, end: usize) -> Result<bool, ()> {
    let eth_size = size_of::<EthHdr>();
    let ipv6_size = size_of::<Ipv6Hdr>();
    if start + eth_size + ipv6_size > end {
        return Ok(false);
    }
    Ok(true)
}
