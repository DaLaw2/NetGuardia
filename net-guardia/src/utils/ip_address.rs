use std::net::IpAddr;

pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_broadcast(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unique_local() // fc00::/7
                || v6.is_unspecified()
                || v6.is_multicast()
        }
    }
}
