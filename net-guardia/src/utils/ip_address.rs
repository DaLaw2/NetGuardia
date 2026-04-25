use std::net::IpAddr;

pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

pub fn is_internal_ip(ip_str: &str) -> bool {
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    is_private_ip(&ip)
}

pub fn ip_version_from_str(ip: &str) -> u8 {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => 4,
        Ok(IpAddr::V6(_)) => 6,
        Err(_) => {
            if ip.contains(':') {
                6
            } else {
                4
            }
        }
    }
}
