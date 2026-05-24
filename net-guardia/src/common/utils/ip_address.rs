use std::net::IpAddr;

use crate::domain::data_plane::error::EbpfError;
use crate::domain::data_plane::ip_version::IpVersion;

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

pub fn ip_version_from_str(ip: &str) -> Result<IpVersion, EbpfError> {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => Ok(IpVersion::V4),
        Ok(IpAddr::V6(_)) => Ok(IpVersion::V6),
        Err(_) => Err(EbpfError::InvalidIpAddress(ip.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_version_from_str_rejects_malformed_input() {
        assert!(matches!(
            ip_version_from_str("not:valid"),
            Err(EbpfError::InvalidIpAddress { .. })
        ));
    }
}
