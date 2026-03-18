use std::net::IpAddr;

use common::define::setting::MAX_RULES_PORT;
use common::model::ip_address::Port;

pub fn convert_ports_to_vec(ports: [u16; MAX_RULES_PORT]) -> Vec<Port> {
    let mut filtered_ports: Vec<Port> = ports.into_iter().filter(|&port| port != 0).collect();
    if filtered_ports.is_empty() {
        filtered_ports.push(0);
    }
    filtered_ports
}

pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unique_local() // fc00::/7
                || v6.is_unspecified()
                || v6.is_multicast()
        }
    }
}