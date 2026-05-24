use std::net::{IpAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use crate::adapter::ebpf::access_control::AccessControl;
use crate::common::error::Error;
use crate::domain::data_plane::direction::FlowDirection;
use crate::domain::data_plane::error::EbpfError;
use crate::domain::data_plane::list_type::ListType;
use crate::interface::data_plane::access_control::AccessControlPort;

pub struct AccessControlAdapter {
    access_control: Arc<AccessControl>,
}

impl AccessControlAdapter {
    pub fn new(access_control: Arc<AccessControl>) -> Self {
        Self { access_control }
    }
}

fn parse_ip(ip: &str) -> Result<IpAddr, Error> {
    let addr = ip.parse().map_err(|_| EbpfError::InvalidIpAddress(ip.to_string()))?;
    Ok(addr)
}

impl AccessControlPort for AccessControlAdapter {
    fn block_ip(&self, ip: &str) -> Result<(), Error> {
        let addr = parse_ip(ip)?;
        match addr {
            IpAddr::V4(v4) => {
                let socket = SocketAddrV4::new(v4, 0);
                self.access_control
                    .add_ipv4_list(FlowDirection::Source, ListType::Black, socket)
            }
            IpAddr::V6(v6) => {
                let socket = SocketAddrV6::new(v6, 0, 0, 0);
                self.access_control
                    .add_ipv6_list(FlowDirection::Source, ListType::Black, socket)
            }
        }
    }

    fn unblock_ip(&self, ip: &str) -> Result<(), Error> {
        let addr = parse_ip(ip)?;
        match addr {
            IpAddr::V4(v4) => {
                let socket = SocketAddrV4::new(v4, 0);
                self.access_control
                    .remove_ipv4_list(FlowDirection::Source, ListType::Black, socket)
            }
            IpAddr::V6(v6) => {
                let socket = SocketAddrV6::new(v6, 0, 0, 0);
                self.access_control
                    .remove_ipv6_list(FlowDirection::Source, ListType::Black, socket)
            }
        }
    }
}
