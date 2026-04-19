use std::net::{IpAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use crate::adapter::ebpf::access_control::AccessControl;
use crate::interface::port::access_control::AccessControlPort;
use crate::model::access_control::list_type::ListType;
use crate::model::error::Error;
use crate::model::error::ebpf::EbpfError;
use crate::model::monitoring::direction::FlowDirection;

/// Adapter that implements AccessControlPort by delegating to the eBPF AccessControl.
pub struct EbpfAccessControlAdapter {
    access_control: Arc<AccessControl>,
}

impl EbpfAccessControlAdapter {
    pub fn new(access_control: Arc<AccessControl>) -> Self {
        Self { access_control }
    }
}

impl AccessControlPort for EbpfAccessControlAdapter {
    fn block_ip(&self, ip: &str) -> Result<(), Error> {
        let addr: IpAddr = ip
            .parse()
            .map_err(|_| Error::from(EbpfError::InvalidIpAddress(ip.to_string())))?;
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
        let addr: IpAddr = ip
            .parse()
            .map_err(|_| Error::from(EbpfError::InvalidIpAddress(ip.to_string())))?;
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
