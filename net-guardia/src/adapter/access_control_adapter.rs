use std::net::{IpAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use async_trait::async_trait;

use crate::core::ebpf::access_control::AccessControl;
use crate::interface::port::access_control::AccessControlPort;
use crate::model::direction::FlowDirection;
use crate::model::error::Error;
use crate::model::list_type::ListType;

/// Adapter that implements AccessControlPort by delegating to the eBPF AccessControl.
pub struct EbpfAccessControlAdapter {
    access_control: Arc<AccessControl>,
}

impl EbpfAccessControlAdapter {
    pub fn new(access_control: Arc<AccessControl>) -> Self {
        Self { access_control }
    }
}

#[async_trait]
impl AccessControlPort for EbpfAccessControlAdapter {
    async fn block_ip(&self, ip: &str) -> Result<(), Error> {
        let addr: IpAddr = ip.parse().map_err(|_| {
            Error::from(crate::model::error::ebpf::EbpfError::InvalidIpAddress { ip: ip.to_string() })
        })?;
        match addr {
            IpAddr::V4(v4) => {
                let socket = SocketAddrV4::new(v4, 0);
                self.access_control
                    .add_ipv4_list(FlowDirection::Source, ListType::Black, socket)
                    .await
            }
            IpAddr::V6(v6) => {
                let socket = SocketAddrV6::new(v6, 0, 0, 0);
                self.access_control
                    .add_ipv6_list(FlowDirection::Source, ListType::Black, socket)
                    .await
            }
        }
    }

    async fn unblock_ip(&self, ip: &str) -> Result<(), Error> {
        let addr: IpAddr = ip.parse().map_err(|_| {
            Error::from(crate::model::error::ebpf::EbpfError::InvalidIpAddress { ip: ip.to_string() })
        })?;
        match addr {
            IpAddr::V4(v4) => {
                let socket = SocketAddrV4::new(v4, 0);
                self.access_control
                    .remove_ipv4_list(FlowDirection::Source, ListType::Black, socket)
                    .await
            }
            IpAddr::V6(v6) => {
                let socket = SocketAddrV6::new(v6, 0, 0, 0);
                self.access_control
                    .remove_ipv6_list(FlowDirection::Source, ListType::Black, socket)
                    .await
            }
        }
    }
}
