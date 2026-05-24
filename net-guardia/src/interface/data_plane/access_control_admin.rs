use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use net_guardia_abi::model::ip_address::Port;

use crate::common::error::Error;
use crate::domain::data_plane::direction::FlowDirection;
use crate::domain::data_plane::list_type::ListType;

pub trait AccessControlAdminPort: Send + Sync {
    fn get_ipv4_list(&self, direction: FlowDirection, list_type: ListType) -> HashMap<Ipv4Addr, Vec<Port>>;

    fn get_ipv6_list(&self, direction: FlowDirection, list_type: ListType) -> HashMap<Ipv6Addr, Vec<Port>>;

    fn add_ipv4_list(&self, direction: FlowDirection, list_type: ListType, address: SocketAddrV4) -> Result<(), Error>;

    fn add_ipv6_list(&self, direction: FlowDirection, list_type: ListType, address: SocketAddrV6) -> Result<(), Error>;

    fn remove_ipv4_list(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV4,
    ) -> Result<(), Error>;

    fn remove_ipv6_list(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV6,
    ) -> Result<(), Error>;
}
