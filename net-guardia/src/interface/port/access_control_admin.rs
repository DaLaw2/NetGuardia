use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use common::model::ip_address::Port;

use crate::model::access_control::list_type::ListType;
use crate::model::error::Error;
use crate::model::monitoring::direction::FlowDirection;

/// Admin-level ACL port — add/remove individual IPv4/IPv6 ACL list entries.
///
/// Distinct from `AccessControlPort` (which only exposes `block_ip` /
/// `unblock_ip` for SOAR). `AclService` uses this richer API to serve the
/// `/api/acl` HTTP routes.
pub trait AccessControlAdminPort: Send + Sync {
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

    fn get_ipv4_list(&self, direction: FlowDirection, list_type: ListType) -> HashMap<Ipv4Addr, Vec<Port>>;

    fn get_ipv6_list(&self, direction: FlowDirection, list_type: ListType) -> HashMap<Ipv6Addr, Vec<Port>>;
}
