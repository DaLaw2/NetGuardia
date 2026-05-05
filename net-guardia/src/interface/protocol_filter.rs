use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use common::model::http_method::HttpMethod;

use crate::domain::common::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

pub trait ProtocolFilterPort: Send + Sync {
    fn get_http_service(&self, version: IpVersion) -> HashMap<SocketAddr, Vec<HttpMethod>>;
    fn add_http_service(&self, version: IpVersion, address: SocketAddr, methods: Vec<HttpMethod>) -> Result<(), Error>;
    fn remove_http_service(
        &self,
        version: IpVersion,
        address: SocketAddr,
        methods: Vec<HttpMethod>,
    ) -> Result<(), Error>;

    fn is_ssh_white_list_enable(&self) -> bool;
    fn enable_ssh_white_list(&self) -> Result<(), Error>;
    fn disable_ssh_white_list(&self) -> Result<(), Error>;

    fn get_ssh_service(&self, version: IpVersion) -> Vec<SocketAddr>;
    fn add_ssh_service(&self, version: IpVersion, address: SocketAddr) -> Result<(), Error>;
    fn remove_ssh_service(&self, version: IpVersion, address: SocketAddr) -> Result<(), Error>;

    fn get_ssh_white_list(&self, version: IpVersion) -> Vec<IpAddr>;
    fn add_ssh_white_list(&self, version: IpVersion, ip: IpAddr) -> Result<(), Error>;
    fn remove_ssh_white_list(&self, version: IpVersion, ip: IpAddr) -> Result<(), Error>;

    fn get_ssh_black_list(&self, version: IpVersion) -> Vec<IpAddr>;
    fn add_ssh_black_list(&self, version: IpVersion, ip: IpAddr) -> Result<(), Error>;
    fn remove_ssh_black_list(&self, version: IpVersion, ip: IpAddr) -> Result<(), Error>;
}
