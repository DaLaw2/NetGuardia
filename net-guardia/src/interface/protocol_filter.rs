use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use common::model::http_method::HttpMethod;

use crate::domain::common::error::Error;

pub trait ProtocolFilterPort: Send + Sync {
    fn get_ipv4_http_service(&self) -> HashMap<SocketAddrV4, Vec<HttpMethod>>;
    fn get_ipv6_http_service(&self) -> HashMap<SocketAddrV6, Vec<HttpMethod>>;
    fn add_ipv4_http_service(&self, address: SocketAddrV4, methods: Vec<HttpMethod>) -> Result<(), Error>;
    fn add_ipv6_http_service(&self, address: SocketAddrV6, methods: Vec<HttpMethod>) -> Result<(), Error>;
    fn remove_ipv4_http_service(&self, address: SocketAddrV4, methods: Vec<HttpMethod>) -> Result<(), Error>;
    fn remove_ipv6_http_service(&self, address: SocketAddrV6, methods: Vec<HttpMethod>) -> Result<(), Error>;

    fn is_ssh_white_list_enable(&self) -> bool;
    fn enable_ssh_white_list(&self) -> Result<(), Error>;
    fn disable_ssh_white_list(&self) -> Result<(), Error>;

    fn get_ipv4_ssh_service(&self) -> Vec<SocketAddrV4>;
    fn get_ipv6_ssh_service(&self) -> Vec<SocketAddrV6>;
    fn add_ipv4_ssh_service(&self, address: SocketAddrV4) -> Result<(), Error>;
    fn add_ipv6_ssh_service(&self, address: SocketAddrV6) -> Result<(), Error>;
    fn remove_ipv4_ssh_service(&self, address: SocketAddrV4) -> Result<(), Error>;
    fn remove_ipv6_ssh_service(&self, address: SocketAddrV6) -> Result<(), Error>;

    fn get_ipv4_ssh_white_list(&self) -> Vec<Ipv4Addr>;
    fn get_ipv6_ssh_white_list(&self) -> Vec<Ipv6Addr>;
    fn add_ipv4_ssh_white_list(&self, ip: Ipv4Addr) -> Result<(), Error>;
    fn add_ipv6_ssh_white_list(&self, ip: Ipv6Addr) -> Result<(), Error>;
    fn remove_ipv4_ssh_white_list(&self, ip: Ipv4Addr) -> Result<(), Error>;
    fn remove_ipv6_ssh_white_list(&self, ip: Ipv6Addr) -> Result<(), Error>;

    fn get_ipv4_ssh_black_list(&self) -> Vec<Ipv4Addr>;
    fn get_ipv6_ssh_black_list(&self) -> Vec<Ipv6Addr>;
    fn add_ipv4_ssh_black_list(&self, ip: Ipv4Addr) -> Result<(), Error>;
    fn add_ipv6_ssh_black_list(&self, ip: Ipv6Addr) -> Result<(), Error>;
    fn remove_ipv4_ssh_black_list(&self, ip: Ipv4Addr) -> Result<(), Error>;
    fn remove_ipv6_ssh_black_list(&self, ip: Ipv6Addr) -> Result<(), Error>;
}
