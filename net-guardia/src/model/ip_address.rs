use std::net::{Ipv4Addr, Ipv6Addr};
use serde::Serialize;
use net_guardia_common::model::ip_address::{
    AddrPortV4 as EbpfAddrPortV4, AddrPortV6 as EbpfAddrPortV6
};
use crate::utils::definition::IntoString;

#[derive(Serialize, Debug, PartialEq, Eq, Hash)]
pub struct AddrPortV4 {
    pub ip: u32,
    pub port: u16,
}


#[derive(Serialize, Debug, PartialEq, Eq, Hash)]
pub struct AddrPortV6 {
    pub ip: u128,
    pub port: u16,
}

impl IntoString for EbpfAddrPortV4 {
    fn into_string(self) -> String {
        let ip_addr = Ipv4Addr::from(self[0]);
        let port = self[1] as u16;
        format!("{}:{}", ip_addr, port)
    }
}

impl IntoString for EbpfAddrPortV6 {
    fn into_string(self) -> String {
        let ip_addr = Ipv6Addr::from(self[0]);
        let port = self[1] as u16;
        format!("[{}]:{}", ip_addr, port)
    }
}
