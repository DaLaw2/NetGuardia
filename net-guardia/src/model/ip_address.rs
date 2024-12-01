use crate::utils::definition::IntoString;
use net_guardia_common::model::ip_address::{EbpfAddrPortV4, EbpfAddrPortV6};
use std::net::{Ipv4Addr, Ipv6Addr};

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
