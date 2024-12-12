use net_guardia_common::model::ip_address::{IPv4, IPv6};
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};

pub trait IpAddressType: Copy {
    type Native: Eq + PartialEq + Hash;
    fn into_native(self) -> Self::Native;
    fn from_native(native: Self::Native) -> Self;
}

impl IpAddressType for IPv4 {
    type Native = Ipv4Addr;

    fn into_native(self) -> Self::Native {
        Ipv4Addr::from(self)
    }

    fn from_native(native: Self::Native) -> Self {
        native.into()
    }
}

impl IpAddressType for IPv6 {
    type Native = Ipv6Addr;

    fn into_native(self) -> Self::Native {
        Ipv6Addr::from(self)
    }

    fn from_native(native: Self::Native) -> Self {
        native.into()
    }
}
