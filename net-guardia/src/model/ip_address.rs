use net_guardia_common::model::ip_address::{IPv4, IPv6, EbpfAddrPortV4, EbpfAddrPortV6};
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

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

pub trait SocketAddressType: Copy {
    type Native: Eq + PartialEq + Hash;
    fn into_native(self) -> Self::Native;
    fn from_native(native: Self::Native) -> Self;
}

impl SocketAddressType for EbpfAddrPortV4 {
    type Native = SocketAddrV4;

    fn into_native(self) -> Self::Native {
        SocketAddrV4::new(Ipv4Addr::from(self[0]), self[1] as u16)
    }

    fn from_native(native: Self::Native) -> Self {
        [(*native.ip()).into(), native.port() as u32]
    }
}

impl SocketAddressType for EbpfAddrPortV6 {
    type Native = SocketAddrV6;

    fn into_native(self) -> Self::Native {
        SocketAddrV6::new(Ipv6Addr::from(self[0]), self[1] as u16, 0, 0)
    }

    fn from_native(native: Self::Native) -> Self {
        [(*native.ip()).into(), native.port() as u128]
    }
}
