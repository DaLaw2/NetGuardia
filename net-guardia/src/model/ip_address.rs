use net_guardia_common::model::ip_address::{IPv4, IPv6, EbpfAddrPortV4, EbpfAddrPortV6};
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

pub trait IntoNative: Copy {
    type Native: Eq + PartialEq + Hash;
    fn into_native(self) -> Self::Native;
}

impl IntoNative for IPv4 {
    type Native = Ipv4Addr;

    fn into_native(self) -> Self::Native {
        Ipv4Addr::from(self)
    }
}

impl IntoNative for IPv6 {
    type Native = Ipv6Addr;

    fn into_native(self) -> Self::Native {
        Ipv6Addr::from(self)
    }
}

impl IntoNative for EbpfAddrPortV4 {
    type Native = SocketAddrV4;

    fn into_native(self) -> Self::Native {
        SocketAddrV4::new(Ipv4Addr::from(self[0]), self[1] as u16)
    }
}

impl IntoNative for EbpfAddrPortV6 {
    type Native = SocketAddrV6;

    fn into_native(self) -> Self::Native {
        SocketAddrV6::new(Ipv6Addr::from(self[0]), self[1] as u16, 0, 0)
    }
}
