use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use common::model::ip_address::*;

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

impl IntoNative for AddrPortV4 {
    type Native = SocketAddrV4;

    fn into_native(self) -> Self::Native {
        SocketAddrV4::new(Ipv4Addr::from(self.ip), self.port)
    }
}

impl IntoNative for AddrPortV6 {
    type Native = SocketAddrV6;

    fn into_native(self) -> Self::Native {
        SocketAddrV6::new(Ipv6Addr::from(self.ip), self.port, 0, 0)
    }
}
