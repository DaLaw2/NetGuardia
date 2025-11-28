use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use common::model::ip_address::*;

pub trait NativeConvert: Copy {
    type Native: Eq + PartialEq + Hash;
    fn into_native(self) -> Self::Native;
    fn from_native(native: Self::Native) -> Self;
}

impl NativeConvert for IPv4 {
    type Native = Ipv4Addr;

    fn into_native(self) -> Self::Native {
        // eBPF 儲存的是 big-endian，需要轉換成 host order
        Ipv4Addr::from(u32::from_be(self))
    }

    fn from_native(native: Self::Native) -> Self {
        // 轉回 big-endian 給 eBPF
        native.to_bits().to_be()
    }
}

impl NativeConvert for IPv6 {
    type Native = Ipv6Addr;

    fn into_native(self) -> Self::Native {
        Ipv6Addr::from(u128::from_be(self))
    }

    fn from_native(native: Self::Native) -> Self {
        native.to_bits().to_be()
    }
}

impl NativeConvert for AddrPortV4 {
    type Native = SocketAddrV4;

    fn into_native(self) -> Self::Native {
        SocketAddrV4::new(
            Ipv4Addr::from(u32::from_be(self.ip())),
            self.port()
        )
    }

    fn from_native(native: Self::Native) -> Self {
        AddrPortV4::new(
            native.ip().to_bits().to_be(),
            native.port()
        )
    }
}

impl NativeConvert for AddrPortV6 {
    type Native = SocketAddrV6;

    fn into_native(self) -> Self::Native {
        SocketAddrV6::new(
            Ipv6Addr::from(u128::from_be(self.ip())),
            self.port(),
            0,
            0
        )
    }

    fn from_native(native: Self::Native) -> Self {
        AddrPortV6::new(
            native.ip().to_bits().to_be(),
            native.port()
        )
    }
}