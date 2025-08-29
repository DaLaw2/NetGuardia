#[cfg(feature = "user")]
use aya::Pod;

pub type IPv4 = u32;
pub type IPv6 = u128;
pub type Port = u16;

#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub struct AddrPortV4 {
    pub ip: IPv4,
    pub port: Port,
}

impl AddrPortV4 {
    pub fn new(ip: IPv4, port: Port) -> Self {
        AddrPortV4 {
            ip,
            port,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for AddrPortV4 {}

#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub struct AddrPortV6 {
    pub ip: IPv6,
    pub port: Port,
}

impl AddrPortV6 {
    pub fn new(ip: IPv6, port: Port) -> Self {
        AddrPortV6 {
            ip,
            port,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for AddrPortV6 {}
