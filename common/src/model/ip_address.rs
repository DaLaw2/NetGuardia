#[cfg(feature = "user")]
use aya::Pod;

pub type IPv4 = u32;
pub type IPv6 = u128;
pub type Port = u16;

#[repr(transparent)]
#[derive(Debug, Copy, Clone)]
pub struct AddrPortV4([u8; 8]);

impl AddrPortV4 {
    #[inline(always)]
    pub fn new(ip: u32, port: u16) -> Self {
        let mut key = [0u8; 8];
        key[0..4].copy_from_slice(&ip.to_ne_bytes());
        key[4..6].copy_from_slice(&port.to_ne_bytes());
        Self(key)
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    #[inline(always)]
    pub fn ip(&self) -> IPv4 {
        let mut ip_bytes = [0u8; 4];
        ip_bytes.copy_from_slice(&self.0[0..4]);
        u32::from_ne_bytes(ip_bytes)
    }

    #[inline(always)]
    pub fn port(&self) -> Port {
        let mut port_bytes = [0u8; 2];
        port_bytes.copy_from_slice(&self.0[4..6]);
        u16::from_ne_bytes(port_bytes)
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for AddrPortV4 {}

#[repr(transparent)]
#[derive(Debug, Copy, Clone)]
pub struct AddrPortV6([u8; 32]);

impl AddrPortV6 {
    #[inline(always)]
    pub fn new(ip: u128, port: u16) -> Self {
        let mut key = [0u8; 32];
        key[0..16].copy_from_slice(&ip.to_ne_bytes());
        key[16..18].copy_from_slice(&port.to_ne_bytes());
        Self(key)
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[inline(always)]
    pub fn ip(&self) -> IPv6 {
        let mut ip_bytes = [0u8; 16];
        ip_bytes.copy_from_slice(&self.0[0..16]);
        u128::from_ne_bytes(ip_bytes)
    }

    #[inline(always)]
    pub fn port(&self) -> Port {
        let mut port_bytes = [0u8; 2];
        port_bytes.copy_from_slice(&self.0[16..18]);
        u16::from_ne_bytes(port_bytes)
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for AddrPortV6 {}
