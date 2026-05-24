#[cfg(feature = "user")]
use aya::Pod;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DnsName {
    pub data: [u8; 128],
}

impl DnsName {
    pub const fn zeroed() -> Self {
        Self { data: [0u8; 128] }
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for DnsName {}
