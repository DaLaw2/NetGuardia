#[cfg(feature = "user")]
use aya::Pod;

/// Fixed-size DNS name in wire format (length-prefixed labels).
/// Stored lowercase, zero-padded. Example: \x07example\x03com\x00
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
