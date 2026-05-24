#[cfg(feature = "user")]
use aya::Pod;
#[cfg(feature = "user")]
use serde::Serialize;

#[repr(C, align(8))]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Serialize, Debug))]
pub struct FlowStats {
    pub bytes: u64,
    pub packets: u64,
    pub last_seen: u64,
}

impl FlowStats {
    pub fn new(bytes: u64, packets: u64, last_seen: u64) -> Self {
        Self {
            bytes,
            packets,
            last_seen,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for FlowStats {}
