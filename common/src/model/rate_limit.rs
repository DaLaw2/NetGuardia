#[cfg(feature = "user")]
use aya::Pod;

pub const MAX_TRACKED_IPS: u32 = 65536;
pub const DEFAULT_WINDOW_NS: u64 = 1_000_000_000;
pub const DEFAULT_PACKET_RATE: u64 = 10000;
pub const DEFAULT_SYN_RATE: u64 = 100;
pub const DEFAULT_UDP_RATE: u64 = 5000;
pub const DEFAULT_DNS_RATE: u64 = 200;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RateState {
    pub count: u64,
    pub window_start: u64,
}

#[cfg(feature = "user")]
unsafe impl Pod for RateState {}
