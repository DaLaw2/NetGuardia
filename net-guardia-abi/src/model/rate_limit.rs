#[cfg(feature = "user")]
use aya::Pod;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RateState {
    pub count: u64,
    pub window_start: u64,
}

#[cfg(feature = "user")]
unsafe impl Pod for RateState {}
