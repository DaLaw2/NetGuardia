#![no_std]

#[cfg(feature = "user")]
extern crate std;

pub mod model;
pub mod utils;
#[cfg(feature = "kernel")]
pub mod ebpf;

pub const MAX_STATS: u32 = 131072;
pub const MAX_RULES: u32 = 128;
pub const MAX_RULES_PORT: usize = 32;
pub const MAX_PORT_ACCESS: usize = 12;
