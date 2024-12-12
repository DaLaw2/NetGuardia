#![no_std]

pub mod model;

/// Maximum number of statistics entries that can be stored
///
/// This constant defines the upper limit for statistical data entries
/// to prevent unbounded memory growth.
pub const MAX_STATS: u32 = 100000;
/// Maximum number of network filtering rules allowed
///
/// Limits the number of rules that can be configured to ensure
/// predictable performance and resource usage.
pub const MAX_RULES: u32 = 1000;
/// Maximum number of port-specific rules allowed
///
/// Defines the upper limit for port-based filtering rules to maintain
/// efficient rule processing.
pub const MAX_RULES_PORT: usize = 32;

pub const MAX_PORT_ACCESS: usize = 12;
