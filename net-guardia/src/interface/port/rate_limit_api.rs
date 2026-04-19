use crate::model::error::Error;

/// Data-plane rate-limit config port.
///
/// Split into five per-protocol knobs to match the underlying eBPF per-class
/// counters. `RateLimitService` (HTTP CRUD) and `SoarEngine` (the
/// adjust-rate-limit action) both depend on this port.
pub trait RateLimitPort: Send + Sync {
    fn set_packet_rate(&self, rate: u64) -> Result<(), Error>;
    fn set_syn_rate(&self, rate: u64) -> Result<(), Error>;
    fn set_udp_rate(&self, rate: u64) -> Result<(), Error>;
    fn set_dns_rate(&self, rate: u64) -> Result<(), Error>;
    fn set_window_ns(&self, ns: u64) -> Result<(), Error>;

    fn get_packet_rate(&self) -> Result<u64, Error>;
    fn get_syn_rate(&self) -> Result<u64, Error>;
    fn get_udp_rate(&self) -> Result<u64, Error>;
    fn get_dns_rate(&self) -> Result<u64, Error>;
    fn get_window_ns(&self) -> Result<u64, Error>;
}
