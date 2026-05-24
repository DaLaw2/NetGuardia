use crate::common::error::Error;

pub trait RateLimitPort: Send + Sync {
    fn get_packet_rate(&self) -> Result<u64, Error>;
    fn get_syn_rate(&self) -> Result<u64, Error>;
    fn get_udp_rate(&self) -> Result<u64, Error>;
    fn get_dns_rate(&self) -> Result<u64, Error>;
    fn get_window_ns(&self) -> Result<u64, Error>;
    fn set_packet_rate(&self, rate: u64) -> Result<(), Error>;
    fn set_syn_rate(&self, rate: u64) -> Result<(), Error>;
    fn set_udp_rate(&self, rate: u64) -> Result<(), Error>;
    fn set_dns_rate(&self, rate: u64) -> Result<(), Error>;
    fn set_window_ns(&self, ns: u64) -> Result<(), Error>;
}
