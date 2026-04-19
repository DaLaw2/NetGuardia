use aya::Ebpf;
use aya::maps::{Array, MapData};
use parking_lot::Mutex;

use crate::interface::port::rate_limit_api::RateLimitPort;
use crate::model::error::Error;
use crate::model::error::ebpf::EbpfError;

pub struct RateLimitConfig {
    config_map: Mutex<Option<Array<MapData, u64>>>,
}

impl RateLimitConfig {
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, Error> {
        let map = ebpf.take_map("RATE_LIMIT_CONFIG").ok_or(EbpfError::MapNotFound)?;
        let config_map = Array::try_from(map).map_err(EbpfError::MapOperationError)?;
        Ok(Self {
            config_map: Mutex::new(Some(config_map)),
        })
    }

    pub fn unavailable() -> Self {
        Self {
            config_map: Mutex::new(None),
        }
    }

    fn set_at(&self, index: u32, value: u64) -> Result<(), Error> {
        let mut guard = self.config_map.lock();
        let map = guard.as_mut().ok_or(EbpfError::NotLoaded)?;
        map.set(index, value, 0).map_err(EbpfError::MapOperationError)?;
        Ok(())
    }

    fn get_at(&self, index: u32) -> Result<u64, Error> {
        let guard = self.config_map.lock();
        let map = guard.as_ref().ok_or(EbpfError::NotLoaded)?;
        map.get(&index, 0).map_err(|e| EbpfError::MapOperationError(e).into())
    }

    pub fn set_packet_rate(&self, rate: u64) -> Result<(), Error> {
        self.set_at(0, rate)
    }

    pub fn set_syn_rate(&self, rate: u64) -> Result<(), Error> {
        self.set_at(1, rate)
    }

    pub fn set_udp_rate(&self, rate: u64) -> Result<(), Error> {
        self.set_at(2, rate)
    }

    pub fn set_dns_rate(&self, rate: u64) -> Result<(), Error> {
        self.set_at(3, rate)
    }

    pub fn set_window_ns(&self, ns: u64) -> Result<(), Error> {
        self.set_at(4, ns)
    }

    pub fn get_packet_rate(&self) -> Result<u64, Error> {
        self.get_at(0)
    }

    pub fn get_syn_rate(&self) -> Result<u64, Error> {
        self.get_at(1)
    }

    pub fn get_udp_rate(&self) -> Result<u64, Error> {
        self.get_at(2)
    }

    pub fn get_dns_rate(&self) -> Result<u64, Error> {
        self.get_at(3)
    }

    pub fn get_window_ns(&self) -> Result<u64, Error> {
        self.get_at(4)
    }
}

impl RateLimitPort for RateLimitConfig {
    fn set_packet_rate(&self, rate: u64) -> Result<(), Error> {
        self.set_packet_rate(rate)
    }
    fn set_syn_rate(&self, rate: u64) -> Result<(), Error> {
        self.set_syn_rate(rate)
    }
    fn set_udp_rate(&self, rate: u64) -> Result<(), Error> {
        self.set_udp_rate(rate)
    }
    fn set_dns_rate(&self, rate: u64) -> Result<(), Error> {
        self.set_dns_rate(rate)
    }
    fn set_window_ns(&self, ns: u64) -> Result<(), Error> {
        self.set_window_ns(ns)
    }
    fn get_packet_rate(&self) -> Result<u64, Error> {
        self.get_packet_rate()
    }
    fn get_syn_rate(&self) -> Result<u64, Error> {
        self.get_syn_rate()
    }
    fn get_udp_rate(&self) -> Result<u64, Error> {
        self.get_udp_rate()
    }
    fn get_dns_rate(&self) -> Result<u64, Error> {
        self.get_dns_rate()
    }
    fn get_window_ns(&self) -> Result<u64, Error> {
        self.get_window_ns()
    }
}
