use aya::maps::{Array, MapData};
use aya::Ebpf;
use parking_lot::Mutex;

use crate::model::error::ebpf::EbpfError;
use crate::model::error::Error;

pub struct RateLimitConfig {
    config_map: Mutex<Array<MapData, u64>>,
}

impl RateLimitConfig {
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, Error> {
        let map = ebpf.take_map("RATE_LIMIT_CONFIG").ok_or(EbpfError::MapNotFound)?;
        let config_map = Array::try_from(map).map_err(EbpfError::MapOperationError)?;
        Ok(Self { config_map: Mutex::new(config_map) })
    }

    pub fn set_packet_rate(&self, rate: u64) -> Result<(), Error> {
        self.config_map.lock().set(0, rate, 0).map_err(EbpfError::MapOperationError)?;
        Ok(())
    }

    pub fn set_syn_rate(&self, rate: u64) -> Result<(), Error> {
        self.config_map.lock().set(1, rate, 0).map_err(EbpfError::MapOperationError)?;
        Ok(())
    }

    pub fn set_udp_rate(&self, rate: u64) -> Result<(), Error> {
        self.config_map.lock().set(2, rate, 0).map_err(EbpfError::MapOperationError)?;
        Ok(())
    }

    pub fn set_dns_rate(&self, rate: u64) -> Result<(), Error> {
        self.config_map.lock().set(3, rate, 0).map_err(EbpfError::MapOperationError)?;
        Ok(())
    }

    pub fn set_window_ns(&self, ns: u64) -> Result<(), Error> {
        self.config_map.lock().set(4, ns, 0).map_err(EbpfError::MapOperationError)?;
        Ok(())
    }
}
