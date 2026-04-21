use super::helpers::{override_parsed, override_string, seed_key};
use crate::interface::port::setting::SettingRepo;
use crate::model::error::Error;

#[derive(Debug, Clone)]
pub struct EbpfConfig {
    pub ingress_ifname: String,
    pub egress_ifname: String,
    pub combined_queue_count: u32,
    pub channel_size: usize,
    pub fill_queue_size: u32,
    pub comp_queue_size: u32,
    pub tx_queue_size: u32,
    pub rx_queue_size: u32,
    pub frame_size: u32,
    pub frame_count: u32,
    pub refresh_interval: u64,
    pub packet_buffer_size: usize,
    pub buffer_pool_capacity: usize,
}

impl EbpfConfig {
    pub fn defaults() -> Self {
        Self {
            ingress_ifname: "eth0".to_string(),
            egress_ifname: "eth1".to_string(),
            combined_queue_count: 1,
            channel_size: 4096,
            fill_queue_size: 4096,
            comp_queue_size: 4096,
            tx_queue_size: 4096,
            rx_queue_size: 4096,
            frame_size: 4096,
            frame_count: 4096,
            refresh_interval: 5,
            packet_buffer_size: 2048,
            buffer_pool_capacity: 1024,
        }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        override_string(&mut cfg.ingress_ifname, repo, "ingress_interface")?;
        override_string(&mut cfg.egress_ifname, repo, "egress_interface")?;
        override_parsed(&mut cfg.combined_queue_count, repo, "combined_queue_count")?;
        override_parsed(&mut cfg.channel_size, repo, "channel_size")?;
        override_parsed(&mut cfg.fill_queue_size, repo, "fill_queue_size")?;
        override_parsed(&mut cfg.comp_queue_size, repo, "comp_queue_size")?;
        override_parsed(&mut cfg.tx_queue_size, repo, "tx_queue_size")?;
        override_parsed(&mut cfg.rx_queue_size, repo, "rx_queue_size")?;
        override_parsed(&mut cfg.frame_size, repo, "frame_size")?;
        override_parsed(&mut cfg.frame_count, repo, "frame_count")?;
        override_parsed(&mut cfg.refresh_interval, repo, "refresh_interval")?;
        override_parsed(&mut cfg.packet_buffer_size, repo, "packet_buffer_size")?;
        override_parsed(&mut cfg.buffer_pool_capacity, repo, "buffer_pool_capacity")?;
        Ok(cfg)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        seed_key(repo, "ingress_interface", "eth0")?;
        seed_key(repo, "egress_interface", "eth1")?;
        seed_key(repo, "combined_queue_count", "1")?;
        seed_key(repo, "channel_size", "4096")?;
        seed_key(repo, "fill_queue_size", "4096")?;
        seed_key(repo, "comp_queue_size", "4096")?;
        seed_key(repo, "tx_queue_size", "4096")?;
        seed_key(repo, "rx_queue_size", "4096")?;
        seed_key(repo, "frame_size", "4096")?;
        seed_key(repo, "frame_count", "4096")?;
        seed_key(repo, "refresh_interval", "5")?;
        seed_key(repo, "packet_buffer_size", "2048")?;
        seed_key(repo, "buffer_pool_capacity", "1024")?;
        Ok(())
    }
}
