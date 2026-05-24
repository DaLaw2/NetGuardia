use macros::config_settings;

use crate::common::error::Error;
use crate::domain::common::config::require_config_field;

#[config_settings]
#[derive(Debug, Clone)]
pub struct EbpfConfig {
    #[setting(section = "network", key = "ingress_interface", default = "eth0")]
    pub ingress_ifname: String,
    #[setting(section = "network", key = "egress_interface", default = "eth1")]
    pub egress_ifname: String,
    #[setting(section = "network", key = "refresh_interval", default = "5")]
    pub refresh_interval: u64,
    #[setting(section = "xdp", key = "combined_queue_count", default = "1")]
    pub combined_queue_count: u32,
    #[setting(section = "xdp", key = "channel_size", default = "4096")]
    pub channel_size: usize,
    #[setting(section = "xdp", key = "fill_queue_size", default = "4096")]
    pub fill_queue_size: u32,
    #[setting(section = "xdp", key = "comp_queue_size", default = "4096")]
    pub comp_queue_size: u32,
    #[setting(section = "xdp", key = "tx_queue_size", default = "4096")]
    pub tx_queue_size: u32,
    #[setting(section = "xdp", key = "rx_queue_size", default = "4096")]
    pub rx_queue_size: u32,
    #[setting(section = "xdp", key = "frame_size", default = "4096")]
    pub frame_size: u32,
    #[setting(section = "xdp", key = "frame_count", default = "4096")]
    pub frame_count: u32,
    #[setting(section = "xdp", key = "packet_buffer_size", default = "2048")]
    pub packet_buffer_size: usize,
    #[setting(section = "xdp", key = "buffer_pool_capacity", default = "1024")]
    pub buffer_pool_capacity: usize,
    #[setting(section = "xdp", key = "xsk_completion_batch_size", default = "256")]
    pub xsk_completion_batch_size: usize,
    #[setting(section = "xdp", key = "xsk_rx_batch_size", default = "64")]
    pub xsk_rx_batch_size: usize,
    #[setting(section = "xdp", key = "xsk_tx_batch_size", default = "64")]
    pub xsk_tx_batch_size: usize,
    #[setting(section = "xdp", key = "default_packet_rate", default = "10000", api = false)]
    pub default_packet_rate: u64,
    #[setting(section = "xdp", key = "default_syn_rate", default = "100", api = false)]
    pub default_syn_rate: u64,
    #[setting(section = "xdp", key = "default_udp_rate", default = "5000", api = false)]
    pub default_udp_rate: u64,
    #[setting(section = "xdp", key = "default_dns_rate", default = "200", api = false)]
    pub default_dns_rate: u64,
}

impl EbpfConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.refresh_interval > 0, "ebpf.refresh_interval")?;
        require_config_field(self.refresh_interval <= 3600, "ebpf.refresh_interval")?;
        require_config_field(self.combined_queue_count > 0, "ebpf.combined_queue_count")?;
        require_config_field(self.channel_size > 0, "ebpf.channel_size")?;
        require_config_field(self.fill_queue_size > 0, "ebpf.fill_queue_size")?;
        require_config_field(self.comp_queue_size > 0, "ebpf.comp_queue_size")?;
        require_config_field(self.tx_queue_size > 0, "ebpf.tx_queue_size")?;
        require_config_field(self.rx_queue_size > 0, "ebpf.rx_queue_size")?;
        require_config_field(self.frame_size > 0, "ebpf.frame_size")?;
        require_config_field(self.frame_count > 0, "ebpf.frame_count")?;
        require_config_field(self.packet_buffer_size > 0, "ebpf.packet_buffer_size")?;
        require_config_field(self.buffer_pool_capacity > 0, "ebpf.buffer_pool_capacity")?;
        require_config_field(self.xsk_completion_batch_size > 0, "ebpf.xsk_completion_batch_size")?;
        require_config_field(self.xsk_rx_batch_size > 0, "ebpf.xsk_rx_batch_size")?;
        require_config_field(self.xsk_tx_batch_size > 0, "ebpf.xsk_tx_batch_size")
    }
}

#[cfg(test)]
mod tests {
    use super::EbpfConfig;

    #[test]
    fn zero_runtime_sizes_are_invalid() {
        let invalid_cases: [fn(&mut EbpfConfig); 4] = [
            |cfg: &mut EbpfConfig| cfg.refresh_interval = 0,
            |cfg: &mut EbpfConfig| cfg.channel_size = 0,
            |cfg: &mut EbpfConfig| cfg.packet_buffer_size = 0,
            |cfg: &mut EbpfConfig| cfg.buffer_pool_capacity = 0,
        ];

        for apply_invalid in invalid_cases {
            let mut cfg = EbpfConfig::defaults();
            apply_invalid(&mut cfg);

            assert!(cfg.validate().is_err());
        }
    }
}
