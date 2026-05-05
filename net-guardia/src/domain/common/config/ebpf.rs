use macros::config_settings;

#[config_settings]
#[derive(Debug, Clone)]
pub struct EbpfConfig {
    // ── network ────────────────────────────────────────────────────
    #[setting(section = "network", key = "ingress_interface", default = "eth0")]
    pub ingress_ifname: String,
    #[setting(section = "network", key = "egress_interface", default = "eth1")]
    pub egress_ifname: String,
    #[setting(section = "network", key = "refresh_interval", default = "5")]
    pub refresh_interval: u64,

    // ── xdp ────────────────────────────────────────────────────────
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
    // ── internal (not exposed in API) ──────────────────────────────
    #[setting(section = "xdp", key = "default_packet_rate", default = "10000", api = false)]
    pub default_packet_rate: u64,
    #[setting(section = "xdp", key = "default_syn_rate", default = "100", api = false)]
    pub default_syn_rate: u64,
    #[setting(section = "xdp", key = "default_udp_rate", default = "5000", api = false)]
    pub default_udp_rate: u64,
    #[setting(section = "xdp", key = "default_dns_rate", default = "200", api = false)]
    pub default_dns_rate: u64,
}
