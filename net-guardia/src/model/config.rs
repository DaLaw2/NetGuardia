use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct ConfigTable {
    #[serde(rename = "Config")]
    pub config: Config,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub ingress_ifname: String,
    pub egress_ifname: String,
    pub geoip_db_name: String,
    pub deep_autoencoder_name: String,
    pub random_forest_name: String,
    pub mlp_name: String,
    pub models_config_name: String,
    pub combined_queue_count: u32,
    pub channel_size: usize,
    pub fill_queue_size: u32,
    pub comp_queue_size: u32,
    pub tx_queue_size: u32,
    pub rx_queue_size: u32,
    pub frame_size: u32,
    pub frame_count: u32,
    pub refresh_interval: u64,
    pub http_server_bind_port: u16,
    pub max_concurrent_flows: usize,
    pub min_packets_for_inference: usize,
    pub inference_interval_secs: u64,
}
