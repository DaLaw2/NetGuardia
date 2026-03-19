use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct AppConfigTable {
    #[serde(rename = "Http")]
    pub http: HttpConfig,
    #[serde(rename = "Network")]
    pub network: NetworkConfig,
    #[serde(rename = "Inference")]
    pub inference: InferenceConfig,
    #[serde(rename = "Misc")]
    pub misc: MiscConfig,
    #[serde(rename = "Pipeline")]
    pub pipeline: PipelineConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpConfig {
    pub http_server_bind_port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkConfig {
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InferenceConfig {
    pub deep_autoencoder_name: String,
    pub classifier_name: String,
    pub models_config_name: String,
    pub max_concurrent_flows: usize,
    pub min_packets_for_inference: usize,
    pub inference_interval_secs: u64,
    pub aggregator_window_secs: u64,
    pub inference_batch_size: usize,
    pub traffic_logging_mode: bool,
    pub traffic_log_csv_path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MiscConfig {
    pub geoip_db_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PipelineConfig {
    pub ingress: Vec<String>,
    pub egress: Vec<String>,
}
