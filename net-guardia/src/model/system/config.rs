use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::model::ml_detection::ClipParams;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpConfig {
    pub http_server_bind_port: u16,
    #[serde(default = "default_jwt_expiry")]
    pub jwt_expiry_hours: u64,
    /// Explicit CORS allowed origins. Empty = allow RFC1918 private networks only.
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
}

fn default_jwt_expiry() -> u64 {
    24
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
    #[serde(default = "default_packet_buffer_size")]
    pub packet_buffer_size: usize,
    #[serde(default = "default_buffer_pool_capacity")]
    pub buffer_pool_capacity: usize,
}

fn default_packet_buffer_size() -> usize {
    2048
}
fn default_buffer_pool_capacity() -> usize {
    1024
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
    #[serde(default = "default_db_path")]
    pub database_path: String,
}

fn default_db_path() -> String {
    "net-guardia.db".to_string()
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PipelineConfig {
    pub ingress: Vec<String>,
    pub egress: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLInferenceConfig {
    pub ae_feature_names: Vec<String>,
    pub ae_clip_params: HashMap<String, ClipParams>,
    pub ae_scaler_mean: Vec<f64>,
    pub ae_scaler_std: Vec<f64>,
    pub ae_post_clip_min: f64,
    pub ae_post_clip_max: f64,
    pub ae_threshold: f32,
    pub classifier_feature_names: Vec<String>,
    pub attack_labels: HashMap<String, String>,
}

impl MLInferenceConfig {
    pub fn num_ae_features(&self) -> usize {
        self.ae_feature_names.len()
    }

    pub fn num_classifier_features(&self) -> usize {
        self.classifier_feature_names.len()
    }

    pub fn num_attack_types(&self) -> usize {
        self.attack_labels.len()
    }
}
