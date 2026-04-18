use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::model::detection::ml_detection::ClipParams;

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
    /// Rotation: close the current CSV when it reaches this many bytes
    /// and open a fresh one. 500MB default — large enough that dropdown
    /// analysis tools can eat a shard in one gulp, small enough that
    /// a browser download finishes in reasonable time.
    #[serde(default = "default_flow_trace_max_file_bytes")]
    pub flow_trace_max_file_bytes: u64,
    /// Rotation: also roll when the active file crosses this age in
    /// seconds, so analysts always have bounded-age shards regardless
    /// of traffic volume. 1h default.
    #[serde(default = "default_flow_trace_max_file_age_secs")]
    pub flow_trace_max_file_age_secs: u64,
    /// FIFO budget: total bytes across every rotated shard in the
    /// directory. When exceeded, oldest files are deleted until the
    /// sum is back under budget. 10GB default keeps a few days of
    /// recording on a typical office link.
    #[serde(default = "default_flow_trace_total_budget_bytes")]
    pub flow_trace_total_budget_bytes: u64,
    /// Hard ceiling on the multipart `.onnx` stream. 100MB default fits
    /// every shipped shape of netguardia's own model plus headroom for
    /// medium BYO networks; very large models (modern transformers)
    /// can raise this, at the cost of a wider DoS surface.
    #[serde(default = "default_model_upload_max_onnx_bytes")]
    pub model_upload_max_onnx_bytes: usize,
    /// Hard ceiling on the multipart `manifest` YAML stream. 64KB
    /// default is ~100× the largest realistic manifest.
    #[serde(default = "default_model_upload_max_manifest_bytes")]
    pub model_upload_max_manifest_bytes: usize,
    /// Hard ceiling on the optional `scaler` JSON sidecar stream.
    /// Shares the 64KB default with the manifest cap — sidecars are
    /// numeric arrays whose size scales with feature count, so even a
    /// generous feature set stays well under.
    #[serde(default = "default_model_upload_max_scaler_bytes")]
    pub model_upload_max_scaler_bytes: usize,
}

fn default_flow_trace_max_file_bytes() -> u64 {
    500 * 1024 * 1024
}
fn default_flow_trace_max_file_age_secs() -> u64 {
    3600
}
fn default_flow_trace_total_budget_bytes() -> u64 {
    10 * 1024 * 1024 * 1024
}
fn default_model_upload_max_onnx_bytes() -> usize {
    100 * 1024 * 1024
}
fn default_model_upload_max_manifest_bytes() -> usize {
    64 * 1024
}
fn default_model_upload_max_scaler_bytes() -> usize {
    64 * 1024
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SuricataConfig {
    pub enabled: bool,
    pub binary_path: String,
    pub config_path: String,
    pub eve_log_path: String,
    pub auto_restart_on_crash: bool,
    pub restart_backoff_secs: u64,
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
    pub anomaly_threshold: f32,
    pub c2_threshold: f32,
    #[serde(default = "default_class_min_confidence")]
    pub class_min_confidence: f32,
    /// Multiplier applied to the confidence threshold before the aggregator
    /// fires an alert. The manifest can override this via
    /// `thresholds.alert_multiplier`.
    #[serde(default = "default_alert_threshold_multiplier")]
    pub alert_threshold_multiplier: f32,
    pub model_type: String,
    pub output_names: Vec<String>,
    pub ae_feature_weights: HashMap<String, f64>,
}

fn default_class_min_confidence() -> f32 {
    0.4
}

fn default_alert_threshold_multiplier() -> f32 {
    1.2
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
