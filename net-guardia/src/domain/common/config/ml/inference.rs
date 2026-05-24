use macros::config_settings;

use crate::common::error::Error;
use crate::domain::common::config::require_config_field;

#[config_settings]
#[derive(Debug, Clone)]
pub struct InferenceConfig {
    #[setting(section = "inference", key = "max_concurrent_flows", default = "10000")]
    pub max_concurrent_flows: usize,
    #[setting(section = "inference", key = "min_packets_for_inference", default = "5")]
    pub min_packets_for_inference: usize,
    #[setting(section = "ml", key = "ml_min_packets_floor", default = "5")]
    pub min_packets_floor: usize,
    #[setting(section = "inference", key = "inference_interval_secs", default = "5")]
    pub inference_interval_secs: u64,
    #[setting(section = "inference", key = "aggregator_window_secs", default = "30")]
    pub aggregator_window_secs: u64,
    #[setting(section = "inference", key = "inference_batch_size", default = "200")]
    pub inference_batch_size: usize,
    #[setting(section = "ml", key = "ml_confirmation_window_fraction", default = "2")]
    pub confirmation_window_fraction: u64,
    #[setting(section = "inference", key = "traffic_logging_mode", default = "false")]
    pub traffic_logging_mode: bool,
    #[setting(section = "inference", key = "traffic_log_csv_path", default = "traffic_log.csv")]
    pub traffic_log_csv_path: String,
    #[setting(section = "ml", key = "ml_onnx_load_timeout_secs", default = "5")]
    pub onnx_load_timeout_secs: u64,
    #[setting(section = "ml", key = "ml_model_watcher_debounce_secs", default = "5")]
    pub model_watcher_debounce_secs: u64,
}

impl InferenceConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.max_concurrent_flows > 0, "ml.inference.max_concurrent_flows")?;
        require_config_field(
            self.min_packets_for_inference > 0,
            "ml.inference.min_packets_for_inference",
        )?;
        require_config_field(self.min_packets_floor > 0, "ml.inference.min_packets_floor")?;
        require_config_field(self.inference_interval_secs > 0, "ml.inference.inference_interval_secs")?;
        require_config_field(self.aggregator_window_secs > 0, "ml.inference.aggregator_window_secs")?;
        require_config_field(self.inference_batch_size > 0, "ml.inference.inference_batch_size")?;
        require_config_field(
            self.confirmation_window_fraction > 0,
            "ml.inference.confirmation_window_fraction",
        )?;
        require_config_field(self.onnx_load_timeout_secs > 0, "ml.inference.onnx_load_timeout_secs")
    }
}
