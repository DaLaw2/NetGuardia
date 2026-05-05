use macros::config_settings;

#[config_settings]
#[derive(Debug, Clone)]
pub struct MlConfig {
    #[setting(section = "models", key = "models_config_name", default = "inference_config.json")]
    pub models_config_name: String,

    // ── inference ──────────────────────────────────────────────────
    #[setting(section = "inference", key = "max_concurrent_flows", default = "10000")]
    pub max_concurrent_flows: usize,
    #[setting(section = "inference", key = "min_packets_for_inference", default = "5")]
    pub min_packets_for_inference: usize,
    #[setting(section = "inference", key = "inference_interval_secs", default = "5")]
    pub inference_interval_secs: u64,
    #[setting(section = "inference", key = "aggregator_window_secs", default = "30")]
    pub aggregator_window_secs: u64,
    #[setting(section = "inference", key = "inference_batch_size", default = "200")]
    pub inference_batch_size: usize,
    #[setting(section = "inference", key = "traffic_logging_mode", default = "false")]
    pub traffic_logging_mode: bool,
    #[setting(section = "inference", key = "traffic_log_csv_path", default = "traffic_log.csv")]
    pub traffic_log_csv_path: String,

    // ── ml ─────────────────────────────────────────────────────────
    #[setting(section = "ml", key = "ml_min_packets_floor", default = "5")]
    pub min_packets_floor: usize,
    #[setting(section = "ml", key = "ml_confirmation_window_fraction", default = "2")]
    pub confirmation_window_fraction: u64,
    #[setting(section = "ml", key = "ml_drift_window_secs", default = "3600")]
    pub drift_window_secs: u64,
    #[setting(section = "ml", key = "ml_drift_max_snapshots", default = "10000")]
    pub drift_max_snapshots: usize,
    #[setting(section = "ml", key = "ml_drift_channel_capacity", default = "1024")]
    pub drift_channel_capacity: usize,
    #[setting(section = "ml", key = "ml_alert_channel_capacity", default = "1024")]
    pub alert_channel_capacity: usize,
    #[setting(section = "ml", key = "ml_circuit_breaker_threshold", default = "5")]
    pub circuit_breaker_threshold: u32,
    #[setting(section = "ml", key = "ml_circuit_breaker_window_secs", default = "60")]
    pub circuit_breaker_window_secs: u64,
    #[setting(section = "ml", key = "ml_circuit_breaker_cooldown_secs", default = "120")]
    pub circuit_breaker_cooldown_secs: u64,
    #[setting(section = "ml", key = "ml_onnx_load_timeout_secs", default = "5")]
    pub onnx_load_timeout_secs: u64,
    #[setting(section = "ml", key = "ml_model_watcher_debounce_secs", default = "5")]
    pub model_watcher_debounce_secs: u64,
    #[setting(section = "ml", key = "ml_flow_max_packets_per_direction", default = "1000")]
    pub flow_max_packets_per_direction: usize,
    #[setting(section = "ml", key = "ml_flow_max_periods", default = "1000")]
    pub flow_max_periods: usize,
    #[setting(section = "ml", key = "ml_flow_idle_threshold_us", default = "1000000")]
    pub flow_idle_threshold_us: u64,
    #[setting(section = "ml", key = "ml_flow_bulk_min_packets", default = "4")]
    pub flow_bulk_min_packets: u64,
    #[setting(section = "ml", key = "ml_flow_bulk_min_bytes", default = "1000")]
    pub flow_bulk_min_bytes: u64,
    #[setting(section = "ml", key = "ml_flow_idle_timeout_us", default = "120000000")]
    pub flow_idle_timeout_us: u64,
    #[setting(section = "ml", key = "ml_flow_terminated_timeout_us", default = "5000000")]
    pub flow_terminated_timeout_us: u64,

    // ── flow_trace ─────────────────────────────────────────────────
    #[setting(section = "flow_trace", key = "flow_trace_max_file_bytes", default = "524288000")]
    pub flow_trace_max_file_bytes: u64,
    #[setting(section = "flow_trace", key = "flow_trace_max_file_age_secs", default = "3600")]
    pub flow_trace_max_file_age_secs: u64,
    #[setting(
        section = "flow_trace",
        key = "flow_trace_total_budget_bytes",
        default = "10737418240"
    )]
    pub flow_trace_total_budget_bytes: u64,
    #[setting(section = "flow_trace", key = "traffic_logger_channel_capacity", default = "65536")]
    pub traffic_logger_channel_capacity: usize,

    // ── model_upload ───────────────────────────────────────────────
    #[setting(section = "model_upload", key = "model_upload_max_onnx_bytes", default = "104857600")]
    pub model_upload_max_onnx_bytes: usize,
    #[setting(section = "model_upload", key = "model_upload_max_manifest_bytes", default = "65536")]
    pub model_upload_max_manifest_bytes: usize,
    #[setting(section = "model_upload", key = "model_upload_max_scaler_bytes", default = "65536")]
    pub model_upload_max_scaler_bytes: usize,
}
