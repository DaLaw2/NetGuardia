use super::helpers::{override_bool, override_parsed, override_string_nonempty, seed_key};
use crate::domain::common::error::Error;
use crate::interface::port::setting::SettingRepo;

#[derive(Debug, Clone)]
pub struct MlConfig {
    pub deep_autoencoder_name: String,
    pub classifier_name: String,
    pub models_config_name: String,
    pub max_concurrent_flows: usize,
    pub min_packets_for_inference: usize,
    pub min_packets_floor: usize,
    pub inference_interval_secs: u64,
    pub aggregator_window_secs: u64,
    pub inference_batch_size: usize,
    pub confirmation_window_fraction: u64,
    pub traffic_logging_mode: bool,
    pub traffic_log_csv_path: String,
    pub flow_trace_max_file_bytes: u64,
    pub flow_trace_max_file_age_secs: u64,
    pub flow_trace_total_budget_bytes: u64,
    pub traffic_logger_channel_capacity: usize,
    pub model_upload_max_onnx_bytes: usize,
    pub model_upload_max_manifest_bytes: usize,
    pub model_upload_max_scaler_bytes: usize,
    pub drift_window_secs: u64,
    pub drift_max_snapshots: usize,
    pub drift_channel_capacity: usize,
    pub alert_channel_capacity: usize,
    pub circuit_breaker_threshold: u32,
    pub circuit_breaker_window_secs: u64,
    pub circuit_breaker_cooldown_secs: u64,
    pub onnx_load_timeout_secs: u64,
    pub model_watcher_debounce_secs: u64,
    pub flow_max_packets_per_direction: usize,
    pub flow_max_periods: usize,
    pub flow_idle_threshold_us: u64,
    pub flow_bulk_min_packets: u64,
    pub flow_bulk_min_bytes: u64,
    pub flow_idle_timeout_us: u64,
    pub flow_terminated_timeout_us: u64,
}

impl MlConfig {
    pub fn defaults() -> Self {
        Self {
            deep_autoencoder_name: "deep_autoencoder.onnx".to_string(),
            classifier_name: "classifier.onnx".to_string(),
            models_config_name: "inference_config.json".to_string(),
            max_concurrent_flows: 10_000,
            min_packets_for_inference: 5,
            min_packets_floor: 5,
            inference_interval_secs: 5,
            aggregator_window_secs: 30,
            inference_batch_size: 200,
            confirmation_window_fraction: 2,
            traffic_logging_mode: false,
            traffic_log_csv_path: "traffic_log.csv".to_string(),
            flow_trace_max_file_bytes: 500 * 1024 * 1024,
            flow_trace_max_file_age_secs: 3600,
            flow_trace_total_budget_bytes: 10 * 1024 * 1024 * 1024,
            traffic_logger_channel_capacity: 65_536,
            model_upload_max_onnx_bytes: 100 * 1024 * 1024,
            model_upload_max_manifest_bytes: 64 * 1024,
            model_upload_max_scaler_bytes: 64 * 1024,
            drift_window_secs: 3600,
            drift_max_snapshots: 10_000,
            drift_channel_capacity: 1024,
            alert_channel_capacity: 1024,
            circuit_breaker_threshold: 5,
            circuit_breaker_window_secs: 60,
            circuit_breaker_cooldown_secs: 120,
            onnx_load_timeout_secs: 5,
            model_watcher_debounce_secs: 5,
            flow_max_packets_per_direction: 1000,
            flow_max_periods: 1000,
            flow_idle_threshold_us: 1_000_000,
            flow_bulk_min_packets: 4,
            flow_bulk_min_bytes: 1000,
            flow_idle_timeout_us: 120_000_000,
            flow_terminated_timeout_us: 5_000_000,
        }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        override_string_nonempty(&mut cfg.deep_autoencoder_name, repo, "deep_autoencoder_name")?;
        override_string_nonempty(&mut cfg.classifier_name, repo, "classifier_name")?;
        override_string_nonempty(&mut cfg.models_config_name, repo, "models_config_name")?;
        override_parsed(&mut cfg.max_concurrent_flows, repo, "max_concurrent_flows")?;
        override_parsed(&mut cfg.min_packets_for_inference, repo, "min_packets_for_inference")?;
        override_parsed(&mut cfg.min_packets_floor, repo, "ml_min_packets_floor")?;
        override_parsed(&mut cfg.inference_interval_secs, repo, "inference_interval_secs")?;
        override_parsed(&mut cfg.aggregator_window_secs, repo, "aggregator_window_secs")?;
        override_parsed(&mut cfg.inference_batch_size, repo, "inference_batch_size")?;
        override_parsed(
            &mut cfg.confirmation_window_fraction,
            repo,
            "ml_confirmation_window_fraction",
        )?;
        override_bool(&mut cfg.traffic_logging_mode, repo, "traffic_logging_mode")?;
        override_string_nonempty(&mut cfg.traffic_log_csv_path, repo, "traffic_log_csv_path")?;
        override_parsed(&mut cfg.flow_trace_max_file_bytes, repo, "flow_trace_max_file_bytes")?;
        override_parsed(
            &mut cfg.flow_trace_max_file_age_secs,
            repo,
            "flow_trace_max_file_age_secs",
        )?;
        override_parsed(
            &mut cfg.flow_trace_total_budget_bytes,
            repo,
            "flow_trace_total_budget_bytes",
        )?;
        override_parsed(
            &mut cfg.traffic_logger_channel_capacity,
            repo,
            "traffic_logger_channel_capacity",
        )?;
        override_parsed(
            &mut cfg.model_upload_max_onnx_bytes,
            repo,
            "model_upload_max_onnx_bytes",
        )?;
        override_parsed(
            &mut cfg.model_upload_max_manifest_bytes,
            repo,
            "model_upload_max_manifest_bytes",
        )?;
        override_parsed(
            &mut cfg.model_upload_max_scaler_bytes,
            repo,
            "model_upload_max_scaler_bytes",
        )?;
        override_parsed(&mut cfg.drift_window_secs, repo, "ml_drift_window_secs")?;
        override_parsed(&mut cfg.drift_max_snapshots, repo, "ml_drift_max_snapshots")?;
        override_parsed(&mut cfg.drift_channel_capacity, repo, "ml_drift_channel_capacity")?;
        override_parsed(&mut cfg.alert_channel_capacity, repo, "ml_alert_channel_capacity")?;
        override_parsed(&mut cfg.circuit_breaker_threshold, repo, "ml_circuit_breaker_threshold")?;
        override_parsed(
            &mut cfg.circuit_breaker_window_secs,
            repo,
            "ml_circuit_breaker_window_secs",
        )?;
        override_parsed(
            &mut cfg.circuit_breaker_cooldown_secs,
            repo,
            "ml_circuit_breaker_cooldown_secs",
        )?;
        override_parsed(&mut cfg.onnx_load_timeout_secs, repo, "ml_onnx_load_timeout_secs")?;
        override_parsed(
            &mut cfg.model_watcher_debounce_secs,
            repo,
            "ml_model_watcher_debounce_secs",
        )?;
        override_parsed(
            &mut cfg.flow_max_packets_per_direction,
            repo,
            "ml_flow_max_packets_per_direction",
        )?;
        override_parsed(&mut cfg.flow_max_periods, repo, "ml_flow_max_periods")?;
        override_parsed(&mut cfg.flow_idle_threshold_us, repo, "ml_flow_idle_threshold_us")?;
        override_parsed(&mut cfg.flow_bulk_min_packets, repo, "ml_flow_bulk_min_packets")?;
        override_parsed(&mut cfg.flow_bulk_min_bytes, repo, "ml_flow_bulk_min_bytes")?;
        override_parsed(&mut cfg.flow_idle_timeout_us, repo, "ml_flow_idle_timeout_us")?;
        override_parsed(
            &mut cfg.flow_terminated_timeout_us,
            repo,
            "ml_flow_terminated_timeout_us",
        )?;
        Ok(cfg)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        seed_key(repo, "deep_autoencoder_name", "deep_autoencoder.onnx")?;
        seed_key(repo, "classifier_name", "classifier.onnx")?;
        seed_key(repo, "models_config_name", "inference_config.json")?;
        seed_key(repo, "max_concurrent_flows", "10000")?;
        seed_key(repo, "min_packets_for_inference", "5")?;
        seed_key(repo, "ml_min_packets_floor", "5")?;
        seed_key(repo, "inference_interval_secs", "5")?;
        seed_key(repo, "aggregator_window_secs", "30")?;
        seed_key(repo, "inference_batch_size", "200")?;
        seed_key(repo, "ml_confirmation_window_fraction", "2")?;
        seed_key(repo, "traffic_logging_mode", "false")?;
        seed_key(repo, "traffic_log_csv_path", "traffic_log.csv")?;
        seed_key(repo, "flow_trace_max_file_bytes", &(500_u64 * 1024 * 1024).to_string())?;
        seed_key(repo, "flow_trace_max_file_age_secs", "3600")?;
        seed_key(
            repo,
            "flow_trace_total_budget_bytes",
            &(10_u64 * 1024 * 1024 * 1024).to_string(),
        )?;
        seed_key(repo, "traffic_logger_channel_capacity", "65536")?;
        seed_key(
            repo,
            "model_upload_max_onnx_bytes",
            &(100_usize * 1024 * 1024).to_string(),
        )?;
        seed_key(repo, "model_upload_max_manifest_bytes", &(64_usize * 1024).to_string())?;
        seed_key(repo, "model_upload_max_scaler_bytes", &(64_usize * 1024).to_string())?;
        seed_key(repo, "ml_drift_window_secs", "3600")?;
        seed_key(repo, "ml_drift_max_snapshots", "10000")?;
        seed_key(repo, "ml_drift_channel_capacity", "1024")?;
        seed_key(repo, "ml_alert_channel_capacity", "1024")?;
        seed_key(repo, "ml_circuit_breaker_threshold", "5")?;
        seed_key(repo, "ml_circuit_breaker_window_secs", "60")?;
        seed_key(repo, "ml_circuit_breaker_cooldown_secs", "120")?;
        seed_key(repo, "ml_onnx_load_timeout_secs", "5")?;
        seed_key(repo, "ml_model_watcher_debounce_secs", "5")?;
        seed_key(repo, "ml_flow_max_packets_per_direction", "1000")?;
        seed_key(repo, "ml_flow_max_periods", "1000")?;
        seed_key(repo, "ml_flow_idle_threshold_us", "1000000")?;
        seed_key(repo, "ml_flow_bulk_min_packets", "4")?;
        seed_key(repo, "ml_flow_bulk_min_bytes", "1000")?;
        seed_key(repo, "ml_flow_idle_timeout_us", "120000000")?;
        seed_key(repo, "ml_flow_terminated_timeout_us", "5000000")?;
        Ok(())
    }
}
