use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::domain::common::config::AppConfig;
use crate::domain::common::error::Error;
use crate::domain::common::error::misc::MiscError;
use crate::interface::port::app_repo::AppRepo;
use crate::interface::port::secret_store::SecretStorePort;

/// Keys that must be routed through SecretStore instead of plaintext settings.
const SECRET_KEYS: &[&str] = &["smtp_password"];

/// Valid eBPF pipeline stage names.
const VALID_PIPELINE_STAGES: &[&str] = &["access_control", "rate_limit", "service"];

/// All configurable settings grouped by section.
const SETTINGS_MAP: &[(&str, &[&str])] = &[
    (
        "network",
        &["ingress_interface", "egress_interface", "refresh_interval"],
    ),
    ("http", &["http_port", "jwt_expiry_hours", "force_https"]),
    (
        "inference",
        &[
            "max_concurrent_flows",
            "min_packets_for_inference",
            "inference_interval_secs",
            "aggregator_window_secs",
            "inference_batch_size",
            "traffic_logging_mode",
            "traffic_log_csv_path",
        ],
    ),
    (
        "xdp",
        &[
            "combined_queue_count",
            "channel_size",
            "fill_queue_size",
            "comp_queue_size",
            "tx_queue_size",
            "rx_queue_size",
            "frame_size",
            "frame_count",
            "packet_buffer_size",
            "buffer_pool_capacity",
        ],
    ),
    (
        "models",
        &["deep_autoencoder_name", "classifier_name", "models_config_name"],
    ),
    // report_dir and log_dir intentionally NOT configurable via API to prevent
    // arbitrary directory write/read. They use hardcoded safe defaults.
    ("misc", &["geoip_db_name"]),
    (
        "soar",
        &[
            "soar_max_auto_block_cap",
            "soar_max_ttl_secs",
            "soar_handle_concurrency",
            "soar_max_pending_unblock_retries",
            "soar_default_block_ttl_secs",
            "soar_default_rate_limit_factor",
            "soar_default_rate_limit_ttl_secs",
            "soar_default_webhook_timeout_secs",
            "soar_default_frequency_window_secs",
            "soar_default_single_source_high_min_confidence",
            "soar_default_cooldown_expiry_secs",
            "soar_rate_limit_cmd_channel_capacity",
            "soar_frequency_max_tracked_keys",
            "soar_fallback_cooldown_secs",
        ],
    ),
    (
        "ml",
        &[
            "ml_drift_window_secs",
            "ml_min_packets_floor",
            "ml_confirmation_window_fraction",
            "ml_drift_max_snapshots",
            "ml_drift_channel_capacity",
            "ml_alert_channel_capacity",
            "ml_circuit_breaker_threshold",
            "ml_circuit_breaker_window_secs",
            "ml_circuit_breaker_cooldown_secs",
            "ml_onnx_load_timeout_secs",
            "ml_model_watcher_debounce_secs",
            "ml_flow_max_packets_per_direction",
            "ml_flow_max_periods",
            "ml_flow_idle_threshold_us",
            "ml_flow_bulk_min_packets",
            "ml_flow_bulk_min_bytes",
            "ml_flow_idle_timeout_us",
            "ml_flow_terminated_timeout_us",
        ],
    ),
    (
        "flow_trace",
        &[
            "flow_trace_max_file_bytes",
            "flow_trace_max_file_age_secs",
            "flow_trace_total_budget_bytes",
            "traffic_logger_channel_capacity",
        ],
    ),
    (
        "model_upload",
        &[
            "model_upload_max_onnx_bytes",
            "model_upload_max_manifest_bytes",
            "model_upload_max_scaler_bytes",
        ],
    ),
    (
        "telegram",
        &[
            "telegram_rate_limit_max_messages",
            "telegram_rate_limit_window_secs",
            "telegram_max_retries",
        ],
    ),
    ("dns", &["dns_max_domains_per_request"]),
    ("smtp", &["smtp_host", "smtp_port", "smtp_username", "smtp_recipient"]),
    (
        "suricata",
        &[
            "suricata_enabled",
            "suricata_binary_path",
            "suricata_config_path",
            "suricata_eve_log_path",
            "suricata_auto_restart_on_crash",
            "suricata_restart_backoff_secs",
            "suricata_poll_interval_ms",
            "suricata_file_wait_interval_secs",
            "suricata_confidence_high",
            "suricata_confidence_medium",
            "suricata_confidence_low",
            "suricata_confidence_info",
        ],
    ),
    ("detection", &["detection_cleanup_interval_secs"]),
    (
        "fusion",
        &[
            "fusion_dedup_window_secs",
            "fusion_repeat_offender_window_secs",
            "fusion_max_dedup_entries",
        ],
    ),
    (
        "beaconing",
        &[
            "beaconing_analysis_interval_secs",
            "beaconing_min_observations",
            "beaconing_cv_threshold",
            "beaconing_max_cache_entries",
            "beaconing_expiry_secs",
            "beaconing_alert_cooldown_secs",
        ],
    ),
    (
        "correlation",
        &[
            "correlation_scan_window_secs",
            "correlation_scan_threshold",
            "correlation_lateral_window_secs",
            "correlation_lateral_threshold",
            "correlation_botnet_window_secs",
            "correlation_botnet_threshold",
            "correlation_max_tracked_entries",
        ],
    ),
    (
        "observability",
        &[
            "log_buffer_capacity",
            "log_buffer_max_message_bytes",
            "log_max_download_size",
            "log_live_default_limit",
            "log_live_max_limit",
            "fusion_explain_scan_limit",
            "fusion_explain_response_cap",
            "default_event_channel_capacity",
            "drop_channel_capacity",
        ],
    ),
];

pub struct ConfigService {
    db: Arc<dyn AppRepo>,
    secrets: Option<Arc<dyn SecretStorePort>>,
    app_config: Arc<ArcSwap<AppConfig>>,
}

impl ConfigService {
    pub fn new(db: Arc<dyn AppRepo>, app_config: Arc<ArcSwap<AppConfig>>) -> Self {
        Self {
            db,
            secrets: None,
            app_config,
        }
    }

    pub fn with_secret_store(mut self, secrets: Arc<dyn SecretStorePort>) -> Self {
        self.secrets = Some(secrets);
        self
    }

    pub fn get_config(&self) -> serde_json::Value {
        let get = |key: &str| -> String { self.db.get_setting(key).ok().flatten().unwrap_or_default() };

        let mut root = serde_json::Map::new();
        for (section, keys) in SETTINGS_MAP {
            let mut section_obj = serde_json::Map::new();
            for key in *keys {
                section_obj.insert(key.to_string(), serde_json::Value::String(get(key)));
            }
            root.insert(section.to_string(), serde_json::Value::Object(section_obj));
        }
        root.insert(
            "pipeline".to_string(),
            serde_json::json!({
                "ingress": get("pipeline_ingress"),
                "egress": get("pipeline_egress"),
            }),
        );
        serde_json::Value::Object(root)
    }

    pub fn update_config(&self, body: &serde_json::Value) -> Result<Vec<String>, Error> {
        let mut updated: Vec<String> = Vec::new();
        let mut new_cfg: Option<AppConfig> = None;

        self.db.transaction(&mut |repo| {
            for (section, keys) in SETTINGS_MAP {
                if let Some(section_obj) = body.get(section).and_then(|v| v.as_object()) {
                    for key in *keys {
                        if let Some(val) = section_obj.get(*key).and_then(json_value_as_string) {
                            repo.set_setting(key, &val)?;
                            updated.push(key.to_string());
                        }
                    }
                }
            }

            if let Some(ref secrets) = self.secrets {
                for key in SECRET_KEYS {
                    let section = key.split('_').next().unwrap_or("");
                    if let Some(val) = body
                        .get(section)
                        .and_then(|v| v.as_object())
                        .and_then(|obj| obj.get(*key))
                        .and_then(json_value_as_string)
                    {
                        let envelope = secrets.encrypt_envelope(&val)?;
                        repo.set_app_secret(key, &envelope)?;
                        repo.set_setting(key, "")?;
                        updated.push(key.to_string());
                    }
                }
            }

            if let Some(pipeline_obj) = body.get("pipeline").and_then(|v| v.as_object()) {
                for (field, db_key) in [("ingress", "pipeline_ingress"), ("egress", "pipeline_egress")] {
                    if let Some(val) = pipeline_obj.get(field).and_then(|v| v.as_str()) {
                        if !val.is_empty() {
                            let stages: Vec<&str> = val.split(',').map(|s| s.trim()).collect();
                            for stage in &stages {
                                if !stage.is_empty() && !VALID_PIPELINE_STAGES.contains(stage) {
                                    Err(MiscError::ValidationError(format!(
                                        "Invalid pipeline stage '{}'. Valid stages: {}",
                                        stage,
                                        VALID_PIPELINE_STAGES.join(", ")
                                    )))?;
                                }
                            }
                        }
                        repo.set_setting(db_key, val)?;
                        updated.push(db_key.to_string());
                    }
                }
            }

            new_cfg = Some(AppConfig::from_settings(repo)?);
            Ok(())
        })?;

        if let Some(cfg) = new_cfg {
            self.app_config.store(Arc::new(cfg));
        }

        Ok(updated)
    }
}

fn json_value_as_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}
