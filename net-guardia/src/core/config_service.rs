use std::sync::Arc;

use crate::interface::port::repository::RepositoryPort;
use crate::model::error::Error;
use crate::model::error::misc::MiscError;

/// Valid eBPF pipeline stage names.
const VALID_PIPELINE_STAGES: &[&str] = &["access_control", "rate_limit", "service"];

/// All configurable settings grouped by section.
const SETTINGS_MAP: &[(&str, &[&str])] = &[
    ("network", &["ingress_interface", "egress_interface", "refresh_interval"]),
    ("http", &["http_port", "jwt_expiry_hours"]),
    ("inference", &["max_concurrent_flows", "min_packets_for_inference",
                    "inference_interval_secs", "aggregator_window_secs",
                    "inference_batch_size", "traffic_logging_mode",
                    "traffic_log_csv_path"]),
    ("xdp", &["combined_queue_count", "channel_size", "fill_queue_size", "comp_queue_size",
               "tx_queue_size", "rx_queue_size", "frame_size", "frame_count",
               "packet_buffer_size", "buffer_pool_capacity"]),
    ("models", &["deep_autoencoder_name", "classifier_name", "models_config_name"]),
    ("misc", &["geoip_db_name"]),
    ("smtp", &["smtp_host", "smtp_port", "smtp_username", "smtp_password", "smtp_recipient"]),
];

/// Domain service for system configuration read/write.
pub struct ConfigService {
    db: Arc<dyn RepositoryPort>,
}

impl ConfigService {
    pub fn new(db: Arc<dyn RepositoryPort>) -> Self {
        Self { db }
    }

    /// Read all user-configurable settings from DB as structured JSON.
    pub fn get_config(&self) -> serde_json::Value {
        let get = |key: &str| -> String {
            self.db.get_setting(key).ok().flatten().unwrap_or_default()
        };

        serde_json::json!({
            "network": {
                "ingress_interface": get("ingress_interface"),
                "egress_interface": get("egress_interface"),
                "refresh_interval": get("refresh_interval"),
            },
            "http": {
                "http_port": get("http_port"),
                "jwt_expiry_hours": get("jwt_expiry_hours"),
            },
            "inference": {
                "max_concurrent_flows": get("max_concurrent_flows"),
                "min_packets_for_inference": get("min_packets_for_inference"),
                "inference_interval_secs": get("inference_interval_secs"),
                "aggregator_window_secs": get("aggregator_window_secs"),
                "inference_batch_size": get("inference_batch_size"),
                "traffic_logging_mode": get("traffic_logging_mode"),
                "traffic_log_csv_path": get("traffic_log_csv_path"),
            },
            "xdp": {
                "combined_queue_count": get("combined_queue_count"),
                "channel_size": get("channel_size"),
                "fill_queue_size": get("fill_queue_size"),
                "comp_queue_size": get("comp_queue_size"),
                "tx_queue_size": get("tx_queue_size"),
                "rx_queue_size": get("rx_queue_size"),
                "frame_size": get("frame_size"),
                "frame_count": get("frame_count"),
                "packet_buffer_size": get("packet_buffer_size"),
                "buffer_pool_capacity": get("buffer_pool_capacity"),
            },
            "models": {
                "deep_autoencoder_name": get("deep_autoencoder_name"),
                "classifier_name": get("classifier_name"),
                "models_config_name": get("models_config_name"),
            },
            "misc": {
                "geoip_db_name": get("geoip_db_name"),
            },
            "pipeline": {
                "ingress": get("pipeline_ingress"),
                "egress": get("pipeline_egress"),
            },
            "smtp": {
                "smtp_host": get("smtp_host"),
                "smtp_port": get("smtp_port"),
                "smtp_username": get("smtp_username"),
                "smtp_recipient": get("smtp_recipient"),
            },
        })
    }

    /// Update settings from a JSON body. Returns list of updated keys.
    /// Validates pipeline stage names. Only writes non-empty values.
    pub fn update_config(&self, body: &serde_json::Value) -> Result<Vec<String>, Error> {
        let mut updated = Vec::new();

        // Standard key-value settings
        for (section, keys) in SETTINGS_MAP {
            if let Some(section_obj) = body.get(section).and_then(|v| v.as_object()) {
                for key in *keys {
                    if let Some(val) = section_obj.get(*key).and_then(json_value_as_string) {
                        self.db.set_setting(key, &val)?;
                        updated.push(key.to_string());
                    }
                }
            }
        }

        // Pipeline settings — validate stage names
        if let Some(pipeline_obj) = body.get("pipeline").and_then(|v| v.as_object()) {
            for (field, db_key) in [("ingress", "pipeline_ingress"), ("egress", "pipeline_egress")] {
                if let Some(val) = pipeline_obj.get(field).and_then(|v| v.as_str()) {
                    if !val.is_empty() {
                        let stages: Vec<&str> = val.split(',').map(|s| s.trim()).collect();
                        for stage in &stages {
                            if !stage.is_empty() && !VALID_PIPELINE_STAGES.contains(stage) {
                                return Err(MiscError::ValidationError {
                                    message: format!(
                                        "Invalid pipeline stage '{}'. Valid stages: {}",
                                        stage,
                                        VALID_PIPELINE_STAGES.join(", ")
                                    ),
                                }.into());
                            }
                        }
                    }
                    self.db.set_setting(db_key, val)?;
                    updated.push(db_key.to_string());
                }
            }
        }

        Ok(updated)
    }
}

/// Extract a JSON value as a non-empty string, handling string, boolean, and number types.
fn json_value_as_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}
