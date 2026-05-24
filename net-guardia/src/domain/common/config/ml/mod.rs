use macros::config_settings;

use crate::common::error::Error;
use crate::domain::common::config::{ConfigValues, require_config_field};

pub mod circuit_breaker;
pub mod drift;
pub mod flow;
pub mod flow_trace;
pub mod inference;
pub mod model_upload;

use circuit_breaker::CircuitBreakerConfig;
use drift::DriftConfig;
use flow::FlowConfig;
use flow_trace::FlowTraceConfig;
use inference::InferenceConfig;
use model_upload::ModelUploadConfig;

#[config_settings]
#[derive(Debug, Clone)]
pub struct MlConfig {
    #[setting(section = "models", key = "models_config_name", default = "inference_config.json")]
    pub models_config_name: String,
    #[setting(flatten)]
    pub inference: InferenceConfig,
    #[setting(flatten)]
    pub flow: FlowConfig,
    #[setting(flatten)]
    pub drift: DriftConfig,
    #[setting(flatten)]
    pub circuit_breaker: CircuitBreakerConfig,
    #[setting(flatten)]
    pub flow_trace: FlowTraceConfig,
    #[setting(flatten)]
    pub model_upload: ModelUploadConfig,
    #[setting(section = "ml", key = "ml_alert_channel_capacity", default = "1024")]
    pub alert_channel_capacity: usize,
}

impl MlConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.alert_channel_capacity > 0, "ml.alert_channel_capacity")?;
        self.inference.validate()?;
        self.flow.validate()?;
        self.drift.validate()?;
        self.circuit_breaker.validate()?;
        self.flow_trace.validate()?;
        self.model_upload.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::MlConfig;

    #[test]
    fn zero_aggregator_window_is_invalid() {
        let mut cfg = MlConfig::defaults();
        cfg.inference.aggregator_window_secs = 0;

        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_drift_window_is_invalid() {
        let mut cfg = MlConfig::defaults();
        cfg.drift.window_secs = 0;

        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_flow_tracker_limits_are_invalid() {
        let invalid_cases: [fn(&mut MlConfig); 5] = [
            |cfg: &mut MlConfig| cfg.flow.idle_threshold_us = 0,
            |cfg: &mut MlConfig| cfg.flow.bulk_min_packets = 0,
            |cfg: &mut MlConfig| cfg.flow.bulk_min_bytes = 0,
            |cfg: &mut MlConfig| cfg.flow.idle_timeout_us = 0,
            |cfg: &mut MlConfig| cfg.flow.terminated_timeout_us = 0,
        ];

        for apply_invalid in invalid_cases {
            let mut cfg = MlConfig::defaults();
            apply_invalid(&mut cfg);

            assert!(cfg.validate().is_err());
        }
    }

    #[test]
    fn invalid_flow_trace_rotation_limits_are_rejected() {
        let mut cfg = MlConfig::defaults();
        cfg.flow_trace.max_file_bytes = 0;
        assert!(cfg.validate().is_err());

        let mut cfg = MlConfig::defaults();
        cfg.flow_trace.max_file_age_secs = 0;
        assert!(cfg.validate().is_err());

        let mut cfg = MlConfig::defaults();
        cfg.flow_trace.max_file_bytes = 1024;
        cfg.flow_trace.total_budget_bytes = 512;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_model_upload_caps_are_invalid() {
        let invalid_cases: [fn(&mut MlConfig); 3] = [
            |cfg: &mut MlConfig| cfg.model_upload.max_onnx_bytes = 0,
            |cfg: &mut MlConfig| cfg.model_upload.max_manifest_bytes = 0,
            |cfg: &mut MlConfig| cfg.model_upload.max_scaler_bytes = 0,
        ];

        for apply_invalid in invalid_cases {
            let mut cfg = MlConfig::defaults();
            apply_invalid(&mut cfg);

            assert!(cfg.validate().is_err());
        }
    }
}
