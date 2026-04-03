use crate::model::system::config::MLInferenceConfig;

/// Baselines loaded from the inference config (scaler mean / std).
/// If inference_config has no scaler data, drift detection is disabled.
pub struct FeatureBaselines {
    pub names: Vec<String>,
    pub means: Vec<f64>,
    pub stds: Vec<f64>,
}

impl FeatureBaselines {
    /// Build baselines from the ML inference config.
    /// Returns `None` if the config has no features (drift detection disabled).
    pub fn from_inference_config(config: &MLInferenceConfig) -> Option<Self> {
        if config.ae_feature_names.is_empty() {
            return None;
        }
        Some(Self {
            names: config.ae_feature_names.clone(),
            means: config.ae_scaler_mean.clone(),
            stds: config.ae_scaler_std.clone(),
        })
    }
}

/// Report emitted when feature drift is detected.
#[derive(Debug, Clone)]
pub struct DriftReport {
    pub drifted_features: Vec<String>,
    pub max_deviation: f64,
}
