use crate::domain::detection::ml_inference_config::MLInferenceConfig;

pub struct FeatureBaselines {
    pub names: Vec<String>,
    pub means: Vec<f64>,
    pub stds: Vec<f64>,
}

impl FeatureBaselines {
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

#[derive(Debug, Clone)]
pub struct DriftReport {
    pub drifted_features: Vec<String>,
    pub max_deviation: f64,
}
