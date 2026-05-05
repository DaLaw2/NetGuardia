use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::domain::detection::ml_detection::ClipParams;

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
