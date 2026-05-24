use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::domain::detection::ml_detection::ClipParams;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MLInferenceConfig {
    pub ae_feature_names: Vec<String>,
    pub ae_clip_params: HashMap<String, ClipParams>,
    pub ae_scaler_mean: Vec<f64>,
    pub ae_scaler_std: Vec<f64>,
    pub ae_post_clip_min: f64,
    pub ae_post_clip_max: f64,
    pub classifier_feature_names: Vec<String>,
    #[serde(default)]
    pub minmax_params: HashMap<String, MinMaxParams>,
    #[serde(default)]
    pub robust_params: HashMap<String, RobustParams>,
    #[serde(default)]
    pub quantile_params: HashMap<String, QuantileParams>,
}

impl MLInferenceConfig {
    pub fn num_ae_features(&self) -> usize {
        self.ae_feature_names.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinMaxParams {
    pub min: f64,
    pub max: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RobustParams {
    pub center: f64,
    pub scale: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuantileParams {
    pub values: Vec<f64>,
    pub quantiles: Vec<f64>,
}
