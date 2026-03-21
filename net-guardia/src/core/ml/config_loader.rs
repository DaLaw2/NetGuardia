use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

use crate::model::error::ml::MLError;
use crate::model::ml_detection::ClipParams;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceConfig {
    pub ae_feature_names: Vec<String>,
    pub ae_clip_params: HashMap<String, ClipParams>,
    pub ae_scaler_mean: Vec<f64>,
    pub ae_scaler_std: Vec<f64>,
    pub ae_post_clip_min: f64,
    pub ae_post_clip_max: f64,
    pub ae_threshold: f32,
    pub classifier_feature_names: Vec<String>,
    pub attack_labels: HashMap<String, String>,
}

impl InferenceConfig {
    pub fn load_file(file: &str) -> Result<Self, MLError> {
        let path = PathBuf::from("models").join(file);
        let content = fs::read_to_string(&path)
            .map_err(|_| MLError::ConfigLoadFailed(path.to_path_buf()))?;
        let config: InferenceConfig = serde_json::from_str(&content)
            .map_err(|e| MLError::ConfigParseFailed(e.to_string()))?;
        if config.ae_feature_names.is_empty() {
            return Err(MLError::ConfigParseFailed("ae_feature_names is empty"));
        }
        if config.ae_scaler_mean.len() != config.ae_feature_names.len() {
            return Err(MLError::ConfigParseFailed("scaler mean length mismatch"));
        }
        if config.ae_scaler_std.len() != config.ae_feature_names.len() {
            return Err(MLError::ConfigParseFailed("scaler std length mismatch"));
        }
        Ok(config)
    }

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