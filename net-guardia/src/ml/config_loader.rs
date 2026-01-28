use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

use crate::model::error::ml::MLError;
use crate::model::ml_detection::{AENormalization, ClipParams};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceConfig {
    pub threshold: f64,
    pub strategy_name: String,
    pub clip_params: HashMap<String, ClipParams>,
    pub scaler_mean: Vec<f64>,
    pub scaler_std: Vec<f64>,
    pub post_clip_min: f64,
    pub post_clip_max: f64,
    pub ae_normalization: AENormalization,
    pub attack_labels: HashMap<String, String>,
    pub feature_names: Vec<String>,
}

impl InferenceConfig {
    pub fn load_file(file: &str) -> Result<Self, MLError> {
        let path = PathBuf::from("models").join(file);
        let content = fs::read_to_string(&path)
            .map_err(|_| MLError::ConfigLoadFailed { path: path.to_path_buf() })?;
        let config: InferenceConfig = serde_json::from_str(&content)
            .map_err(|e| MLError::ConfigParseFailed { reason: e.to_string() })?;
        Ok(config)
    }

    pub fn num_features(&self) -> usize {
        self.feature_names.len()
    }

    pub fn num_attack_types(&self) -> usize {
        self.attack_labels.len()
    }

    pub fn get_attack_label(&self, id: usize) -> Option<&String> {
        self.attack_labels.get(&id.to_string())
    }
}