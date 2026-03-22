use std::fs;
use std::path::PathBuf;

use crate::model::error::ml::MLError;

pub use crate::model::config::MLInferenceConfig;

/// Backward-compatible alias so existing `use config_loader::InferenceConfig` paths still compile.
pub type InferenceConfig = MLInferenceConfig;

impl MLInferenceConfig {
    pub fn load_file(file: &str) -> Result<Self, MLError> {
        let path = PathBuf::from("models").join(file);
        let content = fs::read_to_string(&path)
            .map_err(|_| MLError::ConfigLoadFailed(path.to_path_buf()))?;
        let config: MLInferenceConfig = serde_json::from_str(&content)
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
}
