use std::path::Path;

use crate::domain::detection::error::MLError;
use crate::domain::detection::manifest::ModelManifest;
use crate::domain::detection::ml_inference_config::MLInferenceConfig;

pub trait ModelConfigLoader: Send + Sync {
    fn load_manifest(&self, manifest_path: &Path) -> Result<ModelManifest, MLError>;
    fn load_manifest_with_sidecar(&self, manifest_path: &Path) -> Result<(MLInferenceConfig, ModelManifest), MLError>;
}
