use std::fs;
use std::path::Path;

use crate::domain::detection::error::MLError;
use crate::domain::detection::manifest::ModelManifest;

pub fn load_model_manifest(path: impl AsRef<Path>) -> Result<ModelManifest, MLError> {
    let path = path.as_ref();
    let content = fs::read_to_string(path).map_err(|e| MLError::ManifestReadFailed(path.to_path_buf(), e))?;
    let manifest: ModelManifest =
        serde_yaml_ng::from_str(&content).map_err(|e| MLError::ManifestParseFailed(path.to_path_buf(), e))?;
    manifest.validate(path)?;
    Ok(manifest)
}
