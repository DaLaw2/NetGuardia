use std::fs;
use std::path::Path;

use crate::domain::detection::error::MLError;
use crate::domain::detection::manifest::ModelManifest;

impl ModelManifest {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, MLError> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .map_err(|e| MLError::ManifestInvalid(path.to_path_buf(), format!("read failed: {e}")))?;
        let manifest: ModelManifest = serde_yaml_ng::from_str(&content)
            .map_err(|e| MLError::ManifestInvalid(path.to_path_buf(), format!("YAML parse: {e}")))?;
        manifest.validate(path)?;
        Ok(manifest)
    }
}
