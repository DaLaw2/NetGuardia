use std::path::{Path, PathBuf};

pub trait ModelArtifactResolver: Send + Sync {
    fn resolve_model_path(&self, manifest_path: Option<&Path>, relative_path: &str) -> PathBuf;
}
