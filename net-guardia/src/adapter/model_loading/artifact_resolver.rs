use std::path::{Path, PathBuf};

use crate::domain::detection::manifest::ModelManifest;
use crate::domain::detection::model_files::MODELS_DIR;
use crate::interface::detection::model_artifact_resolver::ModelArtifactResolver;

#[derive(Default)]
pub struct FsModelArtifactResolver;

impl ModelArtifactResolver for FsModelArtifactResolver {
    fn resolve_model_path(&self, manifest_path: Option<&Path>, relative_path: &str) -> PathBuf {
        match manifest_path {
            Some(path) => ModelManifest::resolve_relative(path, relative_path),
            None => PathBuf::from(MODELS_DIR).join(relative_path),
        }
    }
}
