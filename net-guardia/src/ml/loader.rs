use ort::session::Session;
use std::path::{Path, PathBuf};
use crate::model::error::ml::MLError;

pub struct MLModels {
    pub deep_autoencoder: Session,
    pub random_forest: Session,
    pub mlp: Session,
}

impl MLModels {
    pub fn load_from_dir<P: AsRef<Path>>(models_dir: P) -> Result<Self, MLError> {
        let dir = models_dir.as_ref();

        let da_path = dir.join("deep_autoencoder.onnx");
        let deep_autoencoder = Session::builder()
            .map_err(|_| MLError::ModelLoadFailed { path: da_path.clone() })?
            .commit_from_file(&da_path)
            .map_err(|_| MLError::ModelLoadFailed { path: da_path })?;

        let rf_path = dir.join("random_forest.onnx");
        let random_forest = Session::builder()
            .map_err(|_| MLError::ModelLoadFailed { path: rf_path.clone() })?
            .commit_from_file(&rf_path)
            .map_err(|_| MLError::ModelLoadFailed { path: rf_path })?;

        let mlp_path = dir.join("mlp.onnx");
        let mlp = Session::builder()
            .map_err(|_| MLError::ModelLoadFailed { path: mlp_path.clone() })?
            .commit_from_file(&mlp_path)
            .map_err(|_| MLError::ModelLoadFailed { path: mlp_path })?;

        Ok(Self {
            deep_autoencoder,
            random_forest,
            mlp,
        })
    }
}