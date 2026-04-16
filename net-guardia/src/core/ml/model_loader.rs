use std::path::PathBuf;
use std::time::Instant;

use macros::log;
use tract_onnx::prelude::*;
use tract_onnx::tract_hir::infer::Factoid;
use tract_onnx::tract_hir::internal::DimLike;

use crate::infrastructure::app_config::AppConfig;
use crate::model::detection::ml_detection::RunnableModel;
use crate::model::error::ml::MLError;
use crate::model::log::ml::MLLog;
use crate::model::system::config::MLInferenceConfig;

pub struct MLModels {
    pub deep_autoencoder: RunnableModel,
    pub classifier: RunnableModel,
    pub batch_size: usize,
}

impl MLModels {
    pub fn load_models(
        app_config: &Arc<AppConfig>,
        inference_config: &Arc<MLInferenceConfig>,
        batch_size: usize,
    ) -> Result<Self, MLError> {
        Self::load_named(
            &app_config.inference.deep_autoencoder_name,
            &app_config.inference.classifier_name,
            inference_config,
            batch_size,
        )
    }

    /// Manifest-friendly constructor: caller supplies the AE and classifier ONNX filenames
    /// directly. Used when a `ModelManifest` overrides the defaults in `AppConfig`.
    pub fn load_named(
        autoencoder_name: &str,
        classifier_name: &str,
        inference_config: &Arc<MLInferenceConfig>,
        batch_size: usize,
    ) -> Result<Self, MLError> {
        Ok(Self {
            deep_autoencoder: Self::loader(autoencoder_name, inference_config.num_ae_features(), batch_size)?,
            classifier: Self::loader(classifier_name, inference_config.num_classifier_features(), batch_size)?,
            batch_size,
        })
    }

    fn loader(model: &str, features: usize, batch_size: usize) -> Result<RunnableModel, MLError> {
        let model_path = PathBuf::from("models").join(model);

        log!(MLLog::ModelLoading(model.to_string(), features, batch_size));

        let start = Instant::now();
        let result = Self::loader_inner(&model_path, model, features, batch_size);
        let elapsed_ms = start.elapsed().as_millis() as u64;
        log!(MLLog::ModelLoadComplete(model.to_string(), elapsed_ms));

        result
    }

    fn loader_inner(
        model_path: &PathBuf,
        model: &str,
        features: usize,
        batch_size: usize,
    ) -> Result<RunnableModel, MLError> {
        let mut onnx_model = onnx()
            .model_for_path(model_path)
            .map_err(|_| MLError::ModelLoadFailed(model_path.clone()))?;

        // Introspect the ONNX input fact and cross-check its last dim against the
        // expected feature count. A dynamic/symbolic dim is skipped — we only fail
        // when the ONNX graph declares a concrete integer that disagrees.
        if let Some(onnx_dim) = introspect_input_features(&onnx_model) {
            let matched = onnx_dim == features;
            log!(MLLog::OnnxShapeChecked(model.to_string(), features, onnx_dim, matched,));
            if !matched {
                return Err(MLError::FeatureMismatch(model_path.clone(), features, onnx_dim));
            }
        }

        onnx_model
            .set_input_fact(0, f32::fact([batch_size, features]).into())
            .map_err(|_| MLError::ModelLoadFailed(model_path.clone()))?;

        onnx_model
            .into_optimized()
            .and_then(|m| m.into_runnable())
            .map_err(|_| MLError::ModelLoadFailed(model_path.clone()))
    }

    pub fn get_model_info(&self, name: &str) -> String {
        let model = match name {
            "deep_autoencoder" => &self.deep_autoencoder,
            "classifier" => &self.classifier,
            _ => return "unknown model".to_string(),
        };

        let inputs = model.model().inputs.len();
        let outputs = model.model().outputs.len();
        format!(
            "{name}: inputs: {inputs}, outputs: {outputs}, batch_size: {}",
            self.batch_size
        )
    }
}

/// Read the concrete last-dim (feature count) from an ONNX model's declared input fact.
/// Returns None when the dim is dynamic/symbolic or when the model has no input 0.
fn introspect_input_features(model: &InferenceModel) -> Option<usize> {
    let fact = model.input_fact(0).ok()?;
    let rank = fact.shape.rank().concretize()? as usize;
    if rank == 0 {
        return None;
    }
    let last = fact.shape.dim(rank - 1)?;
    last.concretize()?.to_usize().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Integration test: tract must introspect the shipped v10 AE ONNX's input dim as 31.
    /// Silently skipped outside the repo root (no `models/` directory).
    #[test]
    fn introspect_v10_autoencoder_input_is_31() {
        let ae_path = PathBuf::from("models/deep_autoencoder.onnx");
        if !ae_path.exists() {
            eprintln!("skipping: models/deep_autoencoder.onnx absent");
            return;
        }
        let model = onnx().model_for_path(&ae_path).expect("load AE onnx");
        let dim = introspect_input_features(&model).expect("v10 AE should expose a concrete final-dim");
        assert_eq!(dim, 31, "v10 AE ONNX input dim changed unexpectedly");
    }

    #[test]
    fn introspect_v10_classifier_input_is_32() {
        let cls_path = PathBuf::from("models/classifier.onnx");
        if !cls_path.exists() {
            eprintln!("skipping: models/classifier.onnx absent");
            return;
        }
        let model = onnx().model_for_path(&cls_path).expect("load classifier onnx");
        let dim = introspect_input_features(&model).expect("v10 classifier should expose a concrete final-dim");
        assert_eq!(dim, 32, "v10 classifier ONNX input dim changed unexpectedly");
    }

    /// End-to-end M1 smoke: loading v10 via `load_named` with the manifest-driven
    /// names + sidecar-derived inference config must succeed without shape mismatch.
    #[test]
    fn v10_load_named_with_manifest_paths_succeeds() {
        let manifest_path = std::path::Path::new("models/manifest.yaml");
        if !manifest_path.exists() {
            eprintln!("skipping: models/manifest.yaml absent");
            return;
        }
        let (cfg, manifest) =
            MLInferenceConfig::from_manifest_with_sidecar(manifest_path).expect("manifest + sidecar load");
        let cfg = Arc::new(cfg);
        let ae = manifest.models.autoencoder.as_deref().expect("multi_task has AE");
        let cls = manifest
            .models
            .classifier
            .as_deref()
            .expect("multi_task has classifier");
        let _models = MLModels::load_named(ae, cls, &cfg, 8).expect("v10 load via manifest names");
    }
}
