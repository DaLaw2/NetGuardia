//! Factory that builds an `MLModelAdapter` from a `ModelManifest`: inspects
//! the manifest's `adapter` field, loads the named ONNX file(s) with shape
//! validation against the inference config's feature counts, and wraps the
//! `RunnableModel`s in `Arc` so hot-reload can swap without per-tick clones.
//! A shape mismatch yields `MLError::FeatureMismatch` carrying both
//! expected and observed dims for the upload UI to render.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use macros::log;
use tract_onnx::prelude::*;
use tract_onnx::tract_hir::infer::Factoid;
use tract_onnx::tract_hir::internal::DimLike;

use super::adapter::MLModelAdapter;
use super::manifest::{AdapterKind, LabelSpec, ModelManifest};
use crate::model::config::constants::MODELS_DIR;
use crate::model::detection::ml_detection::RunnableModel;
use crate::model::error::ml::MLError;
use crate::model::log::ml::MLLog;
use crate::model::system::config::MLInferenceConfig;

/// Wall-clock budget for a single ONNX parse + optimize + runnable chain.
/// A malformed or maliciously-crafted model can wedge tract's graph solver;
/// the timeout keeps an admin-triggered upload from blocking the watcher
/// indefinitely. Five seconds is generous for the models that currently
/// ship (<10MB) while still bounding pathological inputs.
const ONNX_LOAD_TIMEOUT: Duration = Duration::from_secs(5);

/// Build an `MLModelAdapter` by loading the ONNX file(s) the manifest names,
/// validating shape against the inference config's feature counts, and
/// wrapping the underlying `RunnableModel`s in `Arc` for zero-copy swap.
pub fn build_adapter(
    manifest: &ModelManifest,
    manifest_path: Option<&Path>,
    inference_config: &MLInferenceConfig,
    batch_size: usize,
) -> Result<MLModelAdapter, MLError> {
    let resolve = |rel: &str| -> PathBuf {
        match manifest_path {
            Some(mp) => ModelManifest::resolve_relative(mp, rel),
            None => PathBuf::from(MODELS_DIR).join(rel),
        }
    };

    match manifest.adapter {
        AdapterKind::AutoencoderOnly => {
            let Some(model_name) = manifest.models.model.as_deref() else {
                return Err(MLError::ManifestInvalid(
                    manifest_path.unwrap_or_else(|| Path::new("")).to_path_buf(),
                    "autoencoder_only adapter requires models.model".to_string(),
                ));
            };
            let path = resolve(model_name);
            let n_features = inference_config.num_ae_features();
            let model = Arc::new(loader(&path, model_name, n_features, batch_size)?);
            Ok(MLModelAdapter::AutoencoderOnly {
                model,
                batch_size,
                n_features,
            })
        }
        AdapterKind::ClassifierOnly => {
            let Some(model_name) = manifest.models.model.as_deref() else {
                return Err(MLError::ManifestInvalid(
                    manifest_path.unwrap_or_else(|| Path::new("")).to_path_buf(),
                    "classifier_only adapter requires models.model".to_string(),
                ));
            };
            let path = resolve(model_name);
            let n_features = inference_config.num_classifier_features();
            let model = Arc::new(loader(&path, model_name, n_features, batch_size)?);
            let labels = manifest.labels.clone();
            let normal_idx = find_label_index(&labels, "Normal");
            Ok(MLModelAdapter::ClassifierOnly {
                model,
                batch_size,
                n_features,
                labels,
                normal_idx,
            })
        }
        AdapterKind::MultiTask => {
            let Some(ae_name) = manifest.models.autoencoder.as_deref() else {
                return Err(MLError::ManifestInvalid(
                    manifest_path.unwrap_or_else(|| Path::new("")).to_path_buf(),
                    "multi_task adapter requires models.autoencoder".to_string(),
                ));
            };
            let Some(cls_name) = manifest.models.classifier.as_deref() else {
                return Err(MLError::ManifestInvalid(
                    manifest_path.unwrap_or_else(|| Path::new("")).to_path_buf(),
                    "multi_task adapter requires models.classifier".to_string(),
                ));
            };
            let n_ae = inference_config.num_ae_features();
            let n_cls = inference_config.num_classifier_features();
            let ae = Arc::new(loader(&resolve(ae_name), ae_name, n_ae, batch_size)?);
            let classifier = Arc::new(loader(&resolve(cls_name), cls_name, n_cls, batch_size)?);
            let labels = manifest.labels.clone();
            let normal_idx = find_label_index(&labels, "Normal");
            let c2_idx = find_label_index(&labels, "C2 Communication");
            Ok(MLModelAdapter::MultiTask {
                ae,
                classifier,
                batch_size,
                n_ae,
                n_cls,
                labels,
                normal_idx,
                c2_idx,
            })
        }
    }
}

/// Locate a label index by its `name` field. Used to cache hot-path indices
/// (Normal, C2 Communication) at adapter build time rather than re-scanning
/// the label map on every inference batch.
fn find_label_index(labels: &BTreeMap<String, LabelSpec>, target: &str) -> Option<usize> {
    labels
        .iter()
        .find(|(_, v)| v.name.eq_ignore_ascii_case(target))
        .and_then(|(k, _)| k.parse::<usize>().ok())
}

fn loader(model_path: &Path, model_name: &str, features: usize, batch_size: usize) -> Result<RunnableModel, MLError> {
    log!(MLLog::ModelLoading(model_name.to_string(), features, batch_size));

    let start = Instant::now();
    let path_for_thread = model_path.to_path_buf();
    let name_for_thread = model_name.to_string();
    let result = load_with_timeout(model_path.to_path_buf(), ONNX_LOAD_TIMEOUT, move || {
        loader_inner(&path_for_thread, &name_for_thread, features, batch_size)
    });
    let elapsed_ms = start.elapsed().as_millis() as u64;
    log!(MLLog::ModelLoadComplete(model_name.to_string(), elapsed_ms));

    result
}

/// Run `f` on a dedicated OS thread with a wall-clock cap. Prevents a
/// pathological ONNX from wedging `tract`'s graph solver and holding up
/// the watcher / bootstrap indefinitely. On timeout the worker thread
/// is detached — it will finish on its own and drop its state; the cost
/// of one leaked thread is acceptable for a low-frequency operation
/// gated behind admin upload + manifest validation.
fn load_with_timeout<F, R>(path: PathBuf, budget: Duration, f: F) -> Result<R, MLError>
where
    F: FnOnce() -> Result<R, MLError> + Send + 'static,
    R: Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(budget) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(MLError::ModelLoadTimeout(path, budget.as_secs())),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(MLError::ModelLoadFailed(
            path,
            "loader thread disconnected before completing".to_string(),
        )),
    }
}

fn loader_inner(
    model_path: &Path,
    model_name: &str,
    features: usize,
    batch_size: usize,
) -> Result<RunnableModel, MLError> {
    let mut onnx_model = onnx()
        .model_for_path(model_path)
        .map_err(|e| MLError::ModelLoadFailed(model_path.to_path_buf(), format!("parse ONNX: {e}")))?;

    if let Some(onnx_dim) = introspect_input_features(&onnx_model) {
        let matched = onnx_dim == features;
        log!(MLLog::OnnxShapeChecked(
            model_name.to_string(),
            features,
            onnx_dim,
            matched,
        ));
        if !matched {
            return Err(MLError::FeatureMismatch(model_path.to_path_buf(), features, onnx_dim));
        }
    }

    onnx_model
        .set_input_fact(0, f32::fact([batch_size, features]).into())
        .map_err(|e| MLError::ModelLoadFailed(model_path.to_path_buf(), format!("set_input_fact: {e}")))?;

    onnx_model
        .into_optimized()
        .and_then(|m| m.into_runnable())
        .map_err(|e| MLError::ModelLoadFailed(model_path.to_path_buf(), format!("optimize/runnable: {e}")))
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

    /// Repo-root integration: the shipped v10 AE ONNX's input last-dim must
    /// still be 31. A change here means the shipped manifest + sidecar drifted.
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

    #[test]
    fn load_with_timeout_passes_fast_loader() {
        let result: Result<u32, MLError> =
            load_with_timeout(PathBuf::from("/tmp/fast.onnx"), Duration::from_millis(500), || Ok(42));
        assert_eq!(result.ok(), Some(42));
    }

    #[test]
    fn load_with_timeout_returns_timeout_error_when_budget_exceeded() {
        let path = PathBuf::from("/tmp/slow.onnx");
        let result: Result<u32, MLError> = load_with_timeout(path.clone(), Duration::from_millis(50), || {
            thread::sleep(Duration::from_millis(500));
            Ok(42)
        });
        match result {
            Err(MLError::ModelLoadTimeout {
                path: got_path,
                seconds,
            }) => {
                assert_eq!(got_path, path);
                assert_eq!(seconds, 0, "budget < 1s rounds to 0 on `as_secs`");
            }
            other => panic!("expected ModelLoadTimeout, got {other:?}"),
        }
    }

    #[test]
    fn load_with_timeout_propagates_loader_error() {
        // Failures surface unchanged; timeout wrapping must not swallow them.
        let path = PathBuf::from("/tmp/bad.onnx");
        let err_path = path.clone();
        let result: Result<u32, MLError> = load_with_timeout(path, Duration::from_millis(500), move || {
            Err(MLError::ModelLoadFailed(
                err_path,
                "synthetic parse failure".to_string(),
            ))
        });
        match result {
            Err(MLError::ModelLoadFailed { err, .. }) => assert!(err.contains("synthetic")),
            other => panic!("expected ModelLoadFailed, got {other:?}"),
        }
    }

    /// Smoke: the shipped manifest + sidecar must load and produce a
    /// `MultiTask` adapter with both underlying models.
    #[test]
    fn v10_build_adapter_multitask() {
        let manifest_path = Path::new("models/manifest.yaml");
        if !manifest_path.exists() {
            eprintln!("skipping: models/manifest.yaml absent");
            return;
        }
        let (cfg, manifest) = MLInferenceConfig::from_manifest_with_sidecar(manifest_path).expect("config load");
        let adapter = build_adapter(&manifest, Some(manifest_path), &cfg, 8).expect("build adapter");
        match adapter {
            MLModelAdapter::MultiTask { n_ae, n_cls, .. } => {
                assert_eq!(n_ae, 31);
                assert_eq!(n_cls, 32);
            }
            _ => panic!("v10 manifest should build MultiTask adapter"),
        }
    }
}
