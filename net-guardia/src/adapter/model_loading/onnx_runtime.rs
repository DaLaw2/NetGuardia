use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use macros::log;
use tract_onnx::prelude::*;
use tract_onnx::tract_hir::infer::Factoid;
use tract_onnx::tract_hir::internal::DimLike;

use crate::domain::detection::error::MLError;
use crate::domain::detection::log::MLLog;
use crate::domain::detection::manifest::{OutputHeadSpec, StageKind, output_semantic_is_matrix};
use crate::interface::detection::model_runtime::{ModelRuntime, ModelRuntimeLoader, RuntimeTensor};

type OnnxRunnableModel = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<OnnxRunnableModel>();
};

const MAX_CONCURRENT_ONNX_LOADS: usize = 2;
static ONNX_LOAD_THREADS: AtomicUsize = AtomicUsize::new(0);

#[derive(Default)]
pub struct OnnxRuntimeLoader;

impl ModelRuntimeLoader for OnnxRuntimeLoader {
    fn load(
        &self,
        model_path: &Path,
        model_name: &str,
        features: usize,
        batch_size: usize,
        timeout: Duration,
    ) -> Result<Arc<dyn ModelRuntime>, MLError> {
        load_model(model_path, model_name, features, batch_size, timeout)
            .map(|model| Arc::new(model) as Arc<dyn ModelRuntime>)
    }
}

struct OnnxModel {
    name: String,
    model: OnnxRunnableModel,
}

impl ModelRuntime for OnnxModel {
    fn run_stage_batch(
        &self,
        rows: &[Vec<f32>],
        batch_size: usize,
        n_features: usize,
        stage_kind: StageKind,
        output_heads: &[OutputHeadSpec],
    ) -> Result<Vec<RuntimeTensor>, MLError> {
        let input = padded_input(rows, batch_size, n_features)?;
        match stage_kind {
            StageKind::Autoencoder => self.run_autoencoder_stage_input(input, rows.len(), n_features, output_heads),
            StageKind::Classifier | StageKind::Generic => self.run_generic_stage_input(input, rows.len(), output_heads),
        }
    }
}

impl OnnxModel {
    fn run_autoencoder_stage_input(
        &self,
        input: tract_ndarray::Array2<f32>,
        row_count: usize,
        n_features: usize,
        output_heads: &[OutputHeadSpec],
    ) -> Result<Vec<RuntimeTensor>, MLError> {
        let scores = self.run_autoencoder_input(input, row_count, n_features)?;
        let mut tensors = Vec::with_capacity(output_heads.len());
        for head in output_heads {
            tensors.push(RuntimeTensor::Scalar {
                name: head.name.clone(),
                values: scores.clone(),
            });
        }
        Ok(tensors)
    }

    fn run_generic_stage_input(
        &self,
        input: tract_ndarray::Array2<f32>,
        row_count: usize,
        output_heads: &[OutputHeadSpec],
    ) -> Result<Vec<RuntimeTensor>, MLError> {
        let result = self
            .model
            .run(tvec![input.into_tensor().into()])
            .map_err(|e| MLError::RuntimeFailed(self.name.clone(), e))?;
        let mut tensors = Vec::with_capacity(output_heads.len());
        for head in output_heads {
            if output_semantic_is_matrix(&head.semantic) {
                let view = output_at(&result, head.index, &self.name, &head.name)?
                    .to_array_view::<f32>()
                    .map_err(|e| MLError::RuntimeFailed(self.name.clone(), e))?;
                let rows = collect_matrix_rows(view, row_count, &self.name, &head.name)?;
                tensors.push(RuntimeTensor::Matrix {
                    name: head.name.clone(),
                    rows,
                });
            } else {
                let values = collect_scalar_head(&result, head.index, row_count, &self.name, &head.name)?;
                tensors.push(RuntimeTensor::Scalar {
                    name: head.name.clone(),
                    values,
                });
            }
        }
        Ok(tensors)
    }

    fn run_autoencoder_input(
        &self,
        input: tract_ndarray::Array2<f32>,
        row_count: usize,
        n_features: usize,
    ) -> Result<Vec<f32>, MLError> {
        let result = self
            .model
            .run(tvec![input.clone().into_tensor().into()])
            .map_err(|e| MLError::RuntimeFailed(self.name.clone(), e))?;
        let output_view = output_at(&result, 0, &self.name, "autoencoder")?
            .to_array_view::<f32>()
            .map_err(|e| MLError::RuntimeFailed(self.name.clone(), e))?;
        let output = output_view
            .into_dimensionality::<tract_ndarray::Ix2>()
            .map_err(|e| MLError::RuntimeFailed(self.name.clone(), e))?;
        ensure_autoencoder_output_shape(output.dim(), input.dim(), &self.name)?;
        ensure_finite_values(output.iter().copied(), &self.name, "autoencoder")?;
        let diff = input - output;
        let sq = &diff * &diff;

        let mut scores = Vec::with_capacity(row_count);
        let n_f = n_features as f32;
        for i in 0..row_count {
            scores.push(sq.row(i).sum() / n_f);
        }
        Ok(scores)
    }
}

fn output_at<'a>(
    outputs: &'a TVec<TValue>,
    index: usize,
    model_name: &str,
    head_name: &str,
) -> Result<&'a TValue, MLError> {
    outputs.get(index).ok_or_else(|| {
        MLError::RuntimeFailed(
            model_name.to_string(),
            format!(
                "{head_name} output missing: model returned {} output tensors, expected at least {}",
                outputs.len(),
                index + 1
            ),
        )
    })
}

fn collect_scalar_head(
    outputs: &TVec<TValue>,
    index: usize,
    row_count: usize,
    model_name: &str,
    head_name: &str,
) -> Result<Vec<f32>, MLError> {
    let view = output_at(outputs, index, model_name, head_name)?
        .to_array_view::<f32>()
        .map_err(|e| MLError::RuntimeFailed(model_name.to_string(), e))?;
    let values = view.as_slice().ok_or_else(|| {
        MLError::RuntimeFailed(model_name.to_string(), format!("{head_name} output is not contiguous"))
    })?;
    if values.len() < row_count {
        return Err(MLError::RuntimeFailed(
            model_name.to_string(),
            format!(
                "{head_name} output has {} values, expected at least {row_count}",
                values.len()
            ),
        ));
    }
    ensure_finite_values(values[..row_count].iter().copied(), model_name, head_name)?;
    Ok(values[..row_count].to_vec())
}

fn collect_matrix_rows(
    view: tract_ndarray::ArrayViewD<'_, f32>,
    row_count: usize,
    model_name: &str,
    head_name: &str,
) -> Result<Vec<Vec<f32>>, MLError> {
    let matrix = view
        .into_dimensionality::<tract_ndarray::Ix2>()
        .map_err(|e| MLError::RuntimeFailed(model_name.to_string(), e))?;
    if matrix.nrows() < row_count {
        return Err(MLError::RuntimeFailed(
            model_name.to_string(),
            format!(
                "{head_name} output has {} rows, expected at least {row_count}",
                matrix.nrows()
            ),
        ));
    }
    (0..row_count)
        .map(|i| {
            let row: Vec<f32> = matrix.row(i).iter().copied().collect();
            ensure_finite_values(row.iter().copied(), model_name, head_name)?;
            Ok(row)
        })
        .collect()
}

fn ensure_autoencoder_output_shape(
    output_dim: (usize, usize),
    input_dim: (usize, usize),
    model_name: &str,
) -> Result<(), MLError> {
    if output_dim != input_dim {
        return Err(MLError::RuntimeFailed(
            model_name.to_string(),
            format!("autoencoder output shape {output_dim:?} does not match input shape {input_dim:?}"),
        ));
    }
    Ok(())
}

fn ensure_finite_values(
    values: impl IntoIterator<Item = f32>,
    model_name: &str,
    head_name: &str,
) -> Result<(), MLError> {
    if values.into_iter().any(|value| !value.is_finite()) {
        return Err(MLError::RuntimeFailed(
            model_name.to_string(),
            format!("{head_name} output contains non-finite values"),
        ));
    }
    Ok(())
}

fn padded_input(
    rows: &[Vec<f32>],
    batch_size: usize,
    n_features: usize,
) -> Result<tract_ndarray::Array2<f32>, MLError> {
    validate_batch_shape(rows.len(), batch_size, n_features)?;
    for (idx, row) in rows.iter().enumerate() {
        if row.len() < n_features {
            return Err(MLError::ConfigInvalid(format!(
                "model runtime row {idx} has {} features, expected at least {n_features}",
                row.len()
            )));
        }
    }

    Ok(tract_ndarray::Array2::<f32>::from_shape_fn(
        (batch_size, n_features),
        |(i, j)| {
            if i < rows.len() { rows[i][j] } else { 0.0 }
        },
    ))
}

#[cfg(test)]
fn padded_input_from_flat(
    rows_flat: &[f32],
    row_count: usize,
    batch_size: usize,
    n_features: usize,
) -> Result<tract_ndarray::Array2<f32>, MLError> {
    validate_batch_shape(row_count, batch_size, n_features)?;
    let required_len = row_count
        .checked_mul(n_features)
        .ok_or(MLError::ConfigInvalid("model runtime feature buffer length overflow"))?;
    if rows_flat.len() < required_len {
        return Err(MLError::ConfigInvalid(format!(
            "model runtime feature buffer has {} values, expected at least {required_len}",
            rows_flat.len()
        )));
    }

    let mut input = tract_ndarray::Array2::<f32>::zeros((batch_size, n_features));
    let Some(input_slice) = input.as_slice_mut() else {
        return Err(MLError::ConfigInvalid("model runtime input array is not contiguous"));
    };
    input_slice[..required_len].copy_from_slice(&rows_flat[..required_len]);
    Ok(input)
}

fn validate_batch_shape(row_count: usize, batch_size: usize, n_features: usize) -> Result<(), MLError> {
    if n_features == 0 {
        return Err(MLError::ConfigInvalid("model runtime feature count is zero"));
    }
    if row_count > batch_size {
        return Err(MLError::ConfigInvalid(format!(
            "model runtime row count {row_count} exceeds batch size {batch_size}"
        )));
    }
    Ok(())
}

fn load_model(
    model_path: &Path,
    model_name: &str,
    features: usize,
    batch_size: usize,
    timeout: Duration,
) -> Result<OnnxModel, MLError> {
    log!(MLLog::ModelLoading(model_name.to_string(), features, batch_size));

    let start = Instant::now();
    let path_for_thread = model_path.to_path_buf();
    let name_for_thread = model_name.to_string();
    let result = load_with_timeout(model_path.to_path_buf(), timeout, move || {
        load_model_inner(&path_for_thread, &name_for_thread, features, batch_size)
    });
    let elapsed_ms = start.elapsed().as_millis() as u64;
    log!(MLLog::ModelLoadComplete(model_name.to_string(), elapsed_ms));

    result
}

fn load_with_timeout<F, R>(path: PathBuf, budget: Duration, f: F) -> Result<R, MLError>
where
    F: FnOnce() -> Result<R, MLError> + Send + 'static,
    R: Send + 'static,
{
    let permit = OnnxLoadPermit::try_acquire(&path)?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _permit = permit;
        let _ = tx.send(f());
    });
    match rx.recv_timeout(budget) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => Err(MLError::ModelLoadTimeout(path, budget.as_secs())),
        Err(RecvTimeoutError::Disconnected) => Err(MLError::ModelLoadFailed(
            path,
            "loader thread disconnected before completing".to_string(),
        )),
    }
}

struct OnnxLoadPermit;

impl OnnxLoadPermit {
    fn try_acquire(path: &Path) -> Result<Self, MLError> {
        let mut current = ONNX_LOAD_THREADS.load(Ordering::Acquire);
        loop {
            if current >= MAX_CONCURRENT_ONNX_LOADS {
                return Err(MLError::ModelLoadFailed(
                    path.to_path_buf(),
                    format!("too many concurrent ONNX loads ({MAX_CONCURRENT_ONNX_LOADS})"),
                ));
            }
            match ONNX_LOAD_THREADS.compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(Self),
                Err(next) => current = next,
            }
        }
    }
}

impl Drop for OnnxLoadPermit {
    fn drop(&mut self) {
        ONNX_LOAD_THREADS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn load_model_inner(
    model_path: &Path,
    model_name: &str,
    features: usize,
    batch_size: usize,
) -> Result<OnnxModel, MLError> {
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

    let model = onnx_model
        .into_optimized()
        .and_then(|m| m.into_runnable())
        .map_err(|e| MLError::ModelLoadFailed(model_path.to_path_buf(), format!("optimize/runnable: {e}")))?;

    Ok(OnnxModel {
        name: model_name.to_string(),
        model,
    })
}

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
    use std::sync::Mutex;

    use super::*;

    static LOAD_TIMEOUT_TEST_LOCK: Mutex<()> = Mutex::new(());

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
        let _guard = LOAD_TIMEOUT_TEST_LOCK.lock().unwrap();
        let result: Result<u32, MLError> =
            load_with_timeout(PathBuf::from("/tmp/fast.onnx"), Duration::from_millis(500), || Ok(42));
        assert_eq!(result.ok(), Some(42));
    }

    #[test]
    fn load_with_timeout_returns_timeout_error_when_budget_exceeded() {
        let _guard = LOAD_TIMEOUT_TEST_LOCK.lock().unwrap();
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
        thread::sleep(Duration::from_millis(550));
    }

    #[test]
    fn load_with_timeout_propagates_loader_error() {
        let _guard = LOAD_TIMEOUT_TEST_LOCK.lock().unwrap();
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

    #[test]
    fn padded_input_rejects_short_rows() {
        let rows = vec![vec![1.0, 2.0]];
        let err = padded_input(&rows, 1, 3).expect_err("short row should be rejected");
        assert!(matches!(err, MLError::ConfigInvalid { .. }), "got {err:?}");
    }

    #[test]
    fn padded_input_from_flat_rejects_short_buffer() {
        let err = padded_input_from_flat(&[1.0, 2.0], 1, 1, 3).expect_err("short buffer should be rejected");
        assert!(matches!(err, MLError::ConfigInvalid { .. }), "got {err:?}");
    }

    #[test]
    fn padded_input_rejects_row_count_over_batch_size() {
        let rows = vec![vec![1.0], vec![2.0]];
        let err = padded_input(&rows, 1, 1).expect_err("row count above batch size should be rejected");
        assert!(matches!(err, MLError::ConfigInvalid { .. }), "got {err:?}");
    }

    #[test]
    fn output_at_rejects_missing_output_head() {
        let outputs: TVec<TValue> = tvec![];

        let err = output_at(&outputs, 0, "test-model", "anomaly").expect_err("missing output should be rejected");

        assert!(matches!(err, MLError::RuntimeFailed { .. }), "got {err:?}");
    }

    #[test]
    fn collect_scalar_head_rejects_short_output() {
        let outputs: TVec<TValue> = tvec![tract_ndarray::arr1(&[0.5f32]).into_tensor().into()];

        let err =
            collect_scalar_head(&outputs, 0, 2, "test-model", "anomaly").expect_err("short output should be rejected");

        assert!(matches!(err, MLError::RuntimeFailed { .. }), "got {err:?}");
    }

    #[test]
    fn collect_scalar_head_rejects_non_finite_output() {
        let outputs: TVec<TValue> = tvec![tract_ndarray::arr1(&[f32::NAN]).into_tensor().into()];

        let err = collect_scalar_head(&outputs, 0, 1, "test-model", "anomaly")
            .expect_err("non-finite scalar output should be rejected");

        assert!(matches!(err, MLError::RuntimeFailed { .. }), "got {err:?}");
    }

    #[test]
    fn collect_matrix_rows_rejects_short_output() {
        let output = tract_ndarray::arr2(&[[0.2f32, 0.8]]);

        let err = collect_matrix_rows(output.view().into_dyn(), 2, "test-model", "classifier")
            .expect_err("short matrix output should be rejected");

        assert!(matches!(err, MLError::RuntimeFailed { .. }), "got {err:?}");
    }

    #[test]
    fn collect_matrix_rows_rejects_non_finite_output() {
        let output = tract_ndarray::arr2(&[[0.2f32, f32::INFINITY]]);

        let err = collect_matrix_rows(output.view().into_dyn(), 1, "test-model", "classifier")
            .expect_err("non-finite matrix output should be rejected");

        assert!(matches!(err, MLError::RuntimeFailed { .. }), "got {err:?}");
    }

    #[test]
    fn collect_matrix_rows_returns_requested_rows_only() {
        let output = tract_ndarray::arr2(&[[0.2f32, 0.8], [0.7, 0.3]]);

        let rows = collect_matrix_rows(output.view().into_dyn(), 1, "test-model", "classifier").expect("matrix rows");

        assert_eq!(rows, vec![vec![0.2, 0.8]]);
    }

    #[test]
    fn ensure_autoencoder_output_shape_rejects_mismatch() {
        let err = ensure_autoencoder_output_shape((1, 31), (2, 31), "test-model")
            .expect_err("mismatched autoencoder output shape should be rejected");

        assert!(matches!(err, MLError::RuntimeFailed { .. }), "got {err:?}");
    }
}
