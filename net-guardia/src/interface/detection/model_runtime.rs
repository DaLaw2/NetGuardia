use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::domain::detection::error::MLError;
use crate::domain::detection::manifest::{OutputHeadSpec, StageKind};

#[derive(Debug, Clone)]
pub enum RuntimeTensor {
    Scalar { name: String, values: Vec<f32> },
    Matrix { name: String, rows: Vec<Vec<f32>> },
}

pub trait ModelRuntime: Send + Sync {
    fn run_stage_batch(
        &self,
        rows: &[Vec<f32>],
        batch_size: usize,
        n_features: usize,
        stage_kind: StageKind,
        output_heads: &[OutputHeadSpec],
    ) -> Result<Vec<RuntimeTensor>, MLError>;
}

pub trait ModelRuntimeLoader: Send + Sync {
    fn load(
        &self,
        model_path: &Path,
        model_name: &str,
        features: usize,
        batch_size: usize,
        timeout: Duration,
    ) -> Result<Arc<dyn ModelRuntime>, MLError>;
}
