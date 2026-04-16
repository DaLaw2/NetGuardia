use std::path::PathBuf;

use macros::traceable;

traceable! {
    MLError {
        #[no_source]
        #[error("Initialize Machine Learning detection failed")]
        InitializeFailed => tracing::Level::ERROR,

        #[no_source]
        #[error("Failed to load ONNX model from: {path:?}")]
        ModelLoadFailed { path: PathBuf } => tracing::Level::ERROR,

        #[no_source]
        #[error("Failed to load inference configuration from: {path:?}")]
        ConfigLoadFailed { path: PathBuf } => tracing::Level::ERROR,

        #[no_source]
        #[error("Failed to parse inference configuration: {reason}")]
        ConfigParseFailed { reason: String } => tracing::Level::ERROR,

        #[error("Failed to flush traffic log: {err}")]
        TrafficLogFlushFailed => tracing::Level::ERROR,

        #[no_source]
        #[error("Model manifest at {path:?} is invalid: {reason}")]
        ManifestInvalid { path: PathBuf, reason: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Feature count mismatch for {model:?}: manifest declares {declared}, ONNX input expects {onnx_dim}")]
        FeatureMismatch { model: PathBuf, declared: usize, onnx_dim: usize } => tracing::Level::ERROR,

        #[no_source]
        #[error("Unknown feature '{name}' — not registered in FEATURE_REGISTRY")]
        UnknownFeature { name: String } => tracing::Level::ERROR,
    }
}
