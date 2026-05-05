use std::path::PathBuf;

use macros::traceable;

traceable! {
    MLError {
        #[no_source]
        #[error("Initialize Machine Learning detection failed")]
        InitializeFailed => tracing::Level::ERROR,

        #[error("Failed to load ONNX model from {path:?}: {err}")]
        ModelLoadFailed { path: PathBuf } => tracing::Level::ERROR,

        #[error("Failed to load inference configuration from {path:?}: {err}")]
        ConfigLoadFailed { path: PathBuf } => tracing::Level::ERROR,

        #[error("Failed to parse inference configuration: {err}")]
        ConfigParseFailed => tracing::Level::ERROR,

        #[error("Failed to flush traffic log: {err}")]
        TrafficLogFlushFailed => tracing::Level::ERROR,

        #[error("Model manifest at {path:?} is invalid: {err}")]
        ManifestInvalid { path: PathBuf } => tracing::Level::ERROR,

        #[no_source]
        #[error("Feature count mismatch for {model:?}: manifest declares {declared}, ONNX input expects {onnx_dim}")]
        FeatureMismatch { model: PathBuf, declared: usize, onnx_dim: usize } => tracing::Level::ERROR,

        #[no_source]
        #[error("Model load timed out after {seconds}s: {path:?}")]
        ModelLoadTimeout { path: PathBuf, seconds: u64 } => tracing::Level::ERROR,

        #[no_source]
        #[error("Unknown feature '{name}' — not registered in FEATURE_REGISTRY")]
        UnknownFeature { name: String } => tracing::Level::ERROR,

        #[error("Model watcher failed: {err}")]
        ModelWatcherFailed => tracing::Level::ERROR,
    }
}

traceable! {
    SuricataError {
        #[no_source]
        #[error("Suricata binary not found at '{path}'")]
        BinaryNotFound { path: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Suricata config not found at '{path}'")]
        ConfigNotFound { path: String } => tracing::Level::ERROR,

        #[error("Failed to spawn Suricata subprocess")]
        SpawnFailed => tracing::Level::ERROR,

        #[error("Failed to open eve.json stream at '{path}'")]
        EveOpenFailed { path: String } => tracing::Level::ERROR,
    }
}
