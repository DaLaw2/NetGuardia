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
    }
}
