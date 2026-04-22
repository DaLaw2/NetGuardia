use std::path::PathBuf;

use macros::traceable;

traceable! {
    IOError {
        #[error("Failed to create directory: {path}")]
        CreateDirectoryFailed { path: PathBuf } => tracing::Level::ERROR,

        #[error("Failed to write file: {path}")]
        WriteFileFailed { path: PathBuf } => tracing::Level::ERROR,
    }
}
