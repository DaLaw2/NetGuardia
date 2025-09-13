use std::path::PathBuf;

use macros::traceable;

traceable! {
    IOError {
        #[error("Failed to create directory: {path}")]
        CreateDirectoryFailed { path: PathBuf } => tracing::Level::ERROR,
    }
}
