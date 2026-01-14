use std::path::PathBuf;

use macros::traceable;

traceable! {
    MLError {
        #[error("Initialize Machine Learning detection failed")]
        InitializeFailed => tracing::Level::ERROR,
    }
}
