use macros::loggable;
use tracing;

loggable! {
    MachineLeraningLog {
        #[error("Initializing Machine Learning with inference URL: {url}")]
        Initializing { url: String } => tracing::Level::INFO,

        #[error("Machine Learning detection is disabled (no ml_inference_url configured)")]
        Disabled => tracing::Level::INFO,

        #[error("Machine Learning detection starting")]
        Starting => tracing::Level::INFO,

        #[error("Machine Learning detection ready")]
        Ready => tracing::Level::INFO,

        #[error("Machine Learning detection shutdown")]
        Shutdown => tracing::Level::INFO,
    }
}
