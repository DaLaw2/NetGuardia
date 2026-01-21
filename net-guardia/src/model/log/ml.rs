use macros::loggable;
use tracing;

loggable! {
    MLLog {
        #[error("Initializing Machine Learning with inference URL: {url}")]
        Initializing { url: String } => tracing::Level::INFO,

        #[error("Continuing without Machine Learning detection")]
        Skiped => tracing::Level::WARN,

        #[error("Machine Learning detection is disabled (no ml_inference_url configured)")]
        Disabled => tracing::Level::INFO,

        #[error("Machine Learning detection starting")]
        Starting => tracing::Level::INFO,

        #[error("Machine Learning detection ready")]
        Ready => tracing::Level::INFO,

        #[error("Machine Learning detection shutdown")]
        Shutdown => tracing::Level::INFO,

        #[error("Machine Learning channel disconnected")]
        ChannelDisconnected => tracing::Level::WARN,

        #[error("Failed to forward packet: {error}")]
        ForwardPacketFailed { error: String } => tracing::Level::WARN,

        #[error("Attach XDP program success")]
        AttachProgramSuccess => tracing::Level::INFO,

        #[error("Queue initialization incomplete")]
        QueueInitIncomplete => tracing::Level::WARN,

        #[error("Queue refill incomplete")]
        QueueRefillIncomplete => tracing::Level::WARN,

        #[error("No frames submit to queue")]
        NoFrameSubmit => tracing::Level::WARN,

        #[error("Queue pair {queue_id} started successfully")]
        QueuePairStarted { queue_id: u32 } => tracing::Level::INFO,

        #[error("Loading ML models from directory: {path}")]
        LoadingModels { path: String } => tracing::Level::INFO,

        #[error("ML models loaded successfully")]
        ModelsLoaded => tracing::Level::INFO,

        #[error("Loading inference configuration: {path}")]
        LoadingConfig { path: String } => tracing::Level::INFO,

        #[error("Inference configuration loaded: {features} features, {attacks} attack types")]
        ConfigLoaded { features: usize, attacks: usize } => tracing::Level::INFO,
    }
}