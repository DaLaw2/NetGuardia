use macros::loggable;
use tracing;

loggable! {
    SystemLog {
        #[error("Online now")]
        Online => tracing::Level::INFO,

        #[error("Initializing")]
        Initializing => tracing::Level::INFO,

        #[error("Initialization completed")]
        InitializeComplete => tracing::Level::INFO,

        #[error("Termination in process")]
        Terminating => tracing::Level::INFO,

        #[error("Termination completed")]
        TerminateComplete => tracing::Level::INFO,

        #[error("Invalid configuration")]
        InvalidConfig => tracing::Level::ERROR,

        #[error("Configuration not found")]
        ConfigNotFound => tracing::Level::ERROR,

        #[error("Traffic logging mode enabled — writing packets to: {path}")]
        TrafficLoggingEnabled { path: String } => tracing::Level::INFO,
    }
}
