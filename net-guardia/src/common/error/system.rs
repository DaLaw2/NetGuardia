use macros::traceable;

traceable! {
    SystemError {
        #[no_source]
        #[error("Invalid configuration")]
        InvalidConfig => tracing::Level::ERROR,

        #[no_source]
        #[error("Invalid configuration field: {field}")]
        InvalidConfigField { field: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Invalid setup input: {message}")]
        InvalidSetupInput { message: String } => tracing::Level::WARN,

        #[no_source]
        #[error("Setup already completed")]
        SetupAlreadyComplete => tracing::Level::WARN,

        #[no_source]
        #[error("Setup interrupted")]
        SetupInterrupted => tracing::Level::INFO,

        #[no_source]
        #[error("Invalid pipeline stage '{stage}'. Valid stages: {valid_stages}")]
        InvalidPipelineStage { stage: String, valid_stages: String } => tracing::Level::WARN,

        #[error("Configuration file not found")]
        ConfigNotFound => tracing::Level::ERROR,

        #[error("Unexpected error")]
        UnexpectedError => tracing::Level::ERROR,

        #[error("HTTP server error")]
        HttpServerError => tracing::Level::ERROR,

        #[error("Failed to set user groups")]
        SetUserGroupsFailed => tracing::Level::WARN,

        #[error("Failed to update admin password during setup: {err}")]
        SetupPasswordUpdateFailed => tracing::Level::ERROR,

        #[error("Failed to mark setup as complete: {err}")]
        SetupCompleteFlagFailed => tracing::Level::ERROR,
    }
}
