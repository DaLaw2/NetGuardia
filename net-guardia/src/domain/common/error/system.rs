use macros::traceable;

traceable! {
    SystemError {
        #[no_source]
        #[error("Invalid configuration")]
        InvalidConfig => tracing::Level::ERROR,

        #[no_source]
        #[error("Invalid configuration field: {field}")]
        InvalidConfigField { field: String } => tracing::Level::ERROR,

        #[error("Configuration file not found")]
        ConfigNotFound => tracing::Level::ERROR,

        #[no_source]
        #[error("Failed to send shutdown signal")]
        ShutdownSignalFailed => tracing::Level::ERROR,

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
