use macros::traceable;

traceable! {
    SystemError {
        #[no_source]
        #[error("Unable to run as administrator")]
        RunAsAdminFailed => tracing::Level::ERROR,

        #[no_source]
        #[error("Invalid configuration")]
        InvalidConfig => tracing::Level::ERROR,

        #[error("Configuration file not found")]
        ConfigNotFound => tracing::Level::ERROR,

        #[error("Failed to terminate instance")]
        TerminateError => tracing::Level::ERROR,

        #[no_source]
        #[error("Failed to send shutdown signal")]
        ShutdownSignalFailed => tracing::Level::ERROR,

        #[error("Unexpected thread panic")]
        ThreadPanic => tracing::Level::ERROR,

        #[error("Unexpected error")]
        UnexpectedError => tracing::Level::ERROR,

        #[error("Failed to reload config after setup")]
        ConfigReloadFailed => tracing::Level::ERROR,

        #[error("HTTP server error")]
        HttpServerError => tracing::Level::ERROR,

        #[error("Failed to set user groups")]
        SetUserGroupsFailed => tracing::Level::WARN,

        #[error("Failed to bridge ML alert to SOAR")]
        MlSoarBridgeFailed => tracing::Level::WARN,

        #[error("Failed to store XDP mode")]
        XdpModeStoreFailed => tracing::Level::WARN,

        #[error("Failed to update admin password during setup: {err}")]
        SetupPasswordUpdateFailed => tracing::Level::ERROR,

        #[error("Failed to mark setup as complete: {err}")]
        SetupCompleteFlagFailed => tracing::Level::ERROR,

        #[error("Failed to publish drift detected event")]
        DriftEventPublishFailed => tracing::Level::WARN,
    }
}
