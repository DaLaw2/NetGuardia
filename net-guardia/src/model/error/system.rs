use macros::traceable;

traceable! {
    SystemError {
        #[no_source]
        #[error("Unable to run as administrator")]
        RunAsAdminFailed => tracing::Level::ERROR,

        #[no_source]
        #[error("Invalid configuration")]
        InvalidConfig => tracing::Level::ERROR,

        #[error("Configuration not found")]
        ConfigNotFound => tracing::Level::ERROR,

        #[error("Failed to terminate instance")]
        TerminateError => tracing::Level::ERROR,

        #[no_source]
        #[error("Failed to send shutdown signal")]
        ShutdownSignalFailed => tracing::Level::ERROR,

        #[error("Unexcepted thread panic")]
        ThreadPanic => tracing::Level::ERROR,

        #[error("Unexcepted error")]
        UnexpectError => tracing::Level::ERROR,

        #[no_source]
        #[error("Unknown error")]
        UnknownError => tracing::Level::ERROR,
    }
}
