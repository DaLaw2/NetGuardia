use macros::traceable;

traceable! {
    LicenseError {
        #[no_source]
        #[error("License file not found: {path}")]
        FileNotFound { path: String } => tracing::Level::WARN,

        #[error("Invalid license signature")]
        InvalidSignature => tracing::Level::ERROR,

        #[error("License has expired")]
        Expired => tracing::Level::WARN,

        #[no_source]
        #[error("License validation failed: {reason}")]
        ValidationFailed { reason: String } => tracing::Level::ERROR,
    }
}
