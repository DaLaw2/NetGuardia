use macros::traceable;

traceable! {
    ReportError {
        #[no_source]
        #[error("SMTP is not configured")]
        SmtpNotConfigured => tracing::Level::WARN,

        #[no_source]
        #[error("No SMTP recipient configured")]
        RecipientMissing => tracing::Level::WARN,

        #[error("Failed to read SMTP settings: {err}")]
        SettingsReadFailed => tracing::Level::ERROR,

        #[error("Failed to generate report: {err}")]
        GenerationFailed => tracing::Level::ERROR,

        #[error("Failed to send report: {err}")]
        SendFailed => tracing::Level::ERROR,

        #[error("Report send task failed: {err}")]
        SendTaskFailed => tracing::Level::ERROR,

        #[error("Invalid report snapshot '{key}' value '{value}': {err}")]
        SnapshotParseFailed { key: String, value: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Invalid report snapshot '{key}' shape: expected {expected}")]
        SnapshotShapeInvalid { key: String, expected: String } => tracing::Level::ERROR,
    }
}
