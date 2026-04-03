use macros::loggable;

loggable! {
    CryptoLog {
        #[error("Envelope encryption enabled")]
        EnvelopeEnabled => tracing::Level::INFO,

        #[error("Envelope encryption disabled — no master key (dev mode)")]
        EnvelopeDisabled => tracing::Level::WARN,

        #[error("Migrated secret: {key}")]
        SecretMigrated { key: String } => tracing::Level::INFO,

        #[error("Secret migration complete: {count} secrets encrypted")]
        MigrationComplete { count: usize } => tracing::Level::INFO,

        #[error("Secret migration skipped — already done")]
        MigrationSkipped => tracing::Level::DEBUG,
    }
}
