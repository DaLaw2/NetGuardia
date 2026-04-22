use macros::loggable;

loggable! {
    CryptoLog {
        #[error("Envelope encryption enabled")]
        EnvelopeEnabled => tracing::Level::INFO,

        #[error("Envelope encryption disabled — no master key (dev mode)")]
        EnvelopeDisabled => tracing::Level::WARN,
    }
}
