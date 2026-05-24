use macros::loggable;

loggable! {
    CryptoLog {
        #[error("Envelope encryption enabled")]
        EnvelopeEnabled => tracing::Level::INFO,

        #[error("Envelope encryption disabled — no master key (dev mode)")]
        EnvelopeDisabled => tracing::Level::WARN,

        #[error("NETGUARDIA_DB_KEY is not set — database will NOT be encrypted (dev mode)")]
        DbEncryptionDisabled => tracing::Level::WARN,

        #[error("NETGUARDIA_SECRETS_KEY is not set — API key HMAC derives from NETGUARDIA_DB_KEY")]
        ApiKeyHmacUsingDbKey => tracing::Level::WARN,
    }
}
