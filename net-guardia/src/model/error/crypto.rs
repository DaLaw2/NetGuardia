use macros::traceable;

traceable! {
    CryptoError {
        #[no_source]
        #[error("Encryption failed: {reason}")]
        EncryptionFailed { reason: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Decryption failed: {reason}")]
        DecryptionFailed { reason: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Invalid secret envelope: {reason}")]
        InvalidEnvelope { reason: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Master key not available")]
        MasterKeyUnavailable => tracing::Level::WARN,
    }
}
