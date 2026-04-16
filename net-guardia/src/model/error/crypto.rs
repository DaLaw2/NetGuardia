use macros::traceable;

traceable! {
    CryptoError {
        #[error("Encryption failed: {err}")]
        EncryptionFailed => tracing::Level::ERROR,

        #[error("Decryption failed: {err}")]
        DecryptionFailed => tracing::Level::ERROR,

        #[error("Failed to parse secret envelope: {err}")]
        EnvelopeParseFailed => tracing::Level::ERROR,

        #[no_source]
        #[error("Unsupported envelope version: {version}")]
        UnsupportedEnvelopeVersion { version: u64 } => tracing::Level::ERROR,

        #[no_source]
        #[error("Missing envelope field: {field}")]
        MissingEnvelopeField { field: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Envelope algorithm 'none' rejected in production mode (encryption key is set)")]
        AlgNoneRejected => tracing::Level::ERROR,

        #[no_source]
        #[error("Invalid envelope nonce length")]
        InvalidNonceLength => tracing::Level::ERROR,

        #[no_source]
        #[error("Unsupported envelope algorithm: {alg}")]
        UnsupportedAlgorithm { alg: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Master key not available")]
        MasterKeyUnavailable => tracing::Level::WARN,
    }
}
