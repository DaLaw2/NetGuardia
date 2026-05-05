use macros::loggable;

loggable! {
    CliLog {
        #[error("Decrypting {src} → {dst}")]
        DecryptStarted { src: String, dst: String } => tracing::Level::INFO,

        #[error("Done. Decrypted database written to {dst}")]
        DecryptCompleted { dst: String } => tracing::Level::INFO,

        #[error("Decrypt failed: {err}")]
        DecryptFailed { err: String } => tracing::Level::ERROR,

        #[error("Encrypting {src} → {dst}")]
        EncryptStarted { src: String, dst: String } => tracing::Level::INFO,

        #[error("Done. Encrypted database written to {dst}")]
        EncryptCompleted { dst: String } => tracing::Level::INFO,

        #[error("Encrypt failed: {err}")]
        EncryptFailed { err: String } => tracing::Level::ERROR,

        #[error("Verifying audit_log hash chain in {db_path}")]
        VerifyStarted { db_path: String } => tracing::Level::INFO,

        #[error("OK: {count} audit_log rows verified, chain intact.")]
        VerifyOk { count: usize } => tracing::Level::INFO,

        #[error("FAIL: {err}")]
        VerifyFailed { err: String } => tracing::Level::ERROR,

        #[error("Could not open database at {db_path}: {err}")]
        DbOpenFailed { db_path: String, err: String } => tracing::Level::ERROR,

        #[error("NETGUARDIA_DB_KEY must be set for {op}")]
        MissingDbKey { op: String } => tracing::Level::ERROR,
    }
}
