use macros::loggable;
use tracing;

loggable! {
    MiscLog {
        #[error("NETGUARDIA_DB_KEY is not set — database will NOT be encrypted (dev mode)")]
        DbEncryptionDisabled => tracing::Level::WARN,

        #[error("Database file exists but is neither valid plaintext nor valid encrypted — skipping migration")]
        DbMigrationSkipped => tracing::Level::ERROR,

        #[error("Migrating plaintext database to encrypted format")]
        DbMigrationStarted => tracing::Level::INFO,

        #[error("Database migration to encrypted format completed successfully")]
        DbMigrationCompleted => tracing::Level::INFO,

        #[error("Database encryption migration failed — keeping original plaintext DB: {error}")]
        DbMigrationFailed { error: String } => tracing::Level::ERROR,
    }
}
