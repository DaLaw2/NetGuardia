use macros::loggable;
use tracing;

loggable! {
    MiscLog {
        #[error("NETGUARDIA_DB_KEY is not set — database will NOT be encrypted (dev mode)")]
        DbEncryptionDisabled => tracing::Level::WARN,
    }
}
