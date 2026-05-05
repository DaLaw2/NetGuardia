use macros::traceable;

traceable! {
    MiscError {
        #[no_source]
        #[error("Failed to remove limit on locked memory, ret is: {ret}")]
        RamLimitUnlockError { ret: i32 } => tracing::Level::ERROR,

        #[error("Failed to serialize data")]
        SerializeError => tracing::Level::ERROR,

        #[error("Failed to open GeoIP database '{path}': {err}")]
        GeoIPDatabaseError { path: String } => tracing::Level::ERROR,

        #[error("Failed to create traffic log file '{path}': {err}")]
        TrafficLogCreateError { path: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("DNS label length out of range: {len} (must be 1..64)")]
        DnsLabelOutOfRange { len: usize } => tracing::Level::WARN,

        #[no_source]
        #[error("DNS domain name too long: '{domain}'")]
        DnsDomainTooLong { domain: String } => tracing::Level::WARN,

        #[no_source]
        #[error("Validation error: {message}")]
        ValidationError { message: String } => tracing::Level::WARN,
    }
}
