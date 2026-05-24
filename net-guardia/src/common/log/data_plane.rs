use macros::loggable;
use tracing;

loggable! {
    DataPlaneLog {
        #[error("GeoIP service initialized")]
        GeoIpInitialized => tracing::Level::INFO,

        #[error("Restored {count} DNS blacklist domains from database")]
        DnsBlacklistRestored { count: usize } => tracing::Level::INFO,

        #[error("Restored {count} geo-blocked countries from database")]
        GeoCountriesRestored { count: usize } => tracing::Level::INFO,

        #[error("Restored {count} rate limit settings from database")]
        RateLimitsRestored { count: usize } => tracing::Level::INFO,

        #[error("Restored {count} ACL rules from database")]
        AclRulesRestored { count: usize } => tracing::Level::INFO,

        #[error("GeoIP database not available: {reason}. Country lookups disabled.")]
        GeoIpUnavailable { reason: String } => tracing::Level::WARN,

        #[error("Failed to restore DNS domain '{domain}': {error}")]
        DnsRestoreFailed { domain: String, error: String } => tracing::Level::WARN,

        #[error("Failed to roll back DNS domain '{domain}': {error}")]
        DnsRollbackFailed { domain: String, error: String } => tracing::Level::ERROR,

        #[error("Failed to restore geo-blocked countries: {error}")]
        GeoRestoreFailed { error: String } => tracing::Level::WARN,

        #[error("Failed to restore rate limit '{key}': {error}")]
        RateLimitRestoreFailed { key: String, error: String } => tracing::Level::WARN,

        #[error("Failed to roll back rate limit '{key}': {error}")]
        RateLimitRollbackFailed { key: String, error: String } => tracing::Level::ERROR,

        #[error("Failed to parse IPv4 address '{address}': {error}")]
        AclIpv4ParseFailed { address: String, error: String } => tracing::Level::WARN,

        #[error("Failed to parse IPv6 address '{address}': {error}")]
        AclIpv6ParseFailed { address: String, error: String } => tracing::Level::WARN,

        #[error("Failed to restore ACL rule ({direction} {list_type} {address}:{port}): {error}")]
        AclRuleRestoreFailed { direction: String, list_type: String, address: String, port: u16, error: String } => tracing::Level::WARN,
    }
}
