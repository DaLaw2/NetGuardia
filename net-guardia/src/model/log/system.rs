use macros::loggable;
use tracing;

loggable! {
    SystemLog {
        #[error("Online now")]
        Online => tracing::Level::INFO,

        #[error("Initializing")]
        Initializing => tracing::Level::INFO,

        #[error("Initialization completed")]
        InitializeComplete => tracing::Level::INFO,

        #[error("Termination in process")]
        Terminating => tracing::Level::INFO,

        #[error("Termination completed")]
        TerminateComplete => tracing::Level::INFO,

        #[error("Invalid configuration")]
        InvalidConfig => tracing::Level::ERROR,

        #[error("Configuration not found")]
        ConfigNotFound => tracing::Level::ERROR,

        #[error("Traffic logging mode enabled — writing packets to: {path}")]
        TrafficLoggingEnabled { path: String } => tracing::Level::INFO,

        #[error("Setup not complete — running in setup mode")]
        SetupMode => tracing::Level::INFO,

        #[error("Setup wizard completed — starting full system initialization")]
        SetupCompleted => tracing::Level::INFO,

        #[error("Config reloaded from DB: ingress={ingress}, egress={egress}")]
        ConfigReloaded { ingress: String, egress: String } => tracing::Level::INFO,

        #[error("Full system initialization complete — all services running")]
        FullInitComplete => tracing::Level::INFO,

        #[error("Default admin user created with password 'admin' — password will be set during setup wizard")]
        DefaultAdminCreated => tracing::Level::INFO,

        #[error("Shutdown signal received during setup mode")]
        ShutdownDuringSetup => tracing::Level::INFO,

        #[error("Setup server stopped, starting full system...")]
        SetupServerStopped => tracing::Level::INFO,

        #[error("ML → SOAR bridge started")]
        MlSoarBridgeStarted => tracing::Level::INFO,

        #[error("ML→SOAR bridge lagged by {count} events")]
        MlSoarBridgeLagged { count: u64 } => tracing::Level::WARN,

        #[error("ML alert channel closed, SOAR bridge shutting down")]
        MlAlertChannelClosed => tracing::Level::INFO,

        #[error("Unknown ML attack type '{attack_type}', mapping to 'threat_detected'")]
        UnknownMlAttackType { attack_type: String } => tracing::Level::DEBUG,

        #[error("Enforce mode changed to: {mode}")]
        EnforceModeChanged { mode: String } => tracing::Level::INFO,

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

        #[error("Telegram alerts not available: {reason}. Alerts disabled.")]
        TelegramUnavailable { reason: String } => tracing::Level::WARN,

        #[error("GeoIP database not available: {reason}. Country lookups disabled.")]
        GeoIpUnavailable { reason: String } => tracing::Level::WARN,

        #[error("Failed to restore DNS domain '{domain}': {error}")]
        DnsRestoreFailed { domain: String, error: String } => tracing::Level::WARN,

        #[error("Failed to restore geo-blocked countries: {error}")]
        GeoRestoreFailed { error: String } => tracing::Level::WARN,

        #[error("Failed to restore rate limit '{key}': {error}")]
        RateLimitRestoreFailed { key: String, error: String } => tracing::Level::WARN,

        #[error("Unknown ACL direction '{direction}', skipping")]
        AclUnknownDirection { direction: String } => tracing::Level::WARN,

        #[error("Unknown ACL list type '{list_type}', skipping")]
        AclUnknownListType { list_type: String } => tracing::Level::WARN,

        #[error("Failed to parse IPv4 address '{address}': {error}")]
        AclIpv4ParseFailed { address: String, error: String } => tracing::Level::WARN,

        #[error("Failed to parse IPv6 address '{address}': {error}")]
        AclIpv6ParseFailed { address: String, error: String } => tracing::Level::WARN,

        #[error("Unknown IP version {version}, skipping")]
        AclUnknownIpVersion { version: i32 } => tracing::Level::WARN,

        #[error("Failed to restore ACL rule ({direction} {list_type} {address}:{port}): {error}")]
        AclRuleRestoreFailed { direction: String, list_type: String, address: String, port: u16, error: String } => tracing::Level::WARN,

    }
}
