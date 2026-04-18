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

        #[error("API-triggered shutdown initiated")]
        ApiShutdown => tracing::Level::INFO,

        #[error("API-triggered restart initiated — process will exit and systemd will restart")]
        ApiRestart => tracing::Level::INFO,

        #[error("ML drift detected: {count} features drifted, max deviation {deviation:.2}σ")]
        DriftDetected { count: usize, deviation: f64 } => tracing::Level::WARN,

        #[error("eBPF bring-up failed — continuing without data plane: {details}")]
        EbpfBringupFailed { details: String } => tracing::Level::ERROR,

        #[error("Telegram rate limited, retrying after {retry_after}s (attempt {attempt}/{max})")]
        TelegramRateLimitedRetry { retry_after: u64, attempt: u32, max: u32 } => tracing::Level::WARN,

        #[error("Telegram not configured, skipping alert")]
        TelegramNotConfiguredSkipped => tracing::Level::DEBUG,

        #[error("Telegram rate limit reached ({max_messages} per {window_secs}s), dropping alert for IP {source_ip}")]
        TelegramLocalRateLimitDropped { max_messages: u32, window_secs: u32, source_ip: String } => tracing::Level::WARN,

        #[error("Stats aggregator started (1h interval)")]
        StatsAggregatorStarted => tracing::Level::INFO,

        #[error("Initial stats aggregation failed: {error}")]
        InitialStatsAggregationFailed { error: String } => tracing::Level::ERROR,

        #[error("Stats aggregation failed: {error}")]
        StatsAggregationFailed { error: String } => tracing::Level::ERROR,

        #[error("Stats aggregated: {threats} threats, {blocks} blocks, {unblocks} unblocks, {rules} active rules")]
        StatsAggregated { threats: u64, blocks: u64, unblocks: u64, rules: u64 } => tracing::Level::INFO,

        #[error("Weekly report scheduler started")]
        WeeklyReportSchedulerStarted => tracing::Level::INFO,

        #[error("Weekly report window reached — preparing report")]
        WeeklyReportWindowReached => tracing::Level::INFO,

        #[error("SMTP is not configured (missing smtp_host/port/username/password). Skipping weekly report.")]
        SmtpNotConfigured => tracing::Level::WARN,

        #[error("Failed to read SMTP settings: {error}")]
        SmtpSettingsReadFailed { error: String } => tracing::Level::ERROR,

        #[error("No smtp_recipient configured. Skipping weekly report.")]
        SmtpRecipientMissing => tracing::Level::WARN,

        #[error("Failed to generate weekly report: {error}")]
        WeeklyReportGenerationFailed { error: String } => tracing::Level::ERROR,

        #[error("Weekly report sent successfully")]
        WeeklyReportSent => tracing::Level::INFO,

        #[error("Failed to send weekly report: {error}")]
        WeeklyReportSendFailed { error: String } => tracing::Level::ERROR,

        #[error("Send task panicked: {error}")]
        WeeklyReportSendPanicked { error: String } => tracing::Level::ERROR,

        #[error("HTML report generated at {path}")]
        HtmlReportGenerated { path: String } => tracing::Level::INFO,

        #[error("Cleaned {count} stale model-upload staging directories")]
        StagingOrphansCleaned { count: u64 } => tracing::Level::INFO,

        #[error("Staging-orphan sweep failed: {error}")]
        StagingOrphansSweepFailed { error: String } => tracing::Level::WARN,
    }
}
