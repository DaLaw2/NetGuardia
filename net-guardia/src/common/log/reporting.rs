use macros::loggable;
use tracing;

loggable! {
    ReportingLog {
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

        #[error("Failed to read weekly report send marker: {error}")]
        WeeklyReportSnapshotReadFailed { error: String } => tracing::Level::WARN,

        #[error("Failed to persist weekly report send marker: {error}")]
        WeeklyReportSnapshotWriteFailed { error: String } => tracing::Level::WARN,

        #[error("Failed to send weekly report: {error}")]
        WeeklyReportSendFailed { error: String } => tracing::Level::ERROR,

        #[error("Send task panicked: {error}")]
        WeeklyReportSendPanicked { error: String } => tracing::Level::ERROR,

        #[error("HTML report generated at {path}")]
        HtmlReportGenerated { path: String } => tracing::Level::INFO,
    }
}
