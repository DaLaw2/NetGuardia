use macros::loggable;
use tracing;

loggable! {
    NotificationLog {
        #[error("Telegram alerts not available: {reason}. Alerts disabled.")]
        TelegramUnavailable { reason: String } => tracing::Level::WARN,

        #[error("Telegram rate limited, retrying after {retry_after}s (attempt {attempt}/{max})")]
        TelegramRateLimitedRetry { retry_after: u64, attempt: u32, max: u32 } => tracing::Level::WARN,

        #[error("Telegram not configured, skipping alert")]
        TelegramNotConfiguredSkipped => tracing::Level::DEBUG,

        #[error("Telegram rate limit reached ({max_messages} per {window_secs}s), dropping alert for IP {source_ip}")]
        TelegramLocalRateLimitDropped { max_messages: u32, window_secs: u32, source_ip: String } => tracing::Level::WARN,
    }
}
