use macros::traceable;

traceable! {
    NotificationError {
        #[no_source]
        #[error("SMTP connection failed: {reason}")]
        SmtpConnectionFailed { reason: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("SMTP authentication failed: {reason}")]
        SmtpAuthFailed { reason: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Failed to send email: {reason}")]
        SmtpSendFailed { reason: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Invalid email address: {reason}")]
        InvalidAddress { reason: String } => tracing::Level::WARN,

        #[no_source]
        #[error("Failed to build email message: {reason}")]
        MessageBuildFailed { reason: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Telegram API error: {reason}")]
        TelegramApiError { reason: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Telegram authentication failed (invalid bot token)")]
        TelegramAuthError => tracing::Level::ERROR,

        #[no_source]
        #[error("Telegram chat not found: {chat_id}")]
        TelegramChatNotFound { chat_id: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Telegram rate limited, retry after {retry_after_secs}s")]
        TelegramRateLimited { retry_after_secs: u64 } => tracing::Level::WARN,

        #[no_source]
        #[error("Notification send timed out")]
        Timeout => tracing::Level::ERROR,

        #[no_source]
        #[error("Notification not configured: {channel}")]
        NotConfigured { channel: String } => tracing::Level::WARN,
    }
}
