use macros::traceable;

traceable! {
    NotificationError {
        #[error("SMTP connection failed: {err}")]
        SmtpConnectionFailed => tracing::Level::ERROR,

        #[error("SMTP authentication failed: {err}")]
        SmtpAuthFailed => tracing::Level::ERROR,

        #[error("Failed to send email: {err}")]
        SmtpSendFailed => tracing::Level::ERROR,

        #[error("Invalid {field} email address: {err}")]
        InvalidAddress { field: String } => tracing::Level::WARN,

        #[error("Failed to build email message: {err}")]
        MessageBuildFailed => tracing::Level::ERROR,

        #[error("Telegram notification error: {err}")]
        TelegramRequestFailed => tracing::Level::ERROR,

        #[no_source]
        #[error("Telegram HTTP {status}: {body}")]
        TelegramHttpError { status: u16, body: String } => tracing::Level::ERROR,

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
