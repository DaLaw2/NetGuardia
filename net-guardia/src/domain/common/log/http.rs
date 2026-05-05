use macros::loggable;
use tracing;

loggable! {
    HttpLog {
        #[error("Health WebSocket lagged, skipped {skipped} messages")]
        WebSocketLagged { skipped: u64 } => tracing::Level::WARN,

        #[error("Failed to bind setup server to port {port}: {error}. Falling back to port {fallback_port}.")]
        SetupBindFallback { port: u16, error: String, fallback_port: u16 } => tracing::Level::WARN,

        #[error("Setup HTTP server error: {error}")]
        SetupServerError { error: String } => tracing::Level::ERROR,
    }
}
