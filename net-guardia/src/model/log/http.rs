use macros::loggable;
use tracing;

loggable! {
    HttpLog {
        #[error("Health WebSocket lagged, skipped {skipped} messages")]
        WebSocketLaged { skipped: u64 } => tracing::Level::WARN,
    }
}
