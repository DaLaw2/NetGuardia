use macros::loggable;
use tracing;

loggable! {
    HttpLog {
        #[error("Health WebSocket lagged, skipped {skipped} messages")]
        WebSocketLagged { skipped: u64 } => tracing::Level::WARN,
    }
}
