use crate::model::error::Error;
use async_trait::async_trait;

/// Port for outbound notifications (alerts, reports).
/// Adapters: WebSocket (alerts), SMTP (weekly report)
#[async_trait]
pub trait NotificationPort: Send + Sync {
    async fn send_weekly_report(&self) -> Result<(), Error>;
}
