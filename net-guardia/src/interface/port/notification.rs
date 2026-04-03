use crate::model::error::Error;
use async_trait::async_trait;

/// Alert notification data sent by SOAR engine.
#[derive(Debug, Clone)]
pub struct AlertPayload {
    pub source_ip: String,
    pub dest_ip: String,
    pub country: Option<String>,
    pub threat_type: String,
    pub confidence: f32,
    pub action_description: String,
    pub timestamp: String,
}

/// Port for sending instant alert notifications (Telegram, future channels).
/// Adapters: TelegramAdapter
#[async_trait]
pub trait AlertNotifier: Send + Sync {
    async fn send_alert(&self, payload: &AlertPayload) -> Result<(), Error>;
    async fn send_test_message(&self) -> Result<(), Error>;
}

/// Port for notification channel configuration (Telegram, email, etc.).
pub trait NotificationConfigPort: Send + Sync {
    fn get_notification_config(&self, channel: &str) -> Result<Option<String>, Error>;
    fn set_notification_config(&self, channel: &str, config_json: &str) -> Result<(), Error>;
}
