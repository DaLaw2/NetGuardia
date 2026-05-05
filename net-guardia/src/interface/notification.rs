use std::sync::Arc;

use async_trait::async_trait;

use crate::domain::common::error::Error;
use crate::domain::common::notification::AlertPayload;

/// Port for sending instant alert notifications (Telegram, future channels).
/// Adapters: TelegramAdapter
#[async_trait]
pub trait AlertNotifier: Send + Sync {
    async fn send_alert(&self, payload: &AlertPayload) -> Result<(), Error>;
    async fn send_test_message(&self) -> Result<(), Error>;
}

/// Port for constructing an `AlertNotifier` on demand.
///
/// `NotificationService::test_telegram` needs to test the *current* DB config,
/// which can have been set after the service was wired. A pre-constructed
/// notifier wouldn't reflect the new credentials, and `core/` cannot reach
/// into `adapter/telegram` to build one. The factory inverts this: the
/// implementation lives in the adapter layer, the core service depends only
/// on this trait, and each call gets a fresh notifier reading the latest config.
pub trait AlertNotifierFactory: Send + Sync {
    fn create(&self) -> Result<Arc<dyn AlertNotifier>, Error>;
}
