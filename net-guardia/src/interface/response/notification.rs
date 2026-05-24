use std::sync::Arc;

use async_trait::async_trait;

use crate::common::error::Error;
use crate::domain::common::notification::AlertPayload;

#[async_trait]
pub trait AlertNotifier: Send + Sync {
    async fn send_alert(&self, payload: &AlertPayload) -> Result<(), Error>;
    async fn send_test_message(&self) -> Result<(), Error>;
}

pub trait AlertNotifierFactory: Send + Sync {
    fn create(&self) -> Result<Arc<dyn AlertNotifier>, Error>;
}
