use crate::common::error::Error;

#[async_trait::async_trait]
pub trait WebhookSender: Send + Sync {
    async fn post_json(&self, url: &str, timeout_secs: u64, payload: &serde_json::Value) -> Result<u16, Error>;
}
