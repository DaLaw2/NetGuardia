use async_trait::async_trait;

use crate::domain::common::error::Error;

#[async_trait]
pub trait ConfigRepo: Send + Sync {
    async fn get_config_value(&self, key: &str) -> Result<Option<String>, Error>;
    async fn set_config_value(&self, key: &str, value: &str) -> Result<(), Error>;
    async fn get_app_secret(&self, key: &str) -> Result<Option<String>, Error>;
    async fn set_app_secret(&self, key: &str, plaintext: &str) -> Result<(), Error>;
    async fn get_notification_config(&self, channel: &str) -> Result<Option<String>, Error>;
    async fn set_notification_config(&self, channel: &str, config_json: &str) -> Result<(), Error>;
    async fn update_config_values_atomically(
        &self,
        config_values: Vec<(String, String)>,
        secrets: Vec<(String, String)>,
    ) -> Result<(), Error>;
}
