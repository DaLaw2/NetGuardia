use async_trait::async_trait;

use crate::common::error::Error;

#[async_trait]
pub trait SetupRepo: Send + Sync {
    async fn complete_setup_atomically(
        &self,
        config_values: Vec<(String, String)>,
        secrets: Vec<(String, String)>,
        notification_configs: Vec<(String, String)>,
        admin_username: &str,
        password_hash: &str,
    ) -> Result<(), Error>;
}
