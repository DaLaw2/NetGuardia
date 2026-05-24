use async_trait::async_trait;

use crate::common::error::Error;

#[async_trait]
pub trait SystemStateRepo: Send + Sync {
    async fn get_system_state(&self, key: &str) -> Result<Option<String>, Error>;
}
