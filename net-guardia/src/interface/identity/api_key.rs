use async_trait::async_trait;

use crate::common::error::Error;
use crate::domain::identity::auth::Claims;
use crate::domain::identity::user::ApiKeyView;

#[async_trait]
pub trait ApiKeyRepo: Send + Sync {
    async fn validate_api_key(&self, key_hash: &str) -> Result<Option<Claims>, Error>;
    async fn list_api_keys(&self) -> Result<Vec<ApiKeyView>, Error>;
    async fn insert_api_key(&self, key_hash: &str, name: &str, permission_level: &str) -> Result<i64, Error>;
    async fn delete_api_key(&self, id: i64) -> Result<bool, Error>;
}
