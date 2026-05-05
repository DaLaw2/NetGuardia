use async_trait::async_trait;

use crate::domain::common::error::Error;
use crate::domain::identity::auth::Claims;
use crate::domain::identity::user::ApiKeyView;

/// Identity BC — API key CRUD + validation (distinct from user login,
/// used by MCP / programmatic clients).
#[async_trait]
pub trait ApiKeyRepo: Send + Sync {
    async fn validate_api_key(&self, api_key: &str) -> Result<Option<Claims>, Error>;
    fn hmac_api_key(&self, raw_key: &str) -> String;
    async fn insert_api_key(&self, key_hash: &str, name: &str, permission_level: &str) -> Result<i64, Error>;
    async fn list_api_keys(&self) -> Result<Vec<ApiKeyView>, Error>;
    async fn delete_api_key(&self, id: i64) -> Result<bool, Error>;
}
