use crate::model::error::Error;
use crate::model::identity::auth::Claims;

/// Type alias for API key list items: (id, name, permission_level, created_at, last_used_at)
#[allow(clippy::type_complexity)]
pub type ApiKeyListItem = (i64, String, String, String, Option<String>);

/// Identity BC — API key CRUD + validation (distinct from user login,
/// used by MCP / programmatic clients).
pub trait ApiKeyRepo: Send + Sync {
    fn validate_api_key(&self, api_key: &str) -> Result<Option<Claims>, Error>;
    fn hmac_api_key(&self, raw_key: &str) -> String;
    fn insert_api_key(&self, key_hash: &str, name: &str, permission_level: &str) -> Result<i64, Error>;
    fn list_api_keys(&self) -> Result<Vec<ApiKeyListItem>, Error>;
    fn delete_api_key(&self, id: i64) -> Result<bool, Error>;
}
